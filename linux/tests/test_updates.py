import base64
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from myvpn.model import MAX_DOCUMENT_BYTES
from myvpn.store import Store, StoreError
from myvpn.updates import UpdateError, cache_busted_url, decrypt_update, fetch_document, fetch_update, validate_bootstrap
from test_core import fixture


def bootstrap():
    return {"format": "myvpn-bootstrap-v1", "client": "linux", "url": "https://updates.example/profile.json",
            "key": base64.b64encode(bytes(range(32))).decode(), "minRevision": 2}


def envelope(profile=None, revision=2, *, client="linux", payload_changes=None):
    payload = {"schema": 1, "client": client, "revision": revision, "profile": profile or fixture()}
    if payload_changes:
        payload.update(payload_changes)
    nonce = bytes(range(12))
    ciphertext = AESGCM(bytes(range(32))).encrypt(nonce, json.dumps(payload).encode(),
                                                f"myvpn-update-v1\n{client}\n{revision}".encode())
    return {"format": "myvpn-update-v1", "client": client, "revision": revision,
            "nonce": base64.b64encode(nonce).decode(), "ciphertext": base64.b64encode(ciphertext).decode()}


class UpdateTests(unittest.TestCase):
    def test_successful_authenticated_update_and_equal_revision(self):
        result = decrypt_update(json.dumps(envelope()).encode(), bootstrap(), min_revision=2)
        self.assertEqual(result["revision"], 2)
        self.assertEqual(result["profile"], fixture())
        result["profile"]["host"] = "changed.example"
        self.assertEqual(decrypt_update(envelope(), bootstrap())["profile"]["host"], "203.0.113.10")

    def test_tampered_nonce_ciphertext_and_aad_rejected(self):
        for key in ("nonce", "ciphertext", "revision", "client"):
            doc = envelope()
            if key in ("nonce", "ciphertext"):
                raw = bytearray(base64.b64decode(doc[key])); raw[0] ^= 1
                doc[key] = base64.b64encode(raw).decode()
            elif key == "revision":
                doc[key] += 1
            else:
                doc[key] = "android"
            with self.subTest(key=key), self.assertRaises(UpdateError):
                decrypt_update(doc, bootstrap())

    def test_authenticated_payload_identity_schema_and_profile_checked(self):
        for changes in ({"revision": 3}, {"client": "android"}, {"schema": True}, {"schema": 2}):
            with self.subTest(changes=changes), self.assertRaises(UpdateError):
                decrypt_update(envelope(payload_changes=changes), bootstrap())
        p = fixture(); p["client"] = "mac"
        with self.assertRaises(UpdateError):
            decrypt_update(envelope(profile=p), bootstrap())
        p = fixture(); p["extraXray"][0]["outbound"]["streamSettings"]["sockopt"] = {"mark": 123}
        with self.assertRaises(UpdateError):
            decrypt_update(envelope(profile=p), bootstrap())

    def test_bootstrap_and_persisted_revision_floors_both_enforced(self):
        with self.assertRaises(UpdateError):
            decrypt_update(envelope(revision=1), bootstrap())
        with self.assertRaises(UpdateError):
            decrypt_update(envelope(revision=2), bootstrap(), min_revision=3)
        for revision in (True, 0, -1, 2.0, "2", 2**31):
            doc = envelope(); doc["revision"] = revision
            with self.subTest(revision=revision), self.assertRaises(UpdateError):
                decrypt_update(doc, bootstrap())

    def test_bootstrap_https_and_keys_strict(self):
        for url in ("http://example.com/x", "https://user@example.com/x", "https://example.com/x#f",
                    "https://example.com:8443/x", "https://example.com/x\nHeader:x"):
            b = bootstrap(); b["url"] = url
            with self.subTest(url=url), self.assertRaises(UpdateError):
                validate_bootstrap(b)
        b = bootstrap(); b["key"] = base64.b64encode(bytes(31)).decode()
        with self.assertRaises(UpdateError):
            validate_bootstrap(b)

    def test_cache_nonce_preserves_encoded_path_and_query(self):
        original = "https://example.com/a%20b/c.json?token=a%2Fb%3D&second=1"
        first = cache_busted_url(original)
        second = cache_busted_url(original)
        self.assertNotEqual(first, second)
        self.assertTrue(first.startswith(original + "&_myvpn_refresh="))
        self.assertEqual(urlsplit(first).path, "/a%20b/c.json")

    def test_fetch_once_does_not_retry_failed_authentication(self):
        doc = envelope(); doc["ciphertext"] = base64.b64encode(bytes(40)).decode()
        fetcher = mock.Mock(return_value=json.dumps(doc).encode())
        with self.assertRaises(UpdateError):
            fetch_update(bootstrap(), fetcher=fetcher)
        fetcher.assert_called_once_with(bootstrap()["url"])

    def test_https_rejects_redirect_oversize_and_partial_response(self):
        for status, declared, chunks in [(302, None, []), (200, str(MAX_DOCUMENT_BYTES + 1), []),
                                          (200, "50", [b"partial", b""]), (200, "bad", [])]:
            response = mock.Mock(status=status)
            response.getheader.return_value = declared
            response.read1.side_effect = chunks
            connection = mock.Mock()
            connection.getresponse.return_value = response
            with mock.patch("myvpn.updates.http.client.HTTPSConnection", return_value=connection):
                with self.subTest(status=status, declared=declared), self.assertRaises(UpdateError):
                    fetch_document(bootstrap()["url"])
            connection.close.assert_called_once()

    def test_https_without_length_is_still_bounded(self):
        response = mock.Mock(status=200)
        response.getheader.return_value = None
        response.read1.side_effect = [b"x" * 65536] * 16 + [b"x"]
        connection = mock.Mock()
        connection.getresponse.return_value = response
        with mock.patch("myvpn.updates.http.client.HTTPSConnection", return_value=connection), self.assertRaises(UpdateError):
            fetch_document(bootstrap()["url"])


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "private" / "state.json"
        self.store = Store(self.path, fixture(), bootstrap())

    def test_selection_persists_before_first_update(self):
        self.store.select("HY2")
        restored = Store(self.path, fixture(), bootstrap())
        self.assertEqual(restored.selected, "HY2")
        self.assertEqual(restored.revision, 2)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.path.parent.stat().st_mode & 0o777, 0o700)

    def test_profile_revision_and_removed_selection_commit_together(self):
        self.store.select("custom-vless-xhttp")
        active_snapshot = self.store.profile
        p = fixture(); p["host"] = "next.example"; p["extraXray"].pop(0)
        self.assertTrue(self.store.apply_update({"profile": p, "revision": 3}))
        restored = Store(self.path, fixture(), bootstrap())
        self.assertEqual(restored.profile["host"], "next.example")
        self.assertEqual(restored.selected, "VLESS_TCP")
        self.assertEqual(restored.revision, 3)
        self.assertEqual(active_snapshot["host"], "203.0.113.10")

    def test_failed_atomic_commit_keeps_memory_and_previous_disk_revision(self):
        self.store.select("HY2")
        before = self.path.read_bytes()
        p = fixture(); p["host"] = "next.example"
        with mock.patch("myvpn.store.os.replace", side_effect=OSError("test write failure")):
            with self.assertRaises(OSError):
                self.store.apply_update({"profile": p, "revision": 3})
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self.store.revision, 2)
        self.assertEqual(self.store.profile["host"], fixture()["host"])
        self.assertEqual(list(self.path.parent.glob(".myvpn-*")), [])

    def test_rollback_race_rejected_and_equal_revision_idempotent(self):
        update = {"profile": fixture(), "revision": 4}
        self.assertTrue(self.store.apply_update(update))
        self.assertFalse(self.store.apply_update(update))
        with self.assertRaises(StoreError):
            self.store.apply_update({"profile": fixture(), "revision": 3})
        self.assertEqual(Store(self.path, fixture(), bootstrap()).revision, 4)

    def test_wrong_client_and_mutating_returned_snapshot_cannot_replace_state(self):
        p = self.store.profile; p["host"] = "changed.example"
        self.assertEqual(self.store.profile["host"], fixture()["host"])
        p["client"] = "mac"
        with self.assertRaises(StoreError):
            self.store.apply_update({"profile": p, "revision": 3})

    def test_symlink_world_readable_and_corrupt_state_refused(self):
        self.store.select("HY2")
        target = self.path.with_name("target.json")
        self.path.rename(target)
        self.path.symlink_to(target)
        with self.assertRaises((OSError, StoreError)):
            Store(self.path, fixture(), bootstrap())
        self.path.unlink(); target.rename(self.path)
        self.path.chmod(0o644)
        with self.assertRaises(StoreError):
            Store(self.path, fixture(), bootstrap())
        self.path.chmod(0o600)
        self.path.write_text("bad json")
        with self.assertRaises(ValueError):
            Store(self.path, fixture(), bootstrap())


if __name__ == "__main__":
    unittest.main()
