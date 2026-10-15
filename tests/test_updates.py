import base64
import copy
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("publish_updates", ROOT / "tools/publish_updates.py")
updates = importlib.util.module_from_spec(spec)
spec.loader.exec_module(updates)


def fixture(client="android"):
    profile = json.loads((ROOT / "config/example.json").read_text())
    profile.update(version=2, client=client)
    profile["vless"]["publicKey"] = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
    for field in ("privateKey", "serverPublicKey", "presharedKey"):
        profile["awg"][field] = base64.b64encode(bytes(range(32))).decode()
    profile["hy2"].update(auth="PRIVATE-password-☃", obfsPassword="PRIVATE-salamander", pinSha256="ab" * 32)
    return profile


def bootstrap(client="android"):
    return {"format": updates.BOOTSTRAP_FORMAT, "client": client,
            "url": f"https://raw.githubusercontent.com/Tigersmechom/my_vpn/main/updates/{client}.json",
            "key": base64.b64encode(bytes(range(32))).decode(), "minRevision": 1}


class UpdateCryptoTests(unittest.TestCase):
    def test_roundtrip_each_device_and_aad_contract(self):
        for client in updates.CLIENTS:
            p, b = fixture(client), bootstrap(client)
            envelope = updates.encrypt_update(p, b, 7)
            self.assertEqual({"format", "client", "revision", "nonce", "ciphertext"}, set(envelope))
            plaintext = AESGCM(base64.b64decode(b["key"])).decrypt(
                base64.b64decode(envelope["nonce"]), base64.b64decode(envelope["ciphertext"]),
                f"myvpn-update-v1\n{client}\n7".encode())
            self.assertEqual(json.loads(plaintext), {"schema": 1, "client": client, "revision": 7, "profile": p})
            self.assertEqual(updates.decrypt_update(envelope, b)["profile"], p)

    def test_wrong_key_tampered_ciphertext_nonce_revision_and_client_rejected(self):
        b = bootstrap()
        envelope = updates.encrypt_update(fixture(), b, 2)
        wrong = dict(b, key=base64.b64encode(bytes(reversed(range(32)))).decode())
        with self.assertRaises(updates.UpdateError):
            updates.decrypt_update(envelope, wrong)
        for field in ("ciphertext", "nonce", "revision", "client", "format"):
            changed = copy.deepcopy(envelope)
            if field in ("ciphertext", "nonce"):
                raw = bytearray(base64.b64decode(changed[field]))
                raw[0] ^= 1
                changed[field] = base64.b64encode(raw).decode()
            else:
                changed[field] = {"revision": 3, "client": "mac", "format": "other"}[field]
            with self.subTest(field=field), self.assertRaises(updates.UpdateError):
                updates.decrypt_update(changed, b)

    def test_replay_below_accepted_or_bootstrap_revision_rejected(self):
        b = bootstrap()
        envelope = updates.encrypt_update(fixture(), b, 2)
        self.assertEqual(updates.decrypt_update(envelope, b, min_revision=2)["revision"], 2)
        for args in ((b, 3), (dict(b, minRevision=3), None)):
            with self.assertRaises(updates.UpdateError):
                updates.decrypt_update(envelope, args[0], min_revision=args[1])

    def test_authenticated_payload_must_match_identity_schema_and_profile(self):
        b = bootstrap()
        base = {"schema": 1, "client": "android", "revision": 1, "profile": fixture()}
        cases = [{"schema": True}, {"schema": 2}, {"client": "mac"}, {"revision": 2},
                 {"revision": True}, {"profile": fixture("mac")}, {"profile": {"version": 2}}]
        for change in cases:
            payload = dict(base, **change)
            nonce = bytes(12)
            ciphertext = AESGCM(base64.b64decode(b["key"])).encrypt(
                nonce, json.dumps(payload).encode(), updates.associated_data("android", 1))
            envelope = {"format": updates.UPDATE_FORMAT, "client": "android", "revision": 1,
                        "nonce": base64.b64encode(nonce).decode(), "ciphertext": base64.b64encode(ciphertext).decode()}
            with self.subTest(change=list(change)), self.assertRaises(updates.UpdateError):
                updates.decrypt_update(envelope, b)

    def test_invalid_revision_key_nonce_and_json_rejected(self):
        b = bootstrap()
        for revision in (True, 0, -1, 1.5, "1", 2147483648):
            with self.subTest(revision=revision), self.assertRaises(updates.UpdateError):
                updates.encrypt_update(fixture(), b, revision)
        for key in ("!", base64.b64encode(bytes(16)).decode()):
            with self.assertRaises(updates.UpdateError):
                updates.validate_bootstrap(dict(b, key=key))
        envelope = updates.encrypt_update(fixture(), b, 1)
        for nonce in ("!", base64.b64encode(bytes(11)).decode()):
            with self.assertRaises(updates.UpdateError):
                updates.decrypt_update(dict(envelope, nonce=nonce), b)
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{bad', b'\xff'):
            with self.assertRaises(updates.UpdateError):
                updates.parse_json(raw)

    def test_optional_future_xray_fields_survive_encryption(self):
        profile = fixture()
        profile["xray"] = {"future-option": {"enabled": True}}
        envelope = updates.encrypt_update(profile, bootstrap(), 1)
        self.assertEqual(updates.decrypt_update(envelope, bootstrap())["profile"], profile)

    def test_oversize_utf8_profile_rejected_before_output_and_feed_fits_client_limit(self):
        profile = fixture()
        # Bound encoded UTF-8 bytes, not Unicode character count; base64 adds overhead.
        profile["future"] = "☃" * (updates.MAX_DOCUMENT_BYTES // 8)
        envelope = updates.encrypt_update(profile, bootstrap(), 1)
        wire = updates._json_bytes(envelope)
        self.assertLessEqual(len(wire), 1024 * 1024)
        self.assertEqual(updates.decrypt_update(updates.parse_json(wire), bootstrap())["profile"], profile)
        profile["future"] = "☃" * (updates.MAX_DOCUMENT_BYTES // 4)
        with self.assertRaises(updates.UpdateError):
            updates.encrypt_update(profile, bootstrap(), 1)
        with self.assertRaises(updates.UpdateError):
            updates.parse_json(b" " * (1024 * 1024 + 1))


class UpdatePublisherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.profile, self.bootstrap, self.output = (root / x for x in ("profile.json", "bootstrap.json", "updates/android.json"))
        self.profile.write_text(json.dumps(fixture()))

    def publish(self, init=True):
        return updates.publish(self.profile, self.bootstrap, self.output,
                               init_url=bootstrap()["url"] if init else None)

    def test_publication_increments_with_same_key_and_private_permissions(self):
        first = self.publish()
        original_bootstrap = self.bootstrap.read_bytes()
        self.assertEqual(first["revision"], 1)
        second = self.publish(init=False)
        self.assertEqual(second["revision"], 2)
        self.assertNotEqual(first["nonce"], second["nonce"])
        self.assertEqual(self.bootstrap.read_bytes(), original_bootstrap)
        self.assertEqual(stat.S_IMODE(self.bootstrap.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o644)
        b = updates.read_json(self.bootstrap)
        self.assertEqual(updates.decrypt_update(second, b)["profile"], fixture())
        with self.assertRaises(updates.UpdateError):
            updates.decrypt_update(first, b, min_revision=second["revision"])

    def test_public_output_never_contains_profile_or_key(self):
        self.publish()
        raw = self.output.read_text()
        b = updates.read_json(self.bootstrap)
        for value in (fixture()["host"], fixture()["hy2"]["auth"], fixture()["awg"]["privateKey"], b["key"], '"profile"', '"vless"'):
            self.assertNotIn(value, raw)

    def test_corrupt_previous_file_refused_without_replacing_either_file(self):
        self.publish()
        original_bootstrap = self.bootstrap.read_bytes()
        self.output.write_text('{"revision":900}')
        original_output = self.output.read_bytes()
        with self.assertRaises(updates.UpdateError):
            self.publish(init=False)
        self.assertEqual(self.output.read_bytes(), original_output)
        self.assertEqual(self.bootstrap.read_bytes(), original_bootstrap)

    def test_missing_bootstrap_does_not_rotate_key_for_existing_feed(self):
        self.publish()
        original = self.output.read_bytes()
        self.bootstrap.unlink()
        with self.assertRaises(updates.UpdateError):
            self.publish()
        self.assertFalse(self.bootstrap.exists())
        self.assertEqual(self.output.read_bytes(), original)

    def test_existing_key_and_url_cannot_be_silently_changed(self):
        self.publish()
        b = updates.read_json(self.bootstrap)
        b["key"] = base64.b64encode(bytes(32)).decode()
        self.bootstrap.write_text(json.dumps(b))
        before = self.output.read_bytes()
        with self.assertRaises(updates.UpdateError):
            self.publish(init=False)
        self.assertEqual(self.output.read_bytes(), before)
        with self.assertRaises(updates.UpdateError):
            updates.publish(self.profile, self.bootstrap, self.output, init_url="https://example.org/other")

    def test_first_publication_requires_https_url_and_valid_profile(self):
        with self.assertRaises(updates.UpdateError):
            self.publish(init=False)
        for url in ("http://example.org/feed", "https://user:pass@example.org/feed", "file:///feed"):
            with self.assertRaises(updates.UpdateError):
                updates.publish(self.profile, self.bootstrap, self.output, init_url=url)
        profile = fixture()
        profile["hy2"]["auth"] = ""
        self.profile.write_text(json.dumps(profile))
        with self.assertRaises(updates.UpdateError):
            self.publish()
        self.assertFalse(self.bootstrap.exists())
        self.assertFalse(self.output.exists())

    def test_revision_overflow_and_client_mismatch_leave_feed_intact(self):
        self.publish()
        b = updates.read_json(self.bootstrap)
        maximum = updates.encrypt_update(fixture(), b, updates.MAX_REVISION)
        self.output.write_text(json.dumps(maximum))
        before = self.output.read_bytes()
        with self.assertRaises(updates.UpdateError):
            self.publish(init=False)
        self.assertEqual(self.output.read_bytes(), before)
        self.profile.write_text(json.dumps(fixture("mac")))
        with self.assertRaises(updates.UpdateError):
            self.publish(init=False)
        self.assertEqual(self.output.read_bytes(), before)

    def test_file_alias_and_symlink_are_refused(self):
        with self.assertRaises(updates.UpdateError):
            updates.publish(self.profile, self.profile, self.output, init_url=bootstrap()["url"])
        self.bootstrap.symlink_to(self.profile)
        with self.assertRaises(updates.UpdateError):
            self.publish()


if __name__ == "__main__":
    unittest.main()
