#!/usr/bin/env python3
"""Encrypt private My VPN profiles for the public, per-device update feed.

Only ciphertext belongs in updates/. Keep each bootstrap file private: it contains
the AES key bundled with that device's application. Run one publisher at a time.
"""
import argparse
import base64
import binascii
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


BOOTSTRAP_FORMAT = "myvpn-bootstrap-v1"
UPDATE_FORMAT = "myvpn-update-v1"
CLIENTS = ("android", "mac", "linux")
MAX_REVISION = 2147483647
MAX_DOCUMENT_BYTES = 1024 * 1024

_spec = importlib.util.spec_from_file_location(
    "myvpn_export", Path(__file__).resolve().parents[1] / "server/export.py"
)
_export = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_export)


class UpdateError(ValueError):
    """An invalid update, reported without private field values."""


def _object(value, label):
    if not isinstance(value, dict):
        raise UpdateError(f"{label} must be a JSON object")
    return value


def _revision(value):
    if type(value) is not int or not 1 <= value <= MAX_REVISION:
        raise UpdateError("revision must be a positive 32-bit integer")
    return value


def _client(value):
    if value not in CLIENTS:
        raise UpdateError("client must be android, mac or linux")
    return value


def _decode64(value, label, size=None):
    try:
        if not isinstance(value, str):
            raise ValueError()
        data = base64.b64decode(value, validate=True)
        if size is not None and len(data) != size:
            raise ValueError()
        return data
    except (ValueError, binascii.Error):
        raise UpdateError(f"invalid {label}") from None


def _encode64(value):
    return base64.b64encode(value).decode("ascii")


def _url(value):
    try:
        if not isinstance(value, str) or any(ord(c) < 33 for c in value):
            raise ValueError()
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username
                or parsed.password or parsed.fragment or parsed.port not in (None, 443)):
            raise ValueError()
    except ValueError:
        raise UpdateError("bootstrap URL must use HTTPS without credentials or a fragment") from None
    return value


def validate_bootstrap(value):
    value = _object(value, "bootstrap")
    if value.get("format") != BOOTSTRAP_FORMAT:
        raise UpdateError("unsupported bootstrap format")
    _client(value.get("client"))
    _url(value.get("url"))
    _decode64(value.get("key"), "bootstrap key", 32)
    _revision(value.get("minRevision"))
    return value


def validate_profile(value, client):
    value = _object(value, "profile")
    if type(value.get("version")) is not int or value["version"] != 2:
        raise UpdateError("profile version must be 2")
    if value.get("client") != client:
        raise UpdateError("profile client does not match bootstrap")
    try:
        _export.validate(value)
    except (ValueError, TypeError, KeyError, AttributeError):
        # Exporter's diagnostics can include arbitrary imported field names.
        raise UpdateError("profile has missing or invalid connection fields") from None
    return value


def _pairs(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise UpdateError("duplicate JSON field")
        result[name] = value
    return result


def parse_json(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    if len(data) > MAX_DOCUMENT_BYTES:
        raise UpdateError("JSON document is too large")
    try:
        return json.loads(data, object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(UpdateError("invalid JSON number")))
    except (UnicodeError, json.JSONDecodeError):
        raise UpdateError("invalid JSON document") from None


def _json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                       allow_nan=False) + "\n").encode("utf-8")


def associated_data(client, revision):
    return f"{UPDATE_FORMAT}\n{_client(client)}\n{_revision(revision)}".encode("utf-8")


def encrypt_update(profile, bootstrap, revision):
    """Return an interoperable envelope; nonce and tag follow AESGCM's wire format."""
    validate_bootstrap(bootstrap)
    client = bootstrap["client"]
    validate_profile(profile, client)
    _revision(revision)
    if revision < bootstrap["minRevision"]:
        raise UpdateError("revision is below bootstrap minimum")
    plaintext = _json_bytes({"schema": 1, "client": client, "revision": revision, "profile": profile})
    if len(plaintext) > MAX_DOCUMENT_BYTES // 2:
        raise UpdateError("profile is too large")
    nonce = os.urandom(12)
    key = _decode64(bootstrap["key"], "bootstrap key", 32)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data(client, revision))
    envelope = {"format": UPDATE_FORMAT, "client": client, "revision": revision,
                "nonce": _encode64(nonce), "ciphertext": _encode64(ciphertext)}
    if len(_json_bytes(envelope)) > MAX_DOCUMENT_BYTES:
        raise UpdateError("encrypted update is too large")
    return envelope


def decrypt_update(envelope, bootstrap, *, min_revision=None):
    """Authenticate and validate an envelope, returning its full plaintext object.

    min_revision is the highest already accepted revision, inclusive. Equal versions
    are idempotent; a publisher always advances the existing authenticated version.
    """
    validate_bootstrap(bootstrap)
    envelope = _object(envelope, "envelope")
    if envelope.get("format") != UPDATE_FORMAT:
        raise UpdateError("unsupported update format")
    client = bootstrap["client"]
    if envelope.get("client") != client:
        raise UpdateError("update client does not match bootstrap")
    revision = _revision(envelope.get("revision"))
    floor = bootstrap["minRevision"]
    if min_revision is not None:
        floor = max(floor, _revision(min_revision))
    if revision < floor:
        raise UpdateError("update revision would roll back this client")
    nonce = _decode64(envelope.get("nonce"), "update nonce", 12)
    ciphertext = _decode64(envelope.get("ciphertext"), "update ciphertext")
    if not 16 <= len(ciphertext) <= MAX_DOCUMENT_BYTES:
        raise UpdateError("invalid ciphertext length")
    try:
        plaintext = AESGCM(_decode64(bootstrap["key"], "bootstrap key", 32)).decrypt(
            nonce, ciphertext, associated_data(client, revision)
        )
    except InvalidTag:
        raise UpdateError("update authentication failed") from None
    payload = _object(parse_json(plaintext), "payload")
    if type(payload.get("schema")) is not int or payload["schema"] != 1:
        raise UpdateError("unsupported update schema")
    if payload.get("client") != client or _revision(payload.get("revision")) != revision:
        raise UpdateError("encrypted payload identity does not match envelope")
    validate_profile(payload.get("profile"), client)
    return payload


def read_json(path):
    path = Path(path)
    if path.is_symlink():
        raise UpdateError("refusing a symbolic link")
    with path.open("rb") as stream:
        return parse_json(stream.read(MAX_DOCUMENT_BYTES + 1))


def atomic_json(path, value, mode):
    path = Path(path)
    if path.is_symlink():
        raise UpdateError("refusing a symbolic link")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700 if mode == 0o600 else 0o755)
    fd, temp = tempfile.mkstemp(prefix=".myvpn-update-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(_json_bytes(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def publish(profile_path, bootstrap_path, output_path, *, init_url=None):
    """Publish the next revision locally. Never publish plaintext or rotate a key."""
    profile_path, bootstrap_path, output_path = map(Path, (profile_path, bootstrap_path, output_path))
    if len({p.resolve() for p in (profile_path, bootstrap_path, output_path)}) != 3:
        raise UpdateError("profile, bootstrap and output must be different files")
    profile = _object(read_json(profile_path), "profile")
    client = _client(profile.get("client"))
    validate_profile(profile, client)
    if bootstrap_path.is_symlink() or output_path.is_symlink():
        raise UpdateError("refusing a symbolic link")
    created = not bootstrap_path.exists()
    if created:
        if output_path.exists():
            raise UpdateError("existing update requires its original bootstrap; key rotation refused")
        if init_url is None:
            raise UpdateError("first publication requires --init-url")
        bootstrap = {"format": BOOTSTRAP_FORMAT, "client": client, "url": _url(init_url),
                     "key": _encode64(os.urandom(32)), "minRevision": 1}
    else:
        bootstrap = validate_bootstrap(read_json(bootstrap_path))
        if bootstrap["client"] != client:
            raise UpdateError("profile client does not match bootstrap")
        if init_url is not None and _url(init_url) != bootstrap["url"]:
            raise UpdateError("existing bootstrap URL cannot be changed by --init-url")
    revision = bootstrap["minRevision"]
    if output_path.exists():
        previous = decrypt_update(read_json(output_path), bootstrap)
        revision = _revision(previous["revision"] + 1)
    envelope = encrypt_update(profile, bootstrap, revision)
    # Persist the key first. If writing the feed fails, a retry reuses this key.
    if created:
        atomic_json(bootstrap_path, bootstrap, 0o600)
    else:
        bootstrap_path.chmod(0o600)
    atomic_json(output_path, envelope, 0o644)
    return envelope


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--bootstrap", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--init-url", help="public HTTPS feed URL; required only for first publication")
    args = parser.parse_args(argv)
    try:
        envelope = publish(args.profile, args.bootstrap, args.output, init_url=args.init_url)
    except (OSError, UpdateError):
        # Do not print exception text: paths or imported JSON may contain secrets.
        print("Update publication failed: check paths, profile, bootstrap and authenticated previous feed.", file=sys.stderr)
        return 1
    print(f"Published encrypted {envelope['client']} update, revision {envelope['revision']}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
