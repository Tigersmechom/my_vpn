"""Authenticated portable update feed; downloaded profiles do not run code."""
from __future__ import annotations

import base64
import copy
import http.client
import re
import ssl
import time
import uuid
from urllib.parse import urlsplit, urlunsplit

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .model import MAX_DOCUMENT_BYTES, MAX_REVISION, ProfileError, parse_json, validate_profile

BOOTSTRAP_FORMAT = "myvpn-bootstrap-v1"
UPDATE_FORMAT = "myvpn-update-v1"


class UpdateError(ValueError):
    """Public diagnostic that never includes keys, passwords, or raw payloads."""


def _revision(value, allow_zero=False):
    if type(value) is not int or not (0 if allow_zero else 1) <= value <= MAX_REVISION:
        raise UpdateError("Некорректный номер обновления")
    return value


def _decode64(value, size=None):
    try:
        if not isinstance(value, str) or len(value) > MAX_DOCUMENT_BYTES:
            raise ValueError()
        raw = base64.b64decode(value, validate=True)
        if size is not None and len(raw) != size:
            raise ValueError()
        return raw
    except ValueError:
        raise UpdateError("Некорректный формат защиты обновления") from None


def _url(value):
    try:
        if not isinstance(value, str) or len(value) > 4096 or any(ord(c) < 33 for c in value):
            raise ValueError()
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.fragment or parsed.port not in (None, 443)):
            raise ValueError()
        parsed.hostname.encode("idna")
        return parsed
    except (ValueError, UnicodeError):
        raise UpdateError("Для обновлений требуется HTTPS без пароля и фрагмента") from None


def validate_bootstrap(value):
    if (not isinstance(value, dict) or set(value) != {"format", "client", "url", "key", "minRevision"}
            or value.get("format") != BOOTSTRAP_FORMAT):
        raise UpdateError("Некорректные настройки обновления")
    if not isinstance(value["client"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", value["client"]):
        raise UpdateError("Некорректный идентификатор обновления")
    _url(value["url"])
    _decode64(value["key"], 32)
    _revision(value["minRevision"])
    return copy.deepcopy(value)


def cache_busted_url(url):
    parsed = _url(url)
    query = parsed.query + ("&" if parsed.query else "") + "_myvpn_refresh=" + uuid.uuid4().hex
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))


def decrypt_update(envelope, bootstrap, *, min_revision=0):
    """Authenticate identity/revision both outside and inside AES-GCM."""
    bootstrap = validate_bootstrap(bootstrap)
    _revision(min_revision, allow_zero=True)
    try:
        if isinstance(envelope, (bytes, bytearray, str)):
            envelope = parse_json(envelope)
        if (not isinstance(envelope, dict) or set(envelope) != {"format", "client", "revision", "nonce", "ciphertext"}
                or envelope.get("format") != UPDATE_FORMAT):
            raise UpdateError("Некорректный формат обновления")
        client = bootstrap["client"]
        if envelope.get("client") != client:
            raise UpdateError("Обновление предназначено для другого профиля")
        revision = _revision(envelope.get("revision"))
        if revision < max(bootstrap["minRevision"], min_revision):
            raise UpdateError("Получено устаревшее обновление")
        ciphertext = _decode64(envelope.get("ciphertext"))
        if not 16 <= len(ciphertext) <= MAX_DOCUMENT_BYTES:
            raise UpdateError("Некорректный размер обновления")
        plaintext = AESGCM(_decode64(bootstrap["key"], 32)).decrypt(
            _decode64(envelope.get("nonce"), 12), ciphertext,
            f"{UPDATE_FORMAT}\n{client}\n{revision}".encode("utf-8"))
        payload = parse_json(plaintext)
        if (not isinstance(payload, dict) or set(payload) != {"schema", "client", "revision", "profile"}
                or type(payload.get("schema")) is not int or payload["schema"] != 1):
            raise UpdateError("Для этого формата нужно обновить приложение")
        if payload["client"] != client or _revision(payload["revision"]) != revision:
            raise UpdateError("Не совпадают данные обновления")
        profile = validate_profile(payload["profile"])
        if profile["client"] != client:
            raise UpdateError("Профиль предназначен для другого устройства")
        return {"revision": revision, "profile": profile}
    except InvalidTag:
        raise UpdateError("Не удалось проверить подлинность обновления") from None
    except ProfileError:
        raise UpdateError("В обновлении некорректный профиль") from None


def fetch_document(url):
    """Verified HTTPS, no redirects/proxy environment, bounded response and waits."""
    parsed = _url(cache_busted_url(url))
    connection = http.client.HTTPSConnection(parsed.hostname, port=443, timeout=8,
                                             context=ssl.create_default_context())
    deadline = time.monotonic() + 20
    try:
        target = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        connection.request("GET", target, headers={"Accept": "application/json", "Cache-Control": "no-cache",
                                                   "User-Agent": "MyVPN-Ubuntu/1.2.0"})
        response = connection.getresponse()
        if response.status != 200:
            raise UpdateError("Сервер обновлений временно недоступен")
        content_length = response.getheader("Content-Length")
        if content_length is not None:
            try:
                length = int(content_length)
            except ValueError:
                raise UpdateError("Некорректный ответ сервера обновлений") from None
            if not 0 <= length <= MAX_DOCUMENT_BYTES:
                raise UpdateError("Обновление слишком большое")
        chunks = []
        total = 0
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError()
            # read1 returns after one network read, so slow partial responses do
            # not reset an unbounded read(N) timeout indefinitely.
            chunk = response.read1(min(65536, MAX_DOCUMENT_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_DOCUMENT_BYTES:
                raise UpdateError("Обновление слишком большое")
        if content_length is not None and total != length:
            raise UpdateError("Обновление загружено не полностью")
        return b"".join(chunks)
    except (OSError, http.client.HTTPException):
        raise UpdateError("Не удалось загрузить обновление. Проверьте интернет и повторите.") from None
    finally:
        connection.close()


def fetch_update(bootstrap, applied_revision=0, *, fetcher=None):
    bootstrap = validate_bootstrap(bootstrap)
    _revision(applied_revision, allow_zero=True)
    data = (fetcher or fetch_document)(bootstrap["url"])
    return decrypt_update(data, bootstrap, min_revision=applied_revision)
