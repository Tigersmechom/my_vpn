"""Bounded profile validation and native-core configuration.

This module is shared with the privileged helper. Imported profiles never supply
an entire Xray configuration, filenames, subprocess options, or routing commands.
"""
from __future__ import annotations

import base64
import copy
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import subprocess
import tempfile
import uuid

MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_REVISION = 2147483647
TUN_NAME = "myvpn0"
PRIVATE_NETS = ["10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
                "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "fc00::/7", "fe80::/10"]
BUILTINS = [
    {"id": "VLESS_TCP", "title": "VLESS Reality · TCP", "subtitle": "Vision, маскировка под HTTPS", "uses_xray": True},
    {"id": "HY2", "title": "Hysteria2", "subtitle": "QUIC, UDP", "uses_xray": True},
    {"id": "HY2_OBFS", "title": "Hysteria2 + Salamander", "subtitle": "QUIC с обфускацией, UDP", "uses_xray": True},
    {"id": "AWG", "title": "AmneziaWG", "subtitle": "WireGuard с обфускацией, UDP", "uses_xray": False},
]


class ProfileError(ValueError):
    """Invalid profile; messages contain no imported values or credentials."""


def _fail(message="Некорректные параметры профиля"):
    raise ProfileError(message)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("Повторяющееся поле JSON")
        result[key] = value
    return result


def parse_json(data):
    if not isinstance(data, (str, bytes, bytearray)):
        _fail("Ожидается документ JSON")
    if isinstance(data, str):
        data = data.encode("utf-8")
    if len(data) > MAX_DOCUMENT_BYTES:
        _fail("Документ слишком большой")
    try:
        value = json.loads(data, object_pairs_hook=_pairs,
                           parse_constant=lambda _: _fail("Некорректное число JSON"))
        _bounded(value)
        return value
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        _fail("Некорректный документ JSON")


def _bounded(value, depth=0):
    if depth > 16:
        _fail("Настройки слишком сложные")
    if isinstance(value, dict):
        if len(value) > 128:
            _fail()
        for key, item in value.items():
            _string(key, limit=128)
            _bounded(item, depth + 1)
    elif isinstance(value, list):
        if len(value) > 128:
            _fail()
        for item in value:
            _bounded(item, depth + 1)
    elif isinstance(value, str):
        _string(value, empty=True, limit=65536)
    elif value is not None and not isinstance(value, (int, float, bool)):
        _fail()
    elif isinstance(value, float) and not math.isfinite(value):
        _fail()


def _object(value, allowed=None, required=()):
    if not isinstance(value, dict) or not set(required).issubset(value):
        _fail()
    if allowed is not None and not set(value).issubset(allowed):
        _fail("В профиле есть неподдерживаемые параметры; может требоваться обновление приложения")
    return value


def _string(value, *, empty=False, limit=4096):
    if (not isinstance(value, str) or (not value and not empty) or len(value) > limit
            or any(ord(c) < 32 or 127 <= ord(c) <= 159 or 0xD800 <= ord(c) <= 0xDFFF for c in value)):
        _fail()
    return value


def _integer(value, minimum=0, maximum=65535):
    if type(value) is not int or not minimum <= value <= maximum:
        _fail("Некорректный числовой параметр")
    return value


def _boolean(value):
    if type(value) is not bool:
        _fail()


def _host(value):
    _string(value, limit=253)
    try:
        ipaddress.ip_address(value)
        if "%" in value:
            _fail()
        return value
    except ValueError:
        pass
    if not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part)
               for part in value.split(".")):
        _fail("Некорректный адрес сервера")
    return value


def _key(value, *, urlsafe=False, empty=False):
    _string(value, empty=empty, limit=128)
    if not value and empty:
        return
    pattern = r"[A-Za-z0-9_-]{43}" if urlsafe else r"[A-Za-z0-9+/]{43}="
    try:
        if not re.fullmatch(pattern, value):
            raise ValueError()
        decoded = base64.b64decode(value + "=" * (-len(value) % 4),
                                   altchars=b"-_" if urlsafe else None, validate=True)
        if len(decoded) != 32:
            raise ValueError()
    except ValueError:
        _fail("Некорректный ключ профиля")


def _uuid(value):
    _string(value, limit=36)
    try:
        uuid.UUID(value)
    except ValueError:
        _fail("Некорректный UUID")


def _list(value, minimum=0, maximum=16):
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        _fail()
    return value


def dns_servers(profile):
    text = _string(profile.get("dns"), limit=512)
    result = []
    for part in text.split(","):
        try:
            address = ipaddress.ip_address(part.strip())
            if "%" in part or address.is_unspecified or address.is_multicast:
                raise ValueError()
            result.append(str(address))
        except ValueError:
            _fail("DNS должен содержать IP-адреса через запятую")
    if not 1 <= len(result) <= 8:
        _fail("Некорректный список DNS")
    return result


def validate_profile(value):
    """Validate every field used by the root helper and return an independent copy."""
    _bounded(value)
    if len(json.dumps(value, ensure_ascii=False).encode("utf-8")) > MAX_DOCUMENT_BYTES:
        _fail("Профиль слишком большой")
    _object(value, {"version", "name", "client", "host", "dns", "vless", "awg", "hy2", "extraXray"},
            {"version", "client", "host", "dns", "vless", "awg", "hy2"})
    if type(value["version"]) is not int or value["version"] != 2:
        _fail("Требуется профиль My VPN версии 2")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", _string(value["client"])):
        _fail("Некорректный идентификатор профиля")
    if "name" in value:
        _string(value["name"], limit=80)
    _host(value["host"])
    dns_servers(value)
    v = _object(value["vless"], {"uuid", "sni", "publicKey", "shortId", "fingerprint", "tcpPort"},
                {"uuid", "sni", "publicKey", "shortId", "tcpPort"})
    _uuid(v["uuid"])
    _host(v["sni"])
    _key(v["publicKey"], urlsafe=True)
    _short_id(v["shortId"])
    _string(v.get("fingerprint", "chrome"), limit=64)
    _integer(v["tcpPort"], 1)
    h = _object(value["hy2"], {"port", "obfsPort", "auth", "sni", "pinSha256", "obfsPassword"},
                {"port", "obfsPort", "auth", "sni", "pinSha256", "obfsPassword"})
    _integer(h["port"], 1)
    _integer(h["obfsPort"], 1)
    _host(h["sni"])
    _string(h["auth"])
    _string(h["obfsPassword"])
    if not re.fullmatch(r"[a-fA-F0-9]{64}", _string(h["pinSha256"], limit=64)):
        _fail("Некорректный отпечаток сертификата")
    awg_fields = {"port", "privateKey", "serverPublicKey", "presharedKey", "address", "mtu",
                  "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4",
                  "i1", "i2", "i3", "i4", "i5"}
    a = _object(value["awg"], awg_fields,
                awg_fields - {"presharedKey", "mtu", "i1", "i2", "i3", "i4", "i5"})
    _integer(a["port"], 1)
    if len({h["port"], h["obfsPort"], a["port"]}) != 3:
        _fail("Режимам UDP нужны разные порты")
    _key(a["privateKey"])
    _key(a["serverPublicKey"])
    _key(a.get("presharedKey", ""), empty=True)
    try:
        if ipaddress.ip_interface(_string(a["address"])).version != 4:
            raise ValueError()
    except ValueError:
        _fail("Адрес AmneziaWG должен быть IPv4/CIDR")
    _integer(a.get("mtu", 1280), 1280, 9000)
    for name in ("jc", "jmin", "jmax", "s1", "s2", "s3", "s4"):
        _integer(a[name], 0, 1280)
    if a["jmin"] > a["jmax"]:
        _fail("Некорректные параметры AmneziaWG")
    for name in ("h1", "h2", "h3", "h4"):
        text = str(a[name]) if type(a[name]) is int else _string(a[name], limit=32)
        if not re.fullmatch(r"[0-9]+(?:-[0-9]+)?", text):
            _fail("Некорректные параметры AmneziaWG")
        numbers = [int(n) for n in text.split("-")]
        if any(n > 4294967295 for n in numbers) or numbers[0] > numbers[-1]:
            _fail("Некорректные параметры AmneziaWG")
    for name in ("i1", "i2", "i3", "i4", "i5"):
        _string(a.get(name, ""), empty=True)
    used = set()
    for extra in _list(value.get("extraXray", []), maximum=8):
        _object(extra, {"id", "title", "outbound"}, {"id", "title", "outbound"})
        mode = _string(extra["id"], limit=55)
        if not re.fullmatch(r"custom-[A-Za-z0-9_-]{1,48}", mode) or mode in used:
            _fail("Некорректный или повторяющийся режим")
        used.add(mode)
        if not _string(extra["title"], limit=80).strip():
            _fail("Пустое название режима")
        _validate_outbound(extra["outbound"])
    return copy.deepcopy(value)


def _short_id(value):
    if not re.fullmatch(r"(?:[a-fA-F0-9]{2}){0,8}", _string(value, empty=True, limit=16)):
        _fail("Некорректный Short ID")


def _endpoint(value):
    _host(value.get("address"))
    _integer(value.get("port"), 1)


def _validate_outbound(outbound):
    _object(outbound, {"protocol", "settings", "streamSettings", "mux"}, {"protocol", "settings"})
    protocol = outbound["protocol"]
    if protocol not in ("vless", "vmess", "trojan", "shadowsocks", "hysteria"):
        _fail("Для нового протокола нужно обновить приложение")
    settings = _object(outbound["settings"])
    if protocol in ("vless", "vmess"):
        user_fields = {"id", "encryption", "flow", "security", "alterId", "level"}
        if "vnext" in settings:
            _object(settings, {"vnext"})
            servers = _list(settings["vnext"], 1)
        else:
            servers = [settings]
        for server in servers:
            _object(server, {"address", "port", "users"} | user_fields, {"address", "port"})
            _endpoint(server)
            users = _list(server["users"], 1) if "users" in server else [server]
            for user in users:
                _object(user, user_fields if "users" in server else user_fields | {"address", "port"}, {"id"})
                _uuid(user["id"])
                for name in ("encryption", "flow", "security"):
                    if name in user:
                        _string(user[name], empty=True, limit=128)
                for name in ("alterId", "level"):
                    if name in user:
                        _integer(user[name])
    elif protocol == "hysteria":
        _object(settings, {"version", "address", "port"}, {"address", "port"})
        _endpoint(settings)
        if type(settings.get("version", 2)) is not int or settings.get("version", 2) != 2:
            _fail("Поддерживается только Hysteria 2")
    else:
        if "servers" in settings:
            _object(settings, {"servers"})
            servers = _list(settings["servers"], 1)
        else:
            servers = [settings]
        allowed = {"address", "port", "password", "level", "email"}
        if protocol == "shadowsocks":
            allowed |= {"method", "uot", "UoT", "ivCheck"}
        for server in servers:
            _object(server, allowed, {"address", "port", "password"})
            _endpoint(server)
            _string(server["password"])
            if "level" in server:
                _integer(server["level"])
            if "email" in server:
                _string(server["email"], limit=128)
            if protocol == "shadowsocks":
                if _string(server.get("method"), limit=64) not in {"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
                        "2022-blake3-chacha20-poly1305", "aes-128-gcm", "aes-256-gcm",
                        "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305"}:
                    _fail("Неподдерживаемый метод Shadowsocks")
                for name in ("uot", "UoT", "ivCheck"):
                    if name in server:
                        _boolean(server[name])
    if "streamSettings" in outbound:
        _validate_stream(outbound["streamSettings"])
    if "mux" in outbound:
        mux = _object(outbound["mux"], {"enabled", "concurrency", "xudpConcurrency", "xudpProxyUDP443"})
        if "enabled" in mux:
            _boolean(mux["enabled"])
        for name in ("concurrency", "xudpConcurrency"):
            if name in mux:
                _integer(mux[name], -1, 1024)
        if "xudpProxyUDP443" in mux and mux["xudpProxyUDP443"] not in ("reject", "allow", "skip"):
            _fail()


def _headers(value):
    _object(value)
    for name, content in value.items():
        _string(name, limit=128)
        _string(content, limit=4096)


def _validate_stream(stream):
    _object(stream, {"network", "security", "realitySettings", "tlsSettings", "xhttpSettings",
                     "grpcSettings", "wsSettings", "httpupgradeSettings", "hysteriaSettings", "finalmask"})
    if stream.get("network", "raw") not in ("raw", "tcp", "xhttp", "splithttp", "grpc", "ws", "httpupgrade", "hysteria"):
        _fail("Неподдерживаемый транспорт Xray")
    if stream.get("security", "none") not in ("none", "tls", "reality"):
        _fail("Неподдерживаемая защита транспорта")
    if stream.get("security") == "reality" and "realitySettings" not in stream:
        _fail()
    if "realitySettings" in stream:
        r = _object(stream["realitySettings"], {"serverName", "fingerprint", "publicKey", "password", "shortId", "spiderX"},
                    {"serverName", "shortId"})
        _host(r["serverName"])
        if not ({"publicKey", "password"} & set(r)):
            _fail()
        for name in ("publicKey", "password"):
            if name in r:
                _key(r[name], urlsafe=True)
        _short_id(r["shortId"])
        if "fingerprint" in r:
            _string(r["fingerprint"], limit=64)
        if "spiderX" in r:
            _string(r["spiderX"], empty=True, limit=1024)
    if "tlsSettings" in stream:
        tls = _object(stream["tlsSettings"], {"serverName", "fingerprint", "alpn", "pinnedPeerCertSha256", "allowInsecure"})
        if tls.get("allowInsecure", False) is not False:
            _fail("Проверка TLS-сертификата должна быть включена")
        if "serverName" in tls:
            _host(tls["serverName"])
        if "fingerprint" in tls:
            _string(tls["fingerprint"], limit=64)
        for alpn in _list(tls.get("alpn", []), maximum=8):
            _string(alpn, limit=32)
        if "pinnedPeerCertSha256" in tls and not re.fullmatch(r"[a-fA-F0-9]{64}",
                _string(tls["pinnedPeerCertSha256"], limit=64)):
            _fail()
    if "xhttpSettings" in stream:
        x = _object(stream["xhttpSettings"], {"host", "path", "mode", "headers", "noGRPCHeader", "noSSEHeader"})
        for name in ("host", "path"):
            if name in x:
                _string(x[name], empty=True, limit=1024)
        if "mode" in x and x["mode"] not in ("auto", "packet-up", "stream-up", "stream-one"):
            _fail()
        if "headers" in x:
            _headers(x["headers"])
        for name in ("noGRPCHeader", "noSSEHeader"):
            if name in x:
                _boolean(x[name])
    if "grpcSettings" in stream:
        g = _object(stream["grpcSettings"], {"serviceName", "authority", "multiMode", "idle_timeout", "health_check_timeout",
                                             "permit_without_stream", "initial_windows_size"})
        for name in ("serviceName", "authority"):
            if name in g:
                _string(g[name], empty=True, limit=1024)
        for name in ("multiMode", "permit_without_stream"):
            if name in g:
                _boolean(g[name])
        for name in ("idle_timeout", "health_check_timeout", "initial_windows_size"):
            if name in g:
                _integer(g[name], 0, MAX_REVISION)
    for transport in ("wsSettings", "httpupgradeSettings"):
        if transport in stream:
            w = _object(stream[transport], {"path", "host", "headers"})
            for name in ("path", "host"):
                if name in w:
                    _string(w[name], empty=True, limit=1024)
            if "headers" in w:
                _headers(w["headers"])
    if "hysteriaSettings" in stream:
        h = _object(stream["hysteriaSettings"], {"version", "auth"}, {"version", "auth"})
        if type(h["version"]) is not int or h["version"] != 2:
            _fail()
        _string(h["auth"])
    if "finalmask" in stream:
        masks = _object(stream["finalmask"], {"udp"}, {"udp"})
        for mask in _list(masks["udp"], 1, 1):
            _object(mask, {"type", "settings"}, {"type", "settings"})
            if mask["type"] != "salamander":
                _fail("Неподдерживаемая обфускация")
            _object(mask["settings"], {"password"}, {"password"})
            _string(mask["settings"]["password"])


def connections(profile):
    p = validate_profile(profile)
    return copy.deepcopy(BUILTINS) + [
        {"id": extra["id"], "title": extra["title"],
         "subtitle": "Дополнительный режим Xray · " + extra["outbound"]["protocol"], "uses_xray": True}
        for extra in p.get("extraXray", [])]


def proxy_outbound(profile, mode):
    p = validate_profile(profile)
    if mode == "VLESS_TCP":
        v = p["vless"]
        return {"protocol": "vless", "settings": {"address": p["host"], "port": v["tcpPort"], "id": v["uuid"],
                 "encryption": "none", "flow": "xtls-rprx-vision-udp443"}, "streamSettings": {
                    "network": "raw", "security": "reality", "realitySettings": {
                        "serverName": v["sni"], "fingerprint": v.get("fingerprint", "chrome"),
                        "publicKey": v["publicKey"], "shortId": v["shortId"], "spiderX": "/"}}}
    if mode in ("HY2", "HY2_OBFS"):
        h = p["hy2"]
        stream = {"network": "hysteria", "security": "tls", "hysteriaSettings": {"version": 2, "auth": h["auth"]},
                  "tlsSettings": {"serverName": h["sni"], "alpn": ["h3"], "pinnedPeerCertSha256": h["pinSha256"]}}
        if mode == "HY2_OBFS":
            stream["finalmask"] = {"udp": [{"type": "salamander", "settings": {"password": h["obfsPassword"]}}]}
        return {"protocol": "hysteria", "settings": {"version": 2, "address": p["host"],
                 "port": h["obfsPort" if mode == "HY2_OBFS" else "port"]}, "streamSettings": stream}
    for extra in p.get("extraXray", []):
        if extra["id"] == mode:
            return copy.deepcopy(extra["outbound"])
    _fail("Выбранный режим недоступен")


def _servers(outbound):
    settings = outbound["settings"]
    return settings.get("vnext", settings.get("servers", [settings]))


def endpoint_hosts(profile, mode):
    p = validate_profile(profile)
    if mode == "AWG":
        return [p["host"]]
    return list(dict.fromkeys(server["address"] for server in _servers(proxy_outbound(p, mode))))


def replace_endpoint_ips(outbound, mapping):
    """Freeze endpoint DNS before enabling routes; never alter TLS/REALITY SNI."""
    _validate_outbound(outbound)
    result = copy.deepcopy(outbound)
    for server in _servers(result):
        try:
            address = ipaddress.ip_address(mapping[server["address"]])
            if address.version != 4:
                raise ValueError()
        except (KeyError, TypeError, ValueError):
            _fail("Не удалось определить IPv4 сервера")
        server["address"] = str(address)
    return result


def xray_config(profile, mode, *, tun=False, socks_port=10808):
    """No automatic routes or DNS changes: the helper owns their lifetime."""
    _integer(socks_port, 1)
    proxy = proxy_outbound(profile, mode)
    proxy["tag"] = "proxy"
    inbounds = [{"tag": "socks", "listen": "127.0.0.1", "port": socks_port, "protocol": "socks",
                 "settings": {"auth": "noauth", "udp": True}}]
    if tun:
        inbounds.insert(0, {"tag": "tun", "port": 0, "protocol": "tun", "settings": {
            "name": TUN_NAME, "mtu": 1280, "gateway": ["172.31.255.1/30"],
            "autoSystemRoutingTable": [], "autoSystemDnsToGateway": False}})
    return {"log": {"loglevel": "warning"}, "inbounds": inbounds, "outbounds": [proxy,
             {"tag": "direct", "protocol": "freedom"}, {"tag": "block", "protocol": "blackhole"}],
            "routing": {"domainStrategy": "AsIs", "rules": [
                {"type": "field", "ip": list(PRIVATE_NETS), "outboundTag": "direct"}]}}


def awg_config(profile, endpoint_ip):
    """Generate only awg setconf input; no awg-quick hooks, DNS, or routes."""
    p = validate_profile(profile)
    try:
        if ipaddress.ip_address(endpoint_ip).version != 4:
            raise ValueError()
    except ValueError:
        _fail("Сервер AmneziaWG должен иметь IPv4-адрес")
    a = p["awg"]
    lines = ["[Interface]", "PrivateKey = " + a["privateKey"]]
    for name in ("jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5"):
        if name in a and a[name] != "":
            lines.append(name.capitalize() + " = " + str(a[name]))
    lines += ["", "[Peer]", "PublicKey = " + a["serverPublicKey"]]
    if a.get("presharedKey"):
        lines.append("PresharedKey = " + a["presharedKey"])
    lines += [f"Endpoint = {endpoint_ip}:{a['port']}", "AllowedIPs = 0.0.0.0/0", "PersistentKeepalive = 25"]
    return "\n".join(lines) + "\n"


def validate_core_configs(profile, executable="/usr/lib/myvpn/xray", *, runner=None):
    """Reject unsupported native options before an update becomes current.

    Xray's validation command parses only: it does not create a TUN, listen on a
    port, or dial servers. Never expose its output, which may quote credentials.
    """
    p = validate_profile(profile)
    core = str(Path(executable).resolve())
    run = runner or subprocess.run
    try:
        with tempfile.TemporaryDirectory(prefix="myvpn-validate-") as directory:
            path = Path(directory) / "config.json"
            for connection in connections(p):
                if not connection["uses_xray"]:
                    continue
                config = xray_config(p, connection["id"], tun=False)
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as stream:
                    json.dump(config, stream, ensure_ascii=False, allow_nan=False)
                result = run([core, "run", "-test", "-config", str(path)],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             timeout=8, check=False, cwd=directory,
                             env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
                if result.returncode != 0:
                    _fail("Ядро VPN не поддерживает полученные параметры. Требуется обновление приложения")
    except (OSError, subprocess.TimeoutExpired):
        _fail("Не удалось проверить конфигурацию ядром VPN. Обновление не применено")
