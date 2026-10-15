#!/usr/bin/env python3
"""Private, offline exports for v2RayTun and AmneziaWG. Python 3.9+, no dependencies."""
import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from urllib.parse import quote, urlencode
import uuid


class ProfileError(ValueError):
    pass


def string(value, field, empty=False):
    if not isinstance(value, str) or (not value and not empty) or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ProfileError(f"Некорректное поле {field}")
    return value


def number(value, field, low=0, high=65535):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ProfileError(f"Некорректное числовое поле {field}")
    return value


def host(value, field):
    value = string(value, field)
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if len(value) > 253 or not all(re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", p) for p in value.split('.')):
        raise ProfileError(f"Некорректный адрес в {field}")
    return value


def key(value, field, urlsafe=False, empty=False):
    value = string(value, field, empty=empty)
    if not value and empty:
        return value
    try:
        raw = base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_' if urlsafe else None, validate=True)
        if len(raw) != 32:
            raise ValueError()
    except (ValueError, base64.binascii.Error):
        raise ProfileError(f"В {field} нужен ключ длиной 32 байта в base64") from None
    return value


def validate(profile):
    if not isinstance(profile, dict) or profile.get('version') not in (1, 2):
        raise ProfileError('Ожидается профиль My VPN версии 1 или 2')
    try:
        string(profile['client'], 'client')
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,32}', profile['client']):
            raise ProfileError('Некорректное имя клиента')
        host(profile['host'], 'host')
        v, a, h = (profile[k] for k in ('vless', 'awg', 'hy2'))
        if not all(isinstance(p, dict) for p in (v, a, h)):
            raise ProfileError('vless, awg, hy2 должны быть объектами')
        try:
            uuid.UUID(string(v['uuid'], 'vless.uuid'))
        except ValueError:
            raise ProfileError('Некорректный vless.uuid') from None
        host(v['sni'], 'vless.sni')
        key(v['publicKey'], 'vless.publicKey', urlsafe=True)
        sid = string(v['shortId'], 'vless.shortId', empty=True)
        if len(sid) > 16 or len(sid) % 2 or not re.fullmatch(r'[0-9a-fA-F]*', sid):
            raise ProfileError('Некорректный vless.shortId')
        string(v.get('fingerprint', 'chrome'), 'vless.fingerprint')
        number(v['tcpPort'], 'vless.tcpPort', 1)
        for name in ('port', 'obfsPort'):
            number(h[name], 'hy2.' + name, 1)
        if h['port'] == h['obfsPort']:
            raise ProfileError('Два режима Hysteria должны иметь разные UDP-порты')
        host(h['sni'], 'hy2.sni')
        string(h['auth'], 'hy2.auth')
        string(h['obfsPassword'], 'hy2.obfsPassword')
        pin = string(h['pinSha256'], 'hy2.pinSha256').replace(':', '').lower()
        if not re.fullmatch(r'[0-9a-f]{64}', pin):
            raise ProfileError('hy2.pinSha256 должен содержать SHA-256 сертификата')
        number(a['port'], 'awg.port', 1)
        if a['port'] in (h['port'], h['obfsPort']):
            raise ProfileError('AmneziaWG и Hysteria не могут занимать один UDP-порт')
        key(a['privateKey'], 'awg.privateKey')
        key(a['serverPublicKey'], 'awg.serverPublicKey')
        key(a.get('presharedKey', ''), 'awg.presharedKey', empty=True)
        try:
            interface = ipaddress.ip_interface(string(a['address'], 'awg.address'))
            if interface.version != 4:
                raise ValueError()
        except ValueError:
            raise ProfileError('awg.address должен быть IPv4/CIDR') from None
        number(a.get('mtu', 1280), 'awg.mtu', 1280, 9000)
        for name in ('jc', 'jmin', 'jmax', 's1', 's2', 's3', 's4'):
            number(a[name], 'awg.' + name, 0, 1280)
        if a['jmin'] > a['jmax']:
            raise ProfileError('awg.jmin не может быть больше jmax')
        for name in ('h1', 'h2', 'h3', 'h4'):
            value = string(str(a[name]), 'awg.' + name)
            if not re.fullmatch(r'\d+(?:-\d+)?', value) or any(int(n) > 4294967295 for n in value.split('-')):
                raise ProfileError('Некорректное поле awg.' + name)
        for name in ('i1', 'i2', 'i3', 'i4', 'i5'):
            string(a.get(name, ''), 'awg.' + name, empty=True)
        for dns in string(profile['dns'], 'dns').split(','):
            try:
                ipaddress.ip_address(dns.strip())
            except ValueError:
                raise ProfileError('dns должен содержать IP-адреса через запятую') from None
    except KeyError as exc:
        raise ProfileError(f'Отсутствует поле {exc.args[0]}') from None
    return profile


def authority(address, port):
    return f'[{address}]:{port}' if ':' in address else f'{address}:{port}'


def uri(scheme, auth, address, port, query, label, slash=False):
    return (f'{scheme}://{quote(auth, safe="")}@{authority(address, port)}'
            + ('/' if slash else '') + '?' + urlencode(query, quote_via=quote)
            + '#' + quote(label, safe=''))


def vless_uri(p):
    v = p['vless']
    return uri('vless', v['uuid'], p['host'], v['tcpPort'], {
        'type': 'tcp', 'encryption': 'none', 'security': 'reality',
        'flow': 'xtls-rprx-vision', 'sni': v['sni'], 'fp': v.get('fingerprint', 'chrome'),
        'pbk': v['publicKey'], 'sid': v['shortId'],
    }, f'MyVPN-{p["client"]}-VLESS-REALITY-TCP')


def hy2_uri(p, obfs=False, native=False):
    h = p['hy2']
    pin = h['pinSha256'].replace(':', '').lower()
    query = {'sni': h['sni'], 'alpn': 'h3'}
    if native:
        # Native Hysteria needs insecure + an enforced pin for a self-signed cert.
        query.update(insecure='1', pinSHA256=pin)
    else:
        # v2RayTun Android >=5.24.76 uses Xray's leaf pin, without allowInsecure.
        query.update(pinnedPeerCertSha256=pin, pinSHA256=pin)
    if obfs:
        query.update(obfs='salamander', **{'obfs-password': h['obfsPassword']})
    return uri('hysteria2', h['auth'], p['host'], h['obfsPort' if obfs else 'port'], query,
               f'MyVPN-{p["client"]}-Hysteria2' + ('-Salamander' if obfs else ''), slash=True)


def awg_conf(p):
    a = p['awg']
    lines = ['[Interface]', f'PrivateKey = {a["privateKey"]}', f'Address = {a["address"]}',
             f'DNS = {p["dns"]}', f'MTU = {a.get("mtu", 1280)}']
    for name in ('jc', 'jmin', 'jmax', 's1', 's2', 's3', 's4', 'h1', 'h2', 'h3', 'h4', 'i1', 'i2', 'i3', 'i4', 'i5'):
        value = a.get(name, '')
        if value != '':
            lines.append(f'{name[0].upper() + name[1:]} = {value}')
    lines += ['', '[Peer]', f'PublicKey = {a["serverPublicKey"]}']
    if a.get('presharedKey'):
        lines.append(f'PresharedKey = {a["presharedKey"]}')
    # Capture IPv6 too; the server intentionally has no IPv6 egress, so it is dropped.
    # This avoids sending IPv6 directly outside the VPN on clients supporting dual-stack.
    lines += [f'Endpoint = {authority(p["host"], a["port"])}',
              'AllowedIPs = 0.0.0.0/0, ::/0', 'PersistentKeepalive = 25']
    return '\n'.join(lines) + '\n'


def xray_config(p, mode):
    if mode == 'vless':
        v = p['vless']
        proxy = {'protocol': 'vless', 'settings': {'address': p['host'], 'port': v['tcpPort'],
                 'id': v['uuid'], 'encryption': 'none', 'flow': 'xtls-rprx-vision'},
                 'streamSettings': {'network': 'raw', 'security': 'reality', 'realitySettings': {
                     'serverName': v['sni'], 'fingerprint': v.get('fingerprint', 'chrome'),
                     'publicKey': v['publicKey'], 'shortId': v['shortId']}}}
    else:
        h = p['hy2']
        proxy = {'protocol': 'hysteria', 'settings': {'version': 2, 'address': p['host'],
                 'port': h['obfsPort' if mode == 'hy2-obfs' else 'port']},
                 'streamSettings': {'network': 'hysteria', 'security': 'tls',
                     'hysteriaSettings': {'version': 2, 'auth': h['auth']},
                     'tlsSettings': {'serverName': h['sni'], 'alpn': ['h3'],
                         'pinnedPeerCertSha256': h['pinSha256'].replace(':', '').lower()}}}
        if mode == 'hy2-obfs':
            proxy['streamSettings']['finalmask'] = {'udp': [{'type': 'salamander', 'settings': {'password': h['obfsPassword']}}]}
    proxy['tag'] = 'proxy'
    return {'log': {'loglevel': 'warning'},
            'inbounds': [{'listen': '127.0.0.1', 'port': 10808, 'protocol': 'socks',
                          'settings': {'auth': 'noauth', 'udp': True}}],
            'outbounds': [proxy]}


def build_bundle(profile):
    p = validate(profile)
    links = [vless_uri(p), hy2_uri(p), hy2_uri(p, obfs=True)]
    subscription = '\n'.join(links) + '\n'
    result = {
        'v2raytun-android.txt': subscription,
        'subscription-base64.txt': base64.b64encode(subscription.encode()).decode() + '\n',
        'v2raytun-macos-vless.txt': links[0] + '\n',
        'deep-links.txt': '\n'.join('v2raytun://import/' + link for link in links) + '\n',
        'amneziawg.conf': awg_conf(p),
        'hysteria-native.txt': hy2_uri(p, native=True) + '\n' + hy2_uri(p, True, True) + '\n',
        'IMPORT.txt': (
            'Android: v2RayTun 5.24.76 или новее. Импортируйте содержимое v2raytun-android.txt\n'
            'из буфера: появятся VLESS + REALITY TCP, Hysteria2, Hysteria2 + Salamander.\n'
            'AmneziaWG импортируйте отдельным файлом amneziawg.conf, сохранив S1–S4/H1–H4/I1.\n'
            'Если сборка v2RayTun не принимает .conf — используйте приложение AmneziaWG.\n'
            'В Hysteria проверьте, что сохранён pinnedPeerCertSha256. Не отключайте проверку TLS.\n'
            'macOS: v2raytun-macos-vless.txt; поддержка AWG/Hysteria зависит от сборки клиента.\n'
            'deep-links.txt: по одной ссылке v2raytun://import/ на каждый из трёх Xray-режимов.\n'
            'subscription-base64.txt: готовое тело подписки, но HTTPS-сервис здесь не публикуется.\n'
            'hysteria-native.txt: отдельные ссылки для официального Hysteria (insecure + pin).\n'
            '*-xray.json: диагностический SOCKS 127.0.0.1:10808; сам по себе не системный VPN.\n'
            'Используйте отдельный набор ключей для каждого устройства. Все файлы приватные.\n'
            'Проверяйте IPv4, IPv6 и DNS после подключения; для AWG IPv6 захватывается и блокируется.\n'
        ),
    }
    for mode in ('vless', 'hy2', 'hy2-obfs'):
        result[mode + '-xray.json'] = json.dumps(xray_config(p, mode), ensure_ascii=False, indent=2) + '\n'
    return result


def write_bundle(output, files):
    output = Path(output)
    if output.is_symlink():
        raise ProfileError('Каталог экспорта не должен быть символической ссылкой')
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = output.stat()
    if st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise ProfileError('Каталог экспорта должен принадлежать текущему пользователю и иметь права 700')
    for name, contents in files.items():
        fd, temp = tempfile.mkstemp(prefix='.export-', dir=output)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                stream.write(contents)
            os.replace(temp, output / name)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', required=True, help='My VPN JSON file, or - for stdin')
    parser.add_argument('--output', required=True, help='Private export directory (mode 700)')
    args = parser.parse_args()
    try:
        if args.profile == '-':
            p = json.load(sys.stdin)
        else:
            with open(args.profile, encoding='utf-8') as stream:
                p = json.load(stream)
        files = build_bundle(p)
        write_bundle(args.output, files)
    except (OSError, ValueError, TypeError) as exc:
        # Do not echo untrusted values/credentials in parser errors.
        message = str(exc) if isinstance(exc, ProfileError) else 'Не удалось прочитать профиль или записать экспорт'
        print('Ошибка: ' + message, file=sys.stderr)
        return 1
    print(f'Создано {len(files)} приватных файлов в {args.output}; начните с IMPORT.txt')
    return 0


if __name__ == '__main__':
    sys.exit(main())
