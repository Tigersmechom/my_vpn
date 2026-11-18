#!/usr/bin/env python3
"""Render an isolated TCP/REALITY entry whose only VPN exit is a Hysteria 2 server.

Inputs and outputs contain credentials. This generator never restarts VPN services.
"""
import argparse
import base64
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import tempfile
import uuid

_spec = importlib.util.spec_from_file_location('myvpn_export_tcp', Path(__file__).with_name('export.py'))
_export = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_export)


def validate_keys(keys):
    for name in ('privateKey', 'publicKey'):
        value = keys.get(name)
        if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', value) or len(base64.urlsafe_b64decode(value + '=')) != 32:
            raise ValueError('invalid REALITY key')
    uuid.UUID(keys['uuid'])
    if not re.fullmatch(r'(?:[a-fA-F0-9]{2}){1,8}', keys['shortId']):
        raise ValueError('invalid short ID')
    sni = keys['sni']
    if len(sni) > 253 or not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', part) for part in sni.split('.')):
        raise ValueError('invalid TLS server name')


def build(exit_profile, keys, public_host, port=443):
    validate_keys(keys)
    address = ipaddress.ip_address(public_host)
    if address.version != 4 or not address.is_global or type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('expected public IPv4 and TCP port')
    _export.validate(exit_profile)
    outbound = _export.xray_config(exit_profile, 'hy2')
    if isinstance(outbound, str):
        outbound = json.loads(outbound)
    exit_out = outbound['outbounds'][0]
    exit_out['tag'] = 'exit-spain'
    # No Vision splice: this entry forwards to a QUIC proxy, rather than a raw TCP exit.
    config = {'log': {'loglevel': 'warning'}, 'inbounds': [{
        'tag': 'tcp-reserve', 'listen': '0.0.0.0', 'port': port, 'protocol': 'vless',
        'settings': {'decryption': 'none', 'clients': [{'id': keys['uuid']}]},
        'streamSettings': {'network': 'raw', 'security': 'reality', 'realitySettings': {
            'show': False, 'target': keys['sni'] + ':443', 'xver': 0, 'serverNames': [keys['sni']],
            'privateKey': keys['privateKey'], 'shortIds': [keys['shortId']],
        }},
    }], 'outbounds': [exit_out]}
    client = {'id': 'custom-ru-es-tcp', 'title': 'Россия → Испания · резерв TCP', 'outbound': {
        'protocol': 'vless', 'settings': {'address': public_host, 'port': port, 'id': keys['uuid'], 'encryption': 'none'},
        'streamSettings': {'network': 'raw', 'security': 'reality', 'realitySettings': {
            'serverName': keys['sni'], 'fingerprint': 'firefox', 'publicKey': keys['publicKey'],
            'shortId': keys['shortId'], 'spiderX': '/',
        }},
    }}
    return config, client


def private_json(path, data):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('refusing a symlink')
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix='.tcp-config-', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--exit-profile', type=Path, required=True)
    parser.add_argument('--keys', type=Path, required=True, help='Private JSON: privateKey, publicKey, uuid, shortId, sni')
    parser.add_argument('--public-host', required=True)
    parser.add_argument('--port', type=int, default=443)
    parser.add_argument('--config-output', type=Path, required=True)
    parser.add_argument('--client-output', type=Path, required=True)
    args = parser.parse_args()
    config, client = build(json.loads(args.exit_profile.read_text()), json.loads(args.keys.read_text()), args.public_host, args.port)
    private_json(args.config_output, config)
    private_json(args.client_output, client)
    print('Private server configuration and authenticated client outbound written.')


if __name__ == '__main__':
    main()
