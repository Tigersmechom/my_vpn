#!/usr/bin/env python3
"""Optional Xray transports, isolated from the existing xray/AWG services.

Python 3.9+, standard library only. Run as root on the installed server:
  python3 extra_protocols.py render --output /root/myvpn-extra-preview.json
  python3 extra_protocols.py install [--alternate-sni tested.example.org]
  python3 extra_protocols.py profile android --output /root/android.json

`render` validates a private preview with Xray, but changes no persistent state
and starts no service. New preview credentials are provisional until install. `install` only manages myvpn-extra.service. Updated vpnctl reconciles an existing add-on after adding or removing clients;
older vpnctl versions need an explicit install call. No
firewall or existing listener is changed. Open the listed extra ports separately
if your provider/host firewall filters inbound traffic.
"""
import argparse
import base64
import copy
from contextlib import contextmanager
import fcntl
import grp
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time
import uuid

SERVICE = 'myvpn-extra.service'
PORTS = {'xhttp': 8443, 'grpc': 8444, 'trojan': 9443, 'shadowsocks': 8388, 'vision': 2053}
IDS = {'custom-vless-xhttp', 'custom-vless-grpc', 'custom-trojan-reality',
       'custom-shadowsocks2022', 'custom-vless-vision-alt'}
MAX_FILE = 1024 * 1024
PRIVATE_IPS = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
               '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4',
               '::/128', '::1/128', 'fc00::/7', 'fe80::/10', 'ff00::/8']


class ExtraError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ExtraError(message)


def regular_file(path, private=True):
    s = Path(path).lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_uid == os.geteuid(),
            'Expected a regular file owned by the current user')
    if private:
        require(not stat.S_IMODE(s.st_mode) & 0o077, 'Private input must have mode 600')
    require(s.st_size <= MAX_FILE, 'Input exceeds size limit')
    return s


def read_bytes(path, private=True):
    regular_file(path, private)
    return Path(path).read_bytes()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON field')
        result[key] = value
    return result


def decode_json(data):
    try:
        require(len(data) <= MAX_FILE, 'JSON exceeds size limit')
        return json.loads(data, object_pairs_hook=unique_object)
    except (ValueError, UnicodeError, RecursionError):
        raise ExtraError('Invalid JSON document') from None


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()


def read_env(path):
    """Read only literal assignments; never source or evaluate shell text."""
    result = {}
    try:
        text = read_bytes(path).decode('utf-8')
    except UnicodeError:
        raise ExtraError('Invalid state encoding') from None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        match = re.fullmatch(r"([A-Z][A-Z0-9_]*)=(?:'([^'\r\n]*)'|([0-9]+))", line)
        require(match is not None, 'State contains a nonliteral assignment')
        name, quoted, number = match.groups()
        require(name not in result, 'State contains a duplicate assignment')
        value = quoted if quoted is not None else number
        require(not any(ord(c) < 32 or ord(c) == 127 for c in value), 'Invalid state value')
        result[name] = value
    return result


def valid_name(value):
    require(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_-]{1,32}', value), 'Invalid client name')
    return value


def host(value, dns_only=False):
    require(isinstance(value, str) and bool(value), 'Invalid host')
    if not dns_only:
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            pass
    require(len(value) <= 253 and not re.fullmatch(r'[0-9.]+', value)
            and all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', p)
                    for p in value.split('.')), 'Invalid hostname')
    return value


def key(value, urlsafe=False):
    try:
        require(isinstance(value, str), 'Invalid key')
        raw = base64.b64decode(value + '=' * (-len(value) % 4),
                               altchars=b'-_' if urlsafe else None, validate=True)
        require(len(raw) == 32, 'Invalid key length')
    except (ValueError, TypeError):
        raise ExtraError('Invalid key') from None
    return value


def port(value):
    require(type(value) is int and 1024 <= value <= 65535, 'Extra ports must be 1024–65535')
    return value


def atomic_write(path, data, mode=0o600, gid=None):
    path = Path(path)
    require(not path.is_symlink(), 'Output must not be a symbolic link')
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix='.myvpn-extra-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as file:
            file.write(data)
            file.flush()
            os.fchmod(file.fileno(), mode)
            if gid is not None:
                os.fchown(file.fileno(), -1, gid)
            os.fsync(file.fileno())
        os.replace(temp, path)
        dirfd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


class Paths:
    def __init__(self, root='/'):
        self.root = Path(root).absolute()
        if self.root == Path('/'):
            require(os.geteuid() == 0, 'Run as root on the server')
        else:
            s = self.root.lstat()
            require(stat.S_ISDIR(s.st_mode) and s.st_uid == os.geteuid()
                    and not s.st_mode & 0o077, 'Test root must be an owned directory with mode 700')
        self.state_dir = self.root / 'etc/myvpn'
        self.env = self.state_dir / 'server.env'
        self.clients = self.state_dir / 'clients'
        self.state = self.state_dir / 'extra-protocols.json'
        self.config = self.root / 'usr/local/etc/xray/extra.json'
        self.unit = self.root / 'etc/systemd/system' / SERVICE
        self.xray = self.root / 'usr/local/bin/xray'
        self.vpnctl = self.root / 'usr/local/bin/vpnctl'

    @contextmanager
    def lock(self):
        require(self.state_dir.is_dir() and not self.state_dir.is_symlink(), 'Server state directory is missing')
        descriptor = os.open(self.state_dir / '.extra-protocols.lock',
                             os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            require(os.fstat(descriptor).st_uid == os.geteuid(), 'Invalid lock owner')
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            os.close(descriptor)


def load_inputs(paths):
    server = read_env(paths.env)
    try:
        host(server['PUBLIC_HOST'])
        host(server['REALITY_SNI'], dns_only=True)
        key(server['REALITY_PRIVATE_KEY'], urlsafe=True)
        key(server['REALITY_PUBLIC_KEY'], urlsafe=True)
        for field in ('VLESS_TCP_PORT', 'AWG_PORT', 'HY2_PORT', 'HY2_OBFS_PORT'):
            require(re.fullmatch(r'[1-9][0-9]{0,4}', server[field]) and int(server[field]) <= 65535,
                    'Invalid existing service port')
        clients = {}
        for path in sorted(paths.clients.glob('*.env')):
            name = valid_name(path.stem)
            record = read_env(path)
            require(record.get('CLIENT_NAME') == name, 'Client name differs from filename')
            # Existing credentials are not reused or changed by the add-on.
            uuid.UUID(record['VLESS_UUID'])
            clients[name] = record
        return server, clients
    except (KeyError, TypeError, ValueError):
        raise ExtraError('Invalid installed server/client state') from None


def new_key():
    return base64.b64encode(secrets.token_bytes(32)).decode()


def candidate_state(paths, server, clients, alternate_sni=None, reality_sni=None):
    if paths.state.exists() or paths.state.is_symlink():
        state = decode_json(read_bytes(paths.state))
        validate_state(state, server)
        state = copy.deepcopy(state)
    else:
        state = {'version': 1, 'ports': dict(PORTS),
                 'reality': {'privateKey': server['REALITY_PRIVATE_KEY'],
                             'publicKey': server['REALITY_PUBLIC_KEY'],
                             'shortId': secrets.token_hex(8), 'sni': server['REALITY_SNI']},
                 'xhttpPath': '/' + secrets.token_hex(12),
                 'grpcService': 'vpn' + secrets.token_hex(12),
                 'shadowsocksServerKey': new_key(), 'clients': {}, 'alternateSni': None}
    if alternate_sni is not None:
        state['alternateSni'] = host(alternate_sni, dns_only=True) if alternate_sni else None
    if reality_sni is not None:
        state['reality']['sni'] = host(reality_sni, dns_only=True)
    state['clients'] = {name: state['clients'].get(name) or {
        'uuid': str(uuid.uuid4()), 'trojanPassword': secrets.token_hex(32), 'shadowsocksKey': new_key()
    } for name in clients}
    validate_state(state, server)
    return state


def validate_state(state, server):
    try:
        require(isinstance(state, dict) and type(state['version']) is int and state['version'] == 1,
                'Unsupported extra state format')
        ports = state['ports']
        require(isinstance(ports, dict) and set(ports) == set(PORTS), 'Invalid extra port mapping')
        values = [port(v) for v in ports.values()]
        require(len(values) == len(set(values)), 'Extra ports must be distinct')
        reserved = {int(server[k]) for k in ('VLESS_TCP_PORT', 'AWG_PORT', 'HY2_PORT', 'HY2_OBFS_PORT')}
        require(not reserved.intersection(values), 'Extra ports collide with an existing VPN port')
        reality = state['reality']
        key(reality['privateKey'], urlsafe=True)
        key(reality['publicKey'], urlsafe=True)
        host(reality['sni'], dns_only=True)
        require(re.fullmatch(r'[0-9a-f]{16}', reality['shortId']) is not None, 'Invalid extra REALITY short ID')
        require(re.fullmatch(r'/[A-Za-z0-9_-]{8,64}', state['xhttpPath']) is not None, 'Invalid XHTTP path')
        require(re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{7,63}', state['grpcService']) is not None, 'Invalid gRPC service')
        key(state['shadowsocksServerKey'])
        if state['alternateSni'] is not None:
            host(state['alternateSni'], dns_only=True)
        require(isinstance(state['clients'], dict) and len(state['clients']) <= 253, 'Invalid extra clients')
        uuids = set()
        for name, item in state['clients'].items():
            valid_name(name)
            uuid.UUID(item['uuid'])
            require(item['uuid'] not in uuids, 'Duplicate extra UUID')
            uuids.add(item['uuid'])
            require(re.fullmatch(r'[0-9a-f]{64}', item['trojanPassword']) is not None, 'Invalid Trojan password')
            key(item['shadowsocksKey'])
    except (KeyError, TypeError, ValueError):
        raise ExtraError('Invalid extra protocol state') from None


def reality_stream(state, network, server_side=True, alternate=False):
    reality = state['reality']
    sni = state['alternateSni'] if alternate else reality['sni']
    options = ({'target': sni + ':443', 'serverNames': [sni], 'privateKey': reality['privateKey'],
                'shortIds': [reality['shortId']]} if server_side else
               {'serverName': sni, 'fingerprint': 'chrome', 'publicKey': reality['publicKey'],
                'shortId': reality['shortId']})
    stream = {'network': network, 'security': 'reality', 'realitySettings': options}
    if network == 'xhttp':
        stream['xhttpSettings'] = {'path': state['xhttpPath'], 'mode': 'auto'}
    elif network == 'grpc':
        stream['grpcSettings'] = {'serviceName': state['grpcService']}
    return stream


def server_config(state):
    clients = sorted(state['clients'].items())
    def vless_inbound(name, network, alternate=False):
        users = [{'id': item['uuid'], 'email': client} for client, item in clients]
        if alternate:
            for user in users:
                user['flow'] = 'xtls-rprx-vision'
        return {'tag': 'extra-' + name, 'listen': '0.0.0.0', 'port': state['ports'][name],
                'protocol': 'vless', 'settings': {'clients': users, 'decryption': 'none'},
                'streamSettings': reality_stream(state, network, alternate=alternate)}
    inbounds = [vless_inbound('xhttp', 'xhttp'), vless_inbound('grpc', 'grpc'),
                {'tag': 'extra-trojan', 'listen': '0.0.0.0', 'port': state['ports']['trojan'],
                 'protocol': 'trojan', 'settings': {'clients': [
                     {'password': item['trojanPassword'], 'email': client} for client, item in clients]},
                 'streamSettings': reality_stream(state, 'raw')},
                {'tag': 'extra-shadowsocks', 'listen': '0.0.0.0', 'port': state['ports']['shadowsocks'],
                 'protocol': 'shadowsocks', 'settings': {'network': 'tcp,udp',
                     'method': '2022-blake3-aes-256-gcm', 'password': state['shadowsocksServerKey'],
                     'users': [{'password': item['shadowsocksKey'], 'email': client} for client, item in clients]}}]
    if state['alternateSni']:
        inbounds.append(vless_inbound('vision', 'raw', alternate=True))
    if not clients:
        # An empty SS2022 users array means single-user mode with server key,
        # which previously provisioned clients know. Remove ALL listeners.
        inbounds = []
    return {'log': {'loglevel': 'warning'}, 'inbounds': inbounds,
            'outbounds': [{'protocol': 'freedom', 'tag': 'direct'}, {'protocol': 'blackhole', 'tag': 'block'}],
            'routing': {'domainStrategy': 'IPIfNonMatch', 'rules': [
                {'type': 'field', 'ip': PRIVATE_IPS, 'outboundTag': 'block'},
                {'type': 'field', 'protocol': ['bittorrent'], 'outboundTag': 'block'}]}}


def client_extras(state, name, address):
    name, address = valid_name(name), host(address)
    require(name in state['clients'], 'Client is absent from extra state; run install first')
    client = state['clients'][name]
    def vless_entry(identifier, title, endpoint, network, alternate=False):
        settings = {'address': address, 'port': state['ports'][endpoint], 'id': client['uuid'], 'encryption': 'none'}
        if alternate:
            # Chrome's QUIC/UDP 443 must be forwarded instead of Vision's default reject.
            settings['flow'] = 'xtls-rprx-vision-udp443'
        return {'id': identifier, 'title': title, 'outbound': {'protocol': 'vless', 'settings': settings,
                'streamSettings': reality_stream(state, network, server_side=False, alternate=alternate)}}
    result = [vless_entry('custom-vless-xhttp', 'VLESS · XHTTP + REALITY', 'xhttp', 'xhttp'),
              vless_entry('custom-vless-grpc', 'VLESS · gRPC + REALITY', 'grpc', 'grpc'),
              {'id': 'custom-trojan-reality', 'title': 'Trojan · REALITY', 'outbound': {
                  'protocol': 'trojan', 'settings': {'servers': [{'address': address,
                      'port': state['ports']['trojan'], 'password': client['trojanPassword']}]},
                  'streamSettings': reality_stream(state, 'raw', server_side=False),
                  'mux': {'enabled': True, 'concurrency': 8, 'xudpConcurrency': 8, 'xudpProxyUDP443': 'allow'}}},
              {'id': 'custom-shadowsocks2022', 'title': 'Shadowsocks 2022 · резерв', 'outbound': {
                  'protocol': 'shadowsocks', 'settings': {'servers': [{'address': address,
                      'port': state['ports']['shadowsocks'], 'method': '2022-blake3-aes-256-gcm',
                      'password': state['shadowsocksServerKey'] + ':' + client['shadowsocksKey']}]}}}]
    if state['alternateSni']:
        result.append(vless_entry('custom-vless-vision-alt', 'VLESS · Vision · альтернативный SNI',
                                 'vision', 'raw', alternate=True))
    return result


def merge_profile(profile, state, name):
    require(isinstance(profile, dict) and profile.get('client') == name and profile.get('version') == 2,
            'Base profile has wrong client or version')
    previous = profile.get('extraXray', [])
    require(isinstance(previous, list) and all(isinstance(e, dict) for e in previous), 'Invalid existing extra modes')
    result = copy.deepcopy(profile)
    result['extraXray'] = [e for e in previous if e.get('id') not in IDS] + client_extras(state, name, profile['host'])
    require(len(result['extraXray']) <= 8, 'Profile exceeds eight extra modes')
    return result


def invoke(argv, timeout=30, check=True):
    try:
        result = subprocess.run([str(x) for x in argv], capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise ExtraError('Required command is unavailable or timed out') from None
    if check and result.returncode:
        # Xray errors can include credentials/config fragments; do not print stderr.
        raise ExtraError('Command failed; configuration was not accepted')
    return result


def validate_xray(paths, config):
    paths.config.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.extra-check-', suffix='.json', dir=paths.config.parent)
    try:
        with os.fdopen(fd, 'wb') as file:
            file.write(encoded(config))
        invoke([paths.xray, 'run', '-test', '-format', 'json', '-c', name])
    finally:
        os.unlink(name)


def unit_contents():
    return b'''# Managed by My VPN extra_protocols.py; existing VPN services stay independent.
[Unit]
Description=My VPN additional Xray transports
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=/usr/local/bin/xray run -format json -c /usr/local/etc/xray/extra.json
Restart=on-failure
RestartSec=3
LimitNOFILE=65536
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
'''


def snapshot(path):
    if not path.exists() and not path.is_symlink():
        return None
    s = regular_file(path, private=False)
    return path.read_bytes(), stat.S_IMODE(s.st_mode), s.st_gid


def restore(path, saved):
    if saved is None:
        path.unlink(missing_ok=True)
    else:
        atomic_write(path, saved[0], saved[1], saved[2])


def verify_started(paths):
    # systemctl start can return before Xray binds ports or exits on a conflict.
    # Wait through two checks and reject a restart loop, including an early exit
    # followed by systemd's automatic restart. Disposable roots do not sleep.
    previous_pid = None
    for _ in range(2):
        if paths.root == Path('/'):
            time.sleep(1)
        invoke(['systemctl', 'is-active', '--quiet', SERVICE])
        result = invoke(['systemctl', 'show', '--property=MainPID', '--value', SERVICE])
        pid = result.stdout.strip()
        require(re.fullmatch(rb'[1-9][0-9]*', pid) is not None, 'Add-on has no running process')
        require(previous_pid is None or pid == previous_pid, 'Add-on restarted during startup')
        previous_pid = pid


def check_output(paths, output, base_profile=None):
    protected = {paths.state, paths.env, paths.config, paths.unit, paths.xray, paths.vpnctl}
    if base_profile is not None:
        protected.add(base_profile.absolute())
    # Resolve parent links as well as the final component; a typo must not
    # replace live configuration, a client's env, or an input profile.
    resolved = output.resolve()
    require(resolved not in {p.resolve() for p in protected}
            and paths.clients.resolve() not in resolved.parents,
            'Output must not overwrite server state, executable, or input files')


def install(paths, state, config):
    """Test first; replace atomically; restore files/service state on failure."""
    validate_xray(paths, config)
    saved = {path: snapshot(path) for path in (paths.state, paths.config, paths.unit)}
    active = invoke(['systemctl', 'is-active', '--quiet', SERVICE], check=False).returncode == 0
    enabled = invoke(['systemctl', 'is-enabled', '--quiet', SERVICE], check=False).returncode == 0
    require(not active or saved[paths.config] is not None, 'Active add-on has no managed configuration')
    if (saved[paths.state] and saved[paths.config] and saved[paths.unit]
            and saved[paths.state][0] == encoded(state) and saved[paths.config][0] == encoded(config)
            and saved[paths.unit][0] == unit_contents() and active and enabled):
        return False
    gid = grp.getgrnam('nogroup').gr_gid if paths.root == Path('/') else os.getegid()
    try:
        atomic_write(paths.state, encoded(state))
        atomic_write(paths.config, encoded(config), 0o640, gid)
        atomic_write(paths.unit, unit_contents(), 0o644)
        invoke(['systemctl', 'daemon-reload'])
        invoke(['systemctl', 'enable', SERVICE])
        invoke(['systemctl', 'restart' if active else 'start', SERVICE])
        verify_started(paths)
    except (ExtraError, OSError):
        rollback_failed = False
        for path, value in saved.items():
            try:
                restore(path, value)
            except (ExtraError, OSError):
                rollback_failed = True
        for command in (['daemon-reload'], ['restart' if active else 'stop', SERVICE],
                        ['enable' if enabled else 'disable', SERVICE]):
            try:
                if invoke(['systemctl', *command], check=False).returncode:
                    rollback_failed = True
            except ExtraError:
                rollback_failed = True
        if rollback_failed:
            raise ExtraError('Add-on install failed; rollback needs inspection. Existing xray/AWG services were not touched') from None
        raise ExtraError('Add-on install failed; previous add-on state restored. Existing xray/AWG services were not touched') from None
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--root', default='/', help='Disposable private filesystem root for offline testing')
    sub = parser.add_subparsers(dest='command', required=True)
    for command in ('render', 'install'):
        child = sub.add_parser(command)
        child.add_argument('--alternate-sni', help='Enable alternate Vision on 2053 after checking target TLS 1.3; empty disables')
        child.add_argument('--reality-sni', help='Change add-on XHTTP/gRPC/Trojan target after checking TLS 1.3 + HTTP/2')
        if command == 'render':
            child.add_argument('--output', type=Path, required=True)
    child = sub.add_parser('profile')
    child.add_argument('client')
    child.add_argument('--base-profile', type=Path, help='Optional private profile; otherwise reads vpnctl profile')
    child.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        paths = Paths(args.root)
        with paths.lock():
            server, clients = load_inputs(paths)
            if args.command == 'profile':
                check_output(paths, args.output, args.base_profile)
                name = valid_name(args.client)
                require(name in clients, 'Unknown client')
                state = decode_json(read_bytes(paths.state))
                validate_state(state, server)
                data = (read_bytes(args.base_profile) if args.base_profile else
                        invoke([paths.vpnctl, 'profile', name]).stdout)
                profile = merge_profile(decode_json(data), state, name)
                atomic_write(args.output, encoded(profile))
                print('Private profile written; keys were not printed')
            else:
                state = candidate_state(paths, server, clients, args.alternate_sni, args.reality_sni)
                config = server_config(state)
                if args.command == 'render':
                    check_output(paths, args.output)
                    validate_xray(paths, config)
                    atomic_write(args.output, encoded(config))
                    print('Private preview validated; no persistent state or services changed')
                else:
                    changed = install(paths, state, config)
                    print('Add-on installed' if changed else 'Add-on unchanged; no restart needed')
                    print('TCP: ' + ', '.join(str(i['port']) for i in config['inbounds']) +
                          '; UDP: ' + str(state['ports']['shadowsocks']))
        return 0
    except (ExtraError, OSError, KeyError, TypeError) as exc:
        message = str(exc) if isinstance(exc, ExtraError) else 'Cannot read or write required server files'
        print('Error: ' + message, file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
