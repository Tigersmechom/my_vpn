#!/usr/bin/env python3
"""Forward two or three fixed, encrypted UDP endpoints. No VPN keys are needed here."""
import argparse
import ipaddress
import json
from pathlib import Path
import shutil
import subprocess

CONFIG = Path('/etc/myvpn/udp-relay.json')
CHAINS = [('nat', 'PREROUTING', 'MYVPN_RELAY_IN'),
          ('nat', 'POSTROUTING', 'MYVPN_RELAY_OUT'),
          ('filter', 'FORWARD', 'MYVPN_RELAY_FWD')]


def validate(config):
    if set(config) != {'listen', 'target', 'ports'}:
        raise ValueError('invalid relay configuration')
    for name in ['listen', 'target']:
        address = ipaddress.ip_address(config[name])
        if address.version != 4 or not address.is_global:
            raise ValueError('relay endpoints must be public IPv4')
    if config['listen'] == config['target'] or len(config['ports']) not in (2, 3):
        raise ValueError('expected two or three remote UDP endpoints')
    for pair in config['ports']:
        if not isinstance(pair, list) or len(pair) != 2 or any(type(p) is not int or not 1 <= p <= 65535 for p in pair):
            raise ValueError('invalid UDP port pair')
    if any(len({pair[i] for pair in config['ports']}) != len(config['ports']) for i in [0, 1]):
        raise ValueError('duplicate UDP ports')
    return config


def rules(config):
    validate(config)
    listen, target = config['listen'], config['target']
    for incoming, outgoing in config['ports']:
        original = ['-m', 'conntrack', '--ctdir', 'ORIGINAL', '--ctorigdst', listen, '--ctorigdstport', str(incoming)]
        reply = ['-m', 'conntrack', '--ctdir', 'REPLY', '--ctorigdst', listen, '--ctorigdstport', str(incoming)]
        yield 'nat', 'MYVPN_RELAY_IN', ['-d', listen, '-p', 'udp', '--dport', str(incoming), '-j', 'DNAT', '--to-destination', f'{target}:{outgoing}']
        yield 'nat', 'MYVPN_RELAY_OUT', ['-d', target, '-p', 'udp', '--dport', str(outgoing), *original, '-j', 'SNAT', '--to-source', listen]
        yield 'filter', 'MYVPN_RELAY_FWD', ['-d', target, '-p', 'udp', '--dport', str(outgoing), *original, '-j', 'ACCEPT']
        yield 'filter', 'MYVPN_RELAY_FWD', ['-s', target, '-p', 'udp', '--sport', str(outgoing), *reply, '-j', 'ACCEPT']


def ipt(*args, check=True):
    return subprocess.run(['iptables', '-w', '10', *args], check=check, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def start(config):
    validate(config)
    subprocess.run(['sysctl', '-q', '-w', 'net.ipv4.ip_forward=1'], check=True)
    for table, parent, chain in CHAINS:
        ipt('-t', table, '-N', chain, check=False)
        ipt('-t', table, '-F', chain)
    for table, chain, rule in rules(config):
        ipt('-t', table, '-A', chain, *rule)
    for table, parent, chain in CHAINS:
        if ipt('-t', table, '-C', parent, '-j', chain, check=False).returncode:
            ipt('-t', table, '-I', parent, '1', '-j', chain)


def stop():
    for table, parent, chain in CHAINS:
        while not ipt('-t', table, '-C', parent, '-j', chain, check=False).returncode:
            ipt('-t', table, '-D', parent, '-j', chain)
        ipt('-t', table, '-F', chain, check=False)
        ipt('-t', table, '-X', chain, check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['install', 'start', 'stop'])
    parser.add_argument('--listen')
    parser.add_argument('--target')
    parser.add_argument('--target-ports', nargs='+', type=int)
    parser.add_argument('--listen-ports', nargs='+', type=int, help='Defaults to 10443, 10444, ...')
    args = parser.parse_args()
    if args.action == 'stop':
        stop()
        return
    if args.action == 'install':
        outgoing = args.target_ports or []
        incoming = args.listen_ports if args.listen_ports is not None else [10443+i for i in range(len(outgoing))]
        if len(incoming) != len(outgoing):
            parser.error('listen and target port counts must match')
        config = validate({'listen': args.listen, 'target': args.target,
                           'ports': [list(pair) for pair in zip(incoming, outgoing)]})
        CONFIG.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        CONFIG.write_text(json.dumps(config, indent=2)+'\n')
        CONFIG.chmod(0o600)
        Path('/etc/sysctl.d/90-myvpn-udp-relay.conf').write_text('net.ipv4.ip_forward=1\n')
        destination = Path('/usr/local/lib/myvpn/udp_relay.py')
        destination.parent.mkdir(parents=True, exist_ok=True)
        if Path(__file__).resolve() != destination:
            shutil.copyfile(__file__, destination)
        destination.chmod(0o755)
        Path('/etc/systemd/system/myvpn-udp-relay.service').write_text('''[Unit]
Description=MyVPN fixed UDP relay
Wants=network-online.target
After=network-online.target docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/python3 /usr/local/lib/myvpn/udp_relay.py start
ExecStop=/usr/bin/python3 /usr/local/lib/myvpn/udp_relay.py stop

[Install]
WantedBy=multi-user.target
''')
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
        subprocess.run(['systemctl', 'enable', 'myvpn-udp-relay'], check=True)
        subprocess.run(['systemctl', 'restart', 'myvpn-udp-relay'], check=True)
    else:
        start(json.loads(CONFIG.read_text()))


if __name__ == '__main__':
    main()
