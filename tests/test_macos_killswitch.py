"""Run the real macOS helper in a temporary filesystem with fake network tools.

No sudo, real PF writes, TUN, routes, DNS changes or production core signals.
The separate parser check uses system pfctl with -n (parse only).
"""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
STUB = r'''
import json, os, pathlib, signal, subprocess, sys, time
root = pathlib.Path(os.environ['MYVPN_FIXTURE'])
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with (root/'calls').open('a') as log:
    log.write(json.dumps([name, *args])+'\n')
if name == 'pfctl':
    path = root/'pf.json'
    state = json.loads(path.read_text()) if path.exists() else {'enabled': False, 'rules': ''}
    if args == ['-sr']:
        print(state.get('root', os.environ.get('MYVPN_ROOT_RULES', 'anchor "com.apple/*" all')))
    elif args == ['-a', 'com.apple', '-s', 'Anchors']:
        print(os.environ.get('MYVPN_ANCHORS', '  com.apple/000.myvpn\n  com.apple/100.InternetSharing'))
    elif args == ['-v', '-s', 'Interfaces']:
        print('lo0 (skip)\nen0' + (' (skip)' if os.environ.get('MYVPN_SKIP') else ''))
    elif args == ['-si']:
        print('Status: ' + ('Enabled' if state['enabled'] else 'Disabled'))
    elif args == ['-E']:
        state['enabled'] = True
        print('Token : 6001')
    elif args == ['-X', '6001']:
        state['enabled'] = False
    elif args[:2] == ['-k', '0.0.0.0/0'] or args[:2] == ['-k', '::/0']:
        pass
    elif args == ['-a', 'com.apple/000.myvpn', '-sr']:
        print(state['rules'])
    elif '-f' in args:
        rules = pathlib.Path(args[args.index('-f')+1]).read_text()
        if '-n' not in args:
            if os.environ.get('MYVPN_FAIL_GATE') and 'pass quick on utun' in rules:
                sys.exit(9)
            if os.environ.get('MYVPN_FAIL_RELEASE') and not rules:
                sys.exit(9)
            if '-R' in args:
                state['root'] = 'anchor "com.apple/*" all'
            else:
                state['rules'] = rules
    else:
        sys.exit('Unexpected PF mutation: '+repr(args))
    path.write_text(json.dumps(state))
elif name == 'route':
    if args[:3] == ['-n','get','default']:
        print('gateway: 192.0.2.1\ninterface: en0')
elif name == 'networksetup':
    if args == ['-listallnetworkservices']:
        print('An asterisk denotes a disabled service.\nWi-Fi')
    elif args[:1] == ['-getdnsservers']:
        print("There aren't any DNS Servers set on Wi-Fi.")
elif name == 'ifconfig':
    if len(args) == 1:
        marker = root/args[0]
        if not marker.exists(): sys.exit(1)
        try: os.kill(int(marker.read_text()), 0)
        except ProcessLookupError: sys.exit(1)
elif name in ('xray', 'amneziawg-go'):
    if os.environ.get('MYVPN_FAIL_CORE'):
        sys.exit(8)
    iface = 'utun199' if name == 'xray' else 'utun7'
    if name == 'amneziawg-go' and args == ['utun']:
        assert os.environ.get('MYVPN_OUTBOUND_INTERFACE') == 'en0'
        worker = subprocess.Popen([sys.executable, str(root/'bin'/'amneziawg-go'), 'worker'],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (root/'awg.pid').write_text(str(worker.pid))
        pathlib.Path(os.environ['WG_TUN_NAME_FILE']).write_text(iface)
        sys.exit(0)
    (root/iface).write_text(str(os.getpid()))
    def end(*unused):
        (root/iface).unlink(missing_ok=True)
        sys.exit(0)
    signal.signal(signal.SIGTERM, end)
    while True: time.sleep(.1)
elif name == 'awg':
    if args[:1] == ['setconf'] and os.environ.get('MYVPN_FAIL_SETCONF'):
        sys.exit(8)
elif name == 'pgrep':
    sys.exit(1)
elif name == 'pkill':
    marker = root/'awg.pid'
    if marker.exists():
        try: os.kill(int(marker.read_text()), signal.SIGTERM)
        except ProcessLookupError: pass
elif name not in ('dscacheutil', 'killall'):
    sys.exit('Unexpected network command: '+name)
'''


class MacKillSwitchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='myvpn-killswitch-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bindir = self.root/'bin'
        self.bindir.mkdir()
        self.run = self.root/'run'
        self.run.mkdir()
        for name in ('pfctl', 'route', 'networksetup', 'ifconfig', 'xray', 'amneziawg-go',
                     'awg', 'pgrep', 'pkill', 'dscacheutil', 'killall'):
            file = self.bindir/name
            file.write_text(f'#!{sys.executable}\n'+STUB)
            file.chmod(0o755)
        source = (ROOT/'macos/helper/myvpn-helper').read_text()
        source = source.replace('DIR=/Library/PrivilegedHelperTools/myvpn', f'DIR="{self.bindir}"')
        source = source.replace('RUN=/var/run/myvpn', f'RUN="{self.run}"')
        source = source.replace('LOG=/var/log/myvpn.log', f'LOG="{self.root}/helper.log"')
        source = source.replace('PATH=/usr/bin:/bin:/usr/sbin:/sbin', f'PATH="{self.bindir}:/usr/bin:/bin:/usr/sbin:/sbin"')
        source = source.replace('[[ $EUID -eq 0 ]] || die "нужны права root"', ': # fixture needs no privileges')
        self.helper = self.bindir/'myvpn-helper'
        self.helper.write_text(source)
        (self.bindir/'kill-switch.sh').write_text((ROOT/'macos/helper/kill-switch.sh').read_text())
        self.config = self.root/'xray.json'
        self.config.write_text('{"outbounds":[],"routing":{"rules":[]}}')
        self.conf = self.root/'awg.conf'
        self.conf.write_text('[Interface]\nPrivateKey = fixture\n[Peer]\nEndpoint = 203.0.113.10:443\nAllowedIPs = 0.0.0.0/0\n')
        self.env = dict(os.environ, MYVPN_FIXTURE=str(self.root))
        self.addCleanup(self.cleanup_cores)

    def cleanup_cores(self):
        for file in (self.run/'xray.pid', self.root/'awg.pid'):
            if file.exists():
                try: os.kill(int(file.read_text()), signal.SIGTERM)
                except ProcessLookupError: pass

    def command(self, *args, ok=True):
        result = subprocess.run(['/bin/bash', str(self.helper), *args], env=self.env,
                                capture_output=True, text=True, timeout=15)
        if ok:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
        return result

    def start(self, ip='203.0.113.10', port='443', transport='udp', ok=True):
        return self.command('start-xray', str(self.config), '1.1.1.1', ip, port, transport, ok=ok)

    def pf(self):
        return json.loads((self.root/'pf.json').read_text())

    def calls(self):
        return [json.loads(line) for line in (self.root/'calls').read_text().splitlines()]

    def test_guard_is_armed_before_core_and_old_states_removed_for_both_families(self):
        self.start()
        calls = self.calls()
        start = next(i for i,c in enumerate(calls) if c[0] == 'xray')
        for family in ('0.0.0.0/0', '::/0'):
            self.assertLess(calls.index(['pfctl', '-k', family]), start)
        self.assertIn('pass quick on utun199 inet all no state', self.pf()['rules'])
        self.assertIn('user root keep state (if-bound)', self.pf()['rules'])
        self.assertIn('kill-switch on', self.command('status').stdout)

    def test_core_crash_keeps_guard_and_reports_blocked(self):
        self.start()
        os.kill(int((self.run/'xray.pid').read_text()), signal.SIGTERM)
        for _ in range(50):
            if not (self.root/'utun199').exists(): break
            time.sleep(.02)
        status = self.command('status').stdout
        self.assertTrue(status.startswith('blocked'), status)
        self.assertTrue(self.pf()['enabled'])
        self.assertIn('block drop quick all', self.pf()['rules'])

    def test_start_failure_stays_blocked_and_can_reconnect_to_second_country(self):
        self.env['MYVPN_FAIL_CORE'] = '1'
        self.start(ok=False)
        self.assertTrue(self.command('status').stdout.startswith('blocked'))
        self.assertNotIn('pass quick on utun', self.pf()['rules'])
        del self.env['MYVPN_FAIL_CORE']
        self.start(ip='203.0.113.21', port='29860')
        self.assertIn('to 203.0.113.21 port 29860', self.pf()['rules'])
        self.assertNotIn('203.0.113.10', self.pf()['rules'])
        self.assertFalse(any(c == ['pfctl', '-a', 'com.apple/000.myvpn', '-f', '/dev/null'] for c in self.calls()))

    def test_failed_opening_of_tunnel_gate_does_not_release_guard(self):
        self.env['MYVPN_FAIL_GATE'] = '1'
        self.start(ok=False)
        self.assertTrue(self.pf()['enabled'])
        self.assertNotIn('pass quick on utun', self.pf()['rules'])
        self.assertTrue(self.command('status').stdout.startswith('blocked'))

    def test_explicit_disconnect_restores_dns_and_only_own_anchor_and_token(self):
        self.start()
        self.command('stop')
        self.assertEqual(self.command('status').stdout, 'down\nkill-switch off\n')
        self.assertEqual(self.pf()['rules'], '')
        calls = self.calls()
        self.assertIn(['pfctl', '-X', '6001'], calls)
        self.assertIn(['networksetup', '-setdnsservers', 'Wi-Fi', 'Empty'], calls)
        self.assertFalse(any('-d' in c or '-F' in c for c in calls if c[0] == 'pfctl'))

    def test_failed_disconnect_keeps_recoverable_marker_and_reports_error(self):
        self.start()
        self.env['MYVPN_FAIL_RELEASE'] = '1'
        self.command('stop', ok=False)
        self.assertTrue((self.run/'ks.active').exists())
        self.assertIn('block drop quick all', self.pf()['rules'])
        del self.env['MYVPN_FAIL_RELEASE']
        self.command('stop')
        self.assertFalse((self.run/'ks.active').exists())

    def test_awg_binds_transport_without_host_bypass(self):
        self.command('start-awg', str(self.conf), '10.77.77.2/32', '1280', '1.1.1.1', '203.0.113.10', '443')
        self.assertIn('pass quick on utun7 inet all no state', self.pf()['rules'])
        routes = [c for c in self.calls() if c[0] == 'route']
        self.assertFalse(any('203.0.113.10/32' in c for c in routes))
        self.assertTrue(self.command('status').stdout.startswith('awg utun7'))

    def test_awg_setconf_failure_keeps_guard(self):
        self.env['MYVPN_FAIL_SETCONF'] = '1'
        self.command('start-awg', str(self.conf), '10.77.77.2/32', '1280', '1.1.1.1', '203.0.113.10', '443', ok=False)
        self.assertTrue(self.command('status').stdout.startswith('blocked'))
        self.assertNotIn('pass quick on utun', self.pf()['rules'])

    def test_custom_pf_or_skipped_interface_rejected_before_start(self):
        for key,value in [('MYVPN_ROOT_RULES', 'pass out quick all\nanchor "com.apple/*" all'), ('MYVPN_SKIP','1'),
                          ('MYVPN_ANCHORS', '  com.apple/!earlier\n  com.apple/000.myvpn')]:
            self.env[key] = value
            self.start(ok=False)
            self.assertFalse(any(c[0] == 'xray' for c in self.calls()))
            del self.env[key]

    def test_invalid_endpoint_cannot_inject_rules(self):
        for ip,port,transport in [('203.0.113.256','443','udp'), ('203.0.113.01','443','udp'),
                                  ('203.0.113.10\npass all','443','udp'), ('203.0.113.10','0','udp'),
                                  ('203.0.113.10','65536','udp'), ('203.0.113.10','443','tcp\npass all')]:
            self.start(ip, port, transport, ok=False)
        self.assertFalse((self.root/'calls').exists())

    def test_pf_disabled_externally_never_reported_as_protected(self):
        self.start()
        state = self.pf()
        state['enabled'] = False
        (self.root/'pf.json').write_text(json.dumps(state))
        self.assertIn('kill-switch failed', self.command('status').stdout)

    def test_empty_root_filter_initializes_only_apple_anchor(self):
        self.env['MYVPN_ROOT_RULES'] = ''
        self.start()
        self.assertEqual(self.pf()['root'], 'anchor "com.apple/*" all')
        self.assertIn(['pfctl', '-R', '-f', str(self.run/'pf-root.conf')], self.calls())
        self.assertEqual((self.run/'pf-root.conf').read_text(), 'anchor "com.apple/*"\n')

    def test_installer_refuses_to_replace_active_helper_without_disconnecting(self):
        self.start()
        self.helper.chmod(0o755)
        before = self.helper.read_bytes()
        script = (ROOT/'macos/helper/install-helper.sh').read_text()
        script = script.replace('DEST=/Library/PrivilegedHelperTools/myvpn', f'DEST="{self.bindir}"')
        script = script.replace('SUDOERS=/etc/sudoers.d/myvpn', f'SUDOERS="{self.root}/sudoers"')
        installer = self.root/'installer'
        installer.write_text(script)
        result = subprocess.run(['/bin/bash', str(installer), 'install', str(self.root), '501'],
                                env=self.env, capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Сначала явно отключите VPN', result.stderr)
        self.assertEqual(self.helper.read_bytes(), before)
        self.assertIn('pass quick on utun199', self.pf()['rules'])
        self.assertNotIn(['pfctl', '-a', 'com.apple/000.myvpn', '-f', '/dev/null'], self.calls())

    @unittest.skipUnless(Path('/sbin/pfctl').exists(), 'macOS PF syntax parser required')
    def test_native_pf_parser_accepts_exact_generated_rules_for_all_transports(self):
        for transport in ('tcp', 'udp', 'tcp-udp'):
            for name,value in [('ip','203.0.113.10'), ('port','443'), ('proto',transport)]:
                (self.run/f'ks.{name}').write_text(value+'\n')
            script = 'RUN="$1"; source "$2"; ks_rules utun199'
            rules = subprocess.check_output(['/bin/bash', '-c', script, 'fixture', str(self.run),
                                              str(ROOT/'macos/helper/kill-switch.sh')])
            result = subprocess.run(['/sbin/pfctl', '-n', '-a', 'com.apple/000.myvpn', '-f', '-'],
                                    input=rules, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())


if __name__ == '__main__':
    unittest.main()
