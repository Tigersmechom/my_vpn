import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from urllib.parse import parse_qs, unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('vpn_export', ROOT / 'server/export.py')
export = importlib.util.module_from_spec(spec)
spec.loader.exec_module(export)


def fixture():
    p = json.loads((ROOT / 'config/example.json').read_text())
    p['version'] = 2
    p['client'] = 'test-device'
    p['vless']['publicKey'] = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('=')
    for name in ('privateKey', 'serverPublicKey', 'presharedKey'):
        p['awg'][name] = base64.b64encode(bytes(range(32))).decode()
    p['hy2'].update(auth='user:p@ss /+#?&=%', obfsPassword='salamander /+#?&=%', pinSha256='AB:' * 31 + 'AB')
    return p


class ExportTests(unittest.TestCase):
    def test_scope_and_distinct_hysteria_modes(self):
        p = fixture()
        p['wg'] = {'privateKey': 'DELETED-SECRET'}
        p['vless'].update(xhttpPort=8443, xhttpPath='/REMOVED')
        files = export.build_bundle(p)
        links = files['v2raytun-android.txt'].splitlines()
        self.assertEqual([urlsplit(x).scheme for x in links], ['vless', 'hysteria2', 'hysteria2'])
        self.assertEqual(files['v2raytun-macos-vless.txt'].strip(), links[0])
        self.assertEqual(base64.b64decode(files['subscription-base64.txt']).decode(), files['v2raytun-android.txt'])
        self.assertNotIn('DELETED-SECRET', ''.join(files.values()))
        self.assertNotIn('REMOVED', ''.join(files.values()))
        self.assertNotEqual(urlsplit(links[1]).port, urlsplit(links[2]).port)
        self.assertNotIn('obfs', parse_qs(urlsplit(links[1]).query))
        self.assertEqual(parse_qs(urlsplit(links[2]).query)['obfs'], ['salamander'])

    def test_credentials_roundtrip_without_query_injection(self):
        p = fixture()
        link = urlsplit(export.hy2_uri(p, obfs=True))
        self.assertEqual(unquote(link.username), p['hy2']['auth'])
        query = parse_qs(link.query)
        self.assertEqual(query['obfs-password'], [p['hy2']['obfsPassword']])
        self.assertEqual(query['pinnedPeerCertSha256'], ['ab' * 32])
        self.assertNotIn('insecure', query)
        native = parse_qs(urlsplit(export.hy2_uri(p, native=True)).query)
        self.assertEqual(native['insecure'], ['1'])
        self.assertEqual(native['pinSHA256'], ['ab' * 32])

    def test_xray_and_awg_semantics(self):
        p = fixture()
        files = export.build_bundle(p)
        for name in ('hy2', 'hy2-obfs'):
            cfg = json.loads(files[name + '-xray.json'])
            self.assertEqual(cfg['inbounds'][0]['listen'], '127.0.0.1')
            proxy = cfg['outbounds'][0]
            self.assertEqual(proxy['settings']['address'], p['host'])
            self.assertEqual(proxy['streamSettings']['tlsSettings']['pinnedPeerCertSha256'], 'ab' * 32)
            self.assertNotIn('allowInsecure', proxy['streamSettings']['tlsSettings'])
        conf = files['amneziawg.conf']
        for token in ('S3 = ', 'S4 = ', 'H4 = ', 'I1 = ', 'AllowedIPs = 0.0.0.0/0, ::/0'):
            self.assertIn(token, conf)
        self.assertIn('PresharedKey = ' + p['awg']['presharedKey'], conf)
        self.assertEqual(parse_qs(urlsplit(export.vless_uri(p)).query)['flow'], ['xtls-rprx-vision'])

    def test_ipv6_server_authority(self):
        p = fixture()
        p['host'] = '2001:db8::1'
        self.assertEqual(urlsplit(export.vless_uri(p)).hostname, p['host'])
        self.assertIn('Endpoint = [2001:db8::1]:', export.awg_conf(p))

    def test_invalid_profiles_fail_before_writing(self):
        changes = [
            ('host', 'host.invalid\nPostUp = run'),
            ('client', '../outside'),
            ('hy2.pinSha256', ''),
            ('hy2.pinSha256', 'xx' * 32),
            ('hy2.port', True),
            ('vless.tcpPort', 65536),
            ('awg.i1', '<r 2>\nPostUp=oops'),
            ('awg.privateKey', 'BAD-KEY'),
            ('awg.h1', '-1'),
            ('dns', '1.1.1.1\nBad=true'),
        ]
        for path, value in changes:
            p = fixture()
            obj = p
            keys = path.split('.')
            for k in keys[:-1]:
                obj = obj[k]
            obj[keys[-1]] = value
            with self.subTest(path=path), self.assertRaises(export.ProfileError):
                export.build_bundle(p)

    def test_no_port_collisions(self):
        p = fixture()
        p['hy2']['obfsPort'] = p['hy2']['port']
        with self.assertRaises(export.ProfileError):
            export.build_bundle(p)
        p = fixture()
        p['awg']['port'] = p['hy2']['port']
        with self.assertRaises(export.ProfileError):
            export.build_bundle(p)

    def test_private_atomic_output_and_no_following_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / 'bundle'
            files = export.build_bundle(fixture())
            export.write_bundle(out, files)
            self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o700)
            for f in out.iterdir():
                self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o600)
            victim = Path(temp) / 'victim'
            victim.write_text('unchanged')
            target = out / 'v2raytun-android.txt'
            target.unlink()
            target.symlink_to(victim)
            export.write_bundle(out, files)
            self.assertEqual(victim.read_text(), 'unchanged')
            self.assertFalse(target.is_symlink())
            alias = Path(temp) / 'alias'
            alias.symlink_to(out, target_is_directory=True)
            with self.assertRaises(export.ProfileError):
                export.write_bundle(alias, files)

    def test_cli_stdin_and_errors_do_not_print_secrets(self):
        with tempfile.TemporaryDirectory() as temp:
            p = fixture()
            cmd = [sys.executable, str(ROOT / 'server/export.py'), '--profile', '-', '--output', str(Path(temp) / 'out')]
            result = subprocess.run(cmd, input=json.dumps(p), text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn(p['hy2']['auth'], result.stdout + result.stderr)
            result = subprocess.run(cmd, input='{"hy2":"SECRET-UNPARSEABLE', text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('SECRET-UNPARSEABLE', result.stderr)


if __name__ == '__main__':
    unittest.main()
