"""Add-on rendering and isolated service transaction tests; no real service starts."""
import base64
import copy
import importlib.util
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import subprocess
import socket
import threading
import time
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('extra_protocols', REPO / 'server/extra_protocols.py')
extra = importlib.util.module_from_spec(spec)
spec.loader.exec_module(extra)


def fixture_key(value, urlsafe=False):
    result = base64.urlsafe_b64encode(bytes([value]) * 32).decode() if urlsafe else base64.b64encode(bytes([value]) * 32).decode()
    return result.rstrip('=') if urlsafe else result


class ExtraTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='myvpn-extra-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.paths = extra.Paths(self.root)
        self.paths.clients.mkdir(parents=True)
        self.server = {'PUBLIC_HOST': '192.0.2.15', 'REALITY_SNI': 'www.example.com',
                       'REALITY_PRIVATE_KEY': fixture_key(41, True),
                       'REALITY_PUBLIC_KEY': fixture_key(42, True),
                       'VLESS_TCP_PORT': '443', 'AWG_PORT': '53685', 'HY2_PORT': '443', 'HY2_OBFS_PORT': '29426'}
        self.write_env(self.paths.env, self.server)
        self.write_env(self.paths.clients / 'android.env', {'CLIENT_NAME': 'android',
                       'VLESS_UUID': 'cb92aae2-8ed7-4a46-9e4c-7ef06f576f8b'})
        self.write_env(self.paths.clients / 'mac.env', {'CLIENT_NAME': 'mac',
                       'VLESS_UUID': 'c8517865-216f-48fd-a84d-37e40222ed25'})
        self.clients = extra.load_inputs(self.paths)[1]
        self.state = extra.candidate_state(self.paths, self.server, self.clients, alternate_sni='www.yandex.ru')
        self.config = extra.server_config(self.state)

    def write_env(self, path, value):
        extra.atomic_write(path, ''.join(f"{k}='{v}'\n" for k, v in value.items()).encode())

    def persist(self):
        extra.atomic_write(self.paths.state, extra.encoded(self.state))

    def test_render_deterministic_and_persisted_keys_unchanged(self):
        self.persist()
        same = extra.candidate_state(self.paths, self.server, self.clients)
        self.assertEqual(self.state, same)
        self.assertEqual(self.config, extra.server_config(same))
        self.assertEqual(0o600, self.paths.state.stat().st_mode & 0o777)

    def test_add_remove_clients_preserves_others(self):
        self.persist()
        clients = {'android': {}, 'new_device': {}}
        changed = extra.candidate_state(self.paths, self.server, clients)
        self.assertEqual(self.state['clients']['android'], changed['clients']['android'])
        self.assertNotIn('mac', changed['clients'])
        self.assertNotEqual(changed['clients']['android'], changed['clients']['new_device'])
        self.assertEqual(self.state['shadowsocksServerKey'], changed['shadowsocksServerKey'])

    def test_removing_last_client_removes_all_listeners(self):
        self.persist()
        for file in self.paths.clients.glob('*.env'):
            file.unlink()
        server, clients = extra.load_inputs(self.paths)
        self.assertEqual({}, clients)
        changed = extra.candidate_state(self.paths, server, clients)
        self.assertEqual({}, changed['clients'])
        config = extra.server_config(changed)
        self.assertEqual([], config['inbounds'])
        binary = REPO / 'macos/vendor/xray'
        if binary.is_file():
            file = self.root / 'empty.json'
            extra.atomic_write(file, extra.encoded(config))
            proc = subprocess.run([str(binary), 'run', '-test', '-format', 'json', '-c', str(file)], capture_output=True)
            self.assertEqual(0, proc.returncode, 'Empty add-on config rejected by bundled Xray')

    def test_expected_ports_flow_and_ss_multiuser(self):
        by_tag = {i['tag']: i for i in self.config['inbounds']}
        self.assertEqual([8443, 8444, 9443, 8388, 2053], [i['port'] for i in self.config['inbounds']])
        self.assertNotIn('flow', by_tag['extra-xhttp']['settings']['clients'][0])
        self.assertNotIn('flow', by_tag['extra-grpc']['settings']['clients'][0])
        self.assertEqual('xtls-rprx-vision', by_tag['extra-vision']['settings']['clients'][0]['flow'])
        extras = extra.client_extras(self.state, 'android', self.server['PUBLIC_HOST'])
        ss = extras[3]['outbound']['settings']['servers'][0]
        self.assertEqual(self.state['shadowsocksServerKey'] + ':' + self.state['clients']['android']['shadowsocksKey'], ss['password'])
        self.assertEqual('xtls-rprx-vision-udp443', extras[4]['outbound']['settings']['flow'])
        self.assertTrue(extras[2]['outbound']['mux']['enabled'])
        self.assertEqual('allow', extras[2]['outbound']['mux']['xudpProxyUDP443'])
        self.assertEqual('tcp,udp', by_tag['extra-shadowsocks']['settings']['network'])

    def test_profile_merge_preserves_base_and_other_extra(self):
        original = {'version': 2, 'client': 'android', 'host': '192.0.2.15',
                    'vless': {'tcpPort': 443, 'publicKey': 'unchanged'},
                    'awg': {'privateKey': 'unchanged'}, 'extraXray': [
                        {'id': 'custom-owned', 'outbound': {'protocol': 'trojan'}},
                        {'id': 'custom-vless-xhttp', 'old': True}]}
        saved = copy.deepcopy(original)
        merged = extra.merge_profile(original, self.state, 'android')
        self.assertEqual(saved, original)
        self.assertEqual(saved['vless'], merged['vless'])
        self.assertEqual(saved['awg'], merged['awg'])
        self.assertEqual(6, len(merged['extraXray']))
        self.assertNotIn('old', merged['extraXray'][1])
        self.assertEqual(merged, extra.merge_profile(merged, self.state, 'android'))
        self.assertNotIn(self.state['reality']['privateKey'], json.dumps(merged))
        self.assertNotIn(self.state['clients']['mac']['trojanPassword'], json.dumps(merged))

    def test_bad_profile_identity_or_too_many_extras_rejected(self):
        for profile in ({'version': 2, 'client': 'mac', 'host': '192.0.2.15'},
                        {'version': 1, 'client': 'android', 'host': '192.0.2.15'},
                        {'version': 2, 'client': 'android', 'host': '192.0.2.15',
                         'extraXray': [{'id': 'custom-other-' + str(n)} for n in range(4)]}):
            with self.assertRaises(extra.ExtraError):
                extra.merge_profile(profile, self.state, 'android')

    def test_env_never_executes_shell(self):
        marker = self.root / 'must-not-exist'
        self.paths.env.write_text(f'PUBLIC_HOST=$(touch {marker})\n')
        with self.assertRaises(extra.ExtraError):
            extra.read_env(self.paths.env)
        self.assertFalse(marker.exists())
        self.paths.env.write_text("PUBLIC_HOST='one'\nPUBLIC_HOST='two'\n")
        with self.assertRaises(extra.ExtraError):
            extra.read_env(self.paths.env)

    def test_permissions_symlinks_and_duplicate_json_rejected(self):
        self.paths.env.chmod(0o644)
        with self.assertRaises(extra.ExtraError):
            extra.read_env(self.paths.env)
        link = self.root / 'link'
        link.symlink_to(self.paths.env)
        with self.assertRaises(extra.ExtraError):
            extra.read_bytes(link, private=False)
        with self.assertRaises(extra.ExtraError):
            extra.atomic_write(link, b'bad')
        with self.assertRaises(extra.ExtraError):
            extra.decode_json(b'{"version":1,"version":2}')

    def test_invalid_state_ports_keys_and_target_fail(self):
        mutations = [lambda s: s['ports'].update(xhttp=443),
                     lambda s: s['ports'].update(xhttp=53685),
                     lambda s: s['ports'].update(grpc=8443),
                     lambda s: s['ports'].update(xhttp=True),
                     lambda s: s['reality'].update(privateKey='bad'),
                     lambda s: s.update(alternateSni='example.com;id'),
                     lambda s: s['clients']['android'].update(trojanPassword='bad')]
        for mutate in mutations:
            candidate = copy.deepcopy(self.state)
            mutate(candidate)
            with self.assertRaises(extra.ExtraError):
                extra.validate_state(candidate, self.server)

    def test_xray_reject_keeps_state_config_unit_and_services(self):
        self.persist()
        extra.atomic_write(self.paths.config, b'previous config')
        extra.atomic_write(self.paths.unit, b'previous unit')
        before = [p.read_bytes() for p in (self.paths.state, self.paths.config, self.paths.unit)]
        with patch.object(extra, 'validate_xray', side_effect=extra.ExtraError('rejected')), patch.object(extra, 'invoke') as calls:
            with self.assertRaises(extra.ExtraError):
                extra.install(self.paths, self.state, self.config)
            calls.assert_not_called()
        self.assertEqual(before, [p.read_bytes() for p in (self.paths.state, self.paths.config, self.paths.unit)])

    def test_install_only_touches_addon_service_and_idempotent(self):
        calls = []
        active, enabled = False, False
        def invoke(argv, **kwargs):
            nonlocal active, enabled
            calls.append(argv)
            code = 0
            if argv[1] == 'is-active': code = 0 if active else 3
            elif argv[1] == 'is-enabled': code = 0 if enabled else 1
            elif argv[1] in ('start', 'restart'): active = True
            elif argv[1] == 'enable': enabled = True
            return subprocess.CompletedProcess(argv, code, b'1234' if argv[1] == 'show' else b'', b'')
        with patch.object(extra, 'validate_xray'), patch.object(extra, 'invoke', side_effect=invoke):
            self.assertTrue(extra.install(self.paths, self.state, self.config))
            first = len(calls)
            self.assertFalse(extra.install(self.paths, self.state, self.config))
            self.assertEqual(['is-active', 'is-enabled'], [c[1] for c in calls[first:]])
        for command in calls:
            self.assertEqual('systemctl', command[0])
            if command[1] != 'daemon-reload':
                self.assertEqual(extra.SERVICE, command[-1])
        self.assertEqual(0o640, self.paths.config.stat().st_mode & 0o777)
        self.assertEqual(0o600, self.paths.state.stat().st_mode & 0o777)
        self.assertIn(b'User=nobody', self.paths.unit.read_bytes())
        self.assertNotIn(b'xray.service', self.paths.unit.read_bytes())

    def test_failed_start_restores_previous_active_addon(self):
        self.persist()
        extra.atomic_write(self.paths.config, b'old config', 0o640)
        extra.atomic_write(self.paths.unit, b'old unit', 0o644)
        before = [p.read_bytes() for p in (self.paths.state, self.paths.config, self.paths.unit)]
        calls, restarts = [], 0
        def invoke(argv, **kwargs):
            nonlocal restarts
            calls.append(argv)
            if argv[1] == 'restart':
                restarts += 1
                if restarts == 1:
                    raise extra.ExtraError('failed')
            return subprocess.CompletedProcess(argv, 0, b'1234' if argv[1] == 'show' else b'', b'')
        with patch.object(extra, 'validate_xray'), patch.object(extra, 'invoke', side_effect=invoke):
            with self.assertRaisesRegex(extra.ExtraError, 'restored'):
                extra.install(self.paths, self.state, self.config)
        self.assertEqual(before, [p.read_bytes() for p in (self.paths.state, self.paths.config, self.paths.unit)])
        self.assertEqual(2, restarts)
        self.assertTrue(all(c[-1] == extra.SERVICE or c[1] == 'daemon-reload' for c in calls))

    def test_partial_file_write_failure_rolls_back(self):
        self.persist()
        extra.atomic_write(self.paths.config, b'old config', 0o640)
        extra.atomic_write(self.paths.unit, b'old unit', 0o644)
        before = [p.read_bytes() for p in (self.paths.state, self.paths.config, self.paths.unit)]
        original_write = extra.atomic_write
        failed = False
        def write(path, *args, **kwargs):
            nonlocal failed
            if path == self.paths.config and not failed:
                failed = True
                raise OSError('fixture disk failure')
            return original_write(path, *args, **kwargs)
        def invoke(argv, **kwargs):
            code = 3 if argv[1] in ('is-active', 'is-enabled') else 0
            return subprocess.CompletedProcess(argv, code, b'', b'')
        with patch.object(extra, 'validate_xray'), patch.object(extra, 'atomic_write', side_effect=write), \
                patch.object(extra, 'invoke', side_effect=invoke):
            with self.assertRaisesRegex(extra.ExtraError, 'restored'):
                extra.install(self.paths, self.state, self.config)
        self.assertEqual(before, [p.read_bytes() for p in (self.paths.state, self.paths.config, self.paths.unit)])

    def test_startup_rejects_exited_or_restarting_process(self):
        for pids in ([b'0'], [b'1234', b'5678']):
            values = iter(pids)
            def invoke(argv, **kwargs):
                return subprocess.CompletedProcess(argv, 0, next(values) if argv[1] == 'show' else b'', b'')
            with patch.object(extra, 'invoke', side_effect=invoke):
                with self.assertRaises(extra.ExtraError):
                    extra.verify_started(self.paths)

    def test_preview_and_profile_outputs_cannot_overwrite_inputs(self):
        inputs = [self.paths.state, self.paths.env, self.paths.config, self.paths.unit,
                  self.paths.xray, self.paths.vpnctl, self.paths.clients / 'android.env']
        for output in inputs:
            with self.assertRaises(extra.ExtraError):
                extra.check_output(self.paths, output)
        with self.assertRaises(extra.ExtraError):
            extra.check_output(self.paths, self.root / 'input.json', self.root / 'input.json')
        extra.check_output(self.paths, self.root / 'private-profile.json')

    def test_render_does_not_persist_new_state_or_manage_services(self):
        output = self.root / 'preview.json'
        with patch.object(extra, 'validate_xray'), patch.object(extra, 'invoke') as calls:
            self.assertEqual(0, extra.main(['--root', str(self.root), 'render', '--output', str(output)]))
            calls.assert_not_called()
        self.assertTrue(output.is_file())
        self.assertFalse(self.paths.state.exists())
        self.assertFalse(self.paths.unit.exists())
        self.assertFalse(self.paths.config.exists())

    def test_generated_shadowsocks_multiuser_transfers_full_http_body(self):
        """Exercise real encryption/transport locally, without TUN or Internet."""
        binary = REPO / 'macos/vendor/xray'
        if not binary.is_file():
            self.skipTest('Optional local Xray binary unavailable')
        payload = bytes(range(256)) * 512
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            def log_message(self, *args):
                pass
        httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=httpd.serve_forever,
                                  kwargs={'poll_interval': 0.05}, daemon=True)
        thread.start()
        def close_http():
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=2)
        self.addCleanup(close_http)
        def available_port():
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                return listener.getsockname()[1]
        ss_port, socks_port = available_port(), available_port()
        while socks_port == ss_port:
            socks_port = available_port()
        inbound = copy.deepcopy(next(i for i in self.config['inbounds']
                                     if i['protocol'] == 'shadowsocks'))
        inbound.update(listen='127.0.0.1', port=ss_port)
        # Freedom now blocks loopback even without routing rules. This exception
        # belongs ONLY to this disposable local fixture, never the server config.
        server = {'log': {'loglevel': 'warning'}, 'inbounds': [inbound],
                  'outbounds': [{'protocol': 'freedom', 'settings': {
                      'finalRules': [{'action': 'allow', 'ip': ['127.0.0.1/32']}]}}]}
        entry = next(item for item in extra.client_extras(self.state, 'android', '127.0.0.1')
                     if item['outbound']['protocol'] == 'shadowsocks')
        self.assertEqual('Shadowsocks 2022 · резерв', entry['title'])
        outbound = entry['outbound']
        outbound['settings']['servers'][0]['port'] = ss_port
        client = {'log': {'loglevel': 'warning'}, 'inbounds': [{
            'protocol': 'socks', 'listen': '127.0.0.1', 'port': socks_port,
            'settings': {'auth': 'noauth'}}], 'outbounds': [outbound]}
        processes = []
        def close_process(process):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
        for name, config in [('server', server), ('client', client)]:
            file = self.root / ('ss-transfer-' + name + '.json')
            extra.atomic_write(file, extra.encoded(config))
            process = subprocess.Popen([str(binary), 'run', '-c', str(file)],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            processes.append(process)
            self.addCleanup(close_process, process)
        for endpoint in (ss_port, socks_port):
            deadline = time.monotonic() + 3
            while True:
                self.assertTrue(all(p.poll() is None for p in processes), 'Fixture Xray exited early')
                try:
                    with socket.create_connection(('127.0.0.1', endpoint), timeout=0.1):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        self.fail('Fixture Xray did not start listening')
                    time.sleep(0.025)
        with socket.create_connection(('127.0.0.1', socks_port), timeout=3) as connection:
            def receive(size):
                result = b''
                while len(result) < size:
                    chunk = connection.recv(size - len(result))
                    self.assertTrue(chunk, 'SOCKS connection closed before HTTP response')
                    result += chunk
                return result
            connection.sendall(b'\x05\x01\x00')
            self.assertEqual(b'\x05\x00', receive(2))
            connection.sendall(b'\x05\x01\x00\x01' + socket.inet_aton('127.0.0.1')
                               + httpd.server_port.to_bytes(2, 'big'))
            self.assertEqual(b'\x05\x00\x00\x01', receive(4))
            receive(6)
            http_client = http.client.HTTPConnection('127.0.0.1', httpd.server_port, timeout=3)
            http_client.sock = connection
            try:
                http_client.request('GET', '/')
                response = http_client.getresponse()
                self.assertEqual(200, response.status)
                body = response.read(131073)
                self.assertEqual(131072, len(body))
                self.assertEqual(hashlib.sha256(payload).digest(), hashlib.sha256(body).digest())
            finally:
                http_client.close()
        self.assertNotIn('finalRules', json.dumps(self.config))

    def test_real_xray_accepts_server_and_all_client_configs(self):
        binary = REPO / 'macos/vendor/xray'
        if not binary.is_file():
            self.skipTest('Optional local Xray binary unavailable')
        configs = [self.config]
        for item in extra.client_extras(self.state, 'android', self.server['PUBLIC_HOST']):
            configs.append({'outbounds': [item['outbound']]})
        for index, config in enumerate(configs):
            file = self.root / f'check-{index}.json'
            extra.atomic_write(file, extra.encoded(config))
            proc = subprocess.run([str(binary), 'run', '-test', '-format', 'json', '-c', str(file)], capture_output=True)
            self.assertEqual(0, proc.returncode, f'Bundled Xray rejected fixture config {index}: {proc.stdout!r} {proc.stderr!r}')


if __name__ == '__main__':
    unittest.main()
