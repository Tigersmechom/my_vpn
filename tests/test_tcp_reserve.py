import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from test_updates import fixture

spec = importlib.util.spec_from_file_location('tcp_reserve', Path(__file__).resolve().parents[1] / 'server/tcp_reserve.py')
reserve = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reserve)


class TCPReserveTests(unittest.TestCase):
    def keys(self):
        return dict(privateKey='A' * 43, publicKey='B' * 43,
                    uuid='00000000-0000-4000-8000-000000000001', shortId='0123456789abcdef', sni='example.com')

    def test_remote_exit_is_mandatory_and_private_key_stays_on_server(self):
        keys = self.keys()
        config, client = reserve.build(fixture(), keys, '8.8.8.8')
        inbound = config['inbounds'][0]
        self.assertEqual(inbound['streamSettings']['network'], 'raw')
        self.assertEqual(inbound['streamSettings']['security'], 'reality')
        self.assertEqual(inbound['port'], 443)
        self.assertEqual(config['outbounds'][0]['protocol'], 'hysteria')
        self.assertEqual(len(config['outbounds']), 1)
        self.assertEqual(config['outbounds'][0]['settings']['address'], fixture()['host'])
        self.assertNotIn('flow', inbound['settings']['clients'][0])
        self.assertNotIn('privateKey', json.dumps(client))
        self.assertEqual(client['outbound']['settings']['address'], '8.8.8.8')
        self.assertEqual(client['outbound']['settings']['id'], keys['uuid'])
        self.assertNotIn('allowInsecure', json.dumps(config))
        self.assertNotIn('mux', client['outbound'])

    def test_rejects_invalid_keys_names_and_bind_parameters(self):
        for name, value in [('privateKey', 'bad'), ('uuid', 'bad'), ('sni', 'bad\nname'), ('shortId', 'odd')]:
            keys = self.keys(); keys[name] = value
            with self.assertRaises(ValueError): reserve.build(fixture(), keys, '8.8.8.8')
        for host, port in [('127.0.0.1', 443), ('8.8.8.8', True), ('8.8.8.8', 0)]:
            with self.assertRaises(ValueError): reserve.build(fixture(), self.keys(), host, port)

    def test_private_outputs_are_atomic_and_not_world_readable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            reserve.private_json(path, {'key': 'test-only'})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(path.read_text()), {'key': 'test-only'})
