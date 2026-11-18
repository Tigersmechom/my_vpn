import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('udp_relay', Path(__file__).resolve().parents[1] / 'server/udp_relay.py')
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)


class RelayTests(unittest.TestCase):
    def sample(self):
        return {'listen': '8.8.8.8', 'target': '1.1.1.1', 'ports': [[10443,443],[10444,29426],[10445,53685]]}

    def test_only_fixed_udp_endpoints_are_forwarded(self):
        rules = list(relay.rules(self.sample()))
        self.assertEqual(len(rules), 12)
        for table, chain, rule in rules:
            self.assertIn('udp', rule)
            self.assertIn('1.1.1.1', ' '.join(rule))
            if chain != 'MYVPN_RELAY_IN':
                self.assertIn('--ctorigdst', rule)
                self.assertIn('--ctorigdstport', rule)
        self.assertTrue(all('DNAT' in rule and '8.8.8.8' in rule for _,chain,rule in rules if chain == 'MYVPN_RELAY_IN'))

    def test_two_protocol_relay_preserves_fixed_target_guards(self):
        config = self.sample()
        config['ports'] = [[443, 443], [8443, 54970]]
        rules = list(relay.rules(config))
        self.assertEqual(len(rules), 8)
        for table, chain, rule in rules:
            self.assertIn('udp', rule)
            self.assertIn('1.1.1.1', ' '.join(rule))
            if chain != 'MYVPN_RELAY_IN':
                self.assertIn('--ctorigdst', rule)
                self.assertIn('--ctorigdstport', rule)
        self.assertEqual([r[r.index('--dport')+1] for _, c, r in rules if c == 'MYVPN_RELAY_IN'], ['443', '8443'])
        self.assertEqual([r[r.index('--to-destination')+1] for _, c, r in rules if c == 'MYVPN_RELAY_IN'], ['1.1.1.1:443', '1.1.1.1:54970'])

    def test_rejects_local_destinations_duplicates_and_boolean_ports(self):
        for field,value in [('target','127.0.0.1'),('target','8.8.8.8'),('listen','::1'),('ports',[[10443,443]]),
                            ('ports',[[True,443],[10444,29426],[10445,53685]]),
                            ('ports',[[10443,443],[10443,29426],[10445,53685]])]:
            config=self.sample();config[field]=value
            with self.assertRaises(ValueError): relay.validate(config)
