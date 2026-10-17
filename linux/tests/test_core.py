import copy
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from myvpn.model import (ProfileError, awg_config, connections, dns_servers, endpoint_hosts,
                         parse_json, proxy_outbound, replace_endpoint_ips, validate_core_configs,
                         validate_profile, xray_config)


def fixture():
    profile = json.loads((Path(__file__).resolve().parents[2] / "config/example.json").read_text())
    profile["client"] = "linux"
    base = proxy_outbound(profile, "VLESS_TCP")
    extras = []
    for mode, port, transport, name in [("xhttp", 8443, "xhttp", "XHTTP"), ("grpc", 8444, "grpc", "gRPC"),
                                       ("vision-alt", 2053, "raw", "Другой SNI")]:
        outbound = copy.deepcopy(base)
        outbound["settings"]["port"] = port
        outbound["streamSettings"]["network"] = transport
        if transport != "raw":
            outbound["settings"].pop("flow")
        if transport == "xhttp":
            outbound["streamSettings"]["xhttpSettings"] = {"path": "/myvpn", "mode": "auto"}
        elif transport == "grpc":
            outbound["streamSettings"]["grpcSettings"] = {"serviceName": "myvpn"}
        extras.append({"id": "custom-vless-" + mode, "title": name, "outbound": outbound})
    extras.append({"id": "custom-trojan", "title": "Trojan", "outbound": {
        "protocol": "trojan", "settings": {"servers": [{"address": profile["host"], "port": 9443, "password": "test-only"}]},
        "streamSettings": copy.deepcopy(base["streamSettings"]),
        "mux": {"enabled": True, "concurrency": 8, "xudpConcurrency": 16, "xudpProxyUDP443": "allow"}}})
    extras.append({"id": "custom-ss2022", "title": "Shadowsocks 2022", "outbound": {
        "protocol": "shadowsocks", "settings": {"servers": [{"address": profile["host"], "port": 8388,
            "method": "2022-blake3-aes-256-gcm", "password": profile["awg"]["privateKey"] + ":" + profile["awg"]["privateKey"]}]}}})
    profile["extraXray"] = extras
    return profile


class ModelTests(unittest.TestCase):
    def setUp(self):
        self.profile = fixture()

    def test_complete_profile_has_nine_independent_modes(self):
        p = validate_profile(self.profile)
        modes = connections(p)
        self.assertEqual(len(modes), 9)
        self.assertEqual(sum(m["uses_xray"] for m in modes), 8)
        self.assertEqual(len({m["id"] for m in modes}), 9)
        p["vless"]["tcpPort"] = 1
        self.assertEqual(self.profile["vless"]["tcpPort"], 443)

    def test_generated_tun_is_managed_only_by_helper(self):
        config = xray_config(self.profile, "VLESS_TCP", tun=True, socks_port=10877)
        tun = config["inbounds"][0]
        self.assertEqual(tun["settings"]["name"], "myvpn0")
        self.assertEqual(tun["settings"]["gateway"], ["172.31.255.1/30"])
        self.assertEqual(tun["settings"]["autoSystemRoutingTable"], [])
        self.assertIs(tun["settings"]["autoSystemDnsToGateway"], False)
        self.assertEqual(config["inbounds"][1]["listen"], "127.0.0.1")
        self.assertEqual(config["inbounds"][1]["port"], 10877)
        self.assertEqual(config["outbounds"][0]["settings"]["flow"], "xtls-rprx-vision-udp443")
        self.assertNotIn("dns", config)

    def test_all_xray_modes_build_without_mutating_credentials(self):
        before = copy.deepcopy(self.profile)
        for connection in connections(self.profile):
            if connection["uses_xray"]:
                config = xray_config(self.profile, connection["id"])
                self.assertEqual(len(config["inbounds"]), 1)
                self.assertEqual(config["outbounds"][0]["tag"], "proxy")
        self.assertEqual(self.profile, before)

    def test_hysteria_keeps_certificate_pin_and_optional_salamander(self):
        plain = proxy_outbound(self.profile, "HY2")
        obfs = proxy_outbound(self.profile, "HY2_OBFS")
        self.assertNotIn("finalmask", plain["streamSettings"])
        self.assertEqual(obfs["streamSettings"]["finalmask"]["udp"][0]["type"], "salamander")
        self.assertEqual(plain["streamSettings"]["tlsSettings"]["pinnedPeerCertSha256"], self.profile["hy2"]["pinSha256"])
        self.assertNotIn("allowInsecure", plain["streamSettings"]["tlsSettings"])

    def test_awg_setconf_cannot_modify_routes_or_run_hooks(self):
        conf = awg_config(self.profile, "203.0.113.24")
        self.assertIn("Endpoint = 203.0.113.24:53685", conf)
        self.assertIn("AllowedIPs = 0.0.0.0/0", conf)
        self.assertIn("I1 = <r 2>", conf)
        for forbidden in ("Address =", "DNS =", "MTU =", "PostUp", "PreDown", "Table ="):
            self.assertNotIn(forbidden, conf)
        for value in ("203.0.113.24\nPostUp = /bin/true", "vpn.example", "::1"):
            with self.assertRaises(ProfileError):
                awg_config(self.profile, value)

    def test_endpoint_resolution_changes_dial_address_not_sni(self):
        self.profile["extraXray"][0]["outbound"]["settings"]["address"] = "vpn.example"
        mode = "custom-vless-xhttp"
        outbound = proxy_outbound(self.profile, mode)
        self.assertEqual(endpoint_hosts(self.profile, mode), ["vpn.example"])
        frozen = replace_endpoint_ips(outbound, {"vpn.example": "198.51.100.10"})
        self.assertEqual(frozen["settings"]["address"], "198.51.100.10")
        self.assertEqual(frozen["streamSettings"], outbound["streamSettings"])
        self.assertEqual(outbound["settings"]["address"], "vpn.example")
        with self.assertRaises(ProfileError):
            replace_endpoint_ips(outbound, {"vpn.example": "::1"})

    def test_nested_forbidden_xray_fields_rejected(self):
        for path, name, value in [
            ([], "tag", "steal"), ([], "sendThrough", "127.0.0.1"),
            (["streamSettings"], "sockopt", {"mark": 1}),
            (["streamSettings", "realitySettings"], "privateKey", "secret"),
            (["streamSettings", "realitySettings"], "masterKeyLog", "/etc/passwd"),
            (["streamSettings", "xhttpSettings"], "downloadSettings", {"address": "other.example"}),
            (["settings"], "command", "touch /tmp/pwned"),
        ]:
            with self.subTest(name=name):
                p = copy.deepcopy(self.profile)
                node = p["extraXray"][0]["outbound"]
                for part in path:
                    node = node[part]
                node[name] = value
                with self.assertRaises(ProfileError):
                    validate_profile(p)

    def test_tls_verification_and_external_cert_files_cannot_be_disabled(self):
        for tls in [{"allowInsecure": True}, {"certificateFile": "/tmp/cert"}, {"allowInsecure": 0}]:
            p = copy.deepcopy(self.profile)
            p["extraXray"][0]["outbound"]["streamSettings"]["tlsSettings"] = tls
            with self.assertRaises(ProfileError):
                validate_profile(p)

    def test_config_line_and_endpoint_injections_rejected(self):
        for section, key, value in [("awg", "i1", "<r 2>\nPostUp = id"), ("awg", "h1", "12 #x"),
                                    ("awg", "h2", "42-1"), ("vless", "sni", "site.test/path"),
                                    ("hy2", "port", True), ("vless", "tcpPort", "443")]:
            p = copy.deepcopy(self.profile)
            p[section][key] = value
            with self.subTest(section=section, key=key), self.assertRaises(ProfileError):
                validate_profile(p)

    def test_extra_ids_numbers_and_mode_count_bounded(self):
        bad_profiles = []
        p = copy.deepcopy(self.profile)
        p["extraXray"].append(copy.deepcopy(p["extraXray"][0]))
        bad_profiles.append(p)
        p = copy.deepcopy(self.profile)
        p["extraXray"][0]["id"] = "AWG"
        bad_profiles.append(p)
        p = copy.deepcopy(self.profile)
        p["extraXray"][0]["outbound"]["settings"]["port"] = False
        bad_profiles.append(p)
        p = copy.deepcopy(self.profile)
        p["extraXray"] *= 2
        bad_profiles.append(p)
        for p in bad_profiles:
            with self.assertRaises(ProfileError):
                validate_profile(p)

    def test_json_duplicate_nonfinite_deep_and_oversized_rejected(self):
        for document in [b'{"x":1,"x":2}', b'{"x":NaN}', "[" * 20 + "0" + "]" * 20,
                         " " * (1024 * 1024 + 1), b'"\xff"']:
            with self.subTest(document_length=len(document)), self.assertRaises(ProfileError):
                parse_json(document)

    def test_dns_and_selected_mode_validation(self):
        self.assertEqual(dns_servers(self.profile), ["1.1.1.1", "8.8.8.8"])
        with self.assertRaises(ProfileError):
            proxy_outbound(self.profile, "../../bin/sh")
        with self.assertRaises(ProfileError):
            xray_config(self.profile, "AWG")
        self.profile["dns"] = "1.1.1.1, bad.example"
        with self.assertRaises(ProfileError):
            validate_profile(self.profile)

    def test_native_validator_checks_all_modes_without_tun_and_removes_secrets(self):
        paths = []
        def runner(argv, **kwargs):
            path = Path(argv[-1])
            paths.append(path)
            self.assertEqual(argv[1:4], ["run", "-test", "-config"])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            config = json.loads(path.read_bytes())
            self.assertEqual([item["protocol"] for item in config["inbounds"]], ["socks"])
            self.assertEqual(kwargs["timeout"], 8)
            self.assertNotIn("HOME", kwargs["env"])
            return mock.Mock(returncode=0)
        validate_core_configs(self.profile, runner=runner)
        self.assertEqual(len(paths), 8)
        self.assertTrue(all(not path.exists() for path in paths))

    def test_native_incompatibility_fails_without_disclosing_core_output(self):
        p = copy.deepcopy(self.profile)
        p["extraXray"][0]["outbound"]["settings"]["encryption"] = "unsupported-native-encryption"
        validate_profile(p)  # Valid schema can still exceed the bundled core's capabilities.
        def runner(argv, **_kwargs):
            config = json.loads(Path(argv[-1]).read_bytes())
            encryption = config["outbounds"][0]["settings"].get("encryption")
            return mock.Mock(returncode=int(encryption == "unsupported-native-encryption"), stderr="SECRET")
        with self.assertRaises(ProfileError) as result:
            validate_core_configs(p, runner=runner)
        self.assertNotIn("SECRET", str(result.exception))

    def test_native_validator_timeout_is_safe_failure(self):
        import subprocess
        runner = mock.Mock(side_effect=subprocess.TimeoutExpired("xray", 8))
        with self.assertRaises(ProfileError):
            validate_core_configs(self.profile, runner=runner)


if __name__ == "__main__":
    unittest.main()
