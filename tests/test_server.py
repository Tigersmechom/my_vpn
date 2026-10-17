"""Exercise vpnctl in a disposable filesystem; no VPN or system services run.

Run with ``python3 -m unittest discover -s tests -p 'test_server.py'``.
The real jq and shell perform rendering; only privileged/external commands are
replaced. Generated credentials below are fixtures, never production secrets.
"""

import base64
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from urllib.parse import parse_qs, unquote, urlsplit


REPO = Path(__file__).resolve().parents[1]
VPNCTL = REPO / "server" / "vpnctl"


STUB = r'''
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
import uuid

name = Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ["MYVPN_TEST_LOG"], "a") as log:
    log.write(json.dumps([name, *args]) + "\n")
if name == "xray":
    if args == ["uuid"]:
        print(uuid.uuid4())
    elif args[:2] == ["run", "-test"]:
        config_path = Path(args[args.index("-c") + 1])
        explicit_format = args[args.index("-format") + 1] if "-format" in args else None
        if config_path.suffix != ".json" and explicit_format != "json":
            print("fixture: Xray cannot infer configuration format", file=sys.stderr)
            sys.exit(23)
        json.loads(config_path.read_text())
        if os.environ.get("MYVPN_TEST_XRAY_REJECT") == "1":
            print("fixture: invalid Xray configuration", file=sys.stderr)
            sys.exit(1)
    else:
        sys.exit("unexpected xray call: " + repr(args))
elif name in ("awg", "wg"):
    if args in (["genkey"], ["genpsk"]):
        print(base64.b64encode(secrets.token_bytes(32)).decode())
    elif args == ["pubkey"]:
        print(base64.b64encode(hashlib.sha256(sys.stdin.buffer.read()).digest()).decode())
    elif not args or args[0] not in ("syncconf", "show", "setconf"):
        sys.exit("unexpected key command: " + repr(args))
elif name == "systemctl":
    if args and args[0] == "is-active":
        sys.exit(1)
elif name in ("awg-quick", "wg-quick"):
    if args and args[0] == "strip":
        path = Path(os.environ["MYVPN_ROOT"]) / "etc/amnezia/amneziawg/awg0.conf"
        print(path.read_text())
elif name == "ss":
    print("Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process")
elif name != "iptables":
    sys.exit("unexpected stub: " + name)
'''


def fixture_key(value):
    return base64.b64encode(bytes([value]) * 32).decode()


@unittest.skipUnless(shutil.which("jq"), "vpnctl rendering requires jq")
class ServerIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="myvpn-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / "etc/myvpn"
        self.clients = self.state / "clients"
        self.clients.mkdir(parents=True)
        self.xray_config = self.root / "usr/local/etc/xray/config.json"
        self.xray_config.parent.mkdir(parents=True)
        self.awg_config = self.root / "etc/amnezia/amneziawg/awg0.conf"
        self.awg_config.parent.mkdir(parents=True)
        self.log = self.root / "commands.jsonl"
        self.bindir = self.root / "test-bin"
        self.bindir.mkdir()
        for command in ("xray", "awg", "wg", "awg-quick", "wg-quick", "systemctl", "iptables", "ss"):
            executable = self.bindir / command
            executable.write_text(f"#!{sys.executable}\n" + STUB)
            executable.chmod(0o755)
        xray_binary = self.root / "usr/local/bin/xray"
        xray_binary.parent.mkdir(parents=True)
        xray_binary.symlink_to(self.bindir / "xray")
        self.env = dict(os.environ, MYVPN_ROOT=str(self.root), MYVPN_TEST_LOG=str(self.log))
        self.env["PATH"] = str(self.bindir) + os.pathsep + os.environ["PATH"]
        self.server = {
            "PUBLIC_HOST": "203.0.113.10", "WAN_IF": "eth0",
            "REALITY_SNI": "www.example.com",
            "REALITY_PRIVATE_KEY": base64.urlsafe_b64encode(bytes([61]) * 32).decode().rstrip("="),
            "REALITY_PUBLIC_KEY": base64.urlsafe_b64encode(bytes([62]) * 32).decode().rstrip("="),
            "REALITY_SHORT_ID": "0123456789abcdef",
            "REALITY_FINGERPRINT": "chrome", "VLESS_TCP_PORT": "443",
            "AWG_PORT": "53685", "AWG_NET": "10.77.77",
            "AWG_SERVER_PRIVATE_KEY": fixture_key(1), "AWG_SERVER_PUBLIC_KEY": fixture_key(2),
            "AWG_JC": "4", "AWG_JMIN": "40", "AWG_JMAX": "70",
            "AWG_S1": "113", "AWG_S2": "40", "AWG_S3": "54", "AWG_S4": "8",
            "AWG_H1": "298134308", "AWG_H2": "1558081262",
            "AWG_H3": "1826089798", "AWG_H4": "1828674786",
            "AWG_I1": "<r 2><b 0x01000001>", "CLIENT_DNS": "1.1.1.1, 8.8.8.8",
            "HY2_PORT": "443", "HY2_OBFS_PORT": "29426", "HY2_SNI": "vpn.example.com",
            "HY2_OBFS_PASSWORD": "fixture-obfs", "HY2_PIN": "ab" * 32,
            "HY2_CERT": str(self.xray_config.parent / "hy2.crt"),
            "HY2_KEY": str(self.xray_config.parent / "hy2.key"),
        }
        self.write_env(self.state / "server.env", self.server)

    def write_env(self, path, values):
        lines = []
        for key, value in values.items():
            text = str(value)
            self.assertNotIn("'", text)
            literal = text if text.isdigit() else "'" + text + "'"
            lines.append(f"{key}={literal}\n")
        path.write_text("".join(lines))
        path.chmod(0o600)

    def make_client(self, name="phone", index=2, **extra):
        values = {
            "CLIENT_NAME": name, "CLIENT_INDEX": str(index),
            "VLESS_UUID": f"00000000-0000-4000-8000-{index:012d}",
            "AWG_PRIVATE_KEY": fixture_key(index + 10),
            "AWG_PUBLIC_KEY": fixture_key(index + 20),
            "AWG_PRESHARED_KEY": fixture_key(index + 30),
            "HY2_AUTH": "fixture-auth-" + name,
        }
        values.update(extra)
        self.write_env(self.clients / (name + ".env"), values)
        return values

    def run_ctl(self, *args, ok=True, extra_env=None):
        env = self.env | (extra_env or {})
        result = subprocess.run(["bash", str(VPNCTL), *args], env=env, text=True,
                                capture_output=True, timeout=20)
        if ok:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, "unexpectedly accepted: " + repr(args))
        return result

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def profile(self, name):
        return json.loads(self.run_ctl("profile", name).stdout)

    def test_add_list_profile_remove_client_lifecycle(self):
        self.run_ctl("add", "phone", "--no-render")
        self.run_ctl("add", "laptop", "--no-render")
        first, second = self.profile("phone"), self.profile("laptop")
        self.assertEqual(first["version"], 2)
        self.assertEqual(first["client"], "phone")
        self.assertEqual(first["host"], self.server["PUBLIC_HOST"])
        self.assertNotEqual(first["awg"]["address"], second["awg"]["address"])
        self.assertNotEqual(first["awg"]["privateKey"], second["awg"]["privateKey"])
        self.assertNotEqual(first["vless"]["uuid"], second["vless"]["uuid"])
        self.assertNotEqual(first["hy2"]["auth"], second["hy2"]["auth"])
        listing = self.run_ctl("list").stdout
        self.assertIn("phone", listing)
        self.assertIn("laptop", listing)
        self.assertNotIn("wg", first)
        self.assertNotIn("relay", first)
        self.assertNotIn("xhttpPort", first["vless"])
        self.assertNotIn("xhttpPath", first["vless"])
        self.assertEqual(stat.S_IMODE((self.clients / "phone.env").stat().st_mode), 0o600)
        self.run_ctl("remove", "phone")
        self.assertFalse((self.clients / "phone.env").exists())
        self.assertNotIn("phone", self.run_ctl("list").stdout)
        self.assertEqual(self.profile("laptop"), second)
        self.run_ctl("profile", "phone", ok=False)

    def test_duplicate_add_does_not_replace_credentials(self):
        self.make_client()
        before = (self.clients / "phone.env").read_bytes()
        self.run_ctl("add", "phone", ok=False)
        self.assertEqual((self.clients / "phone.env").read_bytes(), before)

    def test_client_names_cannot_escape_state_directory(self):
        sentinel = self.state / "outside.env"
        sentinel.write_text('touch "$MYVPN_ROOT"/unexpected-source\n')
        for command in ("add", "remove", "profile", "links"):
            for invalid in ("../outside", "", "a/b", "a" * 33, "name;id"):
                with self.subTest(command=command, name=invalid):
                    self.run_ctl(command, invalid, ok=False)
        self.assertTrue(sentinel.exists())
        self.assertFalse((self.root / "unexpected-source").exists())

    def test_render_has_only_requested_protocols_and_every_client(self):
        first = self.make_client()
        second = self.make_client("laptop", 3)
        self.run_ctl("render")
        config = json.loads(self.xray_config.read_text())
        inbounds = config["inbounds"]
        self.assertEqual(len(inbounds), 3)
        self.assertEqual(sorted(item["protocol"] for item in inbounds), ["hysteria", "hysteria", "vless"])
        vless = next(item for item in inbounds if item["protocol"] == "vless")
        self.assertEqual(vless["port"], 443)
        self.assertEqual(vless["streamSettings"]["security"], "reality")
        self.assertIn(vless["streamSettings"]["network"], ("raw", "tcp"))
        self.assertEqual({client["id"] for client in vless["settings"]["clients"]},
                         {first["VLESS_UUID"], second["VLESS_UUID"]})
        for inbound in (item for item in inbounds if item["protocol"] == "hysteria"):
            self.assertEqual(inbound["settings"]["version"], 2)
            self.assertEqual({client["auth"] for client in inbound["settings"]["clients"]},
                             {first["HY2_AUTH"], second["HY2_AUTH"]})
        self.assertEqual(sum("finalmask" in item["streamSettings"] for item in inbounds), 1)
        self.assertNotIn("xhttp", self.xray_config.read_text().lower())
        awg = self.awg_config.read_text()
        self.assertEqual(awg.count("[Peer]"), 2)
        self.assertIn("AllowedIPs = 10.77.77.2/32", awg)
        self.assertIn("AllowedIPs = 10.77.77.3/32", awg)
        self.assertFalse((self.root / "etc/wireguard/wg0.conf").exists())
        self.assertFalse(any("wg-quick@wg0" in call for call in self.calls()))
        validation_calls = [call for call in self.calls() if call[:3] == ["xray", "run", "-test"]]
        self.assertTrue(validation_calls)
        for call in validation_calls:
            self.assertIn("-format", call)
            self.assertEqual(call[call.index("-format") + 1], "json")

    def make_extra_stub(self):
        script = self.root / "usr/local/lib/myvpn/extra_protocols.py"
        script.parent.mkdir(parents=True, exist_ok=True)
        script.write_text("""import json, os, sys
from pathlib import Path
root = Path(os.environ["MYVPN_ROOT"])
with open(os.environ["MYVPN_TEST_LOG"], "a") as file:
    file.write(json.dumps(["extra_protocols", *sys.argv[1:],
                          sorted(p.stem for p in (root / "etc/myvpn/clients").glob("*.env"))]) + "\\n")
""")
        script.chmod(0o755)
        return script

    def test_render_does_not_enable_unconfigured_optional_addon(self):
        self.make_client()
        self.make_extra_stub()
        self.run_ctl("render")
        self.assertFalse(any(call[0] == "extra_protocols" for call in self.calls()))
        self.assertFalse((self.state / "extra-protocols.json").exists())

    def test_render_reconciles_configured_addon_with_disposable_root(self):
        self.make_client()
        self.make_extra_stub()
        state = self.state / "extra-protocols.json"
        state.write_text('{"fixture":true}')
        state.chmod(0o600)
        self.run_ctl("render")
        expected = ["extra_protocols", "--root", str(self.root.resolve()), "install", ["phone"]]
        self.assertIn(expected, self.calls())
        self.assertLess(self.calls().index(expected), self.calls().index(["systemctl", "restart", "xray"]))
        self.assertNotIn("extraXray", self.profile("phone"))

    def test_remove_reconciles_addon_after_client_deleted_including_last(self):
        self.make_client()
        self.make_client("laptop", 3)
        self.make_extra_stub()
        state = self.state / "extra-protocols.json"
        state.write_text('{"fixture":true}')
        state.chmod(0o600)
        self.run_ctl("remove", "phone")
        self.assertIn(["extra_protocols", "--root", str(self.root.resolve()), "install", ["laptop"]], self.calls())
        self.run_ctl("remove", "laptop")
        self.assertIn(["extra_protocols", "--root", str(self.root.resolve()), "install", []], self.calls())

    def test_configured_addon_without_manager_fails_before_services_or_removal(self):
        self.make_client()
        state = self.state / "extra-protocols.json"
        state.write_text('{"fixture":true}')
        state.chmod(0o600)
        self.run_ctl("render", ok=False)
        self.run_ctl("remove", "phone", ok=False)
        self.assertTrue((self.clients / "phone.env").is_file())
        self.assertFalse(self.calls())

    def test_render_rejects_invalid_config_before_restarting_xray(self):
        self.make_client()
        original = '{"existing": "configuration"}\n'
        self.xray_config.write_text(original)
        self.run_ctl("render", ok=False, extra_env={"MYVPN_TEST_XRAY_REJECT": "1"})
        self.assertEqual(self.xray_config.read_text(), original)
        self.assertFalse(any(call[:2] == ["systemctl", "restart"] for call in self.calls()))

    def test_links_encode_authentication_and_obfuscation_values(self):
        secret = "p@ss:/?#&+%= space"
        obfs = "obfs&next=value+#? space"
        self.make_client(HY2_AUTH=secret)
        self.server["HY2_OBFS_PASSWORD"] = obfs
        self.write_env(self.state / "server.env", self.server)
        output = self.run_ctl("links", "phone").stdout
        uris = [line for line in output.splitlines() if line.startswith(("vless://", "hysteria2://", "hy2://"))]
        self.assertEqual(len(uris), 3)
        parsed = [urlsplit(uri) for uri in uris]
        hysteria = [uri for uri in parsed if uri.scheme in ("hysteria2", "hy2")]
        self.assertEqual(len(hysteria), 2)
        for uri in hysteria:
            self.assertEqual(unquote(uri.netloc.rsplit("@", 1)[0]), secret)
            self.assertEqual(uri.hostname, self.server["PUBLIC_HOST"])
            self.assertEqual(parse_qs(uri.query)["sni"], [self.server["HY2_SNI"]])
        obfuscated = next(uri for uri in hysteria if "obfs" in parse_qs(uri.query))
        self.assertEqual(parse_qs(obfuscated.query)["obfs-password"], [obfs])
        self.assertNotIn("xhttp", output.lower())

    def test_removed_relay_commands_are_unavailable(self):
        before = (self.state / "server.env").read_bytes()
        self.run_ctl("set-relay", "203.0.113.20", ok=False)
        self.run_ctl("relay-script", ok=False)
        self.assertEqual((self.state / "server.env").read_bytes(), before)

    def legacy_fixture(self):
        """Version-one state, including settings removed by the migration."""
        self.server.update({
            "WG_PORT": "51820", "WG_NET": "10.66.66",
            "WG_SERVER_PRIVATE_KEY": fixture_key(50), "WG_SERVER_PUBLIC_KEY": fixture_key(51),
            "VLESS_XHTTP_PORT": "8443", "XHTTP_PATH": "/old-path", "RELAY_HOST": "203.0.113.20",
        })
        self.write_env(self.state / "server.env", self.server)
        client = self.make_client(WG_PRIVATE_KEY=fixture_key(52), WG_PUBLIC_KEY=fixture_key(53),
                                  WG_PRESHARED_KEY=fixture_key(54))
        self.xray_config.write_text('{"old_configuration": true}\n')
        self.awg_config.write_text("old Amnezia configuration\n")
        legacy_wg = self.root / "etc/wireguard/wg0.conf"
        legacy_wg.parent.mkdir(parents=True)
        return client, legacy_wg

    def test_migration_backs_up_originals_preserves_keys_and_unrelated_wireguard(self):
        client, legacy_wg = self.legacy_fixture()
        unrelated = "[Interface]\n# User-managed VPN; not generated by My VPN\nPrivateKey = other-key\n"
        legacy_wg.write_text(unrelated)
        originals = {
            "server.env": (self.state / "server.env").read_bytes(),
            "clients/phone.env": (self.clients / "phone.env").read_bytes(),
            "config/xray.json": self.xray_config.read_bytes(),
            "config/awg0.conf": self.awg_config.read_bytes(),
            "config/wg0.conf": legacy_wg.read_bytes(),
        }
        self.run_ctl("migrate")
        snapshots = list((self.state / "backups").iterdir())
        self.assertEqual(len(snapshots), 1)
        for relative, content in originals.items():
            with self.subTest(backup=relative):
                self.assertEqual((snapshots[0] / relative).read_bytes(), content)
        self.assertTrue((snapshots[0] / "manifest.txt").is_file())
        self.assertEqual(legacy_wg.read_text(), unrelated)
        self.assertFalse(any("wg-quick@wg0" in call and call[1] in ("stop", "disable")
                             for call in self.calls()))
        profile = self.profile("phone")
        self.assertEqual(profile["version"], 2)
        self.assertEqual(profile["awg"]["privateKey"], client["AWG_PRIVATE_KEY"])
        self.assertEqual(profile["awg"]["presharedKey"], client["AWG_PRESHARED_KEY"])
        self.assertEqual(profile["awg"]["serverPublicKey"], self.server["AWG_SERVER_PUBLIC_KEY"])
        self.assertEqual(profile["vless"]["uuid"], client["VLESS_UUID"])
        self.assertEqual(profile["vless"]["publicKey"], self.server["REALITY_PUBLIC_KEY"])
        self.assertEqual(profile["hy2"]["auth"], client["HY2_AUTH"])
        self.assertEqual(profile["hy2"]["obfsPassword"], self.server["HY2_OBFS_PASSWORD"])
        for path in (self.state / "server.env", self.clients / "phone.env"):
            keys = {line.split("=", 1)[0] for line in path.read_text().splitlines() if "=" in line}
            self.assertFalse(any(key.startswith("WG_") for key in keys))
            self.assertTrue(keys.isdisjoint({"VLESS_XHTTP_PORT", "XHTTP_PATH", "RELAY_HOST"}))
        self.run_ctl("migrate")
        self.assertEqual(self.profile("phone"), profile)
        self.assertEqual(legacy_wg.read_text(), unrelated)

    def test_migration_removes_only_matching_legacy_wireguard_interface(self):
        client, legacy_wg = self.legacy_fixture()
        # Fixture produced by the original v1 renderer; the migration must prove
        # ownership before stopping this interface, not just test for a filename.
        legacy_wg.write_text(
            "[Interface]\n"
            f"PrivateKey = {self.server['WG_SERVER_PRIVATE_KEY']}\n"
            "Address = 10.66.66.1/24\nListenPort = 51820\n"
            "PostUp = iptables -t nat -A POSTROUTING -s 10.66.66.0/24 -o eth0 -j MASQUERADE; "
            "iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; "
            "iptables -t mangle -A FORWARD -i %i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu\n"
            "PostDown = iptables -t nat -D POSTROUTING -s 10.66.66.0/24 -o eth0 -j MASQUERADE; "
            "iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; "
            "iptables -t mangle -D FORWARD -i %i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu\n"
            "\n# phone\n[Peer]\n"
            f"PublicKey = {client['WG_PUBLIC_KEY']}\nPresharedKey = {client['WG_PRESHARED_KEY']}\n"
            "AllowedIPs = 10.66.66.2/32\n"
        )
        self.run_ctl("migrate")
        self.assertFalse(legacy_wg.exists())
        self.assertTrue(any("wg-quick@wg0" in call and "disable" in call for call in self.calls()))
        self.assertEqual(self.profile("phone")["awg"]["privateKey"], client["AWG_PRIVATE_KEY"])


if __name__ == "__main__":
    unittest.main()
