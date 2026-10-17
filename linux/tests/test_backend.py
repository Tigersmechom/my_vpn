"""No privileges, subprocesses, sockets or host routes are used in these tests."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from myvpn.backend import (BackendError, Engine, INTERFACE, IP, RESOLVECTL,
                           ROUTE_PROTOCOL, STATUS_PATH, atomic_json, validate_journal)
from myvpn.helper import validate_request


class Child:
    def __init__(self):
        self.code = None
        self.terminated = False

    def poll(self):
        return self.code

    def terminate(self):
        self.code = 0
        self.terminated = True

    def kill(self):
        self.code = -9

    def wait(self, timeout):
        return self.code


class FakeRunner:
    def __init__(self):
        self.commands = []
        self.routes = []
        self.link = False
        self.policy = False
        self.other_routes = []
        self.tunnel_default = False
        self.domains = "Link 2 (enp1s0): home"
        self.dns = False
        self.fail = None
        self.fail_delete = False
        self.child = Child()

    def spawn(self, argv, log):
        self.commands.append(argv)
        self.link = True
        return self.child

    def run(self, argv, *, check=True, timeout=12):
        self.commands.append(argv)
        output, code = "", 0
        if self.fail and self.fail(argv):
            code = 1
        elif argv[0] == IP:
            args = argv[1:]
            if args == ["link", "show", "dev", INTERFACE]:
                code = 0 if self.link else 1
            elif args == ["link", "delete", "dev", INTERFACE]:
                self.link = False
                self.dns = False
            elif args[:3] == ["-d", "-j", "link"]:
                kind = "tun" if self.tunnel_default else ""
                output = json.dumps([{"linkinfo": {"info_kind": kind}}])
            elif "rule" in args:
                rules = [{"priority": 0, "table": "local"}, {"priority": 32766, "table": "main"}]
                if self.policy:
                    rules.append({"priority": 100, "table": 51820})
                output = json.dumps(rules)
            elif "route" in args and "get" in args:
                output = json.dumps([{"dev": "enp1s0", "gateway": "192.168.1.1"}])
            elif "route" in args and "show" in args:
                if "proto" in args:
                    output = json.dumps([{"protocol": ROUTE_PROTOCOL}] if self.routes else [])
                elif "default" in args:
                    output = json.dumps([{"dev": "enp1s0", "gateway": "192.168.1.1"}])
                else:
                    output = json.dumps(self.other_routes)
            elif "route" in args and "add" in args:
                self.routes.append(args)
            elif "route" in args and "del" in args:
                if self.fail_delete:
                    code = 1
                else:
                    original = list(args)
                    original[2] = "add"
                    if original in self.routes:
                        self.routes.remove(original)
                    else:
                        code = 2
        elif argv[0] == RESOLVECTL:
            if argv[1:] == ["domain"]:
                output = self.domains
            elif argv[1] == "dns":
                self.dns = True
            elif argv[1] == "revert":
                self.dns = False
        if check and code:
            raise BackendError("Тестовая ошибка настройки сети")
        return subprocess.CompletedProcess(argv, code, output, "")


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.profile = json.loads((Path(__file__).resolve().parents[2] / "config/example.json").read_text())
        self.runner = FakeRunner()
        self.engine = Engine(runner=self.runner, run_dir=self.directory,
                             status_path=self.directory / "status.json", lib_dir=self.directory,
                             resolver=lambda _host: "8.8.4.4", sleep=lambda _: None,
                             ipv6_available=True)

    def assert_clean(self):
        self.assertEqual([], self.runner.routes)
        self.assertFalse(self.runner.dns)
        self.assertFalse(self.runner.link)
        self.assertFalse((self.directory / "journal.json").exists())

    def test_xray_routes_and_dns_are_owned_and_reversed(self):
        self.engine.start(self.profile, "VLESS_TCP")
        config = json.loads((self.directory / "xray.json").read_text())
        self.assertEqual("8.8.4.4", config["outbounds"][0]["settings"]["address"])
        self.assertEqual("www.microsoft.com", config["outbounds"][0]["streamSettings"]["realitySettings"]["serverName"])
        self.assertEqual([], config["inbounds"][0]["settings"]["autoSystemRoutingTable"])
        self.assertEqual(5, len(self.runner.routes))
        self.assertTrue(self.runner.dns)
        self.assertEqual("up", json.loads((self.directory / "status.json").read_text())["state"])
        self.engine.cleanup()
        self.assert_clean()
        self.assertTrue(self.runner.child.terminated)
        for command in self.runner.commands:
            self.assertNotIn("flush", command)
            self.assertNotIn("replace", command)
        self.assertEqual(0o600, (self.directory / "engine.log").stat().st_mode & 0o777)

    def test_awg_foreground_and_setconf_without_hooks(self):
        self.engine.start(self.profile, "AWG")
        text = (self.directory / "awg.conf").read_text()
        self.assertNotIn("PostUp", text)
        self.assertNotIn("Address", text)
        self.assertIn("Endpoint = 8.8.4.4:", text)
        self.assertTrue(any(command[-2:] == ["--foreground", INTERFACE] for command in self.runner.commands))
        self.engine.cleanup()
        self.assert_clean()

    def test_other_vpn_policy_refused_without_mutation(self):
        self.runner.policy = True
        with self.assertRaisesRegex(BackendError, "другого VPN"):
            self.engine.start(self.profile, "VLESS_TCP")
        self.assert_clean()
        self.assertFalse(any("add" in cmd or "setconf" in cmd for cmd in self.runner.commands))

    def test_other_split_vpn_refused_without_mutation(self):
        self.runner.other_routes = [{"dst": "0.0.0.0/1", "dev": "tun0"}]
        with self.assertRaisesRegex(BackendError, "другого VPN"):
            self.engine.start(self.profile, "VLESS_TCP")
        self.assert_clean()

    def test_tunnel_default_and_other_dns_refused(self):
        self.runner.tunnel_default = True
        with self.assertRaisesRegex(BackendError, "другой VPN"):
            self.engine.start(self.profile, "AWG")
        self.runner.tunnel_default = False
        self.runner.domains = "Link 7 (tun2): ~."
        with self.assertRaisesRegex(BackendError, "DNS"):
            self.engine.start(self.profile, "AWG")
        self.assert_clean()

    def test_partial_dns_failure_restores_everything(self):
        self.runner.fail = lambda command: command[:3] == [RESOLVECTL, "domain", INTERFACE]
        self.assertEqual(1, self.engine.serve(self.profile, "VLESS_TCP"))
        self.assert_clean()
        self.assertEqual("error", json.loads((self.directory / "status.json").read_text())["state"])

    def test_route_add_failure_does_not_delete_unowned_route(self):
        self.runner.fail = lambda command: "add" in command and "128.0.0.0/1" in command
        self.assertEqual(1, self.engine.serve(self.profile, "VLESS_TCP"))
        self.assert_clean()
        self.assertFalse(any("del" in command and "128.0.0.0/1" in command for command in self.runner.commands))

    def test_crash_cleanup_reads_journal_and_leaves_other_routes(self):
        self.engine.start(self.profile, "AWG")
        recover = Engine(runner=self.runner, run_dir=self.directory, status_path=self.directory / "status.json")
        recover.cleanup()
        self.engine.log.close()
        self.assert_clean()
        self.assertFalse(any(cmd[:3] == [IP, "route", "flush"] for cmd in self.runner.commands))

    def test_cleanup_failure_keeps_journal_for_retry(self):
        self.engine.start(self.profile, "VLESS_TCP")
        self.runner.fail_delete = True
        with self.assertRaises(BackendError):
            self.engine.cleanup()
        self.assertTrue((self.directory / "journal.json").exists())
        self.runner.fail_delete = False
        self.engine.cleanup()
        self.assert_clean()

    def test_ipv6_disabled_and_native_crash(self):
        self.engine.ipv6_available = False
        self.engine.start(self.profile, "HY2")
        self.assertFalse(any("-6" in cmd for cmd in self.runner.commands))
        self.runner.child.code = 1
        self.engine.cleanup()
        self.assert_clean()

    def test_invalid_request_rejects_command_and_path_injection(self):
        with self.assertRaises(BackendError):
            validate_request({"profile": self.profile, "mode": "AWG", "command": "id"})
        with self.assertRaises(BackendError):
            validate_request({"profile": self.profile, "mode": "../../etc/passwd"})
        profile = copy.deepcopy(self.profile)
        profile["awg"]["privateKey"] += "\nPostUp = id"
        with self.assertRaises(ValueError):
            validate_request({"profile": profile, "mode": "AWG"})

    def test_corrupt_journal_never_executes_a_command(self):
        atomic_json(self.directory / "journal.json", {
            "version": 1, "interface": True, "dns": False,
            "routes": [["-4", "route", "add", "default", "dev", "enp1s0", "proto", "246", "metric", "42600"]]})
        with self.assertRaises(BackendError):
            self.engine.cleanup()
        self.assertEqual([], self.runner.commands)

    def test_atomic_status_parent_is_writable_in_service_sandbox(self):
        unit = (Path(__file__).resolve().parents[1] / "packaging/myvpn-client.service").read_text()
        writable = next(line.split("=", 1)[1].split() for line in unit.splitlines()
                        if line.startswith("ReadWritePaths="))
        self.assertIn(str(STATUS_PATH.parent), writable)
        public_dir = self.directory / "public-status"
        public_dir.mkdir()
        atomic_json(public_dir / "status.json", {"state": "up"}, 0o644)
        self.assertEqual(["status.json"], [path.name for path in public_dir.iterdir()])

    def test_ipv6_or_local_dns_rejected_before_mutation(self):
        for dns in ("192.168.1.1", "2606:4700:4700::1111"):
            with self.subTest(dns=dns):
                self.profile["dns"] = dns
                with self.assertRaisesRegex(BackendError, "DNS"):
                    self.engine.start(self.profile, "VLESS_TCP")
        self.assertEqual([], self.runner.commands)


if __name__ == "__main__":
    unittest.main()
