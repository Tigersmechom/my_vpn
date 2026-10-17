"""Opt-in real-core test, permitted ONLY in a separate Linux network namespace.

Run as root with MYVPN_NAMESPACE_TEST=1 after `unshare --net`. The namespace
must have no links other than lo. This test creates a dummy uplink without a
peer, so no packet can reach a physical NIC or the production VPN server.
systemd-resolved is replaced with an in-memory stub to avoid the host bus.
"""
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from myvpn.backend import Engine, INTERFACE, IP, LIB_DIR, RESOLVECTL, Runner


ENABLED = os.environ.get("MYVPN_NAMESPACE_TEST") == "1"


def assert_isolated_namespace():
    current = os.readlink("/proc/self/ns/net")
    try:
        host = os.readlink("/proc/1/ns/net")
    except PermissionError:
        # A test harness outside the service sandbox records this identifier.
        # Production needs no CAP_SYS_PTRACE merely to run its core.
        host = os.environ.get("MYVPN_HOST_NETNS", "")
        if not re.fullmatch(r"net:\[[0-9]{1,20}\]", host):
            raise RuntimeError("Trusted host network namespace identifier is required")
    if current == host:
        raise RuntimeError("Refusing to run in the host network namespace")


class NamespaceRunner(Runner):
    def __init__(self):
        self.dns = []

    def run(self, argv, **kwargs):
        if argv[0] == RESOLVECTL:
            self.dns.append(argv)
            return subprocess.CompletedProcess(argv, 0, "", "")
        return super().run(argv, **kwargs)


class NamespaceEngine(Engine):
    def check_physical(self, device):
        # Production checks reject dummy devices; this isolated test uplink is
        # deliberately incapable of talking to any physical network.
        if device != "mvtest0":
            raise AssertionError("Unexpected uplink in isolated namespace")


@unittest.skipUnless(ENABLED, "Requires explicitly isolated Linux network namespace")
class NamespaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if sys.platform != "linux" or os.geteuid() != 0:
            raise RuntimeError("Root in a Linux network namespace is required")
        assert_isolated_namespace()
        cls.runner = NamespaceRunner()
        links = json.loads(cls.runner.run([IP, "-j", "link", "show"]).stdout)
        if {link["ifname"] for link in links} != {"lo"}:
            raise RuntimeError("Refusing a namespace that already contains network interfaces")
        cls.runner.run([IP, "link", "add", "mvtest0", "type", "dummy"])
        cls.runner.run([IP, "address", "add", "192.0.2.2/24", "dev", "mvtest0"])
        cls.runner.run([IP, "link", "set", "dev", "mvtest0", "up"])
        cls.runner.run([IP, "route", "add", "default", "via", "192.0.2.1", "dev", "mvtest0"])
        cls.runner.run([IP, "link", "set", "dev", "lo", "up"])

    @classmethod
    def tearDownClass(cls):
        cls.runner.run([IP, "link", "delete", "mvtest0"], check=False)

    def snapshot(self):
        result = {}
        for family in ("-4", "-6"):
            for item in ("route", "rule"):
                args = [IP, "-j", family, item, "show"]
                data = json.loads(self.runner.run(args).stdout)
                result[(family, item)] = sorted(json.dumps(row, sort_keys=True) for row in data)
        return result

    def make_engine(self, directory):
        return NamespaceEngine(runner=self.runner, run_dir=directory,
                               status_path=Path(directory) / "status.json", lib_dir=LIB_DIR,
                               resolver=lambda _: "8.8.4.4", ipv6_available=True)

    def profile(self):
        return json.loads((Path(__file__).resolve().parents[2] / "config/example.json").read_text())

    def exercise(self, mode, *, crash=False):
        before = self.snapshot()
        with tempfile.TemporaryDirectory(prefix="myvpn-netns-") as directory:
            worker = self.make_engine(directory)
            try:
                worker.start(self.profile(), mode)
                self.assertEqual("up", json.loads((Path(directory) / "status.json").read_text())["state"])
                self.assertEqual(0, self.runner.run([IP, "link", "show", "dev", INTERFACE], check=False).returncode)
                routes = json.loads(self.runner.run([IP, "-j", "-4", "route", "show", "proto", "246"]).stdout)
                self.assertEqual(3, len(routes))
                if crash:
                    worker.child.kill()
                    worker.child.wait(timeout=5)
            finally:
                worker.cleanup()
        self.assertEqual(before, self.snapshot())
        self.assertNotEqual(0, self.runner.run([IP, "link", "show", "dev", INTERFACE], check=False).returncode)

    def test_xray_real_tun_routes_and_normal_cleanup(self):
        self.exercise("VLESS_TCP")

    def test_xray_core_crash_cleanup(self):
        self.exercise("HY2", crash=True)

    def test_amnezia_real_userspace_setconf_and_cleanup(self):
        self.exercise("AWG")


if __name__ == "__main__":
    unittest.main()
