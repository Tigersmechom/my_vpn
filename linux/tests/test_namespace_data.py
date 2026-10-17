"""Opt-in real TUN -> HY2 -> HTTP packet test in two isolated namespaces.

No production server, host route, firewall/NAT, or systemd service is touched.
Run inside a fresh `unshare --net` with MYVPN_NAMESPACE_TEST=1. A nested second
namespace contains the test server; its only link is the paired veth endpoint.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from myvpn.backend import Engine, INTERFACE, IP, LIB_DIR, RESOLVECTL, Runner

ENABLED = os.environ.get("MYVPN_NAMESPACE_TEST") == "1"
NSENTER = "/usr/bin/nsenter"
UNSHARE = "/usr/bin/unshare"
SS = "/usr/bin/ss"
ENDPOINT = "203.0.113.1"
PAYLOAD = bytes(range(256)) * 256
HTTP_URL = "http://198.51.100.10:18080/test"


class FixtureRunner(Runner):
    def run(self, argv, **kwargs):
        if argv[0] == RESOLVECTL:
            # Never connect to the production machine's system bus/resolved.
            return subprocess.CompletedProcess(argv, 0, "", "")
        return super().run(argv, **kwargs)


class FixtureEngine(Engine):
    def check_physical(self, device):
        if device != "mvclient0":
            raise AssertionError("Unexpected physical uplink in isolated fixture")


@unittest.skipUnless(ENABLED, "Requires explicitly isolated Linux network namespace")
class NamespaceDataTests(unittest.TestCase):
    def setUp(self):
        if sys.platform != "linux" or os.geteuid() != 0:
            raise RuntimeError("Root in a Linux network namespace is required")
        current = os.readlink("/proc/self/ns/net")
        try:
            host = os.readlink("/proc/1/ns/net")
        except PermissionError:
            host = os.environ.get("MYVPN_HOST_NETNS", "")
            if not re.fullmatch(r"net:\[[0-9]{1,20}\]", host):
                raise RuntimeError("Trusted host network namespace identifier is required")
        if current == host:
            raise RuntimeError("Refusing to run in the host network namespace")
        self.runner = FixtureRunner()
        links = json.loads(self.runner.run([IP, "-j", "link", "show"]).stdout)
        if {link["ifname"] for link in links} != {"lo"}:
            raise RuntimeError("Refusing a namespace containing existing interfaces")
        self.children = []
        self.logs = []
        self.worker = None
        self.temp = tempfile.TemporaryDirectory(prefix="myvpn-data-netns-")
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.cleanup_fixture)
        self.directory = Path(self.temp.name)
        self.server_ns = self.spawn([UNSHARE, "--net", "/bin/sleep", "180"], "namespace")
        for _ in range(100):
            if self.server_ns.poll() is not None:
                raise RuntimeError("Could not create nested server namespace")
            if os.readlink(f"/proc/{self.server_ns.pid}/ns/net") != os.readlink("/proc/self/ns/net"):
                break
            time.sleep(0.03)
        else:
            raise RuntimeError("Nested network namespace did not become ready")
        self.runner.run([IP, "link", "add", "mvclient0", "type", "veth", "peer", "name", "mvserver0"])
        self.runner.run([IP, "link", "set", "mvserver0", "netns", str(self.server_ns.pid)])
        self.runner.run([IP, "address", "add", "203.0.113.2/24", "dev", "mvclient0"])
        self.runner.run([IP, "link", "set", "mvclient0", "up"])
        self.runner.run([IP, "link", "set", "lo", "up"])
        self.runner.run([IP, "route", "add", "default", "via", ENDPOINT, "dev", "mvclient0"])
        self.server_command([IP, "address", "add", ENDPOINT + "/24", "dev", "mvserver0"])
        self.server_command([IP, "link", "set", "mvserver0", "up"])
        self.server_command([IP, "link", "set", "lo", "up"])
        # No default route in the server namespace, and no physical NIC in either.
        self.assertEqual([], json.loads(self.server_command([IP, "-j", "route", "show", "default"]).stdout))

    def spawn(self, argv, label):
        log = open(self.directory / (label + ".log"), "wb")
        self.logs.append(log)
        child = self.runner.spawn(argv, log)
        self.children.append(child)
        return child

    def server_argv(self, argv):
        return [NSENTER, "--target", str(self.server_ns.pid), "--net", "--", *argv]

    def server_command(self, argv):
        return self.runner.run(self.server_argv(argv))

    def cleanup_fixture(self):
        cleanup_error = None
        if self.worker:
            try:
                self.worker.cleanup()
            except Exception as exc:
                cleanup_error = exc
        for child in reversed(self.children):
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=3)
        self.runner.run([IP, "link", "delete", "mvclient0"], check=False)
        for log in self.logs:
            log.close()
        if cleanup_error:
            raise cleanup_error

    def wait_listener(self, process, protocol, port):
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError("Fixture server exited before its listener was ready")
            output = self.server_command([SS, "-H", "-ln" + protocol, "sport", "=", ":" + str(port)]).stdout
            if output.strip():
                return
            time.sleep(0.03)
        raise RuntimeError("Fixture server listener timed out")

    def request(self, timeout):
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(HTTP_URL, timeout=timeout) as response:
            self.assertEqual(200, response.status)
            return response.read(len(PAYLOAD) + 1)

    def test_hysteria_tun_transfers_64k_and_restores_routes(self):
        cert, key = self.directory / "cert.pem", self.directory / "key.pem"
        self.runner.run(["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                         "-days", "1", "-subj", "/CN=myvpn.test", "-addext",
                         "subjectAltName=DNS:myvpn.test", "-keyout", str(key), "-out", str(cert)])
        der = subprocess.run(["/usr/bin/openssl", "x509", "-in", str(cert), "-outform", "DER"],
                             check=True, capture_output=True, timeout=5).stdout
        pin = hashlib.sha256(der).hexdigest()
        profile = json.loads((Path(__file__).resolve().parents[2] / "config/example.json").read_text())
        profile["host"] = ENDPOINT
        profile["hy2"].update(auth="namespace-fixture-auth", sni="myvpn.test", pinSha256=pin)
        http_code = '''from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = bytes(range(256)) * 256
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
HTTPServer(("127.0.0.1", 18080), Handler).serve_forever()
'''
        script = self.directory / "http_fixture.py"
        script.write_text(http_code)
        http = self.spawn(self.server_argv(["/usr/bin/python3", str(script)]), "http")
        self.wait_listener(http, "t", 18080)
        server_config = {
            "log": {"loglevel": "warning"},
            "inbounds": [{"listen": ENDPOINT, "port": 443, "protocol": "hysteria",
                          "settings": {"version": 2, "clients": [{"auth": profile["hy2"]["auth"]}]},
                          "streamSettings": {"network": "hysteria", "security": "tls",
                                             "hysteriaSettings": {"version": 2},
                                             "tlsSettings": {"alpn": ["h3"], "certificates": [
                                                 {"certificateFile": str(cert), "keyFile": str(key)}]}}}],
            "outbounds": [{"protocol": "freedom", "settings": {
                "redirect": "127.0.0.1:18080",
                # Explicitly scoped fixture exception; production never permits
                # imported freedom/file/redirect settings through the helper.
                "finalRules": [{"action": "allow", "ip": ["127.0.0.1/32"]}]}}]}
        config_path = self.directory / "server.json"
        config_path.write_text(json.dumps(server_config))
        xray = self.spawn(self.server_argv([str(LIB_DIR / "xray"), "run", "-c", str(config_path)]), "server")
        self.wait_listener(xray, "u", 443)
        # The HTTP fixture is loopback-only in another namespace. A direct
        # request to this reserved destination cannot accidentally pass.
        with self.assertRaises((urllib.error.URLError, TimeoutError, OSError)):
            self.request(1)
        before = self.runner.run([IP, "-j", "-4", "route", "show"]).stdout
        self.worker = FixtureEngine(runner=self.runner, run_dir=self.directory,
                                    status_path=self.directory / "status.json",
                                    resolver=lambda _: ENDPOINT, ipv6_available=True)
        self.worker.start(profile, "HY2")
        payload = self.request(12)
        self.assertEqual(len(PAYLOAD), len(payload))
        self.assertEqual(hashlib.sha256(PAYLOAD).digest(), hashlib.sha256(payload).digest())
        self.worker.cleanup()
        self.worker = None
        self.assertEqual(before, self.runner.run([IP, "-j", "-4", "route", "show"]).stdout)
        self.assertNotEqual(0, self.runner.run([IP, "link", "show", "dev", INTERFACE], check=False).returncode)
        with self.assertRaises((urllib.error.URLError, TimeoutError, OSError)):
            self.request(1)


if __name__ == "__main__":
    unittest.main()
