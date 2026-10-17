#!/usr/bin/env python3
"""Check app profiles through temporary loopback SOCKS; never create a VPN/TUN.

Pass --interface en0 on macOS to keep these test sockets outside an existing VPN.
Only fixed public HTTPS endpoints and DNS are queried; no credentials are logged.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("profile_export", ROOT / "server/export.py")
export = importlib.util.module_from_spec(spec)
spec.loader.exec_module(export)


def receive(sock, size):
    result = b""
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise ValueError("SOCKS connection closed")
        result += chunk
    return result


def dns_probe(port):
    with socket.create_connection(("127.0.0.1", port), timeout=8) as control:
        control.sendall(b"\x05\x01\x00")
        if receive(control, 2) != b"\x05\x00":
            raise ValueError("SOCKS negotiation failed")
        control.sendall(b"\x05\x03\x00\x01" + bytes(6))
        header = receive(control, 4)
        if header[:3] != b"\x05\x00\x00" or header[3] != 1:
            raise ValueError("SOCKS UDP relay unavailable")
        host = socket.inet_ntoa(receive(control, 4))
        relay_port = int.from_bytes(receive(control, 2), "big")
        if host == "0.0.0.0":
            host = "127.0.0.1"
        if host != "127.0.0.1":
            raise ValueError("unexpected non-local SOCKS relay")
        identity = secrets.token_bytes(2)
        question = (identity + b"\x01\x00\x00\x01" + bytes(6)
                    + b"\x03www\x06google\x03com\x00\x00\x01\x00\x01")
        packet = b"\x00\x00\x00\x01" + socket.inet_aton("1.1.1.1") + struct.pack("!H", 53) + question
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(8)
            udp.sendto(packet, (host, relay_port))
            reply, sender = udp.recvfrom(4096)
        if sender != (host, relay_port) or len(reply) < 22 or reply[:4] != b"\x00\x00\x00\x01":
            raise ValueError("invalid DNS relay response")
        answer = reply[10:]
        if (answer[:2] != identity or not answer[2] & 0x80 or answer[3] & 15
                or int.from_bytes(answer[6:8], "big") == 0):
            raise ValueError("DNS query failed")


def candidates(profile):
    for name, mode in [("VLESS TCP", "vless"), ("Hysteria 2", "hy2"), ("Hysteria 2 Salamander", "hy2-obfs")]:
        config = export.xray_config(profile, mode)
        if isinstance(config, str):
            config = json.loads(config)
        outbound = config["outbounds"][0]
        if mode == "vless":
            outbound["settings"]["flow"] = "xtls-rprx-vision-udp443"
        yield name, outbound
    for item in profile.get("extraXray", []):
        yield item["title"], item["outbound"]


def check(name, outbound, executable, interface):
    result = {"mode": name, "checks": {}}
    with tempfile.TemporaryDirectory(prefix="myvpn-probe-") as directory:
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        outbound = json.loads(json.dumps(outbound))
        if interface:
            outbound.setdefault("streamSettings", {}).setdefault("sockopt", {})["interface"] = interface
        config = {"log": {"loglevel": "warning"}, "inbounds": [{
            "listen": "127.0.0.1", "port": port, "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True},
        }], "outbounds": [outbound]}
        path = Path(directory) / "client.json"
        path.write_text(json.dumps(config))
        path.chmod(0o600)
        validated = subprocess.run([str(executable), "run", "-test", "-c", str(path)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        if validated.returncode:
            result["checks"]["config"] = "FAILED"
            return result
        process = subprocess.Popen([str(executable), "run", "-c", str(path)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(40):
                if process.poll() is not None:
                    raise RuntimeError("core exited")
                try:
                    socket.create_connection(("127.0.0.1", port), timeout=.1).close()
                    break
                except OSError:
                    time.sleep(.05)
            checks = [("Google", "https://www.google.com/", None),
                      ("128KiB", "https://speed.cloudflare.com/__down?bytes=131072", 131072)]
            for label, url, expected_size in checks:
                response = subprocess.run([
                    "curl", "--silent", "--max-time", "15", "--socks5-hostname", f"127.0.0.1:{port}",
                    "--max-filesize", "524288", "--output", "/dev/null", "--write-out", "%{http_code} %{size_download}", url,
                ], capture_output=True, text=True, timeout=18)
                parts = response.stdout.split()
                okay = (response.returncode == 0 and len(parts) == 2 and parts[0] == "200"
                        and int(parts[1]) > 0 and (expected_size is None or int(parts[1]) == expected_size))
                result["checks"][label] = "OK" if okay else "FAILED"
                if not okay:
                    result.setdefault("details", {})[label] = {
                        "curlExit": response.returncode,
                        "httpStatus": parts[0] if parts else None,
                        "receivedBytes": parts[1] if len(parts) > 1 else None,
                    }
            try:
                dns_probe(port)
                result["checks"]["UDP DNS"] = "OK"
            except (OSError, ValueError):
                result["checks"]["UDP DNS"] = "FAILED"
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            result["checks"]["process"] = "FAILED"
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--xray", type=Path, default=ROOT / "macos/vendor/xray")
    parser.add_argument("--interface", help="physical interface for test sockets only, e.g. en0")
    args = parser.parse_args()
    profile = export.validate(json.loads(args.profile.read_text()))
    failed = False
    for name, outbound in candidates(profile):
        result = check(name, outbound, args.xray, args.interface)
        print(json.dumps(result, ensure_ascii=False), flush=True)
        failed |= any(value != "OK" for value in result["checks"].values())
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
