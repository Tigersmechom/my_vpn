"""Root-only, bounded network operations for the Ubuntu client.

There is deliberately no wg-quick, shell evaluation, global DNS replacement,
default-route replacement or automatic service restart here. Network tests use
an injected runner; importing this module cannot change the host network.
"""
from __future__ import annotations

import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import time
import uuid

INTERFACE = "myvpn0"
SERVICE = "myvpn-client.service"
RUN_DIR = Path("/run/myvpn-client")
STATUS_PATH = Path("/run/myvpn-client-status/status.json")
LIB_DIR = Path("/usr/lib/myvpn")
IP = "/usr/sbin/ip"
RESOLVECTL = "/usr/bin/resolvectl"
SYSTEMCTL = "/usr/bin/systemctl"
ROUTE_PROTOCOL = "246"
ROUTE_METRIC = "42600"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}


class BackendError(Exception):
    """A deliberately credential-free error suitable for the GUI."""


class Runner:
    def run(self, argv, *, check=True, timeout=12):
        try:
            result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                                    text=True, timeout=timeout, env=ENV, close_fds=True)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise BackendError("Системная команда недоступна или не ответила вовремя") from exc
        if check and result.returncode:
            # Never send native stderr to an unprivileged caller: it can contain keys.
            raise BackendError("Не удалось настроить сеть; изменения отменены")
        return result

    def spawn(self, argv, log):
        return subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log,
                                stderr=subprocess.STDOUT, env=ENV, close_fds=True)


def atomic_json(path: Path, value: dict, mode=0o600):
    temp = path.with_name(path.name + ".new")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    fd = os.open(temp, flags, mode)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def private_text(path: Path, value: str):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(value)


def ensure_private_directory(path: Path):
    path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise BackendError("Небезопасные права каталога службы VPN")


def read_json(path: Path, *, limit=1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "r", encoding="utf-8") as stream:
        raw = stream.read(limit + 1)
    if len(raw.encode("utf-8")) > limit:
        raise BackendError("Слишком большой файл состояния VPN")
    return json.loads(raw)


def interface_safe(name):
    return isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", name)


def _json_result(result):
    try:
        value = json.loads(result.stdout)
    except (ValueError, TypeError) as exc:
        raise BackendError("Не удалось прочитать состояние сети") from exc
    if not isinstance(value, list):
        raise BackendError("Не удалось прочитать состояние сети")
    return value


def resolve_ipv4(host):
    try:
        addresses = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        address = addresses[0][4][0]
        if not ipaddress.ip_address(address).is_global:
            raise BackendError("Сервер VPN должен иметь публичный IPv4-адрес")
        return address
    except (OSError, IndexError, ValueError) as exc:
        raise BackendError("Не удалось определить IPv4-адрес сервера VPN") from exc


def notify_ready():
    address = os.environ.get("NOTIFY_SOCKET")
    if not address:
        return
    if address.startswith("@"):
        address = "\0" + address[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as channel:
        channel.connect(address)
        channel.sendall(b"READY=1\nSTATUS=VPN tunnel started")


class Engine:
    def __init__(self, *, runner=None, run_dir=RUN_DIR, status_path=STATUS_PATH,
                 lib_dir=LIB_DIR, resolver=resolve_ipv4, sleep=time.sleep,
                 ipv6_available=None):
        self.runner = runner or Runner()
        self.run_dir = Path(run_dir)
        self.status_path = Path(status_path)
        self.lib_dir = Path(lib_dir)
        self.resolver = resolver
        self.sleep = sleep
        self.ipv6_available = (Path("/proc/sys/net/ipv6").exists()
                               if ipv6_available is None else ipv6_available)
        self.journal = {"version": 1, "routes": [], "interface": False, "dns": False}
        self.child = None
        self.log = None
        self.stop_requested = False
        self.status = {"state": "starting", "session": str(uuid.uuid4()),
                       "startedAt": datetime.datetime.now(datetime.timezone.utc).isoformat()}

    def publish(self, state, **kwargs):
        self.status.update(state=state, **kwargs)
        atomic_json(self.status_path, self.status, 0o644)

    def save_journal(self):
        atomic_json(self.run_dir / "journal.json", self.journal)

    def command_json(self, args):
        return _json_result(self.runner.run([IP, "-j", *args]))

    def preflight(self, endpoints):
        if self.runner.run([IP, "link", "show", "dev", INTERFACE], check=False).returncode == 0:
            raise BackendError("Интерфейс myvpn0 уже занят; сначала отключите VPN")
        for family in ("-4", "-6") if self.ipv6_available else ("-4",):
            rules = self.command_json([family, "rule", "show"])
            for rule in rules:
                standard = {0: "local", 32766: "main", 32767: "default"}
                priority = rule.get("priority")
                table = str(rule.get("table", ""))
                if (priority not in standard or table not in
                        {standard[priority], {0: "255", 32766: "254", 32767: "253"}[priority]}):
                    raise BackendError("Обнаружены правила другого VPN или особая маршрутизация. Отключите другой VPN")
            routes = self.command_json([family, "route", "show", "table", "all"])
            for route in routes:
                if str(route.get("protocol")) == ROUTE_PROTOCOL:
                    raise BackendError("Служебные маршруты My VPN уже заняты")
                if route.get("dst") in ("0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"):
                    raise BackendError("Обнаружены маршруты другого VPN. Сначала отключите его")
        defaults = self.command_json(["-4", "route", "show", "default"])
        if not defaults:
            raise BackendError("Нет подключения к сети с IPv4")
        default = min(defaults, key=lambda item: item.get("metric", 0))
        device = default.get("dev")
        self.check_physical(device)
        for route in self.command_json(["-6", "route", "show", "default"]) if self.ipv6_available else []:
            self.check_physical(route.get("dev"))
        endpoint_routes = []
        for endpoint in sorted(set(endpoints)):
            ipaddress.IPv4Address(endpoint)
            route = self.command_json(["-4", "route", "get", endpoint])[0]
            self.check_physical(route.get("dev"))
            args = ["-4", "route", "add", endpoint + "/32"]
            if route.get("gateway"):
                gateway = str(ipaddress.IPv4Address(route["gateway"]))
                args += ["via", gateway]
            args += ["dev", route["dev"], "proto", ROUTE_PROTOCOL, "metric", ROUTE_METRIC]
            endpoint_routes.append(args)
        # A second ~. DNS route could make systemd-resolved query outside the VPN.
        domains = self.runner.run([RESOLVECTL, "domain"]).stdout
        if re.search(r"(?:^|\s)~\.(?:\s|$)", domains):
            raise BackendError("Другая служба уже управляет DNS для всего трафика. Отключите другой VPN")
        return endpoint_routes

    def check_physical(self, device):
        if not interface_safe(device):
            raise BackendError("Неподдерживаемый сетевой интерфейс")
        links = _json_result(self.runner.run([IP, "-d", "-j", "link", "show", "dev", device]))
        if not links:
            raise BackendError("Сетевой интерфейс недоступен")
        kind = links[0].get("linkinfo", {}).get("info_kind", "")
        if (kind not in ("", "bridge", "bond", "vlan") or
                re.match(r"(?i)^(tun|tap|wg|awg|ppp|ipsec|myvpn)", device)):
            raise BackendError("Основной маршрут проходит через другой VPN. Сначала отключите его")

    def add_route(self, args):
        # Journal the exact owned tuple before mutating: ExecStopPost can recover
        # from SIGKILL between the netlink operation and the next Python line.
        self.journal["routes"].append(args)
        self.save_journal()
        result = self.runner.run([IP, *args], check=False)
        if result.returncode:
            self.journal["routes"].pop()
            self.save_journal()
            raise BackendError("Не удалось добавить маршруты VPN; изменения отменены")

    def start(self, profile, mode):
        from .model import (awg_config, dns_servers, endpoint_hosts,
                            replace_endpoint_ips, validate_profile, xray_config)
        profile = validate_profile(profile)
        hosts = endpoint_hosts(profile, mode)
        dns = dns_servers(profile)
        if any(ipaddress.ip_address(address).version != 4 or
               not ipaddress.ip_address(address).is_global for address in dns):
            raise BackendError("Для этого клиента нужны публичные DNS-серверы IPv4")
        resolved = {host: self.resolver(host) for host in hosts}
        endpoint_routes = self.preflight(resolved.values())
        self.status.update(mode=mode, host=hosts[0])
        self.publish("starting")
        self.save_journal()
        if mode == "AWG":
            private_text(self.run_dir / "awg.conf", awg_config(profile, resolved[profile["host"]]))
            argv = [str(self.lib_dir / "amneziawg-go"), "--foreground", INTERFACE]
        else:
            config = xray_config(profile, mode, tun=True)
            outbound = config["outbounds"][0]
            tag = outbound.pop("tag")
            config["outbounds"][0] = {**replace_endpoint_ips(outbound, resolved), "tag": tag}
            atomic_json(self.run_dir / "xray.json", config)
            self.runner.run([str(self.lib_dir / "xray"), "run", "-test", "-c",
                             str(self.run_dir / "xray.json")], timeout=15)
            argv = [str(self.lib_dir / "xray"), "run", "-c", str(self.run_dir / "xray.json")]
        for route in endpoint_routes:
            self.add_route(route)
        self.journal["interface"] = True
        self.save_journal()
        fd = os.open(self.run_dir / "engine.log", os.O_WRONLY | os.O_CREAT |
                     os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        self.log = os.fdopen(fd, "wb")
        self.child = self.runner.spawn(argv, self.log)
        for _ in range(50):
            if self.stop_requested or self.child.poll() is not None:
                raise BackendError("Ядро VPN завершилось до запуска туннеля")
            if self.runner.run([IP, "link", "show", "dev", INTERFACE], check=False).returncode == 0:
                break
            self.sleep(0.1)
        else:
            raise BackendError("Не удалось создать интерфейс VPN")
        if mode == "AWG":
            for _ in range(50):
                if self.stop_requested or self.child.poll() is not None:
                    raise BackendError("Ядро AmneziaWG завершилось до запуска туннеля")
                if self.runner.run([str(self.lib_dir / "awg"), "show", INTERFACE], check=False).returncode == 0:
                    break
                self.sleep(0.1)
            else:
                raise BackendError("Не удалось запустить управление AmneziaWG")
            self.runner.run([str(self.lib_dir / "awg"), "setconf", INTERFACE,
                             str(self.run_dir / "awg.conf")])
            address = str(ipaddress.IPv4Interface(profile["awg"]["address"]))
            self.runner.run([IP, "address", "add", address, "dev", INTERFACE])
            self.runner.run([IP, "link", "set", "dev", INTERFACE, "mtu",
                             str(profile["awg"].get("mtu", 1280)), "up"])
        if self.ipv6_available:
            for prefix in ("::/1", "8000::/1"):
                self.add_route(["-6", "route", "add", "unreachable", prefix,
                                "proto", ROUTE_PROTOCOL, "metric", ROUTE_METRIC])
        for prefix in ("0.0.0.0/1", "128.0.0.0/1"):
            self.add_route(["-4", "route", "add", prefix, "dev", INTERFACE,
                            "proto", ROUTE_PROTOCOL, "metric", ROUTE_METRIC])
        self.journal["dns"] = True
        self.save_journal()
        self.runner.run([RESOLVECTL, "dns", INTERFACE, *dns])
        self.runner.run([RESOLVECTL, "domain", INTERFACE, "~."])
        self.runner.run([RESOLVECTL, "default-route", INTERFACE, "yes"])
        if self.child.poll() is not None:
            raise BackendError("Ядро VPN неожиданно завершилось")
        self.publish("up")

    def stop_signal(self, _signum, _frame):
        self.stop_requested = True

    def serve(self, profile, mode):
        error = None
        try:
            self.start(profile, mode)
            notify_ready()
            while not self.stop_requested:
                if self.child.poll() is not None:
                    raise BackendError("Ядро VPN завершилось; туннель отключён")
                self.sleep(0.25)
        except Exception as exc:
            error = str(exc) if isinstance(exc, BackendError) else "Не удалось запустить туннель VPN"
        finally:
            try:
                self.cleanup()
            except Exception:
                error = "Не удалось полностью убрать маршруты VPN; нажмите «Отключить» повторно"
            self.publish("error" if error else "down", **({"error": error} if error else {}))
        return 1 if error else 0

    def cleanup(self):
        journal_path = self.run_dir / "journal.json"
        if journal_path.exists():
            self.journal = read_json(journal_path)
        # A corrupt journal must never become a source of privileged commands.
        journal = validate_journal(self.journal)
        errors = []
        def best_effort(argv):
            try:
                return self.runner.run(argv, check=False)
            except BackendError:
                errors.append(True)
                return None
        if journal["dns"]:
            best_effort([RESOLVECTL, "revert", INTERFACE])
        for route in reversed(journal["routes"]):
            undo = list(route)
            undo[2] = "del"
            best_effort([IP, *undo])
        # ENOENT is normal when the kernel removed routes with a crashed TUN.
        # Check once after all deletes; another owned route may still have been
        # waiting its turn when an earlier delete reported ENOENT.
        for family in set(route[0] for route in journal["routes"]):
            check = best_effort([IP, "-j", family, "route", "show", "proto", ROUTE_PROTOCOL])
            if check is None or check.returncode or _json_result(check):
                errors.append(True)
        if self.child and self.child.poll() is None:
            try:
                self.child.terminate()
                self.child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    self.child.kill()
                    self.child.wait(timeout=3)
                except ProcessLookupError:
                    pass
            except ProcessLookupError:
                pass
        if journal["interface"]:
            # Name ownership was recorded only after preflight proved absence.
            best_effort([IP, "link", "delete", "dev", INTERFACE])
            remaining = best_effort([IP, "link", "show", "dev", INTERFACE])
            if remaining is None or remaining.returncode == 0:
                errors.append(True)
        if self.log:
            self.log.close()
            self.log = None
        if not errors:
            journal_path.unlink(missing_ok=True)
        for name in ("request.json", "xray.json", "awg.conf"):
            (self.run_dir / name).unlink(missing_ok=True)
        if errors:
            raise BackendError("Не удалось полностью убрать маршруты VPN; повторите отключение")


def validate_journal(value):
    if (not isinstance(value, dict) or value.get("version") != 1 or
            type(value.get("interface")) is not bool or type(value.get("dns")) is not bool or
            not isinstance(value.get("routes"), list) or len(value["routes"]) > 32):
        raise BackendError("Повреждено состояние службы VPN")
    for route in value["routes"]:
        if (not isinstance(route, list) or not all(isinstance(part, str) for part in route) or
                route[:3] not in (["-4", "route", "add"], ["-6", "route", "add"]) or
                route[-4:] != ["proto", ROUTE_PROTOCOL, "metric", ROUTE_METRIC]):
            raise BackendError("Повреждено состояние маршрутов VPN")
        middle = route[3:-4]
        if route[0] == "-6":
            valid = middle in (["unreachable", "::/1"], ["unreachable", "8000::/1"])
        else:
            try:
                network = ipaddress.IPv4Network(middle[0])
                valid = ((middle[0] in ("0.0.0.0/1", "128.0.0.0/1") and
                          middle[1:] == ["dev", INTERFACE]) or
                         (network.prefixlen == 32 and
                          ((len(middle) == 3 and middle[1] == "dev" and interface_safe(middle[2])) or
                           (len(middle) == 5 and middle[1] == "via" and
                            ipaddress.IPv4Address(middle[2]) and middle[3] == "dev" and
                            interface_safe(middle[4])))))
            except (ValueError, IndexError):
                valid = False
        if not valid:
            raise BackendError("Повреждено состояние маршрутов VPN")
    return value
