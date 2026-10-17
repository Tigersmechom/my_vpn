"""Small pkexec boundary and the systemd service entry point."""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import signal
import stat
import sys

from .backend import (BackendError, Engine, RUN_DIR, SERVICE, STATUS_PATH,
                      SYSTEMCTL, Runner, atomic_json, ensure_private_directory,
                      read_json)
from .model import connections, parse_json, validate_profile

MAX_REQUEST = 1024 * 1024
CONTROL_LOCK = Path("/run/myvpn-client-control.lock")


def locked_file(path):
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        os.close(fd)
        raise BackendError("Небезопасные права блокировки службы VPN")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        os.close(fd)
        raise BackendError("Другая операция VPN ещё выполняется") from exc
    return os.fdopen(fd, "r+")


def validate_request(value):
    if not isinstance(value, dict) or set(value) != {"profile", "mode"}:
        raise BackendError("Некорректный запрос приложения")
    profile = validate_profile(value["profile"])
    mode = value["mode"]
    if not isinstance(mode, str) or mode not in {item["id"] for item in connections(profile)}:
        raise BackendError("Выбранный режим недоступен")
    return {"profile": profile, "mode": mode}


def service_state(runner):
    result = runner.run([SYSTEMCTL, "show", SERVICE, "--property=ActiveState", "--value"],
                        check=False, timeout=5)
    return result.stdout.strip() if result.returncode == 0 else "inactive"


def status(runner=None):
    runner = runner or Runner()
    result = {"state": "down"}
    try:
        info = STATUS_PATH.lstat()
        if stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022:
            data = read_json(STATUS_PATH, limit=4096)
            if isinstance(data, dict):
                result = {key: data[key] for key in
                          ("state", "mode", "host", "session", "startedAt", "error")
                          if isinstance(data.get(key), str) and len(data[key]) <= 512}
    except (OSError, ValueError, BackendError):
        pass
    active = service_state(runner)
    if active == "activating":
        result["state"] = "starting"
    elif active != "active" and result.get("state") in ("up", "starting"):
        result["state"] = "error" if active == "failed" else "down"
        if active == "failed":
            result["error"] = "Служба VPN завершилась; туннель отключён"
    if result.get("state") not in ("up", "starting", "down", "error"):
        result = {"state": "down"}
    return result


def start(request, runner):
    if service_state(runner) in ("active", "activating", "deactivating"):
        raise BackendError("Сначала отключите текущее соединение VPN")
    ensure_private_directory(RUN_DIR)
    public_dir = STATUS_PATH.parent
    public_dir.mkdir(mode=0o755, exist_ok=True)
    info = public_dir.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise BackendError("Небезопасные права каталога состояния VPN")
    public_dir.chmod(0o755)
    # Recover only our authenticated-by-filesystem journal from an earlier crash.
    if (RUN_DIR / "journal.json").exists():
        Engine(runner=runner).cleanup()
    shared = Path("/run/amneziawg")
    shared.mkdir(mode=0o755, exist_ok=True)
    info = shared.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise BackendError("Небезопасные права каталога AmneziaWG")
    atomic_json(RUN_DIR / "request.json", request)
    atomic_json(STATUS_PATH, {"state": "starting", "mode": request["mode"],
                              "host": request["profile"]["host"]}, 0o644)
    result = runner.run([SYSTEMCTL, "start", SERVICE], check=False, timeout=45)
    if result.returncode:
        details = status(runner)
        raise BackendError(details.get("error", "Служба VPN не запустилась; изменения отменены"))
    return status(runner)


def stop(runner):
    runner.run([SYSTEMCTL, "stop", SERVICE], timeout=30)
    ensure_private_directory(RUN_DIR)
    Engine(runner=runner).cleanup()
    if STATUS_PATH.parent.exists():
        atomic_json(STATUS_PATH, {"state": "down"}, 0o644)
    return {"state": "down"}


def engine():
    ensure_private_directory(RUN_DIR)
    with locked_file(RUN_DIR / "engine.lock"):
        request = validate_request(read_json(RUN_DIR / "request.json", limit=MAX_REQUEST))
        worker = Engine()
        signal.signal(signal.SIGTERM, worker.stop_signal)
        signal.signal(signal.SIGINT, worker.stop_signal)
        return worker.serve(request["profile"], request["mode"])


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        if len(argv) != 1 or argv[0] not in ("start", "stop", "status", "engine", "cleanup"):
            raise BackendError("Неизвестная команда службы VPN")
        command = argv[0]
        if command == "status":
            print(json.dumps(status(), ensure_ascii=False))
            return 0
        if os.geteuid() != 0:
            raise BackendError("Для подключения нужны права администратора")
        os.umask(0o077)
        if command == "engine":
            return engine()
        if command == "cleanup":
            ensure_private_directory(RUN_DIR)
            Engine().cleanup()
            return 0
        with locked_file(CONTROL_LOCK):
            runner = Runner()
            if command == "start":
                raw = sys.stdin.buffer.read(MAX_REQUEST + 1)
                if len(raw) > MAX_REQUEST:
                    raise BackendError("Слишком большой запрос приложения")
                result = start(validate_request(parse_json(raw)), runner)
            else:
                result = stop(runner)
            print(json.dumps(result, ensure_ascii=False))
        return 0
    except Exception as exc:
        error = str(exc) if isinstance(exc, BackendError) else "Некорректный профиль или недоступна служба VPN"
        print(json.dumps({"state": "error", "error": error}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    sys.exit(main())
