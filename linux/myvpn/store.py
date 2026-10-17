"""Atomic per-user profile, selection, and authenticated revision persistence."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import stat
import tempfile
import threading

from .model import MAX_DOCUMENT_BYTES, MAX_REVISION, connections, parse_json, validate_profile
from .updates import validate_bootstrap


class StoreError(ValueError):
    pass


def _revision(value):
    if type(value) is not int or not 0 <= value <= MAX_REVISION:
        raise StoreError("Некорректный номер сохранённого обновления")
    return value


def _read_state(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise StoreError("У файла настроек небезопасные права доступа")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            return parse_json(stream.read(MAX_DOCUMENT_BYTES + 1))
    finally:
        os.close(fd)


def _atomic_write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent = path.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid():
        raise StoreError("Недоступна папка настроек")
    path.parent.chmod(0o700)
    if path.is_symlink():
        raise StoreError("Файл настроек не должен быть символической ссылкой")
    data = (json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
    if len(data) > MAX_DOCUMENT_BYTES:
        raise StoreError("Настройки слишком большие")
    fd, temporary = tempfile.mkstemp(prefix=".myvpn-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        # The replacement is the commit point. A directory fsync failure must not
        # cause memory to retain the previous revision after disk has advanced.
        try:
            directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError:
            pass
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class Store:
    def __init__(self, path, bundled_profile, bootstrap=None):
        self.path = Path(path)
        self.bootstrap = validate_bootstrap(bootstrap) if bootstrap is not None else None
        profile = validate_profile(bundled_profile)
        if self.bootstrap is not None and profile["client"] != self.bootstrap["client"]:
            raise StoreError("Профиль не совпадает с настройками обновления")
        self._lock = threading.RLock()
        self._state = {"format": "myvpn-state-v1", "profile": profile,
                       "revision": self.bootstrap["minRevision"] if self.bootstrap else 0, "selected": "VLESS_TCP"}
        if self.path.exists() or self.path.is_symlink():
            state = _read_state(self.path)
            if (not isinstance(state, dict) or set(state) != {"format", "profile", "revision", "selected"}
                    or state.get("format") != "myvpn-state-v1"):
                raise StoreError("Некорректные сохранённые настройки")
            candidate = validate_profile(state["profile"])
            if candidate["client"] != profile["client"]:
                raise StoreError("Сохранён другой профиль")
            revision = _revision(state["revision"])
            # An installed app with a newer bundled revision cannot be rolled
            # back by an older persisted copy. Keep the bundle and its floor.
            if self.bootstrap is not None and revision < self.bootstrap["minRevision"]:
                self._state["revision"] = self.bootstrap["minRevision"]
                self._state["selected"] = self._selection(state["selected"], profile)
            else:
                self._state = {"format": "myvpn-state-v1", "profile": candidate, "revision": revision,
                               "selected": self._selection(state["selected"], candidate)}

    @staticmethod
    def _selection(mode, profile):
        ids = {item["id"] for item in connections(profile)}
        return mode if isinstance(mode, str) and mode in ids else "VLESS_TCP"

    @property
    def profile(self):
        with self._lock:
            return copy.deepcopy(self._state["profile"])

    @property
    def selected(self):
        with self._lock:
            return self._state["selected"]

    @property
    def revision(self):
        with self._lock:
            return self._state["revision"]

    def select(self, mode):
        with self._lock:
            if self._selection(mode, self._state["profile"]) != mode:
                raise StoreError("Выбранный режим недоступен")
            if mode == self._state["selected"]:
                return False
            candidate = copy.deepcopy(self._state)
            candidate["selected"] = mode
            _atomic_write(self.path, candidate)
            self._state = candidate
            return True

    def apply_update(self, update):
        """Publish profile and rollback floor together; active tunnels keep copies."""
        with self._lock:
            if self.bootstrap is None:
                raise StoreError("Обновления не настроены в этой сборке")
            if not isinstance(update, dict) or set(update) != {"profile", "revision"}:
                raise StoreError("Некорректное обновление")
            revision = _revision(update["revision"])
            if revision < max(self._state["revision"], self.bootstrap["minRevision"]):
                raise StoreError("Получено устаревшее обновление")
            profile = validate_profile(update["profile"])
            if profile["client"] != self.bootstrap["client"]:
                raise StoreError("Обновление предназначено для другого профиля")
            candidate = {"format": "myvpn-state-v1", "profile": profile, "revision": revision,
                         "selected": self._selection(self._state["selected"], profile)}
            if candidate == self._state:
                return False
            _atomic_write(self.path, candidate)
            self._state = candidate
            return True
