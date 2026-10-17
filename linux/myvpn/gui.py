"""Small native GTK desktop client. Network privileges stay in the helper."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from typing import Callable

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gio, GLib, Gtk  # noqa: E402

from .model import connections, parse_json, validate_core_configs  # noqa: E402
from .store import Store  # noqa: E402
from .updates import fetch_update, validate_bootstrap  # noqa: E402

HELPER = "/usr/lib/myvpn/myvpn-helper"
RESOURCE_DIR = Path("/usr/share/myvpn")
APP_ID = "app.myvpn.desktop"

STYLE = b"""
.app-title { font-size: 23px; font-weight: bold; }
.section-title { font-size: 14px; font-weight: bold; }
.status-title { font-size: 22px; font-weight: bold; }
.status-card { background: alpha(@theme_fg_color, 0.045); border-radius: 16px; }
.card { background: alpha(@theme_fg_color, 0.045); border-radius: 12px; }
.muted { opacity: 0.72; }
.notice { padding: 10px; background: alpha(@theme_selected_bg_color, 0.10); border-radius: 8px; }
.problem { color: @error_color; }
.protocol-list { background: transparent; }
.protocol-list row { padding: 10px; border-radius: 8px; }
.connect-button { padding: 12px 30px; font-weight: bold; }
"""


class BackendError(Exception):
    """A fixed, safe user-facing message, never raw process output."""


def _status_error(value) -> str | None:
    # The installed helper emits only fixed credential-free BackendError text.
    # Never display arbitrary stdout, stderr, profile fields or tracebacks.
    if not isinstance(value, dict):
        return None
    message = value.get("error")
    if (isinstance(message, str) and 0 < len(message) <= 512
            and not any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in message)):
        return message
    return None


def _read_json(path: Path, limit: int) -> dict:
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("Configuration is too large")
    return parse_json(raw)


def _helper(action: str, payload: dict | None = None) -> dict:
    command = [HELPER, action]
    if action != "status":
        command.insert(0, "/usr/bin/pkexec")
    try:
        result = subprocess.run(
            command,
            input=json.dumps(payload).encode("utf-8") if payload is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=90 if action == "start" else 45 if action == "stop" else 5,
            check=False,
        )
    except FileNotFoundError as exc:
        raise BackendError("Служебный компонент не найден. Переустановите пакет My VPN.") from exc
    except subprocess.TimeoutExpired as exc:
        raise BackendError("Служебный компонент не ответил вовремя. Проверьте состояние подключения.") from exc
    if result.returncode:
        if action != "status" and result.returncode in (126, 127):
            raise BackendError("Доступ администратора не подтверждён. Подключение не изменено.")
        if len(result.stdout) <= 8192:
            try:
                message = _status_error(json.loads(result.stdout))
                if message:
                    raise BackendError(message)
            except (ValueError, UnicodeError):
                pass
        raise BackendError("Не удалось выполнить действие. Проверьте сеть и повторите попытку.")
    if action != "status":
        return {}
    try:
        if len(result.stdout) > 8192:
            raise ValueError("Oversized status")
        status = json.loads(result.stdout)
        if not isinstance(status, dict) or status.get("state") not in ("down", "starting", "up", "error"):
            raise ValueError("Invalid status")
        for name in ("mode", "host"):
            if name in status and (not isinstance(status[name], str) or len(status[name]) > 253):
                raise ValueError("Invalid status field")
        return status
    except (ValueError, UnicodeDecodeError) as exc:
        raise BackendError("Не удалось прочитать состояние служебного компонента.") from exc


def _diagnostics() -> str:
    """Bounded requests through the current system tunnel; no route changes."""
    environment = dict(os.environ)
    for key in list(environment):
        if key.lower() in ("http_proxy", "https_proxy", "all_proxy", "no_proxy"):
            del environment[key]
    results = []
    checks = (
        ("Google", "https://www.google.com/generate_204", 204, 0),
        ("Cloudflare, 64 КиБ", "https://speed.cloudflare.com/__down?bytes=65536", 200, 65536),
    )
    for title, url, expected_status, expected_size in checks:
        command = [
            "/usr/bin/curl", "--silent", "--fail", "--proto", "=https", "--noproxy", "*",
            "--connect-timeout", "5", "--max-time", "12", "--max-filesize", "65536",
            "--output", "/dev/null", "--write-out", "%{http_code} %{size_download}", url,
        ]
        try:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    timeout=14, env=environment, check=False)
            response = result.stdout.decode("ascii", errors="replace").strip().split()
            succeeded = (result.returncode == 0 and len(response) == 2
                         and response[0] == str(expected_status)
                         and response[1] == str(expected_size))
            if succeeded:
                text = "доступен" if expected_size == 0 else "загрузка выполнена"
            elif result.returncode == 28:
                text = "время ожидания истекло"
            elif result.returncode == 6:
                text = "ошибка DNS"
            elif result.returncode in (35, 51, 60):
                text = "ошибка TLS"
            else:
                text = "проверка не пройдена"
        except subprocess.TimeoutExpired:
            text = "время ожидания истекло"
        except OSError:
            text = "не удалось запустить проверку"
        results.append(f"{title}: {text}")
    return "\n".join(results)


def _label(text: str = "", css: str | None = None, wrap: bool = False) -> Gtk.Label:
    label = Gtk.Label(label=text, xalign=0)
    label.set_line_wrap(wrap)
    if css:
        label.get_style_context().add_class(css)
    return label


def _box(spacing: int = 8, css: str | None = None, margin: int = 0) -> Gtk.Box:
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=spacing)
    if css:
        box.get_style_context().add_class(css)
    if margin:
        box.set_border_width(margin)
    return box


class VPNWindow(Gtk.ApplicationWindow):
    def __init__(self, app: Gtk.Application, store: Store, bootstrap: dict | None, smoke: bool = False):
        super().__init__(application=app, title="My VPN")
        self.store = store
        self.bootstrap = bootstrap
        self.smoke = smoke
        self.status = {"state": "down"}
        self._operation: str | None = None
        self._polling = False
        self._closing = False
        self._status_known = smoke
        self._diagnostic_identity = None
        self._rows: dict[str, Gtk.ListBoxRow] = {}
        self.set_default_size(540, 800)
        self.set_size_request(420, 500)
        self.set_icon_name("myvpn")
        self.connect("delete-event", self._on_close)
        self.connect("destroy", self._on_destroy)

        provider = Gtk.CssProvider()
        provider.load_from_data(STYLE)
        Gtk.StyleContext.add_provider_for_screen(self.get_screen(), provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

        header = Gtk.HeaderBar(title="My VPN", subtitle="Ubuntu 24.04")
        header.set_show_close_button(True)
        self.set_titlebar(header)
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.add(scroll)
        content = _box(spacing=18, margin=22)
        scroll.add(content)

        status_card = _box(spacing=9, css="status-card")
        status_inner = _box(spacing=10, margin=22)
        status_card.add(status_inner)
        content.add(status_card)
        self.status_label = _label("Проверка состояния…", "status-title")
        self.status_label.set_xalign(0.5)
        status_inner.add(self.status_label)
        self.active_label = _label("", "muted", wrap=True)
        self.active_label.set_xalign(0.5)
        status_inner.add(self.active_label)
        self.server_label = _label("", "muted", wrap=True)
        self.server_label.set_xalign(0.5)
        self.server_label.set_selectable(True)
        status_inner.add(self.server_label)
        self.toggle_button = Gtk.Button(label="Подключить")
        self.toggle_button.set_halign(Gtk.Align.CENTER)
        self.toggle_button.get_style_context().add_class("suggested-action")
        self.toggle_button.get_style_context().add_class("connect-button")
        self.toggle_button.connect("clicked", self._toggle)
        status_inner.add(self.toggle_button)
        self.connection_note = _label("Для управления VPN Ubuntu запросит пароль администратора.", "muted", wrap=True)
        self.connection_note.set_xalign(0.5)
        status_inner.add(self.connection_note)

        self.error_label = _label("", "problem", wrap=True)
        self.error_label.set_selectable(True)
        self.error_label.set_no_show_all(True)
        content.add(self.error_label)
        content.add(_label("Режим подключения", "section-title"))
        self.mode_note = _label("Выберите режим перед подключением.", "muted", wrap=True)
        content.add(self.mode_note)
        self.mode_list = Gtk.ListBox()
        self.mode_list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self.mode_list.set_activate_on_single_click(True)
        self.mode_list.get_style_context().add_class("protocol-list")
        self.mode_list.connect("row-selected", self._mode_selected)
        content.add(self.mode_list)

        update_card = _box(spacing=8, css="card")
        update_inner = _box(spacing=8, margin=14)
        update_card.add(update_inner)
        self.update_button = Gtk.Button(label="Обновить конфигурацию")
        self.update_button.connect("clicked", self._update)
        update_inner.add(self.update_button)
        self.update_label = _label("Серверы и совместимые режимы обновляются без переустановки приложения."
                                   if bootstrap else "Канал обновлений не настроен в этой сборке.", "muted", wrap=True)
        update_inner.add(self.update_label)
        content.add(update_card)

        self.check_button = Gtk.Button(label="Проверить соединение")
        self.check_button.connect("clicked", self._check)
        content.add(self.check_button)
        self.check_label = _label("Проверка HTTPS и небольшой загрузки через текущее подключение.", "muted", wrap=True)
        self.check_label.set_selectable(True)
        content.add(self.check_label)
        self._populate_modes()
        self._render()
        self.show_all()
        if not smoke:
            self._poll_status()
            self._timer = GLib.timeout_add_seconds(3, self._poll_status)
        else:
            self._timer = None

    def _populate_modes(self):
        for row in self.mode_list.get_children():
            self.mode_list.remove(row)
        self._rows.clear()
        for mode in connections(self.store.profile):
            row = Gtk.ListBoxRow()
            row.mode_id = mode["id"]
            item = _box(spacing=3)
            title = _label(mode["title"])
            item.add(title)
            item.add(_label(mode["subtitle"], "muted", wrap=True))
            row.add(item)
            self.mode_list.add(row)
            self._rows[mode["id"]] = row
        self.mode_list.select_row(self._rows.get(self.store.selected))
        self.mode_list.show_all()

    def _mode_selected(self, _listbox, row):
        if row is None or self._operation or self.status["state"] in ("up", "starting"):
            return
        try:
            self.store.select(row.mode_id)
        except (OSError, ValueError):
            self._show_error("Не удалось сохранить выбранный режим. Проверьте доступ к папке настроек.")

    def _identity(self):
        return (self.status.get("state"), self.status.get("mode"), self.status.get("host"),
                self.status.get("session", self.status.get("startedAt")))

    def _render(self):
        state = self.status["state"]
        active = state in ("up", "starting")
        title = {"down": "Отключено", "starting": "Подключение…", "up": "Туннель запущен",
                 "error": "Туннель остановлен"}[state]
        if not self._status_known:
            title = "Состояние недоступно"
        if self._operation in ("start", "stop"):
            title = "Подключение…" if self._operation == "start" else "Отключение…"
        self.status_label.set_text(title)
        self.toggle_button.set_label("Отключить" if active else "Подключить")
        self.toggle_button.set_sensitive(self._operation is None and state != "starting" and self._status_known)
        self.mode_list.set_sensitive(not active and self._operation is None)
        self.update_button.set_sensitive(self.bootstrap is not None and self._operation is None)
        self.update_button.set_label("Обновление…" if self._operation == "update" else "Обновить конфигурацию")
        self.check_button.set_sensitive(state == "up" and self._operation is None and self._status_known)
        self.check_button.set_label("Проверка…" if self._operation == "check" else "Проверить соединение")
        host = self.status.get("host") if active else self.store.profile.get("host")
        self.server_label.set_text(f"Сервер: {host}" if host else "")
        modes = {mode["id"]: mode for mode in connections(self.store.profile)}
        selected = self.status.get("mode") if active else self.store.selected
        self.active_label.set_text(modes.get(selected, {}).get("title", "Текущий режим" if active else ""))
        self.connection_note.set_text("Проверьте соединение, если сайты не открываются." if state == "up"
                                      else "Для управления VPN Ubuntu запросит пароль администратора.")
        self.mode_note.set_text("Чтобы сменить режим, сначала отключите VPN." if active
                                else "Выберите режим перед подключением.")

    def _show_error(self, message: str | None):
        self.error_label.set_text(message or "")
        self.error_label.set_visible(bool(message))

    def _thread(self, work: Callable, complete: Callable):
        def run():
            try:
                value, error = work(), None
            except Exception as exc:
                value, error = None, exc
            GLib.idle_add(deliver, value, error)

        def deliver(value, error):
            if not self._closing:
                complete(value, error)
            return GLib.SOURCE_REMOVE

        threading.Thread(target=run, daemon=True, name="myvpn-operation").start()

    def _poll_status(self):
        if self._closing:
            return GLib.SOURCE_REMOVE
        if self._polling or self._operation in ("start", "stop"):
            return GLib.SOURCE_CONTINUE
        self._polling = True

        def complete(status, error):
            self._polling = False
            previous_known = self._status_known
            self._status_known = error is None
            if error:
                self._show_error(str(error) if isinstance(error, BackendError) else "Не удалось узнать состояние VPN.")
            else:
                before = self._identity()
                self.status = status
                if before != self._identity():
                    self.check_label.set_text("Проверка HTTPS и небольшой загрузки через текущее подключение.")
                if status["state"] == "error":
                    self._show_error(_status_error(status) or "VPN остановился. Можно выбрать другой режим и подключиться снова.")
                elif not previous_known:
                    self._show_error(None)
            self._render()

        self._thread(lambda: _helper("status"), complete)
        return GLib.SOURCE_CONTINUE

    def _toggle(self, _button):
        if self._operation:
            return
        self._change_connection("stop" if self.status["state"] == "up" else "start")

    def _change_connection(self, action: str, close_after: bool = False):
        self._operation = action
        self._show_error(None)
        self.check_label.set_text("Проверка HTTPS и небольшой загрузки через текущее подключение.")
        payload = {"profile": self.store.profile, "mode": self.store.selected} if action == "start" else None
        self._render()

        def complete(_value, error):
            self._operation = None
            if error:
                self._show_error(str(error) if isinstance(error, BackendError) else "Не удалось изменить подключение.")
            if close_after and error is None:
                self._closing = True
                self.destroy()
                return
            self._poll_status()
            self._render()

        self._thread(lambda: _helper(action, payload), complete)

    def _update(self, _button):
        if self._operation or self.bootstrap is None:
            return
        self._operation = "update"
        self._show_error(None)
        self.update_label.set_text("Загрузка и проверка зашифрованного профиля…")
        self._render()

        def work():
            update = fetch_update(self.bootstrap, applied_revision=self.store.revision)
            validate_core_configs(update["profile"])
            changed = self.store.apply_update(update)
            return changed, self.store.revision

        def complete(value, error):
            self._operation = None
            if error:
                self.update_label.set_text("Обновление не применено. Текущая конфигурация сохранена.")
                self._show_error("Не удалось получить или проверить обновление. Если VPN не передаёт трафик, отключите его и повторите попытку.")
            else:
                changed, revision = value
                self._populate_modes()
                prefix = "Конфигурация обновлена" if changed else "Уже установлена актуальная конфигурация"
                self.update_label.set_text(f"{prefix} (версия {revision}). Параметры применятся при следующем подключении.")
            self._render()

        self._thread(work, complete)

    def _check(self, _button):
        if self._operation or self.status["state"] != "up":
            return
        self._operation = "check"
        self._diagnostic_identity = self._identity()
        self.check_label.set_text("Проверка Google и загрузки 64 КиБ с Cloudflare…")
        self._render()

        def complete(value, error):
            self._operation = None
            if self._identity() != self._diagnostic_identity:
                self.check_label.set_text("Подключение изменилось во время проверки. Запустите её ещё раз.")
            elif error:
                self.check_label.set_text("Проверка не завершена. Попробуйте ещё раз.")
            else:
                self.check_label.set_text(value)
            self._render()

        self._thread(_diagnostics, complete)

    def _on_close(self, _window, _event):
        if self._operation:
            dialog = Gtk.MessageDialog(transient_for=self, modal=True, message_type=Gtk.MessageType.INFO,
                                       buttons=Gtk.ButtonsType.OK, text="Дождитесь завершения операции")
            dialog.format_secondary_text("После этого приложение можно закрыть.")
            dialog.run()
            dialog.destroy()
            return True
        if self.status["state"] in ("up", "starting") or not self._status_known:
            dialog = Gtk.MessageDialog(transient_for=self, modal=True, message_type=Gtk.MessageType.QUESTION,
                                       buttons=Gtk.ButtonsType.NONE, text="Закрыть My VPN?")
            dialog.format_secondary_text("VPN может работать после закрытия окна. Выберите, сохранить подключение или отключить его.")
            dialog.add_button("Отмена", Gtk.ResponseType.CANCEL)
            dialog.add_button("Оставить VPN", Gtk.ResponseType.NO)
            dialog.add_button("Отключить и закрыть", Gtk.ResponseType.YES)
            dialog.set_default_response(Gtk.ResponseType.CANCEL)
            response = dialog.run()
            dialog.destroy()
            if response == Gtk.ResponseType.YES:
                self._change_connection("stop", close_after=True)
                return True
            if response != Gtk.ResponseType.NO:
                return True
        self._closing = True
        return False

    def _on_destroy(self, _window):
        self._closing = True
        if self._timer:
            GLib.source_remove(self._timer)
            self._timer = None


class VPNApplication(Gtk.Application):
    def __init__(self, resources: Path = RESOURCE_DIR, smoke: bool = False):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.NON_UNIQUE if smoke else Gio.ApplicationFlags.FLAGS_NONE)
        self.resources = resources
        self.smoke = smoke
        self.smoke_result = 1
        self.window: VPNWindow | None = None
        self._temporary_state = None

    def do_activate(self):
        if self.window is not None:
            self.window.present()
            return
        try:
            profile = _read_json(self.resources / "default_profile.json", 512 * 1024)
            bootstrap_path = self.resources / "update_bootstrap.json"
            bootstrap = validate_bootstrap(_read_json(bootstrap_path, 16 * 1024)) if bootstrap_path.exists() else None
            if self.smoke:
                self._temporary_state = tempfile.TemporaryDirectory(prefix="myvpn-ui-smoke-")
                state_path = Path(self._temporary_state.name) / "state.json"
            else:
                config_home = Path(os.environ.get("XDG_CONFIG_HOME", ""))
                if not config_home.is_absolute():
                    config_home = Path.home() / ".config"
                state_path = config_home / "myvpn" / "state.json"
            store = Store(state_path, profile, bootstrap=bootstrap)
            self.window = VPNWindow(self, store, bootstrap, smoke=self.smoke)
            self.window.present()
            if self.smoke:
                GLib.idle_add(self._finish_smoke)
        except Exception:
            if self.smoke:
                print("My VPN GUI smoke test: initialization failed", file=sys.stderr)
                self.quit()
                return
            dialog = Gtk.MessageDialog(modal=True, message_type=Gtk.MessageType.ERROR, buttons=Gtk.ButtonsType.CLOSE,
                                       text="Не удалось открыть My VPN")
            dialog.format_secondary_text("Проверьте установку приложения и доступ к папке ~/.config/myvpn. Личные настройки не изменены.")
            dialog.run()
            dialog.destroy()
            self.quit()

    def _finish_smoke(self):
        assert self.window is not None
        count = len(self.window._rows)
        valid = (count == len(connections(self.window.store.profile)) and count >= 4
                 and self.window.status_label.get_text() == "Отключено"
                 and self.window.toggle_button.get_sensitive())
        self.smoke_result = 0 if valid else 1
        print(json.dumps({"gui": "ok" if valid else "failed", "modes": count, "network_changed": False}))
        self.window.destroy()
        self.quit()
        return GLib.SOURCE_REMOVE

    def do_shutdown(self):
        if self._temporary_state is not None:
            self._temporary_state.cleanup()
        Gtk.Application.do_shutdown(self)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="My VPN для Ubuntu 24.04")
    parser.add_argument("--smoke-test", action="store_true", help="Проверить запуск интерфейса без подключения к VPN")
    parser.add_argument("--resource-dir", type=Path, help="Тестовые ресурсы (только вместе с --smoke-test)")
    args = parser.parse_args(argv)
    if args.resource_dir is not None and not args.smoke_test:
        parser.error("--resource-dir requires --smoke-test")
    application = VPNApplication(args.resource_dir or RESOURCE_DIR, smoke=args.smoke_test)
    result = application.run(["myvpn"])
    return application.smoke_result if args.smoke_test else result
