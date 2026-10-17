"""GUI boundary tests; use xvfb-run on Linux for the native widget checks."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

try:
    from myvpn import gui
except ImportError as exc:
    raise unittest.SkipTest("GTK 3 is required for GUI tests") from exc


class HelperBoundaryTests(unittest.TestCase):
    def test_start_passes_profile_on_stdin_without_command_line_credentials(self):
        profile = {"secret": "must-not-be-an-argument"}
        with patch.object(gui.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"", b"")) as run:
            gui._helper("start", {"profile": profile, "mode": "VLESS_TCP"})
        arguments, options = run.call_args
        self.assertEqual(arguments[0], ["/usr/bin/pkexec", gui.HELPER, "start"])
        self.assertEqual(json.loads(options["input"])["profile"], profile)
        self.assertLessEqual(options["timeout"], 90)

    def test_backend_error_never_displays_raw_output(self):
        result = subprocess.CompletedProcess([], 1, b"private-key-value", b"secret-password")
        with patch.object(gui.subprocess, "run", return_value=result), self.assertRaises(gui.BackendError) as caught:
            gui._helper("start", {})
        self.assertNotIn("private-key-value", str(caught.exception))
        self.assertNotIn("secret-password", str(caught.exception))

    def test_explicit_sanitized_helper_error_explains_how_to_recover(self):
        message = "Основной маршрут проходит через другой VPN. Сначала отключите его"
        result = subprocess.CompletedProcess([], 1, json.dumps({"state": "error", "error": message}).encode(), b"private")
        with patch.object(gui.subprocess, "run", return_value=result), self.assertRaises(gui.BackendError) as caught:
            gui._helper("start", {})
        self.assertEqual(str(caught.exception), message)

    def test_status_never_requests_privilege(self):
        result = subprocess.CompletedProcess([], 0, b'{"state":"up","mode":"AWG","host":"example.com"}', b"")
        with patch.object(gui.subprocess, "run", return_value=result) as run:
            self.assertEqual(gui._helper("status")["state"], "up")
        self.assertEqual(run.call_args.args[0], [gui.HELPER, "status"])

    def test_invalid_status_cannot_claim_connected(self):
        for raw in (b'{"state":"connected"}', b'{"state":"up","host":[]}', b"x" * 8193):
            with self.subTest(raw_length=len(raw)):
                result = subprocess.CompletedProcess([], 0, raw, b"")
                with patch.object(gui.subprocess, "run", return_value=result), self.assertRaises(gui.BackendError):
                    gui._helper("status")


class DiagnosticsTests(unittest.TestCase):
    def test_small_bounded_download_and_no_inherited_proxy(self):
        responses = (subprocess.CompletedProcess([], 0, b"204 0", b""),
                     subprocess.CompletedProcess([], 0, b"200 65536", b""))
        with patch.dict(gui.os.environ, {"HTTPS_PROXY": "http://secret:password@proxy"}), \
                patch.object(gui.subprocess, "run", side_effect=responses) as run:
            message = gui._diagnostics()
        self.assertIn("Google: доступен", message)
        self.assertIn("загрузка выполнена", message)
        self.assertEqual(run.call_count, 2)
        for call in run.call_args_list:
            command = call.args[0]
            self.assertEqual(command[command.index("--max-time") + 1], "12")
            self.assertEqual(command[command.index("--max-filesize") + 1], "65536")
            self.assertNotIn("--insecure", command)
            self.assertNotIn("HTTPS_PROXY", call.kwargs["env"])

    def test_partial_download_never_claims_success(self):
        responses = (subprocess.CompletedProcess([], 28, b"000 0", b""),
                     subprocess.CompletedProcess([], 0, b"200 16000", b""))
        with patch.object(gui.subprocess, "run", side_effect=responses):
            message = gui._diagnostics()
        self.assertIn("время ожидания истекло", message)
        self.assertIn("проверка не пройдена", message)
        self.assertNotIn("загрузка выполнена", message)


class NativeWindowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        initialized = gui.Gtk.init_check([])
        if not initialized[0]:
            raise unittest.SkipTest("Run with xvfb-run for native widget tests")
        cls.app = gui.Gtk.Application(application_id="app.myvpn.gui.tests", flags=gui.Gio.ApplicationFlags.NON_UNIQUE)
        cls.app.register(None)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="myvpn-gui-test-")
        self.addCleanup(self.temporary.cleanup)
        profile_path = Path(__file__).resolve().parents[2] / "config" / "example.json"
        # Source-tree tests only use the intentionally public example credentials.
        self.profile = json.loads(profile_path.read_text())
        self.profile["client"] = "linux"
        self.store = gui.Store(Path(self.temporary.name) / "state.json", self.profile)
        self.window = gui.VPNWindow(self.app, self.store, None, smoke=True)
        self.addCleanup(self.window.destroy)

    def test_status_does_not_promise_internet_and_preserves_active_host(self):
        self.window.status = {"state": "up", "mode": "AWG", "host": "old-server.example"}
        self.window._render()
        self.assertEqual(self.window.status_label.get_text(), "Туннель запущен")
        self.assertEqual(self.window.server_label.get_text(), "Сервер: old-server.example")
        self.assertFalse(self.window.mode_list.get_sensitive())
        self.assertTrue(self.window.check_button.get_sensitive())

    def test_closing_active_tunnel_requires_explicit_choice(self):
        self.window.status = {"state": "up", "mode": "AWG", "host": "example.com"}
        with patch.object(gui.Gtk.MessageDialog, "run", return_value=gui.Gtk.ResponseType.CANCEL), \
                patch.object(self.window, "_change_connection") as change:
            self.assertTrue(self.window._on_close(self.window, None))
            change.assert_not_called()
        with patch.object(gui.Gtk.MessageDialog, "run", return_value=gui.Gtk.ResponseType.NO), \
                patch.object(self.window, "_change_connection") as change:
            self.assertFalse(self.window._on_close(self.window, None))
            change.assert_not_called()

    def test_disconnect_and_close_uses_controlled_stop(self):
        self.window.status = {"state": "up", "mode": "AWG", "host": "example.com"}
        with patch.object(gui.Gtk.MessageDialog, "run", return_value=gui.Gtk.ResponseType.YES), \
                patch.object(self.window, "_change_connection") as change:
            self.assertTrue(self.window._on_close(self.window, None))
        change.assert_called_once_with("stop", close_after=True)

    def test_native_core_rejection_preserves_installed_profile(self):
        self.window.bootstrap = {"fixture": True}
        before = self.store.profile

        def immediate(work, complete):
            try:
                result, error = work(), None
            except Exception as exc:
                result, error = None, exc
            complete(result, error)

        update = {"profile": self.profile, "revision": 10}
        with patch.object(gui, "fetch_update", return_value=update), \
                patch.object(gui, "validate_core_configs", side_effect=ValueError("native rejection")), \
                patch.object(self.store, "apply_update") as apply, \
                patch.object(self.window, "_thread", side_effect=immediate):
            self.window._update(None)
        apply.assert_not_called()
        self.assertEqual(self.store.profile, before)
        self.assertIn("Текущая конфигурация сохранена", self.window.update_label.get_text())


if __name__ == "__main__":
    unittest.main()
