import http.server
import socketserver
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs

import wifi_login


class PortalHandler(http.server.BaseHTTPRequestHandler):
    received = {}

    def log_message(self, *_args):
        pass

    def do_GET(self):
        base = f"http://127.0.0.1:{self.server.server_address[1]}"
        if self.path == "/probe":
            self.send_response(302)
            self.send_header(
                "Location", f"{base}/redirect.html?URI={base}/probe"
            )
            self.end_headers()
            return
        if self.path.startswith("/redirect.html"):
            body = (
                f'<script>var path ="{base}/cgi-bin/authlogin"</script>'
            ).encode()
        elif self.path.startswith("/cgi-bin/authlogin"):
            body = (
                b'<form method="POST" action="/submit">'
                b'<input name="serviceName" value="ProntoAuthentication">'
                b'<input name="userId"><input name="password"></form>'
            )
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        size = int(self.headers["Content-Length"])
        type(self).received = parse_qs(self.rfile.read(size).decode())
        self.send_response(200)
        self.end_headers()


class WifiLoginTests(unittest.TestCase):
    def test_requested_ssid_rule_is_exact_case_sensitive_substring(self):
        for ssid in ("L-VIT", "VIT-Hostel", "CampusVIT5G", "ACTIVITY"):
            self.assertTrue(wifi_login.is_vit_ssid(ssid))
        self.assertFalse(wifi_login.is_vit_ssid("L-vit"))
        self.assertFalse(wifi_login.is_vit_ssid(None))

    def test_pronto_redirect_form_and_progress_stages(self):
        server = socketserver.TCPServer(("127.0.0.1", 0), PortalHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        stages = []
        try:
            result = wifi_login.portal_login(
                "student",
                "secret",
                f"http://127.0.0.1:{server.server_address[1]}/probe",
                progress=stages.append,
                connection_is_valid=lambda: True,
            )
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(result, "Login request submitted.")
        self.assertEqual(stages, ["detecting_portal", "submitting_credentials"])
        self.assertEqual(PortalHandler.received["userId"], ["student"])
        self.assertEqual(PortalHandler.received["password"], ["secret"])

    def test_success_publishes_each_user_visible_stage(self):
        statuses = []

        def successful_portal(
            _username, _password, progress=None, connection_is_valid=None, **_kwargs
        ):
            progress("detecting_portal")
            progress("submitting_credentials")
            self.assertTrue(connection_is_valid())
            return "Login request submitted."

        with (
            patch.object(
                wifi_login,
                "load_settings",
                return_value={"username": "student", "enabled": True},
            ),
            patch.object(wifi_login, "connected_ssid", return_value="L-VIT"),
            patch.object(wifi_login, "wait_for_network_ready", return_value=True),
            patch.object(wifi_login, "load_password", return_value="secret"),
            patch.object(wifi_login, "portal_login", side_effect=successful_portal),
            patch.object(wifi_login, "internet_is_working", return_value=True),
        ):
            monitor = wifi_login.Monitor(statuses.append)
            monitor._check_connection(connection_event=True, force_attempt=False)

        self.assertEqual(
            [status["state"] for status in statuses],
            [
                "preparing_network",
                "detecting_portal",
                "submitting_credentials",
                "verifying_internet",
                "online",
            ],
        )
        self.assertIn("safely close", statuses[-1]["detail"])

    def test_failure_schedules_countdown_and_manual_retry(self):
        statuses = []
        with (
            patch.object(
                wifi_login,
                "load_settings",
                return_value={"username": "student", "enabled": True},
            ),
            patch.object(wifi_login, "connected_ssid", return_value="L-VIT"),
            patch.object(wifi_login, "wait_for_network_ready", return_value=True),
            patch.object(wifi_login, "load_password", return_value="secret"),
            patch.object(
                wifi_login,
                "portal_login",
                side_effect=RuntimeError("Portal unavailable"),
            ),
            patch.object(wifi_login, "internet_is_working", return_value=False),
        ):
            monitor = wifi_login.Monitor(statuses.append)
            monitor.last_ssid = "L-VIT"
            monitor._check_connection(connection_event=False, force_attempt=True)

        retry = statuses[-1]
        self.assertEqual(retry["state"], "retry_wait")
        self.assertTrue(retry["can_try_now"])
        self.assertGreaterEqual(retry["next_retry_at"] - time.time(), 13)
        self.assertLessEqual(retry["next_retry_at"] - time.time(), 15.5)

    def test_missing_credentials_pause_without_retrying(self):
        statuses = []
        with (
            patch.object(
                wifi_login,
                "load_settings",
                return_value={"username": "student", "enabled": True},
            ),
            patch.object(wifi_login, "connected_ssid", return_value="VIT-Hostel"),
            patch.object(wifi_login, "wait_for_network_ready", return_value=True),
            patch.object(wifi_login, "load_password", return_value=None),
            patch.object(wifi_login, "internet_is_working", return_value=False),
        ):
            monitor = wifi_login.Monitor(statuses.append)
            monitor._check_connection(connection_event=True, force_attempt=False)

        self.assertEqual(statuses[-1]["state"], "credentials_required")
        self.assertEqual(monitor.next_retry_at, 0)


if __name__ == "__main__":
    unittest.main()
