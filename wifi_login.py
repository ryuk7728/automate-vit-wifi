"""Automatic captive-portal login for VIT Wi-Fi on Windows.

Credentials stay in Windows Credential Manager. The program only attempts a
login after Windows reports that the current Wi-Fi SSID contains ``VIT``.
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from html.parser import HTMLParser
import http.cookiejar
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlsplit
from urllib.request import HTTPCookieProcessor, Request, build_opener, urlopen
import winreg


APP_NAME = "Automate VIT WiFi"
APP_VERSION = "1.3.0"
USER_AGENT = f"AutomateVitWifi/{APP_VERSION}"
PORTAL_USER_AGENT = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) {USER_AGENT}"
CREDENTIAL_TARGET = "AutomateVitWifi:portal-password"
DEFAULT_PROBE_URL = "http://neverssl.com/"
CONNECTIVITY_CHECKS = (
    ("https://www.google.com/generate_204", 204, b""),
    ("https://www.msftconnecttest.com/connecttest.txt", 200, b"Microsoft Connect Test"),
    ("https://cloudflare.com/cdn-cgi/trace", 200, b"fl="),
)
BACKGROUND_MUTEX_NAME = r"Local\AutomateVitWifiBackground"
BACKGROUND_COMMAND_EVENT_NAME = r"Local\AutomateVitWifiCommand"
# Windows raises a WLAN notification as soon as it finishes connecting.  These
# timers are only fallbacks for missed notifications and portal retry recovery.
BACKGROUND_FALLBACK_SECONDS = 60
RETRY_INITIAL_SECONDS = 15
RETRY_MAX_SECONDS = 60
NETWORK_READY_TIMEOUT_SECONDS = 5
NETWORK_READY_INTERVAL_SECONDS = 0.25
POST_LOGIN_SETTLE_SECONDS = 1
UI_STATUS_REFRESH_MS = 250
COMMAND_MAX_AGE_SECONDS = 30
APP_DATA_DIR = Path(os.environ.get("APPDATA", Path.home())) / APP_NAME
SETTINGS_PATH = APP_DATA_DIR / "settings.json"
STATUS_PATH = APP_DATA_DIR / "status.json"
COMMAND_PATH = APP_DATA_DIR / "command.json"

WLAN_NOTIFICATION_SOURCE_ACM = 0x00000008
WLAN_NOTIFICATION_ACM_CONNECTION_COMPLETE = 10
WLAN_NOTIFICATION_ACM_INTERFACE_ARRIVAL = 13
WLAN_NOTIFICATION_ACM_DISCONNECTED = 21


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class WLAN_NOTIFICATION_DATA(ctypes.Structure):
    _fields_ = [
        ("NotificationSource", wintypes.DWORD),
        ("NotificationCode", wintypes.DWORD),
        ("InterfaceGuid", GUID),
        ("dwDataSize", wintypes.DWORD),
        ("pData", ctypes.c_void_p),
    ]


WLAN_NOTIFICATION_CALLBACK = ctypes.WINFUNCTYPE(
    None, ctypes.POINTER(WLAN_NOTIFICATION_DATA), ctypes.c_void_p
)


class CREDENTIAL(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("TargetName", wintypes.LPWSTR),
        ("Comment", wintypes.LPWSTR),
        ("LastWritten", wintypes.FILETIME),
        ("CredentialBlobSize", wintypes.DWORD),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_byte)),
        ("Persist", wintypes.DWORD),
        ("AttributeCount", wintypes.DWORD),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", wintypes.LPWSTR),
        ("UserName", wintypes.LPWSTR),
    ]


PCREDENTIAL = ctypes.POINTER(CREDENTIAL)
ADVAPI32 = ctypes.WinDLL("advapi32", use_last_error=True)
CRED_TYPE_GENERIC = 1
CRED_PERSIST_LOCAL_MACHINE = 2


def save_password(password: str) -> None:
    """Save a password under the current Windows user's credential vault."""
    encoded = password.encode("utf-16-le")
    blob = ctypes.create_string_buffer(encoded, len(encoded))
    credential = CREDENTIAL(
        0, CRED_TYPE_GENERIC, CREDENTIAL_TARGET, None,
        wintypes.FILETIME(), len(encoded), ctypes.cast(blob, ctypes.POINTER(ctypes.c_byte)),
        CRED_PERSIST_LOCAL_MACHINE, 0, None, None, APP_NAME,
    )
    if not ADVAPI32.CredWriteW(ctypes.byref(credential), 0):
        raise ctypes.WinError(ctypes.get_last_error())


def load_password() -> str | None:
    credential_ptr = PCREDENTIAL()
    if not ADVAPI32.CredReadW(CREDENTIAL_TARGET, CRED_TYPE_GENERIC, 0, ctypes.byref(credential_ptr)):
        if ctypes.get_last_error() == 1168:  # ERROR_NOT_FOUND
            return None
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        credential = credential_ptr.contents
        raw = ctypes.string_at(credential.CredentialBlob, credential.CredentialBlobSize)
        return raw.decode("utf-16-le")
    finally:
        ADVAPI32.CredFree(credential_ptr)


def default_settings() -> dict:
    return {"username": "", "enabled": True}


def load_settings() -> dict:
    try:
        with SETTINGS_PATH.open("r", encoding="utf-8") as handle:
            stored = json.load(handle)
        # Version 1.0 stored this same choice as start_with_windows.
        enabled = stored.get("enabled", stored.get("start_with_windows", True))
        return {"username": str(stored.get("username", "")), "enabled": bool(enabled)}
    except (OSError, json.JSONDecodeError):
        return default_settings()


def write_settings(settings: dict) -> None:
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    clean = {"username": settings["username"], "enabled": settings["enabled"]}
    with SETTINGS_PATH.open("w", encoding="utf-8") as handle:
        json.dump(clean, handle, indent=2)


def write_json_atomic(path: Path, value: dict) -> None:
    """Write shared UI/background state without exposing partial JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, separators=(",", ":"))
    os.replace(temporary, path)


def read_json(path: Path) -> dict | None:
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
        return value if isinstance(value, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def make_status(
    state: str,
    heading: str,
    detail: str,
    *,
    ssid: str | None = None,
    active: bool = False,
    can_try_now: bool = False,
    next_retry_at: float | None = None,
) -> dict:
    return {
        "state": state,
        "heading": heading,
        "detail": detail,
        "ssid": ssid,
        "active": active,
        "can_try_now": can_try_now,
        "next_retry_at": next_retry_at,
        "updated_at": time.time(),
    }


def write_status(status: dict) -> None:
    try:
        write_json_atomic(STATUS_PATH, status)
    except OSError:
        # Status reporting must never stop the login engine.
        pass


def load_status() -> dict | None:
    return read_json(STATUS_PATH)


def is_vit_ssid(ssid: str | None) -> bool:
    """The requested case-sensitive VIT network rule."""
    return bool(ssid and "VIT" in ssid)


def signal_background_command() -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateEventW.argtypes = (
        ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR,
    )
    kernel32.CreateEventW.restype = wintypes.HANDLE
    kernel32.SetEvent.argtypes = (wintypes.HANDLE,)
    kernel32.SetEvent.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    event_handle = kernel32.CreateEventW(None, False, False, BACKGROUND_COMMAND_EVENT_NAME)
    if event_handle:
        try:
            kernel32.SetEvent(event_handle)
        finally:
            kernel32.CloseHandle(event_handle)


def send_background_command(command: str) -> None:
    payload = {
        "id": f"{time.time_ns()}-{os.getpid()}",
        "command": command,
        "created_at": time.time(),
    }
    write_json_atomic(COMMAND_PATH, payload)
    signal_background_command()


def startup_command() -> str:
    executable = Path(sys.executable if getattr(sys, "frozen", False) else __file__).resolve()
    if getattr(sys, "frozen", False):
        return f'"{executable}" --background'
    return f'"{sys.executable}" "{executable}" --background'


def set_startup(enabled: bool) -> None:
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
        if enabled:
            winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, startup_command())
        else:
            try:
                winreg.DeleteValue(key, APP_NAME)
            except FileNotFoundError:
                pass


def launch_background() -> None:
    """Start the automation now. A named mutex makes duplicate starts harmless."""
    if getattr(sys, "frozen", False):
        command = [sys.executable, "--background"]
    else:
        command = [sys.executable, str(Path(__file__).resolve()), "--background"]
    subprocess.Popen(command, creationflags=subprocess.CREATE_NO_WINDOW)


def connected_ssid() -> str | None:
    """Return the current WLAN SSID, or None when Windows reports no Wi-Fi."""
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"], capture_output=True,
            text=True, encoding="utf-8", errors="replace", check=False,
            # Prevent a console flash each time the GUI app checks Wi-Fi state.
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except OSError:
        return None
    for line in result.stdout.splitlines():
        match = re.match(r"\s*SSID\s*:\s*(.+?)\s*$", line, re.IGNORECASE)
        if match and not line.strip().upper().startswith("BSSID"):
            ssid = match.group(1).strip()
            return ssid or None
    return None


def has_routable_ipv4() -> bool:
    """Return whether Windows has assigned a usable IPv4 route yet.

    A UDP connect does not send data. It simply asks Windows which local
    address it would use, making it a quick way to avoid starting a portal
    request before DHCP has finished after a Wi-Fi connection event.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("1.1.1.1", 53))
            address = probe.getsockname()[0]
        return bool(address) and not address.startswith("169.254.") and address != "0.0.0.0"
    except OSError:
        return False


def wait_for_network_ready(expected_ssid: str, stop_event: threading.Event) -> bool:
    """Wait briefly for the just-connected Wi-Fi adapter to finish DHCP."""
    deadline = time.monotonic() + NETWORK_READY_TIMEOUT_SECONDS
    while not stop_event.is_set() and time.monotonic() < deadline:
        current_ssid = connected_ssid()
        if current_ssid != expected_ssid:
            return False
        if has_routable_ipv4():
            return True
        stop_event.wait(NETWORK_READY_INTERVAL_SECONDS)
    return connected_ssid() == expected_ssid and has_routable_ipv4()


class WifiConnectionNotifier:
    """Wake a monitor immediately when Windows connects or disconnects Wi-Fi.

    The Windows WLAN API is used only as a signal.  SSID and portal decisions
    remain in the monitor, so a missing WLAN API or a missed notification
    harmlessly falls back to periodic checks.
    """

    def __init__(self, wake_event: threading.Event, connection_event: threading.Event) -> None:
        self.wake_event = wake_event
        self.connection_event = connection_event
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.callback = WLAN_NOTIFICATION_CALLBACK(self._on_notification)

    def start(self) -> None:
        try:
            ctypes.WinDLL("wlanapi", use_last_error=True)
        except OSError:
            return
        self.thread = threading.Thread(target=self._listen, daemon=True, name="wlan-events")
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=1)

    def _on_notification(self, notification_ptr, _context) -> None:
        try:
            notification = notification_ptr.contents
            if not notification.NotificationSource & WLAN_NOTIFICATION_SOURCE_ACM:
                return
            if notification.NotificationCode in {
                WLAN_NOTIFICATION_ACM_CONNECTION_COMPLETE,
                WLAN_NOTIFICATION_ACM_INTERFACE_ARRIVAL,
            }:
                self.connection_event.set()
                self.wake_event.set()
            elif notification.NotificationCode == WLAN_NOTIFICATION_ACM_DISCONNECTED:
                self.wake_event.set()
        except (ValueError, OSError):
            # A callback can race with shutdown; the timer fallback still runs.
            pass

    def _listen(self) -> None:
        wlanapi = ctypes.WinDLL("wlanapi", use_last_error=True)
        wlanapi.WlanOpenHandle.argtypes = (
            wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.HANDLE),
        )
        wlanapi.WlanOpenHandle.restype = wintypes.DWORD
        wlanapi.WlanRegisterNotification.argtypes = (
            wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL,
            WLAN_NOTIFICATION_CALLBACK, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.POINTER(wintypes.DWORD),
        )
        wlanapi.WlanRegisterNotification.restype = wintypes.DWORD
        wlanapi.WlanCloseHandle.argtypes = (wintypes.HANDLE, ctypes.c_void_p)
        wlanapi.WlanCloseHandle.restype = wintypes.DWORD

        negotiated_version = wintypes.DWORD()
        client_handle = wintypes.HANDLE()
        if wlanapi.WlanOpenHandle(2, None, ctypes.byref(negotiated_version), ctypes.byref(client_handle)) != 0:
            return
        try:
            previous_source = wintypes.DWORD()
            result = wlanapi.WlanRegisterNotification(
                client_handle,
                WLAN_NOTIFICATION_SOURCE_ACM,
                True,
                self.callback,
                None,
                None,
                ctypes.byref(previous_source),
            )
            if result != 0:
                return
            self.stop_event.wait()
        finally:
            wlanapi.WlanCloseHandle(client_handle, None)


class BackgroundCommandNotifier:
    """Turn a named Windows event into an immediate monitor wake-up."""

    def __init__(self, wake_event: threading.Event) -> None:
        self.wake_event = wake_event
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        self.thread = threading.Thread(
            target=self._listen, daemon=True, name="background-commands"
        )
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=1)

    def _listen(self) -> None:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateEventW.argtypes = (
            ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR,
        )
        kernel32.CreateEventW.restype = wintypes.HANDLE
        kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        event_handle = kernel32.CreateEventW(
            None, False, False, BACKGROUND_COMMAND_EVENT_NAME
        )
        if not event_handle:
            return
        try:
            while not self.stop_event.is_set():
                if kernel32.WaitForSingleObject(event_handle, 500) == 0:
                    self.wake_event.set()
        finally:
            kernel32.CloseHandle(event_handle)


def internet_is_working() -> bool:
    """Confirm genuine internet access through any one of three HTTPS checks."""
    for url, expected_status, expected_text in CONNECTIVITY_CHECKS:
        try:
            request = Request(url, headers={"User-Agent": USER_AGENT})
            with urlopen(request, timeout=3) as response:
                body = response.read(256)
                if response.status == expected_status and expected_text in body:
                    return True
        except (HTTPError, URLError, TimeoutError, OSError):
            continue
    return False


class LoginFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.in_first_form = False
        self.found_form = False
        self.action = ""
        self.method = "POST"
        self.fields: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag.lower() == "form" and not self.found_form:
            self.in_first_form = True
            self.found_form = True
            self.action = values.get("action", "") or ""
            self.method = (values.get("method", "POST") or "POST").upper()
        elif tag.lower() == "input" and self.in_first_form:
            name = values.get("name")
            if name:
                self.fields[name] = values.get("value", "") or ""

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self.in_first_form:
            self.in_first_form = False


def get_portal_page(opener, probe_url: str) -> tuple[str, str]:
    """Fetch a login page, including Pronto's JavaScript-only redirect step."""
    headers = {"User-Agent": PORTAL_USER_AGENT}
    response = opener.open(Request(probe_url, headers=headers), timeout=12)
    page = response.read().decode(response.headers.get_content_charset() or "utf-8", "replace")
    source_url = response.geturl()

    # Pronto returns redirect.html?URI=..., whose JavaScript does this exact
    # next navigation: path.concat(document.location.search).
    path_match = re.search(r"\bvar\s+path\s*=\s*['\"]([^'\"]+)['\"]", page, re.IGNORECASE)
    if path_match and urlsplit(source_url).path.lower().endswith("/redirect.html"):
        destination = path_match.group(1)
        query = urlsplit(source_url).query
        target = f"{destination}{'&' if '?' in destination else '?'}{query}" if query else destination
        response = opener.open(Request(target, headers=headers), timeout=12)
        page = response.read().decode(response.headers.get_content_charset() or "utf-8", "replace")
        source_url = response.geturl()
    return page, source_url


def portal_login(
    username: str,
    password: str,
    probe_url: str = DEFAULT_PROBE_URL,
    progress=None,
    connection_is_valid=None,
) -> str:
    """Discover the campus captive form and submit the supplied credentials."""
    if not username or not password:
        raise ValueError("Campus username or password is missing.")
    opener = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
    if progress:
        progress("detecting_portal")
    try:
        page, source_url = get_portal_page(opener, probe_url)
    except (HTTPError, URLError, TimeoutError, OSError) as error:
        raise RuntimeError(f"Could not reach the captive portal: {error}") from error

    parser = LoginFormParser()
    parser.feed(page)
    if not parser.found_form or not parser.action:
        return "No captive login form found."
    if parser.method != "POST":
        raise RuntimeError("The captive portal form is not a POST form.")
    if connection_is_valid and not connection_is_valid():
        raise RuntimeError("Wi-Fi changed before credentials were submitted.")

    fields = parser.fields
    fields["userId"] = username
    fields["password"] = password
    fields.setdefault("serviceName", "ProntoAuthentication")
    body = urlencode(fields).encode("utf-8")
    target = urljoin(source_url, parser.action)
    if progress:
        progress("submitting_credentials")
    try:
        response = opener.open(Request(target, data=body, method="POST", headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": PORTAL_USER_AGENT,
        }), timeout=15)
        response.read()
    except (HTTPError, URLError, TimeoutError, OSError) as error:
        raise RuntimeError(f"The portal did not accept the login request: {error}") from error
    return "Login request submitted."


class Monitor:
    """The single background state machine for VIT portal automation."""

    def __init__(self, report) -> None:
        self.report = report
        self.stop_event = threading.Event()
        self.wake_event = threading.Event()
        self.connection_event = threading.Event()
        self.last_ssid: str | None = None
        self.next_retry_at = 0.0
        self.next_retry_wall = 0.0
        self.retry_delay = RETRY_INITIAL_SECONDS
        self.retry_reason = ""
        self.pending_connection_checks = 0
        self.last_command_id: str | None = None
        self.attempt_lock = threading.Lock()

    def start(self) -> None:
        threading.Thread(target=self._run, daemon=True, name="wifi-monitor").start()

    def _publish(self, status: dict) -> None:
        self.report(status)

    def _run(self) -> None:
        wifi_notifier = WifiConnectionNotifier(self.wake_event, self.connection_event)
        command_notifier = BackgroundCommandNotifier(self.wake_event)
        wifi_notifier.start()
        command_notifier.start()
        # Covers helper startup and Windows resume even without a fresh event.
        self.connection_event.set()
        self.wake_event.set()
        try:
            while not self.stop_event.is_set():
                if self.wake_event.is_set():
                    self.wake_event.clear()
                connection_event = self.connection_event.is_set()
                if connection_event:
                    self.connection_event.clear()
                command = self._consume_command()
                self._check_connection(
                    connection_event=connection_event,
                    force_attempt=command == "try_now",
                )
                self._wait_for_next_check()
        finally:
            command_notifier.stop()
            wifi_notifier.stop()

    def _consume_command(self) -> str | None:
        command = read_json(COMMAND_PATH)
        if not command:
            return None
        command_id = str(command.get("id", ""))
        if not command_id or command_id == self.last_command_id:
            return None
        self.last_command_id = command_id
        try:
            age = time.time() - float(command.get("created_at", 0))
        except (TypeError, ValueError):
            return None
        if age < 0 or age > COMMAND_MAX_AGE_SECONDS:
            return None
        value = command.get("command")
        return value if value in {"refresh", "try_now"} else None

    def _wait_for_next_check(self) -> None:
        timeout = BACKGROUND_FALLBACK_SECONDS
        if self.pending_connection_checks:
            timeout = min(timeout, NETWORK_READY_INTERVAL_SECONDS)
        if self.next_retry_at:
            timeout = min(timeout, max(0, self.next_retry_at - time.monotonic()))
        deadline = time.monotonic() + timeout
        while not self.stop_event.is_set() and not self.wake_event.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            self.wake_event.wait(min(0.5, remaining))

    def _check_connection(self, connection_event: bool, force_attempt: bool) -> None:
        if connection_event:
            self.pending_connection_checks = int(
                NETWORK_READY_TIMEOUT_SECONDS / NETWORK_READY_INTERVAL_SECONDS
            )
        settings = load_settings()
        if not settings["enabled"]:
            self._reset_connection_state()
            self._publish(make_status(
                "disabled",
                "Automation is disabled",
                "Enable automation whenever you want automatic VIT login.",
            ))
            return

        ssid = connected_ssid()
        if not ssid:
            if self.pending_connection_checks:
                self.pending_connection_checks -= 1
                self._publish(make_status(
                    "checking_wifi",
                    "Checking the Wi-Fi connection",
                    "Waiting for Windows to finish connecting.",
                    active=True,
                ))
                return
            self._reset_connection_state()
            self._publish(make_status(
                "waiting_wifi",
                "Waiting for VIT Wi-Fi",
                "Connect through Windows to a Wi-Fi network containing VIT.",
            ))
            return

        if not is_vit_ssid(ssid):
            self._reset_connection_state()
            self._publish(make_status(
                "waiting_wifi",
                "Waiting for VIT Wi-Fi",
                f"Connected to {ssid}. Waiting for a network containing VIT.",
                ssid=ssid,
            ))
            return

        is_new_vit_connection = (
            connection_event or self.pending_connection_checks > 0 or ssid != self.last_ssid
        )
        self.pending_connection_checks = 0
        self.last_ssid = ssid

        if force_attempt and not is_new_vit_connection:
            self._publish(make_status(
                "verifying_internet",
                "Checking internet access",
                "Confirming whether a portal login is needed.",
                ssid=ssid,
                active=True,
            ))
            if internet_is_working():
                self._mark_online(ssid)
                return

        if is_new_vit_connection or force_attempt:
            self._clear_retry()
            self._publish(make_status(
                "preparing_network",
                "Preparing the connection",
                f"Waiting for {ssid} to receive a network address.",
                ssid=ssid,
                active=True,
            ))
            if not wait_for_network_ready(ssid, self.stop_event):
                if self.stop_event.is_set():
                    return
                if connected_ssid() != ssid:
                    self.wake_event.set()
                    return
                self._schedule_retry(
                    ssid, "The network address is not ready yet."
                )
                return
            self._attempt_portal_login(ssid, settings)
            return

        if internet_is_working():
            self._mark_online(ssid)
            return

        if not self.next_retry_at or time.monotonic() >= self.next_retry_at:
            self._attempt_portal_login(ssid, settings)
        else:
            self._publish_retry_status(ssid)

    def _connection_is_valid(self, ssid: str) -> bool:
        settings = load_settings()
        return (
            settings["enabled"]
            and connected_ssid() == ssid
            and is_vit_ssid(ssid)
        )

    def _attempt_portal_login(self, ssid: str, settings: dict) -> None:
        if not self.attempt_lock.acquire(blocking=False):
            return
        try:
            username = settings["username"].strip()
            password = load_password() or ""
            if not username or not password:
                self._clear_retry()
                self._publish(make_status(
                    "verifying_internet",
                    "Checking internet access",
                    "Confirming whether a portal login is needed.",
                    ssid=ssid,
                    active=True,
                ))
                if internet_is_working():
                    self._mark_online(ssid)
                else:
                    self._publish(make_status(
                        "credentials_required",
                        "Save your campus credentials",
                        "Enter your username and password below to start automatic login.",
                        ssid=ssid,
                    ))
                return

            def progress(stage: str) -> None:
                if stage == "detecting_portal":
                    status = make_status(
                        "detecting_portal",
                        "Detecting the login portal",
                        "Looking for the VIT captive-portal form.",
                        ssid=ssid,
                        active=True,
                    )
                else:
                    status = make_status(
                        "submitting_credentials",
                        "Signing in to VIT Wi-Fi",
                        "Securely submitting your saved credentials.",
                        ssid=ssid,
                        active=True,
                    )
                self._publish(status)

            try:
                answer = portal_login(
                    username,
                    password,
                    progress=progress,
                    connection_is_valid=lambda: self._connection_is_valid(ssid),
                )
                if not self._connection_is_valid(ssid):
                    self.wake_event.set()
                    return

                self._publish(make_status(
                    "verifying_internet",
                    "Verifying internet access",
                    "Checking that the VIT login completed successfully.",
                    ssid=ssid,
                    active=True,
                ))
                if answer != "No captive login form found.":
                    self.stop_event.wait(POST_LOGIN_SETTLE_SECONDS)
                if not self._connection_is_valid(ssid):
                    self.wake_event.set()
                    return
                if internet_is_working():
                    self._mark_online(ssid)
                elif answer == "No captive login form found.":
                    self._schedule_retry(
                        ssid, "No login form was found and internet is still unavailable."
                    )
                else:
                    self._schedule_retry(
                        ssid, "The login was submitted, but internet is still unavailable."
                    )
            except (RuntimeError, ValueError) as error:
                if not self._connection_is_valid(ssid):
                    self.wake_event.set()
                    return
                self._schedule_retry(ssid, str(error))
        finally:
            self.attempt_lock.release()

    def _mark_online(self, ssid: str) -> None:
        self._clear_retry()
        self._publish(make_status(
            "online",
            "VIT Wi-Fi is online",
            "Internet is working. You can safely close this window.",
            ssid=ssid,
        ))

    def _schedule_retry(self, ssid: str, reason: str) -> None:
        if not self._connection_is_valid(ssid):
            self.wake_event.set()
            return
        delay = self.retry_delay
        self.next_retry_at = time.monotonic() + delay
        self.next_retry_wall = time.time() + delay
        self.retry_reason = reason
        self.retry_delay = min(self.retry_delay * 2, RETRY_MAX_SECONDS)
        self._publish_retry_status(ssid)

    def _publish_retry_status(self, ssid: str) -> None:
        self._publish(make_status(
            "retry_wait",
            "VIT Wi-Fi needs another try",
            self.retry_reason or "Internet is unavailable.",
            ssid=ssid,
            can_try_now=True,
            next_retry_at=self.next_retry_wall or None,
        ))

    def _clear_retry(self) -> None:
        self.next_retry_at = 0.0
        self.next_retry_wall = 0.0
        self.retry_delay = RETRY_INITIAL_SECONDS
        self.retry_reason = ""

    def _reset_connection_state(self) -> None:
        self.last_ssid = None
        self.pending_connection_checks = 0
        self._clear_retry()


class SettingsWindow:
    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title(APP_NAME)
        self.root.resizable(False, False)
        self.root.configure(bg="#f5f7fb")
        self.settings = load_settings()
        self.password_visible = False
        self.progress_running = False
        self.progress_after_id: str | None = None
        self.progress_position = -80
        self._build_ui()
        if self.settings["enabled"]:
            self._show_starting("Checking the current Wi-Fi connection.")
            try:
                launch_background()
                send_background_command("refresh")
            except OSError as error:
                self._show_error(f"Could not start automation: {error}")
        else:
            self._show_disabled()
        self.root.after(UI_STATUS_REFRESH_MS, self._poll_background_status)
        self.root.protocol("WM_DELETE_WINDOW", self.quit)

    def _build_ui(self) -> None:
        card = tk.Frame(self.root, bg="white", padx=28, pady=24)
        card.grid(padx=20, pady=20)
        tk.Label(
            card, text="VIT Wi-Fi", font=("Segoe UI", 20, "bold"),
            bg="white", fg="#172033",
        ).grid(column=0, row=0, columnspan=2, sticky="w")
        tk.Label(
            card, text="Automatic campus Wi-Fi login", font=("Segoe UI", 10),
            bg="white", fg="#64748b",
        ).grid(column=0, row=1, columnspan=2, sticky="w", pady=(0, 18))

        status_box = tk.Frame(
            card, bg="#f8fafc", padx=14, pady=13,
            highlightbackground="#e2e8f0", highlightthickness=1,
        )
        status_box.grid(column=0, row=2, columnspan=2, sticky="ew", pady=(0, 20))
        status_box.grid_columnconfigure(1, weight=1)
        self.status_dot = tk.Canvas(status_box, width=18, height=18, bg="#f8fafc", highlightthickness=0)
        self.status_dot.grid(column=0, row=0, rowspan=2, padx=(0, 10), sticky="n")
        self.dot_id = self.status_dot.create_oval(2, 2, 16, 16, fill="#64748b", outline="")
        self.status_heading = tk.Label(
            status_box, text="Starting automation", font=("Segoe UI", 11, "bold"),
            bg="#f8fafc", fg="#172033",
        )
        self.status_heading.grid(column=1, row=0, sticky="w")
        self.network_label = tk.Label(
            status_box, text="Network: checking...", font=("Segoe UI", 8),
            bg="#f8fafc", fg="#64748b",
        )
        self.network_label.grid(column=1, row=1, sticky="w", pady=(2, 0))
        self.status_detail = tk.Label(
            status_box, text="", font=("Segoe UI", 9), bg="#f8fafc",
            fg="#475569", wraplength=410, justify="left",
        )
        self.status_detail.grid(column=0, row=2, columnspan=2, sticky="w", pady=(8, 0))
        self.progress = tk.Canvas(
            status_box, width=420, height=7, bg="#dbeafe",
            highlightthickness=0,
        )
        self.progress_segment = self.progress.create_rectangle(
            -80, 0, 0, 7, fill="#2563eb", outline="",
        )
        self.progress.grid(column=0, row=3, columnspan=2, sticky="ew", pady=(10, 0))
        self.progress.grid_remove()
        self.retry_label = tk.Label(
            status_box, text="", font=("Segoe UI", 9, "bold"),
            bg="#f8fafc", fg="#b45309",
        )
        self.retry_label.grid(column=0, row=4, columnspan=2, sticky="w", pady=(8, 0))
        self.retry_label.grid_remove()
        self.try_button = ttk.Button(
            status_box, text="Try now", command=self.try_now,
        )
        self.try_button.grid(column=0, row=5, columnspan=2, sticky="w", pady=(10, 0))
        self.try_button.grid_remove()

        tk.Label(
            card, text="Campus username", font=("Segoe UI", 10, "bold"),
            bg="white", fg="#334155",
        ).grid(column=0, row=3, columnspan=2, sticky="w")
        self.username = tk.StringVar(value=self.settings["username"])
        ttk.Entry(card, textvariable=self.username, width=48).grid(column=0, row=4, columnspan=2, sticky="ew", pady=(5, 14))

        tk.Label(
            card, text="Password", font=("Segoe UI", 10, "bold"),
            bg="white", fg="#334155",
        ).grid(column=0, row=5, columnspan=2, sticky="w")
        self.password = tk.StringVar(value=load_password() or "")
        self.password_entry = ttk.Entry(card, textvariable=self.password, width=42, show="\u2022")
        self.password_entry.grid(column=0, row=6, sticky="ew", pady=(5, 4))
        self.eye_button = ttk.Button(card, text="\U0001F441", width=3, command=self.toggle_password)
        self.eye_button.grid(column=1, row=6, sticky="e", pady=(5, 4))
        tk.Label(
            card, text="Stored securely in Windows Credential Manager.",
            font=("Segoe UI", 9), bg="white", fg="#64748b",
        ).grid(column=0, row=7, columnspan=2, sticky="w", pady=(0, 18))

        actions = tk.Frame(card, bg="white")
        actions.grid(column=0, row=8, columnspan=2, sticky="ew")
        ttk.Button(actions, text="Save credentials", command=self.save_credentials).pack(side="left")
        self.toggle_button = ttk.Button(actions, command=self.toggle_automation)
        self.toggle_button.pack(side="right")
        self.update_toggle_button()

    def _poll_background_status(self) -> None:
        try:
            self.settings = load_settings()
            self.update_toggle_button()
            if not self.settings["enabled"]:
                self._show_disabled()
            else:
                status = load_status()
                if status and status.get("state"):
                    self._render_status(status)
            self.root.after(UI_STATUS_REFRESH_MS, self._poll_background_status)
        except tk.TclError:
            pass

    def _render_status(self, status: dict) -> None:
        state = str(status.get("state", "error"))
        colour = {
            "online": "#16a34a",
            "retry_wait": "#d97706",
            "credentials_required": "#d97706",
            "error": "#dc2626",
            "disabled": "#64748b",
            "waiting_wifi": "#64748b",
        }.get(state, "#2563eb")
        self.status_dot.itemconfigure(self.dot_id, fill=colour)
        self.status_heading.configure(text=str(status.get("heading", "Checking connection")))
        self.status_detail.configure(text=str(status.get("detail", "")))
        ssid = status.get("ssid")
        self.network_label.configure(text=f"Network: {ssid}" if ssid else "Network: not connected")

        active = bool(status.get("active"))
        if active and not self.progress_running:
            self.progress.grid()
            self.progress_running = True
            self.progress_position = -80
            self._animate_progress()
        elif not active and self.progress_running:
            self._stop_progress()

        retry_at = status.get("next_retry_at")
        if retry_at:
            try:
                remaining = max(0, int(float(retry_at) - time.time() + 0.999))
            except (TypeError, ValueError):
                remaining = 0
            minutes, seconds = divmod(remaining, 60)
            text = (
                "Retrying now..."
                if remaining == 0
                else f"Automatic retry in {minutes:02d}:{seconds:02d}"
            )
            self.retry_label.configure(text=text)
            self.retry_label.grid()
        else:
            self.retry_label.grid_remove()

        if status.get("can_try_now") and self.settings["enabled"]:
            self.try_button.configure(state="normal")
            self.try_button.grid()
        else:
            self.try_button.configure(state="disabled")
            self.try_button.grid_remove()

    def _show_starting(self, detail: str) -> None:
        status = make_status(
            "checking_wifi", "Starting the connection check", detail, active=True
        )
        write_status(status)
        self._render_status(status)

    def _show_disabled(self, detail: str | None = None) -> None:
        status = make_status(
            "disabled",
            "Automation is disabled",
            detail or "Enable automation whenever you want automatic VIT login.",
        )
        self._render_status(status)

    def _show_error(self, detail: str) -> None:
        status = make_status("error", "Action needed", detail)
        write_status(status)
        self._render_status(status)

    def _animate_progress(self) -> None:
        if not self.progress_running:
            return
        width = max(420, self.progress.winfo_width())
        segment_width = max(70, width // 4)
        self.progress.coords(
            self.progress_segment,
            self.progress_position,
            0,
            self.progress_position + segment_width,
            7,
        )
        self.progress_position += max(8, width // 40)
        if self.progress_position > width:
            self.progress_position = -segment_width
        self.progress_after_id = self.root.after(35, self._animate_progress)

    def _stop_progress(self) -> None:
        self.progress_running = False
        if self.progress_after_id is not None:
            try:
                self.root.after_cancel(self.progress_after_id)
            except tk.TclError:
                pass
            self.progress_after_id = None
        self.progress.grid_remove()

    def toggle_password(self) -> None:
        self.password_visible = not self.password_visible
        self.password_entry.configure(show="" if self.password_visible else "\u2022")
        self.eye_button.configure(text="\u25C9" if self.password_visible else "\U0001F441")

    def _store_credentials(self, require_complete: bool = True) -> bool:
        username = self.username.get().strip()
        password = self.password.get()
        if require_complete and not username:
            self._show_error("Enter your campus username.")
            return False
        if require_complete and not password:
            self._show_error("Enter your campus password.")
            return False
        try:
            save_password(password)
            self.settings["username"] = username
            write_settings(self.settings)
        except OSError as error:
            self._show_error(f"Could not save credentials: {error}")
            return False
        return True

    def save_credentials(self, require_complete: bool = True) -> bool:
        if not self._store_credentials(require_complete=require_complete):
            return False
        if not self.settings["enabled"]:
            self._show_disabled(
                "Credentials saved. Enable automation when you want to connect."
            )
            return True
        self._show_starting("Credentials saved. Starting the connection process.")
        try:
            launch_background()
            send_background_command("try_now")
        except OSError as error:
            self._show_error(f"Credentials were saved, but automation could not start: {error}")
            return False
        return True

    def try_now(self) -> None:
        if not self.settings["enabled"]:
            self._show_disabled()
            return
        self._show_starting("Manual retry requested. Checking VIT Wi-Fi now.")
        self.try_button.configure(state="disabled")
        try:
            launch_background()
            send_background_command("try_now")
        except OSError as error:
            self._show_error(f"Could not start the retry: {error}")

    def toggle_automation(self) -> None:
        if self.settings["enabled"]:
            self.settings["enabled"] = False
            try:
                write_settings(self.settings)
                set_startup(False)
                send_background_command("refresh")
            except OSError as error:
                self._show_error(f"Could not disable automation: {error}")
                return
            self.update_toggle_button()
            disabled = make_status(
                "disabled",
                "Automation is disabled",
                "Automatic checks and portal logins have stopped.",
            )
            write_status(disabled)
            self._render_status(disabled)
            return
        if not self._store_credentials(require_complete=True):
            return
        self.settings["enabled"] = True
        try:
            write_settings(self.settings)
            set_startup(True)
            launch_background()
            self._show_starting("Automation enabled. Checking VIT Wi-Fi now.")
            send_background_command("try_now")
        except OSError as error:
            self._show_error(f"Could not enable automation: {error}")
            return
        self.update_toggle_button()

    def update_toggle_button(self) -> None:
        text = "Disable automation" if self.settings["enabled"] else "Enable automation"
        self.toggle_button.configure(text=text)

    def quit(self) -> None:
        if self.progress_running:
            self._stop_progress()
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()


def acquire_background_mutex():
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.argtypes = (ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR)
    kernel32.CreateMutexW.restype = wintypes.HANDLE
    handle = kernel32.CreateMutexW(None, True, BACKGROUND_MUTEX_NAME)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    if ctypes.get_last_error() == 183:  # ERROR_ALREADY_EXISTS
        kernel32.CloseHandle(handle)
        return None
    return handle


def run_background() -> None:
    """Run the single, UI-free automation process for the signed-in user."""
    if not load_settings()["enabled"]:
        return
    mutex = acquire_background_mutex()
    if mutex is None:
        return
    monitor = Monitor(write_status)
    monitor.start()
    try:
        while not monitor.stop_event.wait(1):
            if not load_settings()["enabled"]:
                monitor.stop_event.set()
                return
    finally:
        ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(mutex)


def main() -> None:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--background", action="store_true")
    args = parser.parse_args()
    if args.background:
        run_background()
    else:
        SettingsWindow().run()


if __name__ == "__main__":
    main()
