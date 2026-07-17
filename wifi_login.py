"""Automatic captive-portal login for VIT Wi-Fi on Windows.

Credentials stay in Windows Credential Manager. The program only attempts a
login after Windows reports that the current Wi-Fi SSID ends in ``-VIT``.
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
from tkinter import messagebox, ttk
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlsplit
from urllib.request import HTTPCookieProcessor, Request, build_opener, urlopen
import winreg


APP_NAME = "Automate VIT WiFi"
CREDENTIAL_TARGET = "AutomateVitWifi:portal-password"
DEFAULT_PROBE_URL = "http://neverssl.com/"
CONNECTIVITY_CHECKS = (
    ("https://www.google.com/generate_204", 204, b""),
    ("https://www.msftconnecttest.com/connecttest.txt", 200, b"Microsoft Connect Test"),
    ("https://cloudflare.com/cdn-cgi/trace", 200, b"fl="),
)
BACKGROUND_MUTEX_NAME = r"Local\AutomateVitWifiBackground"
# Windows raises a WLAN notification as soon as it finishes connecting.  These
# timers are only fallbacks for missed notifications and portal retry recovery.
BACKGROUND_FALLBACK_SECONDS = 60
STATUS_POLL_SECONDS = 20
RETRY_INITIAL_SECONDS = 15
RETRY_MAX_SECONDS = 60
NETWORK_READY_TIMEOUT_SECONDS = 5
NETWORK_READY_INTERVAL_SECONDS = 0.25
POST_LOGIN_SETTLE_SECONDS = 1
SETTINGS_PATH = Path(os.environ.get("APPDATA", Path.home())) / APP_NAME / "settings.json"

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


def internet_is_working() -> bool:
    """Confirm genuine internet access through any one of three HTTPS checks."""
    for url, expected_status, expected_text in CONNECTIVITY_CHECKS:
        try:
            request = Request(url, headers={"User-Agent": "AutomateVitWifi/1.4"})
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
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AutomateVitWifi/1.4"}
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


def portal_login(username: str, password: str, probe_url: str = DEFAULT_PROBE_URL) -> str:
    """Discover the campus captive form and submit the supplied credentials."""
    if not username or not password:
        raise ValueError("Campus username or password is missing.")
    opener = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
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

    fields = parser.fields
    fields["userId"] = username
    fields["password"] = password
    fields.setdefault("serviceName", "ProntoAuthentication")
    body = urlencode(fields).encode("utf-8")
    target = urljoin(source_url, parser.action)
    try:
        response = opener.open(Request(target, data=body, method="POST", headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AutomateVitWifi/1.4",
        }), timeout=15)
        response.read()
    except (HTTPError, URLError, TimeoutError, OSError) as error:
        raise RuntimeError(f"The portal did not accept the login request: {error}") from error
    return "Login request submitted."


class Monitor:
    """Reports VIT state and authenticates immediately after WLAN events."""

    def __init__(self, report, automate: bool) -> None:
        self.report = report
        self.automate = automate
        self.stop_event = threading.Event()
        self.wake_event = threading.Event()
        self.connection_event = threading.Event()
        self.last_ssid: str | None = None
        self.next_retry_at = 0.0
        self.retry_delay = RETRY_INITIAL_SECONDS
        self.pending_connection_checks = 0

    def start(self) -> None:
        threading.Thread(target=self._run, daemon=True, name="wifi-monitor").start()

    def _run(self) -> None:
        notifier = WifiConnectionNotifier(self.wake_event, self.connection_event)
        notifier.start()
        # Covers app startup and Windows resume even if there is no new event.
        self.connection_event.set()
        self.wake_event.set()
        try:
            while not self.stop_event.is_set():
                if self.wake_event.is_set():
                    self.wake_event.clear()
                connection_event = self.connection_event.is_set()
                if connection_event:
                    self.connection_event.clear()
                self._check_connection(connection_event)
                self._wait_for_next_check()
        finally:
            notifier.stop()

    def _wait_for_next_check(self) -> None:
        timeout = STATUS_POLL_SECONDS if not self.automate else BACKGROUND_FALLBACK_SECONDS
        if self.pending_connection_checks:
            timeout = min(timeout, NETWORK_READY_INTERVAL_SECONDS)
        if self.automate and self.next_retry_at:
            timeout = min(timeout, max(0, self.next_retry_at - time.monotonic()))
        deadline = time.monotonic() + timeout
        while not self.stop_event.is_set() and not self.wake_event.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            self.wake_event.wait(min(0.5, remaining))

    def _check_connection(self, connection_event: bool) -> None:
        if connection_event:
            self.pending_connection_checks = int(
                NETWORK_READY_TIMEOUT_SECONDS / NETWORK_READY_INTERVAL_SECONDS
            )
        settings = load_settings()
        if not settings["enabled"]:
            self._reset_connection_state()
            self.report("red", "Automation is disabled.")
            return

        ssid = connected_ssid()
        if not ssid or not ssid.upper().endswith("-VIT"):
            if self.pending_connection_checks:
                self.pending_connection_checks -= 1
                self.report("red", "Checking the Wi-Fi connection...")
                return
            self._reset_connection_state()
            self.report("red", "Not connected to VIT Wi-Fi.")
            return

        is_new_vit_connection = (
            connection_event or self.pending_connection_checks > 0 or ssid != self.last_ssid
        )
        self.pending_connection_checks = 0
        self.last_ssid = ssid
        if is_new_vit_connection:
            self.retry_delay = RETRY_INITIAL_SECONDS
            self.next_retry_at = 0.0
            if not wait_for_network_ready(ssid, self.stop_event):
                if not self.stop_event.is_set():
                    self.report("red", f"{ssid} is connected; waiting for the network address...")
                    self._schedule_retry()
                return
            if self.automate:
                # Go straight to the normal HTTP portal flow.  This is faster
                # than waiting for several HTTPS checks to time out, and it
                # cannot submit credentials unless the real portal form exists.
                self._attempt_portal_login(ssid, settings)
            else:
                self._report_connectivity(ssid)
            return

        if internet_is_working():
            self._mark_online(ssid)
            return

        if self.automate and (
            not self.next_retry_at or time.monotonic() >= self.next_retry_at
        ):
            self._attempt_portal_login(ssid, settings)
        else:
            self.report("red", f"{ssid} is connected, but internet is unavailable.")

    def _attempt_portal_login(self, ssid: str, settings: dict) -> None:
        self.report("red", f"{ssid} is connected; signing in...")
        try:
            answer = portal_login(settings["username"], load_password() or "")
            if answer == "No captive login form found.":
                # The direct HTTP probe is normal when a valid session already
                # exists.  Check HTTPS before deciding it needs attention.
                if internet_is_working():
                    self._mark_online(ssid)
                else:
                    self.report("red", f"{ssid} is connected, but internet is unavailable.")
                    self._schedule_retry()
                return
            self.stop_event.wait(POST_LOGIN_SETTLE_SECONDS)
            if internet_is_working():
                self._mark_online(ssid)
            else:
                self.report("red", f"{ssid}: {answer}")
                self._schedule_retry()
        except (RuntimeError, ValueError) as error:
            self.report("red", f"{ssid}: {error}")
            self._schedule_retry()

    def _report_connectivity(self, ssid: str) -> None:
        if internet_is_working():
            self._mark_online(ssid)
        else:
            self.report("red", f"{ssid} is connected, but internet is unavailable.")

    def _mark_online(self, ssid: str) -> None:
        self.next_retry_at = 0.0
        self.retry_delay = RETRY_INITIAL_SECONDS
        self.report("green", f"{ssid} is connected and internet is working.")

    def _schedule_retry(self) -> None:
        self.next_retry_at = time.monotonic() + self.retry_delay
        self.retry_delay = min(self.retry_delay * 2, RETRY_MAX_SECONDS)

    def _reset_connection_state(self) -> None:
        self.last_ssid = None
        self.next_retry_at = 0.0
        self.retry_delay = RETRY_INITIAL_SECONDS
        self.pending_connection_checks = 0


class SettingsWindow:
    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title(APP_NAME)
        self.root.resizable(False, False)
        self.root.configure(bg="#f5f7fb")
        self.settings = load_settings()
        self.password_visible = False
        self._build_ui()
        # The visible window only reports status. The background process alone
        # performs automatic portal submission.
        self.monitor = Monitor(self.set_status, automate=False)
        self.monitor.start()
        self.root.protocol("WM_DELETE_WINDOW", self.quit)

    def _build_ui(self) -> None:
        card = tk.Frame(self.root, bg="white", padx=28, pady=25)
        card.grid(padx=20, pady=20)
        tk.Label(card, text="VIT Wi-Fi", font=("Segoe UI", 20, "bold"), bg="white", fg="#172033").grid(column=0, row=0, columnspan=2, sticky="w")
        tk.Label(card, text="Automatic campus Wi-Fi login", font=("Segoe UI", 10), bg="white", fg="#64748b").grid(column=0, row=1, columnspan=2, sticky="w", pady=(0, 18))

        status_box = tk.Frame(card, bg="#f8fafc", padx=14, pady=12, highlightbackground="#e2e8f0", highlightthickness=1)
        status_box.grid(column=0, row=2, columnspan=2, sticky="ew", pady=(0, 20))
        self.status_dot = tk.Canvas(status_box, width=18, height=18, bg="#f8fafc", highlightthickness=0)
        self.status_dot.grid(column=0, row=0, rowspan=2, padx=(0, 10))
        self.dot_id = self.status_dot.create_oval(2, 2, 16, 16, fill="#dc2626", outline="")
        self.status_heading = tk.Label(status_box, text="Checking connection...", font=("Segoe UI", 11, "bold"), bg="#f8fafc", fg="#172033")
        self.status_heading.grid(column=1, row=0, sticky="w")
        self.status_detail = tk.Label(status_box, text="", font=("Segoe UI", 9), bg="#f8fafc", fg="#64748b", wraplength=390, justify="left")
        self.status_detail.grid(column=1, row=1, sticky="w", pady=(2, 0))

        tk.Label(card, text="Campus username", font=("Segoe UI", 10, "bold"), bg="white", fg="#334155").grid(column=0, row=3, columnspan=2, sticky="w")
        self.username = tk.StringVar(value=self.settings["username"])
        ttk.Entry(card, textvariable=self.username, width=48).grid(column=0, row=4, columnspan=2, sticky="ew", pady=(5, 14))

        tk.Label(card, text="Password", font=("Segoe UI", 10, "bold"), bg="white", fg="#334155").grid(column=0, row=5, columnspan=2, sticky="w")
        self.password = tk.StringVar(value=load_password() or "")
        self.password_entry = ttk.Entry(card, textvariable=self.password, width=42, show="\u2022")
        self.password_entry.grid(column=0, row=6, sticky="ew", pady=(5, 4))
        self.eye_button = ttk.Button(card, text="\U0001F441", width=3, command=self.toggle_password)
        self.eye_button.grid(column=1, row=6, sticky="e", pady=(5, 4))
        tk.Label(card, text="Stored securely in Windows Credential Manager.", font=("Segoe UI", 9), bg="white", fg="#64748b").grid(column=0, row=7, columnspan=2, sticky="w", pady=(0, 18))

        actions = tk.Frame(card, bg="white")
        actions.grid(column=0, row=8, columnspan=2, sticky="ew")
        ttk.Button(actions, text="Save credentials", command=self.save_credentials).pack(side="left")
        self.toggle_button = ttk.Button(actions, command=self.toggle_automation)
        self.toggle_button.pack(side="right")
        self.update_toggle_button()

    def set_status(self, colour: str, detail: str) -> None:
        def update() -> None:
            try:
                active = colour == "green"
                self.status_dot.itemconfigure(self.dot_id, fill="#16a34a" if active else "#dc2626")
                self.status_heading.configure(text="VIT Wi-Fi is online" if active else "VIT Wi-Fi needs attention")
                self.status_detail.configure(text=detail)
            except tk.TclError:
                pass
        try:
            self.root.after(0, update)
        except tk.TclError:
            pass

    def toggle_password(self) -> None:
        self.password_visible = not self.password_visible
        self.password_entry.configure(show="" if self.password_visible else "\u2022")
        self.eye_button.configure(text="\u25C9" if self.password_visible else "\U0001F441")

    def save_credentials(self, require_complete: bool = True) -> bool:
        username = self.username.get().strip()
        password = self.password.get()
        if require_complete and not username:
            messagebox.showerror(APP_NAME, "Enter your campus username.")
            return False
        if require_complete and not password:
            messagebox.showerror(APP_NAME, "Enter your campus password.")
            return False
        try:
            save_password(password)
            self.settings["username"] = username
            write_settings(self.settings)
        except OSError as error:
            messagebox.showerror(APP_NAME, f"Could not save credentials: {error}")
            return False
        self.status_detail.configure(text="Credentials saved securely on this Windows account.")
        return True

    def toggle_automation(self) -> None:
        if self.settings["enabled"]:
            self.settings["enabled"] = False
            try:
                write_settings(self.settings)
                set_startup(False)
            except OSError as error:
                messagebox.showerror(APP_NAME, f"Could not disable automation: {error}")
                return
            self.update_toggle_button()
            self.set_status("red", "Automation is disabled. It will not start or submit credentials.")
            return
        if not self.save_credentials(require_complete=True):
            return
        self.settings["enabled"] = True
        try:
            write_settings(self.settings)
            set_startup(True)
            launch_background()
        except OSError as error:
            messagebox.showerror(APP_NAME, f"Could not enable automation: {error}")
            return
        self.update_toggle_button()
        self.set_status("red", "Automation enabled. Checking the VIT Wi-Fi connection...")

    def update_toggle_button(self) -> None:
        text = "Disable automation" if self.settings["enabled"] else "Enable automation"
        self.toggle_button.configure(text=text)

    def quit(self) -> None:
        self.monitor.stop_event.set()
        if self.settings["enabled"]:
            launch_background()
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
    monitor = Monitor(lambda _colour, _detail: None, automate=True)
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
