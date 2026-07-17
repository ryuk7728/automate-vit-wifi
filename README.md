# Automate VIT WiFi

Automatically completes the VIT captive-portal login after Windows connects to
a Wi-Fi network whose name ends in `-VIT`.

## Download and use

1. Open this repository's **Releases** page and download
   `Automate-VIT-WiFi-Setup.exe` from the latest release.
2. Run the installer.
3. Open **Automate VIT WiFi** from the Start Menu.
4. Enter your campus username and password, then select **Save credentials**.

That is all. Automation is enabled by default and starts in the background
when you sign in to Windows.

### Status and controls

- **Green** — connected to a `*-VIT` network and the internet check succeeded.
- **Red** — not on VIT Wi-Fi, internet is unavailable, or automation is off.
- **Disable automation** — stops the background helper, Wi-Fi checks, and
  automatic logins. It also prevents automatic startup at the next sign-in.
- **Enable automation** — restores background login and Windows sign-in startup.
- The eye button temporarily reveals the saved password so you can verify it.

The app never connects Windows to Wi-Fi itself. Windows connects to the saved
network normally; this app only completes the web login after connection.

## Important

- Use this only with a VIT account and network access you are authorized to use.
- Your password is stored in **Windows Credential Manager** for your Windows
  account. It is not written to the app's settings file or included in releases.
- The installer is currently unsigned. Download it only from this repository's
  official releases and verify the repository owner before running it.

## Technical details

The application is a Windows Python/Tkinter app packaged with PyInstaller. It:

- listens to Windows Wi-Fi connection events, then falls back to periodic
  checks if an event is missed;
- acts only on names ending in `-VIT`, waits briefly for DHCP to finish, and
  starts the portal flow without an initial polling delay;
- follows the Pronto captive portal's HTTP and JavaScript redirect flow;
- submits the portal's normal `userId`, `password`, and
  `serviceName=ProntoAuthentication` form fields;
- uses Windows Credential Manager for the password;
- verifies connectivity with Google, Microsoft, or Cloudflare HTTPS probes;
- retries a failed portal request after 15, 30, then 60 seconds while it stays
  on the same VIT network;
- runs one per-user background process, started through the Windows sign-in
  registry entry while automation is enabled.

## Build from source

Requirements: Windows, Python 3.10+, and Inno Setup 6.

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\build.ps1
```

The installer is created at:

```text
installer-output\Automate-VIT-WiFi-Setup.exe
```

GitHub Actions builds this installer for manual runs and tag pushes. Pushing a
tag such as `v1.2.0` also creates a GitHub Release with the installer attached.
