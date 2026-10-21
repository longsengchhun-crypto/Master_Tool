# Platform support matrix

The architecture shares everything above the OS (engine, verdicts, quarantine format, console, contracts) and isolates
what differs. Capabilities are reported **separately** because "can scan", "can warn" and "can prevent execution" are
different things and must not be conflated.

| Capability | Windows 10/11 x64 | macOS | Linux |
|---|---|---|---|
| Scan files on demand | **Yes** (tested) | Not built | Not built |
| Scan archives (ZIP family) safely | **Yes** | – | – |
| ClamAV signature engine | **Yes** (ClamAV 1.5.4 Windows build) | Needs `clamd` packaging + notarization | Needs distro packages |
| Folder monitoring (file-change events) | **Yes**, `ReadDirectoryChangesW` via `notify` | FSEvents (not wired) | inotify/fanotify (not wired) |
| Digital-signature check | **Yes**, WinVerifyTrust | Not implemented (codesign/spctl) | n/a |
| Encrypted quarantine, DPAPI-bound key | **Yes** | Key wrap not implemented (file stored raw) | same |
| Notifications, tray, start-at-login (consent) | **Yes** | – | – |
| Installer + desktop shortcut + Start Menu | **Yes** (NSIS, per-user, no admin) | DMG/PKG not built | AppImage/deb/rpm not built |
| Signed application updates | **Yes** (Tauri updater, minisign) | – | – |
| **Warn about a risky file** | **Yes** (notification + report + safe actions) | – | – |
| **Execution guard** (deny-execute permission on one confirmed-malicious file) | **Yes**, opt-in, reversible, verified by read-back and by a test that tries to launch a guarded file | – | – |
| **Prevent any program from launching / intercept a download** | **No.** Needs a signed minifilter driver or WDAC/AppLocker policy integration | **No.** Needs Endpoint Security entitlement | **No.** Needs fanotify permission events + root |
| Behavioral sandbox | No | No | No |
| Hash reputation lookups | No | No | No |

## Windows specifics

* Per-user install (`installMode: currentUser`): no administrator rights, installs to `%LOCALAPPDATA%\SENTRIX`. Creates a
  Start Menu entry and (via installer hook) a Desktop shortcut; the uninstaller removes both.
* Runs alongside Microsoft Defender and SmartScreen; it does not disable or replace them. When Defender blocks a file
  read, SENTRIX reports the provider's detection rather than failing silently.
* Real-time protection scans **after** a file lands in a watched folder and has stopped changing (partial downloads
  such as `.crdownload` are ignored until complete). It does not hook browsers or mail clients.
* Folder watching covers: Downloads, Desktop, Documents, removable drives (re-evaluated every 15 s for hot-plugged
  drives), and user-chosen folders. Anything else is not monitored.
* "Full system scan" covers fixed drives only and says so; unreadable items are listed, never counted clean.

## Execution guard (Windows, user mode)

When a file is confirmed MALICIOUS by a signature engine and is not quarantined, SENTRIX can run
`icacls <file> /deny *S-1-1-0:(X)` (absolute path to `icacls`, arguments passed as an array, never through a shell). The
result is read back and the file is only reported as blocked if `(DENY)(X)` is really present. **Allow this file to run
again** removes exactly that entry.

Limits, stated on the screens that offer it: it stops the file being *launched*; it does not stop it being read or copied,
does not stop a script from being read by an interpreter, does not stop a document from being opened, affects nothing
already running, and any process running as the same user can undo it. It is not pre-download interception and not a driver.

## Background operation

SENTRIX is a per-user tray application, **not a Windows service**. Protection runs while the app runs. It resumes after a
restart only if "Start SENTRIX when I sign in" is on (the Real-Time Protection page says which). Files that arrive while
it is closed are found by a startup folder check and scanned on the next start.

## What a Windows execution-prevention component would require (separate project, not simulated here)

1. A kernel **minifilter** (or user-mode alternative via WDAC/AppLocker/ASR integration) intercepting `IRP_MJ_CREATE`
   for executables and consulting the user-mode engine.
2. Driver signing via the Microsoft Hardware Dev Center (EV certificate + attestation/WHQL), HVCI compatibility,
   Secure Boot testing, crash-safety review (a bug here is a BSOD, not a bug report).
3. Fail-open/fail-closed policy design and an uninstall path that cannot brick boot.
4. A distribution/rollback plan separate from the user-mode app.

## macOS and Linux requirements (not started)

* **macOS:** Developer ID signing, notarization, hardened runtime, Gatekeeper behaviour, Endpoint Security entitlement
  (requires Apple approval), Keychain-based key wrap, `.dmg`/`.pkg`, universal2 Rust build, ClamAV macOS packaging.
* **Linux:** supported-distro list (e.g. Ubuntu LTS, Fedora), `.deb`/`.rpm`/AppImage, systemd user service for the engine,
  fanotify (needs `CAP_SYS_ADMIN`) vs inotify, polkit/AppArmor/SELinux profiles, Secret Service key wrap.

The release pipeline for these is described in [BUILD.md](BUILD.md#other-platforms). None of these installers exist or are claimed.
