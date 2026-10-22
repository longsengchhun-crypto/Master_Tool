# Staying up to date

Everyone gets new versions without doing anything, as long as the release was published with `scripts/publish-release.ps1`.

| What | How it updates | Check |
|---|---|---|
| **Desktop app** (scanner, rules, interface) | Checks the release feed shortly after start and then every 6 hours. A newer version is downloaded, its signature is verified against the public key built into the app, and the app restarts into it. It waits for a running scan to finish. "Keep SENTRIX up to date automatically" in Settings turns it off; "Check for updates" always works by hand. | Minisign signature (same scheme as Tauri's own updater) |
| **Bot service** (`sentrix-botd`) | Looks at `botd-latest.json` every 30 minutes. Downloads, checks the SHA-256 **and** the signature, swaps its own program file, and starts again. | Same key as the app; a test keeps the two keys identical |
| **Malware signatures** (ClamAV) | The bot service refreshes them every 2 hours. The app refreshes them on its own schedule. | ClamAV's own signed database |
| **Telegram groups** | Nothing to update: everyone uses the one bot, so whatever version the service runs is what every group gets. | |

## Publishing a release

1. Raise the version in `apps/desktop/src-tauri/tauri.conf.json`, `apps/desktop/src-tauri/Cargo.toml`, `services/scanner/Cargo.toml`
   and `apps/desktop/package.json`. Updates are only offered for a **higher** version.
2. Commit and push.
3. `powershell -ExecutionPolicy Bypass -File scripts\publish-release.ps1 -Notes "What changed"`

It builds and signs the installer, builds and signs the bot service, writes `latest.json` (what apps read) and
`botd-latest.json` (what the service reads), and creates the GitHub release. The feeds are
`https://github.com/<owner>/<repo>/releases/latest/download/latest.json` and `.../botd-latest.json`.

People are pointed at `https://github.com/<owner>/<repo>/releases/latest/download/SENTRIX-setup.exe` (a fixed name for the newest installer).

## The signing key

`%USERPROFILE%\.sentrix-keys\updater-prod.key` and `updater-prod.password` sign every update. **Back both up somewhere safe and
private.** If they are lost, no installed copy will accept another update and everyone must reinstall by hand. If they leak, anyone
can push software to every user: rotate by shipping an installer with a new public key. Never commit them.

The public half is in `tauri.conf.json` (the app) and `services/scanner/updater.pub` (the bot service).

## Running the bot service so it stays up

`powershell -ExecutionPolicy Bypass -File scripts\install-bot-autostart.ps1` copies the service to `%LOCALAPPDATA%\SENTRIX-Bot`, starts
it, and registers a scheduled task that starts it at every sign-in and restarts it if it stops. It keeps updating itself. The bot
token is read from your existing env file and not copied. `-Remove` undoes it.

Honest limits:

* The bot answers only while that computer is on, signed in and online. For round-the-clock service it needs a server (the same
  program and scripts work on one; a Windows service wrapper or a Linux build would be the next step).
* The installer is **not publisher-signed** (no code-signing certificate), so Windows SmartScreen warns on a first manual install.
  Automatic updates are verified by the update signature and do not show that warning.
* A bad release reaches everyone quickly. Test before publishing; to withdraw one, publish a fixed higher version (updates are never
  offered downward).
* Customers who installed an older build with the development key (version 0.1.0) must install once by hand; from 0.2.0 on it is automatic.
