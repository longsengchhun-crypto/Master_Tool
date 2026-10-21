# Build, test and release

## Prerequisites (Windows 10/11)

| Tool | Version used | Notes |
|---|---|---|
| Node.js | 24 (22+ works) | `npm ci` from the repo root installs all workspaces |
| Rust | 1.99 stable, MSVC target | `rustup` |
| Visual Studio Build Tools | 2022 (14.44), "Desktop development with C++" | Needed to link |
| NSIS | 3.13 | Tauri downloads its own copy if missing |
| WebView2 | Evergreen runtime | Preinstalled on Windows 11 |
| PostgreSQL | 14+ (Neon used in development) | For the console |

## Detection engine (ClamAV)

ClamAV is GPL-2.0 and is used strictly as a separate process.

```powershell
# Official release from Cisco-Talos; verify the published SHA-256 before use.
$msi = "clamav-1.5.4.win.x64.msi"            # https://github.com/Cisco-Talos/clamav/releases/tag/clamav-1.5.4
(Get-FileHash $msi -Algorithm SHA256).Hash    # a025fa23a4b9d64fce448d5a211afcf30dc26ba6528186e6223d1b945f9d95d6
msiexec /a $msi /qn TARGETDIR="$PWD\third_party\clamav-extract"     # administrative extract, no system install
Move-Item third_party\clamav-extract\ClamAV third_party\clamav
```

The MSI itself is **not Authenticode-signed**; the published hash is the only integrity check (recorded in
`apps/desktop/src-tauri/engine-staging/clamav-manifest.json` per-file at staging time). Before shipping, pin the exact
version/hash in your release notes and re-verify.

`apps/desktop/scripts/stage-engine.mjs` copies only the runtime files (clamd, freshclam, DLLs, certs, licenses): about
72 MB instead of 900 MB: into `src-tauri/engine-staging/clamav` and writes a SHA-256 manifest. Signatures are **not**
bundled; the first-run flow downloads them (≈300 MB) through ClamAV's own signed-update mechanism.

## Console

```powershell
cd apps\admin
copy .env.example .env        # DATABASE_URL, SESSION_SECRET, DEVICE_TOKEN_PEPPER  (see ENVIRONMENT.md)
npm run migrate               # forward-only SQL migrations, tracked in schema_migrations
node scripts/bootstrap-admin.mjs   # first Super Administrator (one-time; refuses to run twice)
npm run build && npm run start     # production server on :3100
```

## Tests

```powershell
cargo test --workspace                                           # engine, quarantine, monitor, client, signatures
# Real ClamAV end to end (requires staged third_party\clamav and a signature DB):
$env:SENTRIX_CLAMAV_DIR="$PWD\third_party\clamav"; $env:SENTRIX_DATA_DIR="$PWD\.sentrix-dev"
cargo test -p sentrix-core --test engine -- --include-ignored --nocapture --test-threads=1
cd apps\admin; npm run build; npx vitest run                     # console unit + integration + security (creates/drops a temp schema)
$env:SENTRIX_E2E_DESKTOP="1"; npx vitest run tests/desktop-e2e.test.ts   # Rust client <-> live console
```

Notes:

* The integration tests need a **direct** (non-pooled) Postgres endpoint because they pin a throwaway schema with a
  startup option. The harness derives it by removing `-pooler` from a Neon URL.
* Microsoft Defender may block the EICAR file on disk (observed: os error 225). The suite treats that as the
  OS provider's detection and additionally verifies ClamAV on EICAR via an in-memory stream and a zip.
* Symlink tests need Developer Mode or elevation to create symlinks; without it they **skip with a message**. Junction
  tests (no privilege needed) always run.

## Release build

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build-release.ps1 -DevKey      # local; uses the dev updater key
$env:SENTRIX_SIGNING_KEY_PATH="D:\secure\sentrix-updater.key"; $env:SENTRIX_SIGNING_KEY_PASSWORD="…"
powershell -ExecutionPolicy Bypass -File scripts\build-release.ps1                # production update key
```

The script: `npm ci` → stage engine → `tauri build` (NSIS) → **verifies the update signature against the public key in
`tauri.conf.json`** → writes `dist-release/{installer, .sig, SHA256SUMS.txt, release-manifest.json}` including the real
Authenticode status (`NotSigned` today).

### Authenticode (publisher) signing: BLOCKED, needs a certificate

Update signing (minisign) protects the *updater*. Windows SmartScreen reputation and the publisher name come from an
Authenticode **code-signing certificate** (OV/EV from a CA, or Azure Trusted Signing). This repository has none. After
obtaining one, sign the installer and the main binary, then re-run the update-signing step:

```powershell
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a "target\release\bundle\nsis\SENTRIX_0.1.0_x64-setup.exe"
```

Tauri can also do this at build time via `bundle.windows.certificateThumbprint`. **Do not** use a fake or misleading
publisher to avoid warnings.

### Publishing a release to the console

1. Upload the installer to HTTPS storage/CDN.
2. Console → Releases → New release: version, artifact URL, SHA-256 (from `release-manifest.json`), the contents of
   the `.sig` file as *update signature*, tick "code-signed" only if Authenticode status is `Valid`.
3. Stage (e.g. 10%) → watch Devices → Publish. A release without artifact + hash + signature cannot be staged or published.
4. Rollback stops the offer; it does not downgrade machines that already updated: ship a fixed newer version.

## Other platforms

Not built and not claimed. A CI matrix job per OS (see `.github/workflows/ci.yml`, currently Windows-only for the
desktop) would add `macos-14` (universal2, notarize) and `ubuntu-22.04` (`.deb`/AppImage) once the per-platform items in
[PLATFORM_SUPPORT.md](PLATFORM_SUPPORT.md) are implemented.

## Dependency hygiene

* Lockfiles are committed (`package-lock.json`, `Cargo.lock`).
* CI runs `npm audit`, `cargo audit`, `cargo deny` (licenses: ClamAV GPL is out-of-process), CodeQL and gitleaks.
* Dependabot is configured for npm, cargo and GitHub Actions.
