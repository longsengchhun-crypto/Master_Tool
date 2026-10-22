# SENTRIX

A Windows desktop file-protection product with a centralized, independently deployable administration console.

> **Status: Windows MVP, pre-release.** The detection engine, quarantine, folder monitoring, console, licensing,
> enrollment and update verification are implemented and tested (see [docs/CHECKLIST.md](docs/CHECKLIST.md) for the
> honest, per-requirement status). It is **not production-ready**: there is no Authenticode code-signing certificate,
> the updater key in this repo is a development key, and several items need credentials or services listed in
> [docs/CHECKLIST.md](docs/CHECKLIST.md#what-is-still-missing).

## What it does, and what it does not

| Capability | Status |
|---|---|
| Scan files you choose (PE, scripts, Office, PDF, ZIP/JAR/APK/OOXML, other) by **content**, never by extension | Implemented, tested |
| Real malware-signature engine (ClamAV 1.5.4 as a supervised `clamd`) | Implemented, tested end to end |
| Static heuristics, Authenticode verification, archive inspection with decompression-bomb limits | Implemented, tested |
| Honest verdicts: a file is only CLEAN if a signature engine **completed** and nothing was left unchecked | Implemented, tested |
| Real-time **scanning** of new files in chosen folders (OS file events), with a durable queue: partial downloads wait, duplicates coalesce, locked files retry, changed files are re-scanned, a restart picks up what was missed | Implemented, tested (incl. real ClamAV pipeline) |
| Honest protection status: monitor/queue/engine health, files that **could not be checked**, whether protection resumes after restart | Implemented |
| Reports to **your own Telegram bot** (token DPAPI-protected, delivery queue with retries); optional files-to-bot scanning | Implemented; tested against a local Bot API **test double**, not live Telegram ([docs/TELEGRAM.md](docs/TELEGRAM.md)) |
| Telegram Desktop download-folder scanning with source labels | Implemented, tested |
| **Group Shield**: scans files posted in Telegram groups the owner's bot is in; optional consented deletion of malicious messages | Implemented; tested against a test double and real ClamAV, not live Telegram; runs on the owner's PC ([docs/GROUP_SHIELD.md](docs/GROUP_SHIELD.md)) |
| **Shared SENTRIX bot** | Customers find the bot, press Start and choose **Protect a group** or **Protect my account**; every result arrives in their own private chat, never in a group. Built and tested against a Telegram test double, **not live and not deployed**: see [docs/HOSTED_BOT.md](docs/HOSTED_BOT.md) |
| **Telegram account protection** | Implemented on Telegram's official library (TDLib), QR sign-in only, no password ever collected, two-step-password accounts unsupported. **Not yet verified with a real signed-in account**; see [docs/TELEGRAM_ACCOUNT.md](docs/TELEGRAM_ACCOUNT.md) |
| Execution guard: reversible deny-execute permission on a confirmed-malicious file | Implemented, tested (a guarded file really fails to launch) |
| Encrypted quarantine, tamper-evident metadata and audit log, confirmed restore | Implemented, tested |
| Console: orgs, devices, licenses, policies, releases, users/roles, audit log; MFA, RBAC, tenant isolation | Implemented, tested |
| Device enrollment, policy sync, closed-set remote requests, license revocation | Implemented, tested against the real client |
| Signed application updates with staged rollout | Implemented; verified with a dev key |
| **Intercepting downloads / blocking arbitrary programs before they run** | **Not implemented.** Needs a signed OS driver. SENTRIX scans after a file lands and can guard confirmed-malicious files only |
| Runs as a Windows service | **No.** Tray app; resumes after restart only if "Start SENTRIX when I sign in" is on |
| macOS / Linux builds | **Not implemented** |
| Authenticode-signed installer | **Blocked:** no certificate |
| Behavioral sandbox, hash-reputation lookups | **Not implemented** (designed in [docs/DETECTION.md](docs/DETECTION.md)) |

SENTRIX does not claim to detect all malware, is not a replacement for Windows Security, and never calls a file safe
unless a real engine finished the job.

## Repository layout

```
apps/desktop        Tauri 2 + React/TypeScript/Tailwind desktop app (Rust shell in src-tauri)
apps/admin          Next.js console, public website, REST API, device API (PostgreSQL)
packages/contracts  Shared zod schemas (device API, policy, releases)
services/scanner    sentrix-core: the Rust security engine + sentrix-cli
infrastructure      Dockerfile, compose file, CI notes
docs                Architecture, threat model, detection, operations, build, checklist
scripts             Reproducible release build
third_party         (gitignored) local ClamAV runtime used for development and bundling
```

## Quick start (development)

Prerequisites: Windows 10/11, Node 22+, Rust (MSVC toolchain) with VS Build Tools, NSIS (for installers), PostgreSQL
(or a Neon database). Full details in [docs/BUILD.md](docs/BUILD.md).

```powershell
npm install

# 1. Console
copy apps\admin\.env.example apps\admin\.env      # fill in DATABASE_URL and two random secrets
cd apps\admin
npm run migrate                                    # applies migrations/*.sql
$env:SENTRIX_ADMIN_EMAIL = "you@example.com"
node scripts/bootstrap-admin.mjs                   # creates the first Super Administrator (password shown once)
npm run build ; npm run start                      # http://localhost:3100

# 2. Detection engine (development copy; see docs/BUILD.md)
#    extract ClamAV to third_party\clamav, then:
cargo run -p sentrix-core --bin sentrix-cli -- update-signatures --clamav-dir third_party\clamav --data-dir .sentrix-dev

# 3. Desktop app
cd ..\desktop
npx tauri dev
```

## Tests

```powershell
cargo test --workspace                                   # Rust unit tests (engine, quarantine, client)
$env:SENTRIX_CLAMAV_DIR="$PWD\third_party\clamav"; $env:SENTRIX_DATA_DIR="$PWD\.sentrix-dev"
cargo test -p sentrix-core --test engine --test service --test perf -- --ignored --nocapture --test-threads=1   # real ClamAV, end to end
cd apps\admin ; npm run build ; npx vitest run                              # console unit + integration + security
$env:SENTRIX_E2E_DESKTOP="1" ; npx vitest run tests/desktop-e2e.test.ts      # Rust client against the live console
```

The console tests create a throwaway Postgres schema, run the production build against it, and drop it afterwards.
They never touch real tables.

## Release

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build-release.ps1 -DevKey    # local build, dev updater key
```

Produces the NSIS installer, its update signature, SHA-256 and a manifest in `dist-release/`, and reports the
Authenticode status truthfully (currently UNSIGNED). See [docs/BUILD.md](docs/BUILD.md) and
[docs/KEY_MANAGEMENT.md](docs/KEY_MANAGEMENT.md).

## Documentation

[Architecture](docs/ARCHITECTURE.md) · [Security architecture and threat model](docs/SECURITY_ARCHITECTURE.md) ·
[Detection and verdict rules](docs/DETECTION.md) · [Platform support](docs/PLATFORM_SUPPORT.md) ·
[Build and release](docs/BUILD.md) · [Operations, backup, retention](docs/OPERATIONS.md) ·
[Key management](docs/KEY_MANAGEMENT.md) · [Incident response](docs/INCIDENT_RESPONSE.md) ·
[Telegram integration](docs/TELEGRAM.md) · [Group Shield](docs/GROUP_SHIELD.md) · [Phase 3 gap analysis](docs/PHASE3_GAP_ANALYSIS.md) · [Phase 2 gap analysis](docs/PHASE2_GAP_ANALYSIS.md) · [API](docs/API.md) · [Performance (measured)](docs/PERFORMANCE.md) · [Environment variables](docs/ENVIRONMENT.md) · [Checklist and known limitations](docs/CHECKLIST.md)
