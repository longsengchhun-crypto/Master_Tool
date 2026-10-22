# Status checklist and known limitations

Legend: **DONE** implemented and tested · **PARTIAL** works with stated gaps · **BLOCKED** needs something external ·
**NOT IMPLEMENTED** deliberately not built (reason given).

_Nothing below is claimed without a test or a check named next to it. Results of the last full run are at the bottom._

## Desktop application

| Requirement | Status | Evidence / notes |
|---|---|---|
| Brand icon in ICO/ICNS/PNG, shield-S identity shared by app, installer, tray, site | DONE | Generated from `brand/app-icon.svg` by `tauri icon`; viewed manually |
| Installer with Start Menu entry, **desktop shortcut**, per-user, uninstaller | DONE | Real silent install/uninstall on Windows 11 (see "Installer test") |
| Tray icon with quick actions; close-to-tray only while real-time is on | PARTIAL | Implemented; **not visually verified** (tray not inspected) |
| Start at login **with explicit consent** (off by default) | DONE | Off by default (no Run key after install/uninstall); toggle uses the autostart plugin. Toggling on/off not exercised |
| Authenticode-signed installer/binary | **BLOCKED** | No code-signing certificate. Build output reports `NotSigned`; download page labels it unsigned |
| Dashboard reflects real engine state; never shows "Protected" when engine is down | DONE | `compute_protection`; observed live ("Files cannot be verified right now") |
| Drag-and-drop, multi-file, folder scan, progress, cancel, export/copy report, re-scan | DONE | Engine + UI tests; manual UI check |
| Removable drives | PARTIAL | Scan as folder; monitored when "Removable drives" is on (hot-plug re-evaluated every 15 s). Not tested with physical media |
| Archives without executing | DONE | ZIP/JAR/APK/OOXML in memory with limits (unit tests); 7z/RAR/ISO/DMG rely on ClamAV's unpackers |
| Onboarding covering capabilities, limits, permissions, privacy | DONE | Viewed in the real app (step 4) and in the dev preview (steps 1 and 4) |
| Light/dark themes, keyboard navigation, focus rings, reduced motion | PARTIAL | Every screen reviewed in dark; Home, Scan, Reports, Settings in light (dev preview, 1200 px). Focus rings and reduced-motion are in CSS but **no automated accessibility audit was run** and keyboard-only use was not tested |
| Report contains type, size, SHA-256, time, verdict, engines+versions, checks run/unavailable, findings, next step, completeness, quarantined/blocked | DONE | `report.rs`, `ReportView` |

## Protection and detection

| Requirement | Status | Evidence / notes |
|---|---|---|
| Content-based identification; extension never decides | DONE | `identify` tests; engine test (PE renamed .jpg) |
| Real signature engine (ClamAV 1.5.4) | DONE | Real-ClamAV integration suite |
| Heuristics are evidence only; cannot yield MALICIOUS | DONE | `verdict` tests |
| Verdicts PENDING/CLEAN/SUSPICIOUS/MALICIOUS/UNABLE TO VERIFY with clean-needs-completed-engine rule | DONE | `verdict` tests + engine suite (no engine → UTV, partial → UTV) |
| Authenticode verification | DONE | WinVerifyTrust; code mapping unit-tested. Not exercised against a corpus of signed/invalid binaries |
| Folder monitoring via OS events, dedup, partial-download handling | DONE | `monitor` tests (settle + single callback) |
| Does not claim to monitor browsers/mail clients | DONE | UI + docs state folder-only |
| **Execution blocking** | **NOT IMPLEMENTED** | Requires a signed kernel minifilter/WDAC integration; documented in PLATFORM_SUPPORT.md. UI shows "Not available" separately from scanning/warning |
| Hash-reputation providers (D) | **NOT IMPLEMENTED** | Designed in DETECTION.md; no provider key available |
| Behavioral sandbox (E) | **NOT IMPLEMENTED** | Would require an isolated analysis service; not simulated |
| Check-before-opening actions: details, quarantine, open folder without running, export | DONE | |
| Delete the original file with confirmation (only if byte-identical to what was scanned) | DONE | `delete_scanned_file` + confirm dialog; hash guard in code, not separately tested end to end |
| Dismiss a false-positive warning (SUSPICIOUS only, only where policy allows; never MALICIOUS) | DONE | `dismiss_warning`; stats exclude dismissed files |
| File origin ("Mark of the Web": host + zone only, never the full URL) | DONE | Parser unit test + real NTFS alternate-data-stream test |
| Honest publisher status for the app itself (WinVerifyTrust on own exe) | DONE | Shown in Settings → About |
| Does not replace Defender/SmartScreen | DONE | Coexists; Defender detection is surfaced (os error 225 path) |

## Quarantine

| Requirement | Status | Evidence |
|---|---|---|
| Encrypted vault, no execution/ordinary access | DONE | AEAD blobs; test shows plaintext absent |
| Original path/hash/metadata/reason/time stored; integrity verified on move and restore | DONE | Unit tests |
| Link/path-traversal safety, no overwrite on restore | DONE | Tests incl. Windows junction; **symlink tests skip without Developer Mode/admin** |
| Tamper-evident metadata and audit log | DONE | Tamper tests |
| MALICIOUS restore needs typed confirmation; SUSPICIOUS restore policy-controlled | DONE | Unit tests + UI |
| Never auto-delete; auto-quarantine only for signature-engine MALICIOUS and only if the user enabled it | DONE | Policy schema forbids suspicious; tests |

## Console, API, database

| Requirement | Status | Evidence |
|---|---|---|
| Orgs, devices, licenses, policies, releases, intel versions, events, audit, users/roles | DONE | 70+ integration tests |
| RBAC with least privilege; Super-Admin-only critical settings | DONE | Matrix tests + live role tests |
| MFA mandatory for every admin role; recovery codes; rate limits; CSRF; secure sessions | DONE | Integration tests (found and fixed a recovery-code bug) |
| Re-authentication for sensitive actions | DONE | Integration test |
| Cross-organization isolation (404, not 403) | DONE | Integration tests |
| Audit log append-only + hash chain + tamper detection | DONE | Integration test (trigger blocks edits; forced edit detected) |
| Closed-set remote requests, visible to the user, no shell | DONE | Tests at API/DB/client; real client e2e |
| Enrollment with license-seat enforcement; license/device revocation | DONE | Integration + Rust-client e2e |
| Retention job | DONE | Test seeds old/new rows and verifies; audit untouched |
| Backups and recovery | PARTIAL | Procedure documented; **no restore drill performed** (`pg_dump` unavailable) and PITR window not configured |
| Structured logging, health check, safe errors | DONE | |
| Public site: overview, limits, download (OS detection + manual), release notes, docs, privacy, terms, support | DONE | Legal pages are **drafts needing counsel**; support email unconfigured |
| Separate `apps/api`, `services/updates` packages | N/A | Folded into the Next.js app by design (ARCHITECTURE.md) |

## Updates and release

| Requirement | Status | Evidence |
|---|---|---|
| Signed updates verified before install; tamper/wrong-key/truncation rejected | DONE | `update_signature` tests; real installer verified in build script |
| Staged rollout, cancel, rollback (stops offering), min-supported, unsigned release cannot be offered | DONE | Integration tests |
| Application updates separate from malware signatures | DONE | Separate commands/channels |
| In-app update install exercised end to end | **NOT TESTED** | Needs a UI-driven run against a served newer build; verifier and feed are tested separately |
| Production signing key | **BLOCKED** | Dev key only; generate per KEY_MANAGEMENT.md |
| macOS / Linux installers | **NOT IMPLEMENTED** | Requirements in PLATFORM_SUPPORT.md |
| CI | WRITTEN, NOT RUN | `.github/workflows/ci.yml`, Dependabot, cargo-deny, gitleaks |
| Docker image | WRITTEN, NOT BUILT | No Docker in this environment |

## Phase 2: automatic protection and Telegram

| Requirement | Status | Evidence / notes |
|---|---|---|
| Durable scan queue; restart resumes; missed files reconciled | DONE | `queue` unit tests (16+); `service` test "restart → missed file reconciled, scanned files not repeated" |
| Partial downloads not scanned until stable; one result per download | DONE | Real-ClamAV pipeline test (12 chunks over ~5 s → 1 result for the final size) |
| Duplicate events coalesce; changed-after-scan file is marked stale and re-scanned | DONE | 40 writes → 1 scan; replaced file → new hash scanned |
| Locked/transient failures retry with backoff; never CLEAN; visible as "could not be checked" with manual retry | DONE | Locked-file test; UI list. Permanent failure after 7 attempts |
| Real engine only; engine failure never becomes CLEAN | DONE | Scanner tests + pipeline with real ClamAV; no-engine tests give UNABLE TO VERIFY |
| Honest real-time status (monitor/queue/engine health, per-folder state, resumes-after-restart) | DONE | `protection_health`; UI reviewed in dev preview (healthy and failing scenarios) |
| Resume after reboot | **PARTIAL** | Only if "Start SENTRIX when I sign in" is on; the app is a tray app, **not** a Windows service. Autostart toggling not exercised on this machine |
| Execution guard on confirmed-malicious files | DONE | `guard` tests: guarded copy really fails to launch, reversible, hostile names cannot inject arguments |
| Pre-download interception / blocking arbitrary execution | **NOT IMPLEMENTED** | Needs a signed driver; documented, UI says so |
| Defender not weakened | DONE | No exclusions, no settings touched (nothing in the code reads or writes Defender configuration) |
| Telegram Desktop folder monitoring + source labels | DONE | Pipeline test; detection unit tests (4). Not run against a real Telegram Desktop install's live downloads |
| Telegram **account** integration (TDLib, QR sign-in only, no password/code field, cloud-password accounts refused) | **PARTIAL** | Implemented; scripted-TDLib unit tests; the **real TDLib DLL** loads, is hash-pinned, and the real Telegram servers answered it (invalid `api_id` rejected cleanly). **A full signed-in run (QR approval, real attachment) has NOT been done**: [TELEGRAM_ACCOUNT.md](TELEGRAM_ACCOUNT.md) |
| Personal bot: connect, masked/never-shown token, DPAPI storage, redaction | DONE (against a test double) | `telegram` unit + integration tests. **Not tested against live Telegram: no real token was available** |
| "Connected" shown only after Telegram confirms | DONE (against a test double) | `getMe` + delivered test message required before anything is saved |
| Report pipeline: queue, retry, 429, dedupe, recovery, bounded, delivery failure never alters verdicts | DONE (against a test double) | `queue`, `telegram`, `service` tests; found and fixed during final review: delivered text was retained forever (now erased) and a full queue dropped reports silently (now an event) |
| Files sent to the bot: owner check, 20 MB limit, isolated temp, cleanup | DONE (against a test double) | Pipeline test incl. lying size and foreign sender |
| Dashboard pages | DONE, simplified | Originally nine pages; reduced to seven for non-technical users (Home, Scan, History incl. reports, Quarantine, Protection, Telegram, Settings incl. privacy, organization and about). Only real data; viewed via the dev mock in both themes. **Not opened in the installed app** |
| Console health metrics (counts only), tenant isolation, policy switches | DONE | Migration 003 applied; Phase 2 block in `tests/security.test.ts` |
| Threat model / privacy docs | DONE | SECURITY_ARCHITECTURE T23-T32, TELEGRAM.md, in-app Help and Privacy |
| Performance with real measurements | PARTIAL | Single runs, see [PERFORMANCE.md](PERFORMANCE.md); live Telegram latency and large-queue behaviour not measured |

## Group Shield (Telegram groups)

| Requirement | Status | Evidence / notes |
|---|---|---|
| Reuse the existing bot, token, single worker, outbox, scanner; no second poller or webhook | DONE | One worker serves private chat and groups |
| `/setup`, `/status`, `/help`, `/scanstatus` | DONE | `tests/groups.rs` |
| Detect and scan group documents with the real engine; failures never CLEAN | DONE (test double + real ClamAV) | 15 + 2 tests |
| Reports and prompt MALICIOUS alerts in the group | DONE | Real-engine test: alert text, Eicar detection |
| Optional deletion, off by default, explicit admin consent, permission checks, failure handling | DONE (test double + real ClamAV) | Two-step consent; deletion success/failure both verified |
| Privacy mode, permissions, 20 MB, rate limits, supported types documented | DONE | [GROUP_SHIELD.md](GROUP_SHIELD.md) |
| Isolation and authorization by group id | DONE | Cross-group tests; Telegram-confirmed administrators only |
| Console: registered/protected/scans/threats/errors, no secrets or content | DONE | Migration 004 applied; strict schema; tenant-scoped tests |
| Works without the owner's computer being on | **NO** | Runs on the owner's PC with the owner's bot. A central bot with server-side scanning is a different product |
| Verified against **live Telegram** | **NOT TESTED** | No bot or group was available; privacy mode, `getChatMember` and `deleteMessage` behaviour is per Telegram's documentation |
| Personal Telegram **account** monitoring | **PARTIAL** | Built on TDLib; needs the live test run with a real `api_id` and test account before it can be called verified. Console shows state and counts only (tenant-isolation tests). Details: [TELEGRAM_ACCOUNT.md](TELEGRAM_ACCOUNT.md) |
| Group `/report` (administrators only, counts only, per group) | DONE (test double) | `report_is_for_administrators_only…` |
| Telegram page shows Group / Personal / Both with real status words (Protection active, Limited coverage, Permission required, Scanner unavailable, Connection expired, Disconnected…) | DONE | A status is "Protection active" only when connected, scanner running and something is watched; viewed in the dev preview for the healthy, stopped and expired scenarios |
| **One shared SENTRIX bot for all customers** (the default in the latest brief) | **BLOCKED: product decision** | The repository has no shared bot and no server that polls Telegram. Each customer's own bot runs on their PC. A shared bot needs a hosted service that holds one token, receives every group's updates, scans files (so uploads leave customers' PCs) and routes reports per customer. That is a different architecture and privacy position; see [TELEGRAM.md](TELEGRAM.md) |
| Licence tiers gating Telegram features | **NOT CHANGED** | Existing organization policy switches (`telegramBotAllowed`, `telegramAccountAllowed`, `telegramGroupsAllowed`) are honoured; no new plans or gates were invented |
| Pre-download scanning of Telegram files | **NOT POSSIBLE** | Telegram gives bytes only on download; the UI and docs say so |
| Production-grade TDLib binary | **BLOCKED** | Development copy is a third-party build; build from Telegram's source and re-pin before distribution |

## What is still missing

1. **Authenticode certificate** (OV/EV or Azure Trusted Signing): without it every download shows SmartScreen warnings.
2. **Production updater key** generated offline and the public key swapped into `tauri.conf.json`.
3. **Hosting**: production console domain, TLS, secret store, PITR/backups, monitoring; a real support/security mailbox.
4. **Rotate the Neon database password**: it was shared in a chat transcript.
5. **Legal review** of privacy policy and terms; retention periods stated publicly.
6. **Independent penetration test** and a code-signing/SmartScreen reputation ramp-up.
7. **A Windows execution-prevention component** (separate driver project) if enforcement is a product requirement.
7a. **Live Telegram verification**: connect a real bot (you create it) and run "Send a test message", a file submission and a Desktop-folder download; only a test double was available.
7b. **Telegram account protection live test**: put the test account's `api_id`/`api_hash` in `.sentrix-dev/telegram-api.env`, run the `live_` test (QR scan, send a file, disconnect), then build TDLib from source and re-pin it.
7c. **Windows service** if protection must run before sign-in.
8. macOS/Linux builds, hash-reputation and sandbox services if wanted.

## Last full run (Windows 11, this repository state)

| Suite | Result |
|---|---|
| `cargo test --workspace` (core 114, desktop 12, Telegram client/double 9, service pipeline 9, Group Shield 15, update signatures 6) | 165 passed, 0 failed (9 opt-in tests ignored) |
| Real ClamAV (`--test engine --test service --test groups --test perf -- --ignored`): engine scenarios, 10-scenario Telegram/queue/guard pipeline, 2 Group Shield scenarios, perf | passed |
| Real ClamAV 1.5.4 end to end (`sentrix-core --test engine`, 12 scenarios) | passed |
| Console unit + integration + security (`apps/admin`, production build, real Postgres in a throwaway schema) | 99 passed, 1 skipped (opt-in desktop e2e) |
| Rust desktop client ↔ live console e2e (enroll → restart → job → revoke) | passed (run separately with `SENTRIX_E2E_DESKTOP=1`) |
| Release build script (installer, update signature verified against baked-in key, SHA-256) | passed; Authenticode **NotSigned** |

Bugs found *by* these tests and fixed: MFA recovery codes unusable at login; Rust client timestamps rejected by the
server schema; full-system scan held every report in memory; unknown API routes returned an HTML page. One accident
worth knowing: while a development build was on screen it was clicked by someone other than the assistant, which started
a full scan and a signature download; both were stopped and a confirmation dialog now guards the full scan.

### Installer test (real, on a Windows 11 machine)

`SENTRIX_0.1.0_x64-setup.exe /S` → exit 0; installed to `%LOCALAPPDATA%\SENTRIX` without administrator rights with the
engine bundled (`engine\clamav\clamd.exe`, `freshclam.exe`), a Desktop shortcut, a Start Menu shortcut and a
per-user uninstall entry (publisher "SENTRIX"). The installed app started, stayed up, used ~41 MB at idle, and
`--minimized` reduced the visible top-level windows by one (the main window), indirect evidence that login-start
stays hidden. No auto-start entry was created. `uninstall.exe /S` removed the program, both shortcuts and the registry
entry; user data under `%APPDATA%` is kept by design. The installed binary reports `NotSigned`.

## Known issues and limitations

* Detection is only as good as ClamAV's signatures plus a modest set of heuristics. No detection-rate measurement was made
  (only EICAR and synthetic fixtures were available/authorized). Expect false negatives.
* ClamAV needs ~1 GB RAM and ~7-10 s to load signatures; the first scan after start waits for it.
* The signature database (~300 MB) downloads on first run.
* Catalog-signed Windows binaries appear "not digitally signed" in the embedded-signature check.
* Windows Defender may delete or block EICAR test files in watched/test folders; the product reports Defender's block as a detection.
* Rate limiting trusts `X-Forwarded-For` for the per-IP limit (per-account limit is independent).
* DPAPI protects against other users and offline copying, not against code running as the same user.
* Real-time scanning happens after a file appears; it cannot prevent a download or an execution (the execution guard only marks confirmed-malicious files).
* Telegram bot features were verified against a local protocol test double, not live Telegram.
* Telegram reports are readable by Telegram. Account protection checks a file only after Telegram has delivered and SENTRIX has downloaded it.
* History for very large scans retains only files needing attention (counts are exact).
* The in-app UI was exercised by running the real built app and viewing it; there is no automated UI test suite.
