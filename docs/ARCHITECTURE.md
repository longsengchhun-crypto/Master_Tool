# Architecture

## Components

```
                        ┌────────────────────────────── user's PC ──────────────────────────────┐
                        │  SENTRIX desktop (Tauri 2)                                              │
                        │  ┌─────────────┐  invoke   ┌────────────────────────────────────────┐  │
                        │  │ React UI    │──────────▶│ Rust shell (commands.rs)               │  │
                        │  │ (sandboxed  │◀──events──│  state, settings, history, tray, sync  │  │
                        │  │  webview)   │           └──────────────┬─────────────────────────┘  │
                        │  └─────────────┘                          │ in-process calls            │
                        │                                 ┌─────────▼──────────┐                  │
                        │                                 │ sentrix-core (Rust)│                  │
                        │                                 │ identify · hash    │                  │
                        │                                 │ heuristics · archive                  │
                        │                                 │ authenticode · verdict                │
                        │                                 │ quarantine · monitor                  │
                        │                                 └───────┬────────────┘                  │
                        │                  INSTREAM over 127.0.0.1 │                              │
                        │                                 ┌───────▼────────┐                      │
                        │                                 │ clamd (ClamAV) │ separate GPL process │
                        │                                 └────────────────┘                      │
                        └───────────────┬─────────────────────────────────────────────────────────┘
                                        │ HTTPS: enroll, heartbeat, (opt.) metadata, update feed
                        ┌───────────────▼────────────────────────────────────────────────────────┐
                        │ SENTRIX Console (Next.js)  ── REST API ──▶ PostgreSQL                   │
                        │  public site · admin UI · /api/admin (cookie+CSRF+MFA) · /api/device    │
                        │  (bearer token) · /api/updates (signed feed) · audit log (hash chain)   │
                        └─────────────────────────────────────────────────────────────────────────┘
```

## Key decisions

| Decision | Why |
|---|---|
| **Security engine is a separate Rust crate** (`sentrix-core`) with no UI dependency | Testable in isolation (CLI, integration tests); the UI can never alter a verdict. |
| **ClamAV runs as `clamd`**, fed over INSTREAM on loopback | One signature load (instead of ~10 s per file), no paths handed to the engine, GPL code kept in a separate process. A Windows Job Object kills it if SENTRIX dies. |
| **One open file handle per scan**; every layer reads from it | A file swapped on disk mid-scan cannot make layers disagree about content. |
| **Verdict logic in one place** (`verdict.rs`) with documented rules and tests | The product's honesty contract is a single, auditable function. |
| **Next.js hosts site, console and API** (no separate `apps/api`) | One deployable, one auth model. The spec allowed this; the API is still a distinct route tree with its own contracts (`packages/contracts`). |
| **Postgres with forward-only SQL migrations** | Simple, auditable, no ORM. All queries are parameterized. |
| **Device auth by bearer token (HMAC-stored); admin auth by cookie + CSRF + MFA** | Different threat models, different mechanisms. Device routes ignore cookies; admin routes ignore bearers. |
| **Remote control is a closed enum** (`scan_quick`, `intel_update`, `app_update`) | Makes arbitrary command execution structurally impossible, not merely forbidden. |
| **Console state is reported by devices, never assumed** | A silent or failing device shows as such. Nothing defaults to "healthy". |

## Data flow: scanning a file

1. UI calls `scan_paths` (validated absolute paths only).
2. `Scanner::scan_file` refuses links, opens once, reads the head, hashes (streaming), consults the cache keyed by
   *content hash + engine version + signature version*.
3. Content-based identification, extension-mismatch and double-extension checks.
4. Authenticode verification (PE), EICAR test detector, ClamAV (INSTREAM), then static analyzers / archive
   inspection (each under `catch_unwind`).
5. `verdict::decide` turns checks + findings into a verdict. Missing, failed or partial checks can never be CLEAN.
6. The app applies the user's policy (auto-quarantine only for signature-engine MALICIOUS, only if enabled),
   stores the report locally, notifies once per file hash.

## Data flow: automatic protection (Phase 2)

```
 folder event (notify) ─▶ settle (1.5 s, size/mtime stable) ─▶ durable job queue (SQLite, WAL)
        ▲                                                         │ coalesce per path · dirty flag · backoff
 startup + 10-min reconcile (finds files missed while closed)     ▼
                                                           workers ─▶ Scanner (real engine) ─▶ verdict
                                                                           │
                         policy: auto-quarantine │ execution guard │ warn ◀┘
                                                                           │
                                   history/UI events ◀─ hooks              ▼
                                                              outbox (SQLite) ─▶ Telegram Bot API (the shared SENTRIX bot via the relay, or the user's own bot)
 bot getUpdates ─▶ owner check ─▶ isolated temp download ─▶ scan ─▶ reply     (separate thread; never alters a verdict)
```

* `services/scanner/src/queue.rs`: jobs, file state, outbox, events. Active jobs are unique per path; a change during a
  scan sets `dirty` so the result is marked stale and the file is scanned again; jobs stuck in `scanning` for 10 minutes
  are recovered; 7 attempts with backoff, then "could not be checked", never CLEAN. Queue and outbox are bounded.
* `service.rs`: `ProtectionService` owns monitor, workers, reconciler, health watcher, outbox sender and bot poller.
  The desktop crate only supplies hooks (history, notifications, quarantine, tray).
* `telegram.rs` / `notify.rs`: Bot API client and report formatting. `account.rs`: key vault, attachment gate and the UNABLE TO VERIFY report; `account_td.rs`: personal-account worker on TDLib; `tdjson.rs`: pinned-hash loader for TDLib's JSON interface. `guard.rs`: execution guard. `telegram_desktop.rs`: folder discovery.
* Console receives only counts/booleans for queue and Telegram health, under strict schemas.

## Branding and configuration

"SENTRIX" is a working name and is kept in a few well-defined places so it can be changed without touching logic:

| What | Where |
|---|---|
| Product name, identifier, publisher, installer metadata | `apps/desktop/src-tauri/tauri.conf.json` (`productName`, `identifier`, `bundle.publisher`) |
| Logo and app icon source | `apps/desktop/brand/*.svg`; `npm run icons -w @sentrix/desktop` regenerates ICO/ICNS/PNG |
| Colors and typography | CSS tokens at the top of `apps/desktop/src/index.css` and `apps/admin/src/app/globals.css` |
| Download URLs, release metadata, signing status | Console → Releases (database), not code |
| Licensing plans/seats/expiry | Console → Licenses (database) |
| Support contact | `NEXT_PUBLIC_SUPPORT_EMAIL` |
| Update server | Enrolled console URL, or `SENTRIX_UPDATE_BASE_URL` at compile time |

User-visible strings that say "SENTRIX" are inline in the React components; a rename needs a search-and-replace
(there is no i18n layer yet).

## Where state lives

| State | Location | Protection |
|---|---|---|
| Settings, history, counters | `%APPDATA%\app.sentrix.desktop\*.json` | Atomic writes; corrupt files fall back to safe defaults |
| Quarantine vault | `…\quarantine\{blobs,meta,audit.jsonl,.key}` | ChaCha20-Poly1305; key wrapped by DPAPI; HMAC'd metadata; hash-chained audit |
| Device credential | `…\enrollment.json` | DPAPI-protected; discarded if undecryptable |
| Scan queue, notification queue, events | `…\protection.db` (SQLite, WAL) | Local; message text erased on delivery, rows pruned after 7 days |
| Telegram bot token | `…\telegram-bot.token` | DPAPI (current user); wiped on disconnect |
| Signatures | `…\clamav-db\` | Signed `.cvd` files verified by ClamAV |
| Console data | PostgreSQL | See [OPERATIONS.md](OPERATIONS.md) |

## Privacy boundaries

Local by default. The only things that leave a device are listed in the in-app Account page and the privacy policy:
signature downloads (no file info), an update check (version + platform + random install id), and, **only if enrolled**,
status heartbeats; **only if the user also enables health reporting**, scan counts plus hash + verdict per finding.
File contents are never transmitted; file names only if both the user's reporting switch and the organization policy allow it.

## Visual design

One design language across the desktop app, console and site (`index.css` / `globals.css` hold the tokens):

* Built for people who are not developers: seven destinations (Home, Scan, History, Quarantine, Protection, Telegram, Settings),
  one status on Home, a short "Needs attention" list of things the user can act on, and technical detail behind
  "Details"/"Technical details" disclosures that are closed by default.
* The accent is the logo's teal-to-blue. The navigation rail is always dark navy (the logo's own background); the working
  area follows the theme. Segoe UI Variable, flat surfaces with soft elevation, 8-12 px radii, status colour only for status.
* A pending confirmed-malicious file overrides a "protected" headline everywhere (Home, sidebar); the interface never shows a
  reassuring state while something dangerous is waiting.
* Both themes are authored separately; every text-on-background token pair in use was computed at 4.5:1 or better.
* Brand: the SENTRIX shield-S mark (`apps/desktop/brand/*.svg`, unchanged; `npm run icons -w @sentrix/desktop` regenerates PNG/ICO/ICNS).
