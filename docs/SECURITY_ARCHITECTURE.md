# Security architecture and threat model

## Assets

1. The user's files and system (a scanner that is itself exploitable defeats its purpose).
2. Integrity of verdicts (a false CLEAN is worse than no scanner).
3. Quarantined malware (must not run, must not leak).
4. Console data: device inventory, findings metadata, licenses, audit trail.
5. Credentials: admin passwords/TOTP seeds, device tokens, license keys, update-signing key, DB credential.

## Trust boundaries

| Boundary | Untrusted side | Control |
|---|---|---|
| Scanned file → engine | The file (fully attacker-controlled) | Never executed; memory-only archive inspection; hard limits; `catch_unwind`; ClamAV in a separate process fed over a stream |
| Webview → Rust | The UI | No generic fs/shell plugin; every command validates inputs; strict CSP |
| Desktop → console | Network | HTTPS only (loopback exempt for development); bearer token; strict schemas |
| Console → desktop | Console (or whoever compromises it) | Closed job enum, policy schema without commands/paths, updates verified against a baked-in public key, user notified for each action, user can leave management |
| Browser → console | The browser | `__Host-` HttpOnly Secure SameSite=Strict cookie, CSRF token, Origin check, CSP, no inline user data |
| Org A → Org B | A tenant | Tenant scope in SQL and in the authorization choke-point; out-of-scope IDs return 404 |

## Threats and mitigations (STRIDE-oriented)

| # | Threat | Mitigation | Evidence |
|---|---|---|---|
| T1 | Malicious file crashes/hangs the scanner | Limits, `catch_unwind`, per-entry bounds, cancel-safe workers | archive/heuristics tests, cancel-deadlock test |
| T2 | Decompression bomb / zip-slip / nested archive | Ratio + size + depth + entry limits; no extraction | `archive::tests::*` |
| T3 | Extension spoofing (`invoice.pdf.exe`, EXE as JPG) | Content-based identification, mismatch + double-extension findings | `identify::tests`, engine suite |
| T4 | Symlink/junction redirection of scan or quarantine | Links refused in scan, walk and restore (Windows reparse points included) | junction tests (symlink tests skip without privilege: see limitations) |
| T5 | Path traversal via quarantine IDs or original names | IDs must parse as UUID; names sanitized; `create_new` never overwrites or follows links | `quarantine::tests::*` |
| T6 | Tampered quarantine metadata/blob/audit | HMAC metadata, AEAD blobs, hash-chained log | tamper tests |
| T7 | Restoring malware by accident | MALICIOUS restore requires typed confirmation; suspicious restore is policy-controlled | tests + UI |
| T8 | False "protected" display | Status derived from live engine state; defaults to "cannot verify" | `compute_protection`, UI |
| T9 | Credential stuffing / brute force on admin login | Per-IP and per-account limits (account limit holds across IP rotation), argon2id, timing-equalized unknown users | security suite |
| T10 | Session theft/fixation | Random 256-bit token, only SHA-256 stored, destroyed on logout/deactivation/MFA reset | security suite |
| T11 | CSRF / cross-origin requests | CSRF token + Origin check + SameSite=Strict | security suite |
| T12 | Privilege escalation between roles | Central `authorize()`, default-deny matrix, reauth for sensitive actions | RBAC unit + integration tests |
| T13 | Cross-tenant access (IDOR) | SQL scoping + 404 on out-of-scope IDs | cross-organization tests |
| T14 | SQL injection | Parameterized queries only; strict schemas | injection tests |
| T15 | DB leak exposes credentials | Passwords argon2id; device tokens, enrollment codes and license keys stored as HMAC (pepper in env); TOTP seeds AES-256-GCM sealed; sessions stored hashed | unit + integration tests |
| T16 | Audit-log tampering | Append-only trigger + hash chain, verifiable via API | tamper-detection test |
| T17 | Rogue/compromised console pushes malware via update | Updater verifies minisign signature against baked-in key; installer SHA-256 shown; unsigned releases cannot be staged | `update_signature` tests, release safety tests |
| T18 | Console used as remote shell | No such feature; job kinds are a closed enum; unknown kinds rejected at API, DB (`CHECK`) and client | tests |
| T19 | Over-collection of user data | Metadata-only schemas (strict, unknown keys rejected); file names gated by policy + user consent | tests |
| T20 | Secrets in binaries/repo | `.env` gitignored, device builds contain only the update **public** key; provider keys server-side only | secret-scan CI, review |
| T21 | clamd orphaned after crash | Windows Job Object kill-on-close | engine tests (no leaked process) |
| T22 | Accidental heavy scan / memory exhaustion | Confirmation dialog; streaming discovery; bounded retained results | scanner tests |
| T23 | Bot token leaks (logs, URLs, UI, console, Git, settings file) | DPAPI-protected file, wiped on disconnect; redactor on every error/log path (UTF-8 safe); token never leaves via the console schema; masked/never re-displayed | `telegram` unit tests (token shape, redaction incl. non-ASCII, vault, wipe) |
| T24 | Someone else messages the user's bot to inject files or commands | Only the connected chat id is accepted; others are ignored and counted; no command execution; size checked against declared and received bytes; isolated temp copy deleted after scan | `tests/telegram.rs`, `tests/service.rs` |
| T25 | Hostile file/sender names in reports (HTML injection, bidi spoofing, control chars) | HTML escaping, bidi/control stripping, 4 096-char cap | `telegram` unit tests |
| T26 | Telegram or network outage loses or reorders reports, or blocks scanning | Durable SQLite outbox, backoff, 429 `retry_after`, dedupe, crash recovery; separate thread; delivery state never touches verdicts | `queue`, `telegram`, `service` tests |
| T27 | Reports retain private file names indefinitely | Message text erased on delivery, rows deleted after 7 days and on disconnect | `queue::tests::delivered_text_is_erased_and_old_rows_pruned` |
| T28 | Files lost or "scanned clean" after crash, lock, restart or change during scan | Durable job queue, coalescing, `dirty` flag, stale results, retry with backoff, stuck-job recovery, startup reconciliation; failures never become CLEAN | `queue` + `service` tests (real ClamAV pipeline) |
| T29 | Fake "connected" or "protected" status | Connection state comes from Telegram's response; protection state from monitor/queue/engine health; "could not check" is a separate, visible list | UI + tests |
| T30 | Execution guard abused to deny access to arbitrary files (path injection, links) | Applied only to a hash-verified MALICIOUS file; absolute `icacls`, argv-only; links refused; read-back verified | `guard` tests |
| T31 | Telegram account credentials harvested | **No credential entry exists.** Account transport is not implemented; the session vault only holds a library-produced session blob, DPAPI-protected, never a password/code/2FA | `account` tests; see [TELEGRAM.md](TELEGRAM.md) |
| T33 | A non-administrator (or an administrator of another group) changes a group's protection | Every configuration command checks the sender with a live `getChatMember` for that exact group; display names and text are never trusted; anonymous administrators are refused | `tests/groups.rs` |
| T34 | Automatic deletion switched on by accident or by the wrong person | Off by default; two steps by the same named administrator within 5 minutes; delete permission checked at request, at confirmation and again at the moment of deletion; only MALICIOUS can trigger it; success is claimed only when Telegram returns ok | `tests/groups.rs` (incl. real ClamAV) |
| T35 | One group reads or alters another group's settings or history | All rows keyed by chat id, every query filters on it; per-group rate limits and counters | `groups_cannot_see_or_change_each_others_settings_or_history` |
| T36 | A flood of files or commands exhausts the scanner or hides a threat | 10 scans/min/group (skipped ones are declared), 15 messages/min/group with headroom for malicious alerts, single sequential worker, offsets advanced only after handling | `a_flood_of_files_is_rate_limited…` |
| T37 | Group files treated as clean when they could not be seen or checked | Privacy-mode blindness is surfaced in `/status` and the app; oversized, inaccessible, encrypted or engine-less cases are UNABLE TO VERIFY / not checked, never clean | `a_file_that_could_not_be_checked_is_never_reported_as_clean` |
| T38 | Group names, chat ids, member names or file names reach the console | Strict `groups` heartbeat schema (counts only); no such column exists; device detail/aggregates are tenant-scoped | `tests/security.test.ts` Group Shield block |
| T32 | Console learns message content or secrets | Strict heartbeat schemas (counts/booleans only); org policy can disable bot/account features | `tests/security.test.ts` Phase 2 block |

## Out of scope / residual risk (see also [CHECKLIST.md](CHECKLIST.md))

* **No kernel execution blocking**: SENTRIX cannot stop a program the user launches. It can add a reversible deny-execute
  permission to a confirmed-malicious file (execution guard), nothing more.
* **Telegram can read reports** sent to the user's bot; the user chose the bot, but must trust it and Telegram.
* **Telegram account monitoring is not implemented**; the bot and Desktop folder cover only what they can see.
* **Tray app, not a service**: no protection while SENTRIX is not running.
* **ClamAV vulnerabilities**: ClamAV parses hostile files in a native process. Keep it updated (1.5.4 contains fixes for
  several 2026 parser CVEs). It runs unprivileged as the user, not sandboxed beyond that.
* **Local malware with the user's privileges** can read the DPAPI-protected key and quarantine vault as that user. DPAPI
  protects against other users/offline copying, not against code running as the same user.
* **Dev updater key** in this repo's config: replace with a production key before release ([KEY_MANAGEMENT.md](KEY_MANAGEMENT.md)).
* **Rate limiting trusts `X-Forwarded-For`** only as advisory; deploy behind a proxy that sets it, or the per-IP limit degrades
  (per-account limits still apply).
* **TLS** is terminated by the hosting platform; HSTS is sent.
* The unsigned installer will trigger SmartScreen warnings. That is correct behaviour and must not be bypassed.
* No third-party penetration test has been performed.
