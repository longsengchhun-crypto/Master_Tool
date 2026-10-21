# Phase 2 gap analysis (audit of the repository before Phase 2 work)

Audited from the actual code and the Phase 1 test results, not from the earlier plan.

## What already works and is preserved

* Real engine: ClamAV 1.5.4 as supervised `clamd` + EICAR test detector + heuristics + Authenticode + archive limits.
* Verdict rules (CLEAN only when the signature engine completed), encrypted quarantine, confirmed restore.
* Folder monitoring via OS file events with a settle delay (`monitor.rs`), simple scan per event, auto-quarantine policy.
* Console, licensing, enrollment, policy sync, closed-set remote requests, signed updates, retention, audit chain.

## Gaps against the Phase 2 requirements

| # | Requirement | Current reality | Gap |
|---|---|---|---|
| A.1 | Reliable background monitoring | Events → one inline scan on the monitor thread | No durable queue; no retry/backoff for locked or transient failures; no dedupe beyond the content cache; **a restart loses everything that arrived while SENTRIX was off**; missed events are never reconciled; no stale-result tracking when a file changes after scanning |
| A.2 | Honest real-time status | Realtime = "watching list exists" | No queue depth, no failed/stuck jobs, no per-folder health, no "will it resume after reboot?", no recent protection events |
| A.3 | Pre-execution protection | Scan after the file lands; `blocked` always false | No enforcement at all for a confirmed-malicious file that is not quarantined |
| C | Telegram Desktop | Not present | Folder discovery, source labels, Telegram-specific stats |
| E | Personal Telegram bot | Not present | Client, secure token storage, guided setup, reliable delivery, preferences |
| F | File submission to the bot | Not present | Sender validation, size/rate limits, isolated temp, cleanup |
| G | Report-delivery reliability | Not present | Persistent outbox with retries, dedupe, rate-limit handling |
| D | Telegram account protection | Not present | **See decision below** |
| H | Dashboard | Phase 1 pages | Queue/health/Telegram/events panels; page set per Phase 2 spec |
| I | Console | Fleet health, findings | Queue health, Telegram integration health (counts only), org switch to disable integrations |

## Decision: Telegram account-level monitoring

Official documentation (https://core.telegram.org/api/auth, /api/qr-login, /api/obtaining_api_id) shows a user account can
only be accessed through an MTProto client authorized with the user's own `api_id`/`api_hash` and a phone/QR login.
Findings that drive the decision:

1. Telegram states that accounts logging in through unofficial API clients are automatically placed under observation:
   a real consequence for the user that must be disclosed.
2. The only maintained pure-Rust MTProto client found (`grammers`) says its code **has not been audited**, advises reviewing
   its crypto before security-critical use, and its GitHub repository is archived. TDLib (official) is a large native
   dependency with no Rust binding vetted here.
3. No test Telegram account or `api_id` is available in this environment, so a live login, update stream, and attachment
   download **cannot be verified**.

Therefore Phase 2 builds the *safe, testable parts* of account monitoring and refuses to fake the rest:

* **Built and tested:** DPAPI-protected session vault (with wipe-on-disconnect), a privacy-minimal attachment ingestion
  pipeline that feeds the same scan queue (no message text field exists in its data model), the consent text, the state
  machine and UI, and a `TelegramAccountTransport` trait.
* **Not built (BLOCKED):** the MTProto transport itself. The UI says "Not available in this build" with the exact reason,
  and no credential entry is offered, so nothing is collected for a feature that cannot run.

## Decision: pre-execution protection

A kernel minifilter is a separate, signed-driver project (Phase 1 conclusion unchanged). The strongest *user-mode,
OS-supported, reversible* measure available is an NTFS **deny-execute ACE** on a file confirmed MALICIOUS by a signature
engine (`icacls … /deny *S-1-1-0:(X)`): the OS then refuses to launch the executable (verified in tests by actually trying
to run a guarded copy). Limits: it does not stop interpreters that merely *read* a script, does not stop a document from
being opened, and a process running as the same user can remove it. It is documented as "execution guard", not
"pre-download interception".

## Decision: background service

SENTRIX runs as a per-user tray application that starts at login (opt-in, with consent). It is **not** a Windows service:
a service would need elevated installation and a split-process architecture. The Real-Time Protection page therefore shows
whether protection will resume after a restart (login start enabled or not) instead of implying it will.
