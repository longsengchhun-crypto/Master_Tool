# Phase 3 gap analysis: Group Shield and personal Telegram account protection

Written from the repository as it is, before and after the work. Where the request assumed something the code does not have,
that is stated.

## Corrections to the starting assumptions

| Assumption in the request | What the repository actually has |
|---|---|
| "The SENTRIX bot already exists and is connected to our software" | There is **no SENTRIX-operated bot**. Phase 2 deliberately built *each customer's own bot* (they create it with @BotFather; the token is DPAPI-protected on their PC). |
| An existing "webhook or polling worker", "job queue", "database" on a server | One **desktop** polling worker (`sentrix-tgbot`) per installation, a local SQLite queue/outbox (`protection.db`), and a local scanner. The Next.js console has **no** Telegram code and no scanner; it receives counts only. |
| Group Shield "integrated with the admin dashboard" with scan history per group | Group history stays on the owner's PC (hashes and verdicts only). The console shows aggregate counts per device/organization. |
| A personal-account integration "alongside" the bot | The account transport is **not implemented** (see below). |

Consequence: Group Shield is built on the owner's desktop with the owner's bot. See [GROUP_SHIELD.md](GROUP_SHIELD.md).

## Audit summary

* Bot client, token vault, redaction, outbox, bot worker, scanner, quarantine, execution guard, console schemas and tests
  were inspected and reused. No duplicate worker or webhook was added: Group Shield is handled by the same worker, which now
  serves the owner's private chat and groups, advancing Telegram's offset only after an update was fully handled.
* Existing behaviour preserved. One existing test (`only_the_configured_owner_can_submit_files_to_the_bot`) had asserted that a
  group message was counted as a rejected owner submission; groups now take their own path (ignored when Group Shield is off),
  so that test was updated to assert the property that matters (nothing scanned, no reply, protection never switched on).

## Group Shield: status

Implemented and tested against a local Bot API test double and real ClamAV (details in GROUP_SHIELD.md). Not tested against
live Telegram. Coverage is limited by Telegram (privacy mode, 20 MB, documents only, no channels) and by the computer being on.

## Personal Telegram account protection: status

**Update 2026-10-22: implemented on TDLib (see [TELEGRAM_ACCOUNT.md](TELEGRAM_ACCOUNT.md)).** The owner confirmed an `api_id`/`api_hash`
and a test account are available and decided that accounts with a two-step password are **unsupported** (no password is ever
requested). What changed: TDLib loaded at runtime through a SHA-256-pinned JSON binding; QR-only login; encrypted TDLib database
whose key is DPAPI-protected; attachment pipeline with the earlier gate semantics; desktop UI; console counts.

**Honest status:** the real library loads and talks to Telegram's servers (rejecting an invalid `api_id` with `API_ID_INVALID`),
and the state machine is unit-tested against a scripted TDLib. A real QR login with a real account and a real received
attachment has **not** been run. The `live_` test for it exists and needs the credentials and a person scanning the code.

The remainder of this section describes the position *before* that update and is kept as the record of why it was deferred:



**Not implemented. The live transport cannot be built or verified in this environment.**

What exists and is tested (Phase 2): a DPAPI-protected session vault with wipe, an attachment gate with chat-category switches
(private chats on, groups and channels off by default), size limit and backpressure, scanning through the same engine and report
pipeline, and the transport trait. There is deliberately no field for message text, sender name or chat title.

What is missing, and why it is not faked:

1. **A Telegram client for user accounts.** Only MTProto clients can read a user account's messages. Options considered:
   * *TDLib* (Telegram's official library): the right choice (QR login, update stream, file download with sync state). It is a
     large native dependency; it needs integration, packaging and a Rust binding that must be vetted.
   * *`grammers`* (pure Rust): states that its code is not security-audited; not suitable for handling account sessions.
   * Writing MTProto ourselves: not acceptable for security-sensitive code.
2. **A real `api_id`/`api_hash`** (each customer, or SENTRIX as an application, registers at my.telegram.org). None is available here.
3. **A dedicated Telegram test account** to verify login (QR), sessions, update delivery, downloads, expiry and revocation. None is
   available, and shipping untested code that holds an account session would be irresponsible.
4. **Two-step password.** QR login for an account with a cloud password requires the client to ask for it. The product rule is
   that SENTRIX never collects Telegram passwords. Either such accounts are unsupported, or a deliberate exception is designed
   (a dedicated dialog that hands the password straight to the library, never stores or logs it). That is a decision for the
   product owner, not something to hide inside an implementation.
5. Telegram states that accounts logging in through unofficial API clients may be placed under observation; users must be told.

What would be covered even with a working transport (and what would not): messages and attachments the authorized client can
actually download. Not secret chats, not content never delivered to that account, not protected-content media. The earliest
point is **after download/synchronization**: Telegram does not expose file bytes before the client fetches them, so there is no
pre-download scanning. The earliest supported warning is when the file arrives in the Telegram Desktop download folder (already
implemented via folder monitoring) or, for an account transport, when its download completes.

### What is needed from the owner to finish it

* An `api_id`/`api_hash` (from my.telegram.org) and a dedicated test Telegram account.
* A decision on TDLib as the client and on how to treat accounts protected by a two-step password.
* Then: bind TDLib behind `AccountTransport`, QR login UI, encrypted session in the existing vault, live tests.

## Before download, before opening, before extraction

| Stage | Real today | Not real |
|---|---|---|
| Before download | Nothing. Telegram gives file bytes only after download | Pre-download scanning of Telegram files |
| Earliest warning | Folder watcher scans Telegram Desktop downloads once they settle (partial downloads are ignored until stable); bot/group documents are scanned in memory before anything is saved to the user's disk | Any claim that a folder watcher stops a file being opened first |
| Before open/execution | Confirmed-malicious files can be quarantined, or get a reversible deny-execute permission (verified by read-back and by a test that tries to launch the file); changed files invalidate old verdicts | Blocking arbitrary programs (needs a signed driver); stopping a user opening a document |
| Before extraction | Archives are inspected in memory with depth/size/ratio limits, path traversal and bombs are detected, encrypted archives are UNABLE TO VERIFY | Intercepting extraction inside third-party tools; a "safe extract" feature |
| Defender | Untouched | |

## Other requested items

* Per-user notification routing, bot token handling, delivery status, retries, dedupe, rate limiting, expired-token handling:
  already implemented in Phase 2 (outbox).
* Account connection UI, chat-category controls and "last synchronization" display: added with the transport (Telegram → Your account).
* Admin dashboard: account state (connected/expired), files checked, threats and not-checked counts are reported; group counts as before.
