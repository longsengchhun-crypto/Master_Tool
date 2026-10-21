# Telegram integration

SENTRIX has three separate Telegram-related features. They have different coverage and different privacy properties, and
the app labels them separately. Read the **coverage** column before relying on any of them.

| Feature | What it does | Needs | Status |
|---|---|---|---|
| **Personal bot reports** | Sends scan results to a bot **you** created, in a chat only you can read | A bot token from @BotFather | Implemented. Tested against a local Bot API **test double**; **not** tested against live Telegram (no token was available) |
| **Files sent to your bot** | You send a file to your bot; SENTRIX scans it locally and replies | The bot above | Implemented. Same test status |
| **Telegram Desktop folder** | Files Telegram Desktop saved to disk are scanned like any download and labelled "Telegram Desktop" | Telegram Desktop installed | Implemented; tested with real ClamAV in a folder that stands in for Telegram's download folder |
| **Account monitoring** | Scan attachments in your chats, groups and channels from your account | Official MTProto client, your own `api_id`, a login | **NOT IMPLEMENTED.** See below |

SENTRIX does not claim to see every Telegram message or attachment. It cannot.

## Coverage, exactly

* **Telegram Desktop folder**: only files that exist on this computer's disk. Media you only viewed, or have not
  downloaded, is not scanned. SENTRIX cannot read Telegram's own settings, so it lists *candidate* folders (it finds
  `tdata`, the default `…\Downloads\Telegram Desktop`, and shows how many files each has) and you confirm one. Check it
  against Telegram Desktop → Settings → Advanced → Download path.
* **Bot submissions**: only files sent in the one chat you connected, at most 20 MB (the Bot API cannot download larger
  files; SENTRIX reports "not checked", never "clean"). Messages from any other chat or user are ignored and only counted.
  The computer must be on and SENTRIX running; updates Telegram holds while you are offline are processed on return
  (Telegram keeps them about 24 hours).
* **Reports**: delivered when Telegram accepts them. While Telegram is unreachable they wait in a durable queue.
* **Account monitoring**: nothing is monitored. Secret chats can never be read by any client except the device that holds
  them, and content not delivered to your account (for example in channels you have not opened, or messages deleted
  before they arrived) is not available to any client library.

## Setup (personal bot)

1. In Telegram open **@BotFather**, send `/newbot`, follow the prompts, copy the token.
2. Open your bot and press **Start** (a bot cannot message you until you do).
3. SENTRIX → **Telegram** → paste the token → **Connect**. SENTRIX asks Telegram which chat messaged the bot (asking you to
   choose if there are several, or to type a chat ID if none is found), sends a test message, and only then saves anything.

SENTRIX saves nothing until Telegram has confirmed the token (`getMe`) **and** accepted a test message to that chat. The
status "Connected" is only ever shown after that; later it shows the result of the last real test or delivery, including
Telegram's error text if it failed.

## What is stored, and where

| Item | Where | Protection |
|---|---|---|
| Bot token | `%APPDATA%\app.sentrix.desktop\telegram-bot.token` | Windows DPAPI (current user). Never in settings, logs, URLs, the console, or the UI after saving |
| Chat id, bot username | `settings.json` | Plain; the UI shows only the last 3 digits of the chat id |
| Notification queue | `protection.db` (SQLite) | Local file. Message text may name private files: it is erased as soon as Telegram accepts the message, rows are deleted after 7 days, and everything is deleted on disconnect |
| Telegram account session | `telegram-account.session` (framework only) | DPAPI; wiped on disconnect. **Never created in this build** |

Redaction: every error and log line passes through a redactor that removes anything shaped like a bot token, including
the `bot<token>` part of API URLs, before it reaches a log, the UI or the console. This is unit-tested with non-ASCII text.

## What leaves the computer

* To Telegram (api.telegram.org, HTTPS only): the token (as Telegram's API requires), the report text (file name,
  verdict, source, engines used, optionally the SHA-256), and for bot submissions the files you sent to your bot are downloaded
  from Telegram. **Telegram can read the reports.** Do not connect a bot you do not control.
* File contents are never sent anywhere.
* To an organization console, only if the device is enrolled: queue counts, whether a bot is connected, 24-hour delivery
  failure count and the account state. The schema is strict: file names, hashes, chat ids, tokens and message text are
  rejected by the API.

## Untrusted input

File names and sender names come from outside. In reports they are HTML-escaped and have bidirectional-override and
control characters removed. Submissions are accepted only from the connected chat id; the file is downloaded to an isolated
temporary directory, size-checked against both Telegram's declared size and the bytes received, scanned, and deleted.

## Delivery guarantees

* Reports go through a durable outbox: retried with exponential backoff (5 s → 1 h), `retry_after` from HTTP 429 honoured,
  de-duplicated per file, verdict and day, bounded (1 000 pending; beyond that new reports are dropped **and an event is
  recorded**), and recovered after a crash or restart.
* A delivery failure never changes a verdict or blocks scanning; they run on separate threads and the outbox is
  independent of the scan queue.
* After the maximum number of attempts a message is marked "gave up" and counted, not silently dropped.

## Troubleshooting

| Symptom | Cause / action |
|---|---|
| "Open your bot in Telegram, press Start, then try again" | The bot has no chat yet: open it in Telegram, press Start, then press Connect again |
| Test fails with an unauthorized error | Token revoked or mistyped; get a new one from @BotFather (`/token`) |
| Test fails with a network error | Telegram is blocked or unreachable from this network; reports stay queued |
| Nothing arrives after sending a file to the bot | Submissions toggle off, wrong chat, SENTRIX not running, or file over 20 MB |
| Two programs use the same bot | Only one program can read a bot's updates; use a bot dedicated to SENTRIX |

## Removing your credentials

**Telegram → Disconnect** wipes the token file, clears the chat id, bot name and queued
messages, and stops delivery and submissions. To make the old token useless everywhere, also send `/revoke` to
@BotFather. Deleting the SENTRIX data folder removes everything else it stored.

## Account-level monitoring: why it is not implemented

A user account can only be reached through an MTProto client authorized with the user's **own** `api_id`/`api_hash` and a
phone or QR login (<https://core.telegram.org/api/auth>). Reasons it is not built here:

1. No test Telegram account or `api_id` was available, so login, update streams and downloads could not be verified.
   Shipping untested code that handles a user's account session would be irresponsible.
2. The only maintained pure-Rust MTProto client considered (`grammers`) states that it has not been security-audited and
   its repository is archived. TDLib (official) is a large native dependency with no vetted Rust binding here.
3. Telegram states that accounts using unofficial API clients are automatically placed under observation. Users must be
   told that; it is a real consequence.

What exists: a DPAPI-protected session vault, a minimal attachment-ingestion path that feeds the same scan queue (no
field for message text exists), consent/state handling, and a transport trait, all unit-tested. What is missing: the
transport itself. **Next steps** to finish it: choose an audited client (TDLib recommended), have each user register
their own `api_id` at my.telegram.org, test against a dedicated test account, and add it behind
`TelegramAccountTransport`. SENTRIX will never ask for a Telegram password, login code or two-step password inside its
own windows; login would go through the client's QR/phone flow with the code typed into Telegram's own protocol, and
only with explicit, separate consent.

## Tests

`cargo test -p sentrix-core --test telegram` (9 tests) and `--test service` exercise the client and the pipeline against
`tests/common/mod.rs`, a local Bot API test double: sending, rate limits, outages, dropped connections, redaction,
sender validation, oversized and lying file sizes, and cleanup. **They prove the protocol handling, not live Telegram.**
Before relying on the integration, connect a real bot yourself and use "Send a test message".
