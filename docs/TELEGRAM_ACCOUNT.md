# Telegram protection from the user's own account (the default way)

This is how SENTRIX protects Telegram **with nothing running on the author's machine**. Everything happens on the user's own
computer, through the user's own Telegram account, using Telegram's official client library (TDLib). No bot, no relay and no
server of ours is involved, so there is nothing to host and no cost per user.

* **What it checks:** files in private chats and in **every group the user is a member of** (administrator or not), plus
  channels and photos/video/voice if the user switches them on.
* **Where results go:** the user makes a group called **Scan History** (any capitalisation, "Scans History" also works) and
  SENTRIX posts each result there **from the user's own account**. The user can add other people to read it. A user can have
  **many** Scan History groups; they share a name, so SENTRIX numbers them (**#1, #2, ...**) and says its number in each room
  once. Each group the user is in can be pointed at one Scan History group, or at all of them (the default), in the
  app under Telegram > Your groups. Many groups can share one room.
* **Without a Scan History group:** dangerous and suspicious results (and nothing else, to avoid noise) go to the user's
  **Saved Messages**.
* **The protected group stays silent:** SENTRIX never writes in the group it is checking, and never checks the Scan
  History groups themselves.
* **Pacing:** results are posted one at a time, at least about a second apart, so a burst of files cannot make Telegram throttle
  the account. At most 200 results wait; beyond that the oldest is dropped and an event is recorded.
* **Limits that follow from this design:** it works **only while the user's computer is on and online**; accounts with a
  two-step (cloud) password are not supported (no password is ever collected); the check starts after a file downloads.
* **Messages come from the person, not from a bot.** Everyone in a Scan History group sees the user's account posting there.

The sections below describe the engine itself. The older "report to a bot" wording still applies if the user also connects their
own bot (Telegram > More ways).

> **Test status, stated plainly.** The transport is real and loads Telegram's real library, which has talked to Telegram's
> real servers in testing. A complete **QR login with a real account, and a real attachment received and scanned, has not
> yet been run**, because that needs the API credentials and a phone to scan the code. The one test that does it exists
> (`live_qr_login_then…`, see "Running the live test") and has not been executed. Until it passes, treat
> everything below that depends on a signed-in session as **implemented and unit-tested, not yet proven live**.

## How it works

1. The user opens **Telegram → Your account**, reads what SENTRIX can and cannot cover, ticks an explicit consent box and
   presses *Connect with QR code*. There is no phone-number, login-code or password field anywhere.
2. A QR code is shown. The user approves it in Telegram on their phone (*Settings → Devices → Link Desktop Device*).
3. SENTRIX is now an extra device on the account. TDLib delivers each incoming message. For a file attachment SENTRIX has,
   before downloading anything, only its **name, size, type and the chat category**.
4. Eligible files are downloaded into an isolated folder, checked by the same real engine (ClamAV, heuristics, archive
   inspection), and the **downloaded copy is deleted whatever the result**. A report is posted from the user's own account into their Scan History group (or Saved Messages), and also goes to the
   user's own bot if they connected one. Only the text of the result leaves the computer.
5. Files that cannot be checked are reported **UNABLE TO VERIFY** with the reason. Never clean.

## What is and is not covered

| Chat category | Status |
|---|---|
| Private chats (including chats with bots) | Supported, **on** by default |
| Basic groups and supergroups | Supported, **off** by default (user switch) |
| Channels | Supported, **off** by default (user switch) |
| Secret chats | **Not supported.** Secret chats are not enabled in the client; Telegram does not deliver them to other devices |
| Chats with *protected content* (saving blocked) | **Not downloaded** (SENTRIX does not work around it). Reported UNABLE TO VERIFY |

| Attachment | Status |
|---|---|
| Documents (executables, scripts, archives, Office/PDF, everything sent "as a file") | Supported |
| Photos, videos, audio, voice and video messages, animations | Supported, **off** by default (user switch) |
| Text, stickers, polls, locations | Not attachments; ignored |
| Files over 200 MB | Not downloaded; reported UNABLE TO VERIFY |
| Encrypted archives, archive bombs, path traversal | Handled by the existing archive inspector: reported UNABLE TO VERIFY / flagged |

Not covered at all: anything while the computer is off or offline; content Telegram never delivered to this account;
messages deleted before they arrived. **No protection is complete and SENTRIX does not claim it.**

## Before download, before opening, before extraction

| Stage | Real? | Detail |
|---|---|---|
| **Before download** | **No.** | Telegram gives file *bytes* only on download. SENTRIX sees only name/size/type first and can decline to download (too large, protected, category off). It never claims pre-download scanning |
| Earliest content check | After download | Immediately when the download completes, before the user is told anything; the file is in SENTRIX's isolated folder |
| **The user's own copy** | Not controlled by this feature | If the user opens a file in Telegram itself, Telegram stores it where *it* chooses. The existing Telegram Desktop folder watch scans those, **after** they land. A folder watcher cannot stop a file being opened first |
| Before open / execution | Partial, existing | Confirmed-malicious files in watched folders can be quarantined or given a reversible deny-execute permission (read back and tested). Not a kernel driver; arbitrary programs cannot be blocked |
| Before extraction | Partial, existing | Archives are inspected in memory with depth/size/ratio limits, bombs and path traversal detected, encrypted archives UNABLE TO VERIFY. SENTRIX does **not** intercept extraction inside other programs |

## Credentials and sessions

* **Sign-in is QR only.** The phone number, SMS/Telegram code and two-step password are never requested, received, stored,
  logged or sent anywhere by SENTRIX. A QR approval is done inside Telegram on the user's phone.
* **Accounts with a two-step (cloud) password are not supported.** Telegram's QR flow would require the password to be
  typed into the desktop client. SENTRIX refuses: it signs the attempt out, erases local data and says so. (Decision
  recorded 2026-10-22: strict reading of the "never collect passwords" rule.)
* **API ID/hash** identify *the application* to Telegram; they grant no access to any account. Source, in order: process
  environment (`SENTRIX_TG_API_ID`, `SENTRIX_TG_API_HASH`), values compiled into the build, and in development the
  gitignored `.sentrix-dev/telegram-api.env`. They are never committed. Every Telegram client ships its own.
* **Session storage.** TDLib keeps its state (including the account's authorization key) in `…\app.sentrix.desktop\tg-account\db`,
  encrypted by TDLib with a random 256-bit key. That key exists only in `telegram-account.session`, **protected with Windows
  DPAPI** (bound to the signed-in Windows user). Without that user's Windows session the database cannot be opened. The
  session never reaches the web UI, logs, analytics or the console (the UI model has no field for it; the login link is
  `serde(skip)`). The library's own logging is switched off.
* **Disconnect** signs out at Telegram (`logOut`), then overwrites and deletes the key and removes the database. If
  Telegram cannot be reached the local erase still happens, and the UI tells the user to end the session under
  *Settings → Devices*. Revocation from the phone is detected and shown as **Expired**, with a bot notice if enabled.
* **Retention.** TDLib's message and chat-info databases are **off**; secret chats are off. SENTRIX keeps counts, a
  de-duplication list of Telegram message/file identifiers (a few thousand, bounded) and, in memory only, the last 20 results
  with file names. No message text, sender name or chat title exists anywhere in the data model.

## Robustness

* Redelivered messages and re-posted identical files are checked once (persisted, bounded identifier list).
* Partial downloads are never scanned: completion is required, and the on-disk size must equal Telegram's declared size.
  A stalled download (10 min) is abandoned and reported.
* At most 16 downloads in flight and a bounded scan queue; overflow is *declared* (UNABLE TO VERIFY "busy"), not dropped
  silently and not queued without limit.
* Leftovers in the download folder from a crash are removed at start; removal only ever deletes inside that folder.
* After a restart the saved session is resumed automatically. It never starts a new login by itself: if Telegram no longer
  accepts the session, the state is **Expired** and the user must sign in again on purpose.
* Network loss: the UI shows the real connection state; the overall Home status turns to "needs attention" when the session
  ended or is offline. It never shows green while the account protection the user turned on is down.

## The TDLib files

TDLib 1.8.61 for Windows x64 is pinned by SHA-256 in `services/scanner/tdlib.sha256`. **Every pinned file is hashed and must
match before any of them is loaded**; the build script refuses to stage a file that does not match. The development copy comes
from the `tdlib-rs` project's prebuilt release (a third-party build of TDLib, **not** Telegram's own binary).

* **Before distributing**, build TDLib from Telegram's source (<https://github.com/tdlib/td>, `cmake`, OpenSSL and zlib from
  vcpkg), replace the files in `third_party/tdlib` and update the pins. Treat the prebuilt as development-only.
* The hash check runs just before loading; it cannot protect against someone who can already write to the application folder
  (a per-user install is user-writable). It catches corruption and casual replacement, not a determined local attacker.

## Tests actually run

| Test | Kind | Result |
|---|---|---|
| 28 `account_td` unit tests (QR-only login, no phone/password requests, cloud-password refusal, revoked/expired session, category switches, secret chats, protected content, oversize, duplicates, partial/short/stalled/failed downloads, backpressure, cleanup, persistence, QR content) | scripted TDLib **fake** | pass |
| 3 `tdjson` tests (modified/missing/relocated library refused) | real files | pass |
| `real_tdlib_loads_after_its_pins_verify_and_answers_a_request` | **real TDLib DLL** | pass: loaded, answered `getOption version` |
| `real_tdlib_refuses_a_tampered_copy` | real files | pass |
| `real_tdlib_with_an_invalid_api_id_…` | **real TDLib → real Telegram servers** | pass: `API_ID_INVALID` returned, state `Failed`, nothing left on disk |
| Console: heartbeat strictness, tenant isolation of account state/counts | real Postgres schema | see CHECKLIST |
| `live_qr_login_then_a_received_file_is_scanned…` | **real account + real ClamAV + a person** | **NOT RUN** |

## Giving a build its API credentials

Without credentials the Telegram → Your account tab says account protection is unavailable (nothing is faked). Two ways:

* **Bake them into the installer.** Fill `.sentrix-dev/telegram-api.env` (gitignored), then run `scripts\build-release.ps1 -DevKey`.
  The script reads that file and compiles the values into the build.
* **Without rebuilding.** Set `SENTRIX_TG_API_ID` and `SENTRIX_TG_API_HASH` as Windows user environment variables and restart
  SENTRIX. The process environment is checked first.

## Running the live test

1. Put the test account's `api_id`/`api_hash` (my.telegram.org → API development tools) in `.sentrix-dev/telegram-api.env`.
2. Have ClamAV and its database set up as for the other engine tests (`SENTRIX_CLAMAV_DIR`, `SENTRIX_DATA_DIR`).
3. Run:
   ```
   cargo test -p sentrix-core --test account_td live_ -- --ignored --nocapture --test-threads=1
   ```
   It prints a QR code in the terminal; scan it with the **test** account, then send that account a file (a zip containing
   the EICAR test string works; Defender removes bare EICAR files). It checks the file was scanned, the downloaded copy
   removed, and that *Disconnect* erased the key and database. Afterwards confirm in Telegram *Settings → Devices* that the
   SENTRIX session is gone.

## Known limits and open questions

* **Offline catch-up is unverified.** With the message and chat databases off, whether TDLib replays messages that arrived
  while SENTRIX was closed has not been observed. Do not assume it.
* Telegram states that accounts using unofficial clients may be watched more closely; the UI says so before connecting.
* Windows only. macOS/Linux have no tested path (see PLATFORM_SUPPORT.md).
* A second copy of every checked file exists briefly on disk (TDLib's download and the scanner's isolated copy), both removed.
* File names appear in the in-app list and in bot reports (they are the user's own incoming files). They are not stored after exit
  except in the history the user already keeps for scans.
