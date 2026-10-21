# SENTRIX Group Shield

Group Shield scans files posted in Telegram **groups** that the owner's own bot was added to, and posts the result in the
group. It extends the existing Telegram bot integration: the same bot token (DPAPI-protected on the owner's PC), the same
single bot worker, the same outbox, the same scanner. There is no second bot, no second poller and no webhook.

## Where it runs (read this first)

SENTRIX has no central bot and no server-side scanner. Each customer connects **their own** bot (Telegram page), and that bot
is polled by the desktop app on the customer's computer, which also does the scanning. Therefore:

* Group Shield works only **while the owner's computer is on** and SENTRIX is running. Files posted while it is off wait at
  Telegram (about 24 hours) and are scanned when SENTRIX starts again.
* A group belongs to the bot owner's installation. Different customers' groups are on different computers; the admin console
  only receives counts.
* A SENTRIX-operated central bot with server-side scanning would be a different product (hosting, privacy and legal
  implications: file contents would leave users' computers). It is not built.

## Setting it up

1. **Owner** (Telegram page): connect a bot, then turn on **Protect Telegram groups**. This is the owner's consent that
   groups may be scanned on this computer. It is off by default.
2. Add the bot to the group.
3. Make the bot a **group administrator**, *or* in @BotFather send `/setprivacy`, choose the bot, then **Disable**, and add the
   bot to the group again. Otherwise Telegram does not deliver ordinary messages to the bot (see "What it can see").
4. A **group administrator** sends `/setup on` in the group. Until then the group is registered and nothing is scanned.

## Commands

| Command | Who | What it does |
|---|---|---|
| `/help` | anyone | Explains what the bot does and its limits |
| `/status` | anyone | Protection on/off, scanner ready, whether the bot can see files here, deletion on/off (and whether the bot still has the permission) |
| `/scanstatus` | anyone | This group's scan counts: last 24 h and all time, skipped/failed, last scan |
| `/setup` | administrators | Shows options and current state |
| `/setup on`, `/setup off` | administrators | Start or stop scanning this group (off also turns deletion off) |
| `/setup autodelete on` then `/setup autodelete confirm` | administrators | Two-step consent for automatic deletion (below) |
| `/setup autodelete off` | administrators | Turns deletion off and erases the recorded consent |
| `/setup clean on\|off` | administrators | Also post clean results (default off) |
| `/setup incomplete on\|off` | administrators | Post files that could not be checked (default on) |

Commands addressed to another bot (`/status@other_bot`) are ignored.

## What it can and cannot inspect

| Case | Result |
|---|---|
| File sent as a **document**, up to 20 MB, bot receives the message | Downloaded to an isolated temporary folder, scanned with the real engine, deleted |
| Bot is in the group with **privacy mode on** and is **not** an administrator | Telegram does not send it ordinary messages, so **it never sees the file**. `/status` says so; the app warns the owner. Nothing is claimed as scanned |
| Photos, videos, voice, video notes, stickers | **Not scanned** (Telegram recompresses them) and not reported |
| File over 20 MB (Telegram's Bot API download limit) | Not downloaded; reported as **not checked** |
| File Telegram will not serve (expired, removed) | Reported as **not checked**, counted as an error |
| Encrypted/partly unreadable archive, no engine, engine error | **UNABLE TO VERIFY**, never clean |
| Channels (channel posts) | Not supported |
| Secret chats, private chats between other people | Not visible to any bot |
| Edited messages, files posted before the bot joined | Not rescanned / not seen |
| A group upgraded from "group" to "supergroup" | Telegram changes its chat id; it appears as a new, unprotected group |

SENTRIX does **not** provide complete group protection, and says so. It scans the files that Telegram delivers to the bot
and that the scanner can read.

## Authorization and isolation

* Configuration commands are accepted only from a person Telegram **currently** confirms (live `getChatMember`) is an
  administrator of **that group**. Message text, display names and earlier replies are never trusted. Being an administrator
  of another group grants nothing.
* An administrator posting **anonymously** cannot be identified, so cannot run `/setup`-level changes that need identity or
  grant deletion consent.
* Everything stored is keyed by the group's chat id and every query filters on it: settings, history, counts, queued messages.
  One group cannot read or change another.
* The owner's master switch gates everything. With it off the bot answers once an hour that groups are not protected (the bot
  worker only runs while Group Shield or private-chat submissions is on; with both off the bot is silent and Telegram simply
  holds the messages).
* Disconnecting the bot, or an organization policy (`telegramGroupsAllowed`), turns it off and erases the local group data.

## Automatic deletion (off by default)

Deleting a message is destructive, so it needs three things:

1. `/setup autodelete on` from a named administrator, only if the bot **currently** has the *Delete messages* permission;
2. the **same** administrator sends `/setup autodelete confirm` within 5 minutes (another administrator or a member cannot
   complete it); the permission is checked again at that moment;
3. at the time of a detection the permission is checked **again** before deleting, and settings are re-read (an administrator
   may have changed them while the file was being scanned).

Only a verdict of **MALICIOUS** (a signature engine positively identified the file) can trigger deletion. Suspicious,
unverifiable and clean files are never deleted. If Telegram refuses (permission removed, message already gone) the alert says
"could not delete the message" and the `delete_failed` action is recorded: success is only ever claimed when Telegram returned ok.

## Rate limits and abuse resistance

* At most 10 documents per group per minute are scanned; the rest are recorded as **skipped** and the group is told they were
  **not checked** (once a minute, not once per file).
* The bot posts at most 15 messages per group per minute (20 for malicious alerts, so a flood of ordinary replies can never hide
  a threat); drops are logged as events. Telegram's own limit is about 20.
* Messages are handled one at a time by the single worker; an update is only acknowledged to Telegram after it was fully
  handled, so a crash replays it instead of losing it. Telegram redeliveries of the same message are processed once.
* A 403 from a group (bot removed or muted) turns protection for that group off instead of retrying forever.

## What is stored, and what the console sees

* Locally (`protection.db`): per group the title, settings, who/when consented (Telegram user id and time), and per handled
  message only the **hash, size, verdict and action**, kept 30 days. **No file names, no message text, no file contents.**
* The owner's desktop notification (and history) for a group detection includes the file name, because it is the owner's own
  computer. Group scan results are not kept as files on disk.
* The admin console receives **counts only** (registered, protected, with automatic deletion, scans, threats and errors in
  24 h). The heartbeat schema is strict: group names, chat ids, member names or file names are rejected by the API.

## Tests actually run

`cargo test -p sentrix-core --test groups` against a local Bot API test double (**not live Telegram**): 15 tests. Registration
switched off by default; administrators vs members vs administrators of other groups; anonymous administrators; commands for
other bots; owner master switch; bot removal; ignored files in unprotected groups (never downloaded); a file that cannot be
checked is never reported clean; oversized and inaccessible files; redelivered messages handled once; rate limiting with the
skipped files declared; cross-group isolation of settings and history; two-step deletion consent (wrong confirmer, member,
missing permission, anonymous).

Against **real ClamAV** (`--ignored`): 2 tests. A malicious zip (EICAR inside) produces a MALICIOUS alert and nothing is
deleted while deletion is off; a second group that never enabled protection is untouched; after consent the message is deleted
and the alert says so; after the permission is removed the next malicious file is **not** deleted and the alert says so; a clean
file is reported clean only because the engine completed. Console: strict heartbeat schema, tenant-scoped aggregates, device
detail access, policy flag.

**Not tested:** live Telegram. The behaviour of privacy mode, `getChatMember` and `deleteMessage` follows Telegram's documented
Bot API but must be confirmed with a real bot in a real group before relying on it.
