# The shared SENTRIX bot

One bot, owned by SENTRIX, for every customer. Nobody creates a bot. A customer finds the bot in Telegram, presses **Start**,
and chooses what to protect. Every result arrives in **that customer's own private chat with the bot**. Results are never
posted in a group.

> **Test status, stated plainly.** The whole flow is built and tested end to end against a local **test double** of the
> Telegram Bot API, with the real service, the real relay and (in one test) real ClamAV. It has **not** been run against live
> Telegram, because that needs the bot token on a machine you run (see "What you need to do"). Treat the Telegram-facing
> behaviour (Start, the group picker, the privacy setting, delivery) as **implemented, not yet proven live**.

## What the customer sees

1. **Start.** They open the bot and press Start. The bot answers with two buttons: **Protect a group** and
   **Protect my account** (plus *My protection* and *How it works*).
2. **Protect a group.** The customer makes a new group called **Scan History** and adds the bot to it (they can add other people
   too: everyone in it can read the results). The bot recognises the name and links the group to the person who added it, after
   Telegram confirms that person is a member. Then the customer presses **Choose a group** in the bot, which opens Telegram's
   own group picker; Telegram adds the bot to the group to protect. The customer only needs to be a **member** of that group,
   not an administrator. From then on, documents posted in it are checked and **every result goes to a Scan History group of
   that customer, labelled with the protected group's name**. The protected group itself never sees a scan, an alert or a notice.
   Until a Scan History group exists, results come to the customer's private chat with the bot, with a reminder to make one.
   * **As many protected groups as they like**, and **as many Scan History groups as they like** (up to 25 at once, only to stop
     one account making the bot post into thousands of rooms). Each Scan History group is numbered ("Scan History #2") in
     its welcome message, because they all have the same name.
   * **Which Scan History group each protected group reports to is the customer's choice.** With one Scan History group there
     is nothing to choose. With two or more, the bot asks right after a group is protected, with one button per numbered room
     plus "All of them", and *My protection* has a "Change where ... reports" button per group. Many protected groups can report
     to the same room, or each can have its own. Until chosen, a group reports to all of them, so nothing is lost.
   * A member can protect a group nobody protects yet. Taking over a group someone else already protects needs an
     administrator, so a member cannot quietly redirect another person's reports.
3. **Protect my account.** Account protection runs in the SENTRIX desktop app on the customer's own computer, because that is
   where their Telegram login must stay. The bot gives a one-time code (`ABCD-EFGH`, valid 10 minutes, works once). The
   customer types it into the app (Telegram → Link). The app then sends the *text of each result* through the bot's relay to
   the customer's chat. The bot never sees a Telegram login, phone number or password.
4. **My protection** lists their groups (pause, resume, remove) and linked computers (unlink). Everything is checked against
   the customer's Telegram user id.

## How the bot "adds itself" to a group

A bot cannot add itself to a group; Telegram does not allow it. What SENTRIX uses is Telegram's supported mechanism: a
`https://t.me/<bot>?startgroup=<code>` link. Pressing it opens the group picker, Telegram adds the bot, and posts
`/start <code>` in the group on the person's behalf. SENTRIX then:

* looks the code up (it is one-time, expires after 30 minutes, and was made for that exact person);
* checks that the sender is that person (a link made for someone else is refused);
* asks **Telegram** (`getChatMember`) whether that person is in the group (the message text is never trusted); a group someone
  else already protects can only be taken over by an administrator;
* checks the person has pressed Start, so the result can actually be delivered;
* only then switches protection on, recording the person as the group's owner.

`/setup on` typed in a group by an administrator still works, but only for an administrator who has pressed Start in the bot.

## Where results go, and what is shared

| Thing | Goes to | Notes |
|---|---|---|
| Group file scan result | The Scan History group of the person who protects the group (their private chat with the bot until they make one) | Never the protected group. Includes the group's name, file name, verdict, detection name. **Everyone in Scan History can read it** |
| `/report` in a group (administrators) | The same place | Counts only |
| Clean results | Also reported, in the same place | A group protected through the shared bot reports every result, including "no known threat", because the reports go to a separate room. An administrator can switch clean reports off with `/setup clean off`; that choice is kept |
| Scan History group | Linked by adding the bot to a group named exactly "Scan History" (any capitalisation), or `/link` in it | The adder must be a member (Telegram is asked). Renaming it, or removing the bot, unlinks it. A person can have many (numbered #1, #2, ...); two people never share routing |
| App (account protection) result | The customer's private chat, via the relay | Text only: file name, verdict, time. Files stay on the customer's computer |
| Group files | The bot's server, **in memory and a temporary folder, deleted right after the check** | Up to 20 MB, documents only. This is the one place customer files reach SENTRIX's server; the bot says so |

Reaching a person requires that they pressed Start and have not blocked the bot. If they blocked it, they are marked
unreachable, nothing is sent, the gap is recorded as an event, and pressing Start again restores delivery.

## Architecture

```
 customers ──Telegram──▶  @SentrixBot  ◀──── sentrix-botd (this repo: services/scanner/src/bin/botd.rs)
                                            │   ├ Telegram polling (one worker) and the group logic
                                            │   ├ the scan engine (ClamAV) and quarantine
                                            │   ├ SQLite: people, one-time codes, linked apps, groups, outbox
                                            │   └ HTTP relay (127.0.0.1:8787) ◀── SENTRIX desktop app (HTTPS via a reverse proxy)
```

* **One** polling worker, no webhook, so there is nothing to register twice. Updates are acknowledged only after they are
  handled, so a crash replays them.
* Reports go through the same durable outbox as everywhere else (retry with back-off, 429 handling, de-duplication, 1 message a
  second per chat).
* The relay is a small HTTP service. Run it behind HTTPS; the desktop app refuses a non-HTTPS relay address (except this machine).

### Relay API

| Call | Auth | Does |
|---|---|---|
| `POST /v1/link` `{code, name}` | none (rate limited: 10 per 10 min per address, 100 per 10 min overall) | Exchanges the bot's one-time code for a device token, shown once |
| `POST /v1/report` `{text}` | `Authorization: Bearer <token>` | Queues a report to the token owner's chat. 6/minute and 60/hour per device. The request cannot name a chat |
| `GET /v1/status` | Bearer | `{linked, reachable}` |
| `DELETE /v1/link` | Bearer | Unlinks this computer |

Report text is reduced to `<b>`, `<i>`, `<code>` and the basic entities; links, scripts and any other tag are shown as plain
characters. Only the SHA-256 of a device token is stored.

## Security controls

* A person can only affect their own groups, codes and linked computers: every action is checked against the Telegram user id of
  the person acting. Tests prove one person cannot pause, remove, resume, list or unlink another person's things, cannot reuse
  another person's link, and cannot aim a relay report at another chat.
* One-time codes: single use, short expiry, bound to one person. Guessing is rate limited.
* The bot token is read from the environment, never printed, logged or returned by any call.
* Telegram messages are escaped; file names are stripped of look-alike and right-to-left characters before display.
* Scan results that are incomplete are reported "not checked", never clean. A missing scan engine makes every file "not checked".
* Automatic deletion of malicious messages stays **off by default** and needs a group administrator's two-step consent, as before.

## What you need to do (one time)

1. **Token.** Put the bot token in `.sentrix-dev/bot.env` (gitignored) as `SENTRIX_BOT_TOKEN=...`. Do not paste it into chat or commit it.
   If it was ever shared anywhere public, open @BotFather → your bot → **Revoke current token** and use the new one.
2. **BotFather settings** (once, for all customers):
   * `/setprivacy` → choose the bot → **Disable**. Without this Telegram hides ordinary group messages (and files) from the bot.
     (The Telegram member list shows such a bot as "has no access to messages".) Remove and re-add the bot in groups that
     already had it.
   * `/setjoingroups` → **Enable**.
   * `/setcommands` → paste:
     ```
     start - Open the menu
     help - How SENTRIX works
     groups - Your protected groups and computers
     account - Link the SENTRIX app
     ```
3. **Run the service** (`sentrix-botd --check` validates the token and prints the bot's username; then run without `--check`).
   Environment: `SENTRIX_BOT_TOKEN`, `SENTRIX_DATA_DIR`, `SENTRIX_CLAMAV_DIR`, `SENTRIX_RELAY_BIND`, `SENTRIX_TRUST_PROXY`,
   `SENTRIX_DOWNLOAD_URL`. It must stay running (a Windows service, `systemd` unit or container) for protection to work.
4. **HTTPS for the relay.** Put a reverse proxy (for example Caddy) in front of `SENTRIX_RELAY_BIND` and give the desktop build the
   public address: `SENTRIX_RELAY_URL=https://relay.example.com` and `SENTRIX_BOT_USERNAME=YourBotName` (environment, or
   compiled in via `scripts\build-release.ps1`).
5. **Back up** `botd.db` (it holds who is linked to what). Losing it unlinks everyone; they press Start and link again.

## Limits and known gaps

* **Not tested against live Telegram.** Behaviour of Start, the group picker, `startgroup`, privacy mode and delivery follows
  Telegram's documentation and a local test double.
* A server that holds one bot for everyone is a single point of failure: when `sentrix-botd` is down, group protection stops and
  desktop reports queue on the customer's computer until it returns.
* **Scan History is a normal group.** Everyone the customer adds sees every result, including file names. The bot says so when it links.
* Group scanning means customers' group files reach this server (briefly). That needs to be in the privacy policy and terms.
* Files over 20 MB, photos, videos and voice messages are not checked in groups (Telegram's bot limit and the product's scope).
* Secret chats and content Telegram withholds from bots are not visible. No antivirus catches everything.
* The administrator dashboard does not show the hosted bot's numbers yet (people, groups, linked apps, scans). They are in the
  service log and `botd.db`; a counts-only feed to the console is the next step.
* One server, one bot token: there is no multi-region or failover.
