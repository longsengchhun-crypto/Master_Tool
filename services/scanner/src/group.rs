//! SENTRIX Group Shield: scans files posted in Telegram groups the owner's bot was added to.
//!
//! This runs inside the same single bot worker that already handles the owner's private chat (no second poller, no
//! webhook). What it can and cannot see is decided by Telegram, not by us:
//!
//!   * With BotFather "privacy mode" ON (the default) a bot in a group only receives commands, mentions and replies, so it
//!     never sees ordinary files. It sees every message only if privacy mode is OFF or the bot is a group administrator.
//!   * Only files sent as *documents* are scanned. Photos, videos, voice and stickers are recompressed by Telegram and
//!     are not inspected. Channel posts and files larger than 20 MB (the Bot API download limit) cannot be inspected.
//!   * Anything that cannot be checked is reported as UNABLE TO VERIFY, never as clean.
//!
//! Authorization: configuration commands are accepted only from a person Telegram confirms (live `getChatMember`) is an
//! administrator of that very group; anonymous administrators cannot be identified, so they cannot grant the consent that
//! turns on automatic deletion. Every row and query is keyed by the group's chat id.

use crate::queue::{now_ms, Group};
use crate::service::Inner;
use crate::telegram::{esc, safe_display_name, BotClient, BotInfo, Document, Incoming, MemberChange, MAX_BOT_DOWNLOAD};
use crate::types::{FindingKind, ScanReport, Verdict};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Documents scanned per group per minute. The rest are recorded as skipped (and said so), not silently dropped.
pub const SCANS_PER_MIN: usize = 10;
/// Messages the bot posts per group per minute (Telegram's own limit for a group is about 20). A malicious-file alert may
/// use the extra headroom so a flood of ordinary replies can never hide a threat.
pub const MSGS_PER_MIN: usize = 15;
pub const URGENT_MSGS_PER_MIN: usize = 20;
/// An administrator has this long to confirm turning on automatic deletion.
pub const CONSENT_WINDOW_MS: i64 = 5 * 60 * 1000;

/// The group each person makes to receive the reports of the groups they protect.
pub const HISTORY_GROUP_NAME: &str = "Scan History";

/// "Scan History" or "Scans History" (people write both), in any capitalisation, ignoring extra spaces. Nothing else
/// counts: no prefixes, no look-alikes.
pub fn is_history_title(t: &str) -> bool {
    let name = t.split_whitespace().collect::<Vec<_>>().join(" ");
    name.eq_ignore_ascii_case(HISTORY_GROUP_NAME) || name.eq_ignore_ascii_case("Scans History")
}

/// A file at least this big gets a "Checking..." message at once, replaced by the result when it is ready.
pub const PLACEHOLDER_MIN_BYTES: u64 = 1_000_000;

/// One file posted in a protected group, waiting for a worker.
pub(crate) struct DocJob {
    pub bot: Arc<BotClient>,
    pub me: BotInfo,
    pub group: Group,
    pub update: Incoming,
    pub doc: Document,
    pub mid: i64,
}

#[derive(Default)]
pub(crate) struct GroupState {
    /// (group, message) pairs queued or being checked, so the same message is never checked twice at once.
    pub(crate) inflight: Mutex<HashSet<(i64, i64)>>,
    /// "Checking..." messages waiting to be replaced by the result: (group, message) -> (where it was posted, its id, file name).
    pub(crate) placeholders: Mutex<HashMap<(i64, i64), (i64, i64, String)>>,
    pub bot_info: Mutex<Option<(BotInfo, Instant)>>,
    msgs: Mutex<HashMap<i64, VecDeque<Instant>>>,
    scans: Mutex<HashMap<i64, VecDeque<Instant>>>,
    /// Messages per person in private chats with the shared bot.
    pub(crate) private: Mutex<HashMap<i64, VecDeque<Instant>>>,
    notices: Mutex<HashMap<(i64, &'static str), Instant>>,
}

pub(crate) fn allow(map: &Mutex<HashMap<i64, VecDeque<Instant>>>, chat: i64, limit: usize, window: Duration) -> bool {
    let mut m = map.lock().unwrap();
    let q = m.entry(chat).or_default();
    let now = Instant::now();
    while q.front().is_some_and(|t| now.duration_since(*t) > window) {
        q.pop_front();
    }
    if q.len() >= limit {
        return false;
    }
    q.push_back(now);
    true
}

fn verdict_code(v: Verdict) -> &'static str {
    match v {
        Verdict::Malicious => "MALICIOUS",
        Verdict::Suspicious => "SUSPICIOUS",
        Verdict::Clean => "CLEAN",
        Verdict::UnableToVerify | Verdict::Pending => "UNABLE_TO_VERIFY",
    }
}

fn ago_text(ms: Option<i64>) -> String {
    match ms {
        None => "never".into(),
        Some(t) => {
            let s = ((now_ms() - t) / 1000).max(0);
            if s < 60 {
                "just now".into()
            } else if s < 3600 {
                format!("{} min ago", s / 60)
            } else if s < 86_400 {
                format!("{} h ago", s / 3600)
            } else {
                format!("{} d ago", s / 86_400)
            }
        }
    }
}

const HELP: &str = "<b>SENTRIX Group Shield</b>\nI scan files posted in this group on the bot owner's computer and report threats.\n\n/status: protection state\n/scanstatus: scan counts\n/report: administrators get a summary of the last 7 days\n/setup: administrators turn protection on or off\n\n<b>Limits</b>\nOnly files sent as documents, up to 20 MB, and only while the owner's computer is on. Photos, videos and voice messages are not scanned. If I cannot see a file (Telegram privacy mode) or cannot check it fully, it is not reported as safe.";

const HELP_HOSTED: &str = "<b>SENTRIX</b>\nI check files posted in this group. The results go to the Scan History group of the administrator who set me up, never here.\n\n/status: protection state\n/scanstatus: scan counts\n/report: administrators get a summary privately\n/setup: administrators turn protection on or off\n\n<b>Limits</b>\nOnly files sent as documents, up to 20 MB. Photos, videos and voice messages are not checked. If I cannot see a file (Telegram privacy mode) or cannot check it fully, it is not reported as safe.";

impl Inner {
    /// The bot's own details, refreshed every ten minutes. Also records whether privacy mode hides group files from it.
    pub(crate) fn bot_info(&self, bot: &BotClient) -> Option<BotInfo> {
        {
            let g = self.groups.bot_info.lock().unwrap();
            if let Some((b, t)) = g.as_ref() {
                if t.elapsed() < Duration::from_secs(600) {
                    return Some(b.clone());
                }
            }
        }
        match bot.get_me() {
            Ok(b) => {
                self.store.kv_set("tg_privacy_blocking", if b.can_read_all_group_messages == Some(false) { "1" } else { "0" });
                *self.groups.bot_info.lock().unwrap() = Some((b.clone(), Instant::now()));
                Some(b)
            }
            Err(_) => self.groups.bot_info.lock().unwrap().as_ref().map(|(b, _)| b.clone()),
        }
    }

    /// Queue a message for a group, subject to a per-group rate limit. Returns whether it was queued.
    pub(crate) fn say(&self, chat: i64, reply_to: Option<i64>, key: &str, kind: &str, text: String, urgent: bool) -> bool {
        let limit = if urgent { URGENT_MSGS_PER_MIN } else { MSGS_PER_MIN };
        if !allow(&self.groups.msgs, chat, limit, Duration::from_secs(60)) {
            if self.notice_due(chat, "rate_limited", Duration::from_secs(300)) {
                self.event("group_rate_limited", "warning", "A group is receiving more bot messages than Telegram allows; some replies were dropped.");
            }
            return false;
        }
        self.store.enqueue_notification_to(&format!("g:{chat}:{key}"), kind, &text, now_ms(), Some(chat), reply_to).unwrap_or(false)
    }

    /// True at most once per `every` for this (group, tag): keeps repeated refusals from spamming a group.
    fn notice_due(&self, chat: i64, tag: &'static str, every: Duration) -> bool {
        let mut n = self.groups.notices.lock().unwrap();
        let now = Instant::now();
        match n.get(&(chat, tag)) {
            Some(t) if now.duration_since(*t) < every => false,
            _ => {
                n.insert((chat, tag), now);
                true
            }
        }
    }

    /// Entry point for every update that came from a group or supergroup.
    pub(crate) fn handle_group_update(&self, bot: &BotClient, me: &BotInfo, u: &Incoming) {
        if !matches!(u.chat_type.as_str(), "group" | "supergroup") {
            return;
        }
        let now = now_ms();
        if self.cfg.read().unwrap().hosted.is_some() {
            let title = u.chat_title.as_deref().unwrap_or("");
            if is_history_title(title) {
                // A group called "Scan History" is where reports go. It is never scanned or protected itself.
                self.on_history_group(bot, u);
                return;
            }
            if u.member_change.is_none() && self.store.history_chat_known(u.chat_id) {
                // It was a Scan History group and has been renamed: it stops receiving reports.
                self.store.history_clear_chat(u.chat_id);
                self.event("history_unlinked", "info", "A Scan History group was renamed, so reports no longer go there.");
            }
        }
        if let Some(mc) = &u.member_change {
            self.on_membership(u, mc);
            return;
        }
        let shield = self.cfg.read().unwrap().group_shield;
        // A group we have not heard about yet (bot added while SENTRIX was closed) is registered, switched OFF.
        let g = match self.store.group_get(u.chat_id) {
            Ok(Some(g)) if g.left_at.is_none() => g,
            _ => {
                let _ = self.store.group_joined(u.chat_id, u.chat_title.as_deref().unwrap_or(""), &u.chat_type, "member", now);
                match self.store.group_get(u.chat_id) {
                    Ok(Some(g)) => g,
                    _ => return,
                }
            }
        };
        if let Some(text) = u.text.as_deref() {
            if text.trim_start().starts_with('/') {
                self.on_command(bot, me, u, text, &g, shield);
                return;
            }
        }
        if !shield || !g.enabled {
            // Shared bot: a file arrived but nobody has switched protection on. Say so once an hour instead of staying silent,
            // so an administrator who only added the bot knows what is missing. Nothing about the file is said.
            if shield && u.document.is_some() && self.cfg.read().unwrap().hosted.is_some() && self.notice_due(u.chat_id, "not_on", Duration::from_secs(3600)) {
                let _ = self.say(
                    u.chat_id,
                    u.message_id,
                    &format!("noton:{}", u.update_id),
                    "group_notice",
                    "<b>SENTRIX is in this group, but protection is not on, so this file was not checked.</b> A group administrator turns it on: open the SENTRIX bot in a private chat, press Start, choose Protect a group, then Choose a group. Results are sent to that person privately, not posted here.".into(),
                    false,
                );
            }
            return;
        }
        if let Some(doc) = &u.document {
            self.queue_document(me, &g, u, doc);
        }
        // Photos, videos, audio and stickers are deliberately not scanned (see the module comment).
    }

    /// Where a group's scan reports go: the private chat of the person who protects it (shared bot), or the bot owner's
    /// private chat (own bot). Never the group itself, so other members do not see who posted what.
    fn report_dest(&self, g: &Group) -> Option<i64> {
        let cfg = self.cfg.read().unwrap();
        if cfg.hosted.is_some() {
            self.person_dest(g.enabled_by?)
        } else {
            cfg.chat_id
        }
    }

    fn report_body(&self, g: &Group, dest: i64, body: String) -> String {
        let title: String = g.title.chars().filter(|c| !c.is_control()).take(60).collect();
        let mut text = format!("<b>Group:</b> {}\n{}", esc(&title), body);
        // Falling back to the private chat: remind them once per report where reports are meant to go.
        if self.cfg.read().unwrap().hosted.is_some() && dest > 0 {
            text += &format!("\n\n<i>Tip: make a group called {HISTORY_GROUP_NAME}, add me to it, and reports will go there instead.</i>");
        }
        text
    }

    /// For a big file, say at once that it is being checked. Only when the result will certainly be posted (so the message is
    /// always replaced) and only in shared-bot mode, where results go to a separate room.
    fn start_placeholder(&self, bot: &BotClient, g: &Group, mid: i64, shown: &str, size: u64) {
        if size < PLACEHOLDER_MIN_BYTES || self.cfg.read().unwrap().hosted.is_none() || !g.report_clean || !g.report_incomplete {
            return;
        }
        let Some(dest) = self.report_dest(g) else { return };
        if !allow(&self.groups.msgs, dest, MSGS_PER_MIN, Duration::from_secs(60)) {
            return;
        }
        let text = self.report_body(g, dest, format!("<b>{shown}</b>\nChecking this file now. The result will appear here in a moment."));
        if let Ok(id) = bot.send_reply(dest, &text, None) {
            if id > 0 {
                self.groups.placeholders.lock().unwrap().insert((g.chat_id, mid), (dest, id, shown.to_string()));
            }
        }
    }

    /// A worker crashed with a "Checking..." message outstanding: replace it, so it never claims a check is still going.
    pub(crate) fn settle_placeholder_after_crash(&self, chat: i64, mid: i64) {
        let taken = self.groups.placeholders.lock().unwrap().remove(&(chat, mid));
        if let (Some((dest, id, shown)), Some(bot)) = (taken, self.bot.read().unwrap().clone()) {
            let _ = bot.edit_message_text(dest, id, &format!("<b>{shown}</b>\nThis file <b>could not be checked</b> because of an internal error. It is not known to be safe."));
        }
    }

    /// Where this person's reports go: their Scan History group if they made one, otherwise their private chat with the bot.
    pub(crate) fn person_dest(&self, user: i64) -> Option<i64> {
        self.store.history_get(user).map(|h| h.0).or_else(|| Some(user).filter(|u| self.store.user_reachable(*u)))
    }

    fn post_report(&self, g: &Group, key: &str, body: String, urgent: bool) -> bool {
        let Some(dest) = self.report_dest(g) else {
            self.event("group_report_undeliverable", "warning", "A scan report could not be sent because the person who protects the group cannot be reached. They need to open the bot and press Start.");
            return false;
        };
        let text = self.report_body(g, dest, body);
        // A "Checking..." message for this very file is replaced in place; only if that fails is a new message sent.
        if let Some(mid) = key.strip_prefix('m').and_then(|k| k.parse::<i64>().ok()) {
            if let Some((pdest, pid, _)) = self.groups.placeholders.lock().unwrap().remove(&(g.chat_id, mid)) {
                let bot = self.bot.read().unwrap().clone();
                if let Some(bot) = bot {
                    if bot.edit_message_text(pdest, pid, &text).is_ok() {
                        return true;
                    }
                }
            }
        }
        self.say(dest, None, &format!("r:{}:{key}", g.chat_id), "group_scan", text, urgent)
    }

    /// Everything that happens inside a group called "Scan History" (shared-bot mode).
    fn on_history_group(&self, bot: &BotClient, u: &Incoming) {
        let chat = u.chat_id;
        let title = u.chat_title.as_deref().unwrap_or("");
        if let Some(mc) = &u.member_change {
            match mc.new_status.as_str() {
                "left" | "kicked" => {
                    if self.store.history_clear_chat(chat) > 0 {
                        self.event("history_unlinked", "info", "The bot was removed from a Scan History group, so reports no longer go there.");
                    }
                }
                // Added: the person who added the bot is the one these reports are for.
                "member" | "administrator" => {
                    if let Some(adder) = u.from_id {
                        self.link_history(bot, chat, title, adder, u.update_id, true);
                    }
                }
                _ => {}
            }
            return;
        }
        // Only an explicit /link in the group links it, so nobody claims a group by chatting in it.
        let Some(text) = u.text.as_deref() else { return };
        let cmd = text.split_whitespace().next().unwrap_or("").split('@').next().unwrap_or("").to_ascii_lowercase();
        match cmd.as_str() {
            "/link" if !u.anonymous_admin => {
                if let Some(uid) = u.from_id {
                    self.link_history(bot, chat, title, uid, u.update_id, false);
                }
            }
            "/link" => {
                let _ = self.say(chat, u.message_id, &format!("anon:{}", u.update_id), "group_reply", "I cannot tell who you are while you post anonymously. Turn off \"Remain anonymous\" and send /link again.".into(), false);
            }
            "/help" | "/start" | "/status" => {
                if self.notice_due(chat, "history_help", Duration::from_secs(60)) {
                    let _ = self.say(chat, u.message_id, &format!("hh:{}", u.update_id), "group_reply", format!("<b>SENTRIX {HISTORY_GROUP_NAME}</b>\nScan reports for the groups protected by the person who linked this group appear here. Everyone in this group can read them. To link it to you, send /link here."), false);
                }
            }
            _ => {}
        }
    }

    /// Make `chat` this person's Scan History group, but only if Telegram says they are in it.
    fn link_history(&self, bot: &BotClient, chat: i64, title: &str, user: i64, update_id: i64, quiet_on_refusal: bool) {
        let now = now_ms();
        let member = bot.get_chat_member(chat, user).map(|m| m.is_member());
        match member {
            Ok(true) => {
                if self.store.history_set(user, chat, title, now).is_ok() {
                    self.event("history_linked", "info", "A Scan History group was linked to a person. Their scan reports now go there.");
                    let _ = self.store.group_forget(chat); // it is a report room, not a protected group
                    let _ = self.say(chat, None, &format!("linked:{chat}:{user}:{update_id}"), "group_notice", format!("<b>SENTRIX {HISTORY_GROUP_NAME}</b>\nReports for the groups this person protects will appear here. Everyone in this group can read them, so add only people who should."), false);
                }
            }
            Ok(false) => {
                if !quiet_on_refusal {
                    let _ = self.say(chat, None, &format!("refused:{chat}:{update_id}"), "group_notice", "You are not a member of this group, so it cannot be your Scan History.".into(), false);
                }
            }
            Err(_) => {
                if !quiet_on_refusal {
                    let _ = self.say(chat, None, &format!("refused:{chat}:{update_id}"), "group_notice", "I could not check who is in this group yet. Try /link again in a minute.".into(), false);
                }
            }
        }
    }

    fn on_membership(&self, u: &Incoming, mc: &MemberChange) {
        let now = now_ms();
        match mc.new_status.as_str() {
            "member" | "administrator" => {
                let was_out = matches!(mc.old_status.as_str(), "left" | "kicked" | "");
                let _ = self.store.group_joined(u.chat_id, u.chat_title.as_deref().unwrap_or(""), &u.chat_type, &mc.new_status, now);
                if was_out {
                    self.event("group_joined", "info", "The SENTRIX bot was added to a group. Protection stays off until a group administrator sends /setup on.");
                    // Shared bot: the protected group stays completely quiet. People are told what to do in the bot's menu.
                    if self.cfg.read().unwrap().group_shield && self.cfg.read().unwrap().hosted.is_none() {
                        let hosted = false;
                        let blind = mc.new_status != "administrator" && self.store.kv_get("tg_privacy_blocking").as_deref() == Some("1");
                        let mut t = if hosted {
                            String::from("<b>SENTRIX</b> was added. It is <b>off</b> until a group administrator opens the SENTRIX bot in a private chat, presses Start and chooses Protect a group. Scan results are sent to that person privately, never posted here. Send /help for what it can and cannot see.")
                        } else {
                            String::from("<b>SENTRIX Group Shield</b> was added. It is <b>off</b> until a group administrator sends <code>/setup on</code>. Scan results are sent privately to the bot owner, not posted here. Send /help for what it can and cannot see.")
                        };
                        if blind {
                            t += "\n\n<b>Telegram is hiding this group's files from me.</b> Make me a group administrator (no special rights are needed) so I can see them.";
                        }
                        let _ = self.say(u.chat_id, None, &format!("welcome:{}", u.update_id), "group_notice", t, false);
                    }
                }
            }
            "left" | "kicked" => {
                let _ = self.store.group_left(u.chat_id, now);
                self.event("group_removed", "info", "The SENTRIX bot was removed from a group. Protection for it was turned off.");
            }
            _ => {}
        }
    }

    /// `Ok(user id)` only when Telegram itself says this person is an administrator of this group right now.
    fn require_admin(&self, bot: &BotClient, u: &Incoming) -> Result<i64, &'static str> {
        if u.anonymous_admin {
            return Err("I cannot tell who you are while you post anonymously. Turn off \"Remain anonymous\" for this command.");
        }
        let Some(uid) = u.from_id else { return Err("I could not tell who sent that.") };
        match bot.get_chat_member(u.chat_id, uid) {
            Ok(m) if m.is_admin() => Ok(uid),
            Ok(_) => Err("Only group administrators can change these settings."),
            Err(_) => Err("I could not verify that you are an administrator, so nothing was changed."),
        }
    }

    fn on_command(&self, bot: &BotClient, me: &BotInfo, u: &Incoming, text: &str, g: &Group, shield: bool) {
        let mut words = text.split_whitespace();
        let first = words.next().unwrap_or("");
        let (cmd, target) = match first.split_once('@') {
            Some((c, t)) => (c, Some(t)),
            None => (first, None),
        };
        // `/status@SomeOtherBot` is meant for another bot.
        if let Some(t) = target {
            if me.username.as_deref().map(|n| n.eq_ignore_ascii_case(t)) != Some(true) {
                return;
            }
        }
        let cmd = cmd.to_ascii_lowercase();
        if !matches!(cmd.as_str(), "/help" | "/start" | "/status" | "/scanstatus" | "/setup" | "/report") {
            return;
        }
        let args: Vec<String> = words.map(|w| w.to_ascii_lowercase()).collect();
        let hosted = self.cfg.read().unwrap().hosted.is_some();
        // Shared bot: the person pressed "Choose a group" in a private chat and Telegram posted /start <code> here.
        if hosted && cmd == "/start" && args.first().is_some_and(|a| a.starts_with("g_")) {
            self.hosted_link_group(bot, me, u, &args[0]);
            return;
        }
        let chat = u.chat_id;
        let reply = |tag: &str, body: String| {
            let _ = self.say(chat, u.message_id, &format!("{tag}:{}", u.update_id), "group_reply", body, false);
        };

        if !shield {
            if self.notice_due(chat, "off", Duration::from_secs(3600)) {
                reply("off", "Group protection is turned off in the SENTRIX app on the bot owner's computer.".into());
            }
            return;
        }

        match cmd.as_str() {
            "/help" | "/start" => reply("help", if hosted { HELP_HOSTED.into() } else { HELP.into() }),
            "/status" => reply("status", self.status_text(bot, me, g)),
            "/scanstatus" => reply("scanstatus", self.scanstatus_text(g)),
            "/report" => match self.require_admin(bot, u) {
                Ok(uid) => {
                    // A summary is a report: it goes to the administrator's private chat, never into the group.
                    let dest = if hosted { self.person_dest(uid) } else { self.cfg.read().unwrap().chat_id };
                    match dest {
                        Some(d) => {
                            let t = format!("<b>Group:</b> {}\n{}", esc(&g.title), self.report_text(g));
                            let _ = self.say(d, None, &format!("rpt:{}:{}", g.chat_id, u.update_id), "group_scan", t, false);
                            reply("report", if hosted { "The summary was sent to your Scan History group (or to you privately if you have none).".into() } else { "The summary was sent to you privately.".into() });
                        }
                        None => reply("report", "Open the SENTRIX bot privately and press Start first. Reports are sent there, not here.".into()),
                    }
                }
                Err(why) => {
                    self.rejected.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    reply("denied", why.into());
                }
            },
            "/setup" => {
                let uid = match self.require_admin(bot, u) {
                    Ok(uid) => uid,
                    Err(why) => {
                        self.rejected.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        self.event("group_unauthorized", "warning", "Someone who is not a group administrator tried to change Group Shield settings. Nothing was changed.");
                        reply("denied", why.into());
                        return;
                    }
                };
                self.setup(bot, me, u, g, uid, &args);
            }
            _ => {}
        }
    }

    fn status_text(&self, bot: &BotClient, me: &BotInfo, g: &Group) -> String {
        let engine = self.scanner.engine_status();
        let own = bot.get_chat_member(g.chat_id, me.id).ok();
        let is_admin = own.as_ref().is_some_and(|m| m.is_admin());
        let privacy_hides = me.can_read_all_group_messages == Some(false) && !is_admin;
        let mut t = String::from("<b>SENTRIX Group Shield</b>\n");
        t += &format!("Protection: <b>{}</b>\n", if g.enabled { "ON" } else { "OFF" });
        t += &format!("Scanner: {}\n", if engine.state == "running" { "ready" } else { "not ready, files cannot be called safe" });
        t += &format!("Can I see files here: {}\n", if privacy_hides { "<b>No</b>. Privacy mode is on and I am not an administrator." } else { "yes" });
        t += &format!("Automatic deletion of malicious files: {}", if g.auto_delete { "ON" } else { "off" });
        if g.auto_delete && !own.as_ref().is_some_and(|m| m.may_delete()) {
            t += " (<b>but I no longer have the Delete messages permission</b>)";
        }
        if !g.enabled {
            t += "\n\nAn administrator can send <code>/setup on</code> to start.";
        }
        t
    }

    /// Summary for administrators: counts only (no file names or senders), this group only.
    fn report_text(&self, g: &Group) -> String {
        let now = now_ms();
        let week = self.store.group_stats(g.chat_id, now - 7 * 86_400_000).unwrap_or_default();
        let all = self.store.group_stats(g.chat_id, 0).unwrap_or_default();
        format!(
            "<b>Security report</b> (this group only)\nLast 7 days: {} scanned, {} malicious, {} suspicious, {} not fully checked, {} skipped or failed\nAll time: {} scanned, {} malicious\nLast scan: {}\nProtection: {}. Automatic deletion: {}\n\nCounts only. A file that was not fully checked is not known to be safe. See /help for what cannot be scanned.",
            week.scans, week.threats, week.suspicious, week.unverified, week.skipped + week.errors, all.scans, all.threats, ago_text(all.last_scan_at), if g.enabled { "on" } else { "off" }, if g.auto_delete { "on" } else { "off" }
        )
    }

    fn scanstatus_text(&self, g: &Group) -> String {
        let now = now_ms();
        let day = self.store.group_stats(g.chat_id, now - 86_400_000).unwrap_or_default();
        let all = self.store.group_stats(g.chat_id, 0).unwrap_or_default();
        format!(
            "<b>Scan status</b> (this group only)\nLast 24 h: {} scanned, {} malicious, {} suspicious, {} not fully checked\nAll time: {} scanned, {} malicious\nSkipped or failed in 24 h: {}\nLast scan: {}",
            day.scans, day.threats, day.suspicious, day.unverified, all.scans, all.threats, day.skipped + day.errors, ago_text(all.last_scan_at)
        )
    }

    fn setup(&self, bot: &BotClient, me: &BotInfo, u: &Incoming, g: &Group, uid: i64, args: &[String]) {
        let chat = u.chat_id;
        let now = now_ms();
        let say = |tag: &str, body: String| {
            let _ = self.say(chat, u.message_id, &format!("{tag}:{}", u.update_id), "group_reply", body, false);
        };
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        match a.as_slice() {
            [] => say(
                "setup",
                format!(
                    "<b>Group Shield setup</b>\n/setup on or off: scan files posted here\n/setup autodelete on: remove messages containing a confirmed-malicious file (needs your confirmation and my Delete messages permission)\n/setup autodelete off\n/setup clean on or off: also post clean results (now {})\n/setup incomplete on or off: post files that could not be checked (now {})\n\n{}",
                    if g.report_clean { "on" } else { "off" },
                    if g.report_incomplete { "on" } else { "off" },
                    self.status_text(bot, me, g)
                ),
            ),
            ["on"] => {
                if self.cfg.read().unwrap().hosted.is_some() && !self.store.user_reachable(uid) {
                    return say("start", "Open the SENTRIX bot privately and press Start first, so I can send you the results. Then send /setup on again.".into());
                }
                let _ = self.store.group_set_enabled(chat, true, uid, now);
                if self.cfg.read().unwrap().hosted.is_some() {
                    let _ = self.store.group_set_report(chat, Some(true), None);
                }
                let own = bot.get_chat_member(chat, me.id).ok();
                let blind = me.can_read_all_group_messages == Some(false) && !own.as_ref().is_some_and(|m| m.is_admin());
                self.event("group_enabled", "info", "Group Shield was turned on for a group by one of its administrators.");
                say(
                    "on",
                    if blind {
                        "Protection is <b>on</b>, but I cannot see files yet: Telegram privacy mode is on. Make me a group administrator, or ask the bot owner to run /setprivacy in @BotFather and choose Disable, then re-add me.".into()
                    } else {
                        "Protection is <b>on</b>. Files posted as documents (up to 20 MB) will be scanned. Results are sent privately to the administrator who turned this on, not posted here.".into()
                    },
                );
            }
            ["off"] => {
                let _ = self.store.group_set_enabled(chat, false, uid, now);
                self.event("group_disabled", "info", "Group Shield was turned off for a group by one of its administrators.");
                say("off", "Protection is <b>off</b>. Automatic deletion is off too.".into());
            }
            ["autodelete", "on"] => {
                if !g.enabled {
                    return say("ad", "Turn protection on first: <code>/setup on</code>.".into());
                }
                if u.anonymous_admin {
                    return say("ad", "Automatic deletion needs a named administrator. Turn off \"Remain anonymous\".".into());
                }
                match bot.get_chat_member(chat, me.id) {
                    Ok(m) if m.may_delete() => {
                        self.store.kv_set(&format!("gs_consent:{chat}"), &format!("{uid}:{now}"));
                        say("ad", "Please confirm. If you agree, I will <b>delete any message that contains a file my scanner positively identifies as malicious</b>. Deleted messages cannot be restored. Within 5 minutes, send <code>/setup autodelete confirm</code>.".into());
                    }
                    _ => say("ad", "I cannot delete messages here. Make me an administrator with the <b>Delete messages</b> permission, then try again.".into()),
                }
            }
            ["autodelete", "confirm"] => {
                let pending = self.store.kv_get(&format!("gs_consent:{chat}")).and_then(|v| v.split_once(':').map(|(a, b)| (a.parse::<i64>().ok(), b.parse::<i64>().ok())).map(|(a, b)| (a, b)));
                let ok = matches!(pending, Some((Some(who), Some(at))) if who == uid && now - at <= CONSENT_WINDOW_MS);
                if !ok || u.anonymous_admin {
                    return say("ad", "There is nothing to confirm. Send <code>/setup autodelete on</code> first; the same administrator must confirm within 5 minutes.".into());
                }
                self.store.kv_delete(&format!("gs_consent:{chat}"));
                // The permission is checked again at the moment of consent, not only when it was requested.
                match bot.get_chat_member(chat, me.id) {
                    Ok(m) if m.may_delete() => {
                        let _ = self.store.group_set_auto_delete(chat, true, uid, now);
                        self.event("group_autodelete_on", "info", "Automatic deletion of malicious files was enabled for a group by one of its administrators.");
                        say("ad", "Automatic deletion is <b>on</b>. Turn it off any time with <code>/setup autodelete off</code>.".into());
                    }
                    _ => say("ad", "I no longer have the Delete messages permission, so automatic deletion was not turned on.".into()),
                }
            }
            ["autodelete", "off"] => {
                let _ = self.store.group_set_auto_delete(chat, false, uid, now);
                self.store.kv_delete(&format!("gs_consent:{chat}"));
                say("ad", "Automatic deletion is <b>off</b>.".into());
            }
            ["clean", v @ ("on" | "off")] => {
                let _ = self.store.group_set_report(chat, Some(*v == "on"), None);
                say("clean", format!("Clean results will {}be posted.", if *v == "on" { "" } else { "not " }));
            }
            ["incomplete", v @ ("on" | "off")] => {
                let _ = self.store.group_set_report(chat, None, Some(*v == "on"));
                say("inc", format!("Files that could not be checked will {}be posted.", if *v == "on" { "" } else { "not " }));
            }
            _ => say("bad", "I did not understand that. Send /setup to see the options.".into()),
        }
    }

    /// Hand a file to the worker pool and return at once, so the listening thread never waits on a download or a scan.
    fn queue_document(&self, me: &BotInfo, g: &Group, u: &Incoming, doc: &Document) {
        let Some(mid) = u.message_id else { return };
        let Some(bot) = self.bot.read().unwrap().clone() else { return };
        if !self.groups.inflight.lock().unwrap().insert((g.chat_id, mid)) {
            return; // already queued or being checked
        }
        let job = DocJob { bot, me: me.clone(), group: g.clone(), update: u.clone(), doc: doc.clone(), mid };
        let tx = self.docs.lock().unwrap().clone();
        match tx {
            Some(tx) => {
                if let Err(e) = tx.try_send(job) {
                    let job = match e {
                        std::sync::mpsc::TrySendError::Full(j) | std::sync::mpsc::TrySendError::Disconnected(j) => j,
                    };
                    self.groups.inflight.lock().unwrap().remove(&(g.chat_id, mid));
                    let _ = self.store.group_record_scan(g.chat_id, mid, job.doc.file_unique_id.as_deref(), "", job.doc.file_size.unwrap_or(0), "UNABLE_TO_VERIFY", false, "skipped_busy", None, now_ms());
                    if g.report_incomplete {
                        let _ = self.post_report(g, &format!("busy:{mid}"), format!("<b>{}</b> arrived while SENTRIX was busy with many other files. It was <b>not checked</b> and is not known to be safe.", safe_display_name(job.doc.file_name.as_deref().unwrap_or("file"))), false);
                    }
                }
            }
            // The service is not running its pool (a unit test, or shutting down): do it here.
            None => {
                self.run_document(job);
                self.groups.inflight.lock().unwrap().remove(&(g.chat_id, mid));
            }
        }
    }

    pub(crate) fn run_document(&self, j: DocJob) {
        self.on_document(&j.bot, &j.me, &j.group, &j.update, &j.doc);
    }

    fn on_document(&self, bot: &BotClient, me: &BotInfo, g: &Group, u: &Incoming, doc: &Document) {
        let chat = g.chat_id;
        let Some(mid) = u.message_id else { return };
        // Telegram can redeliver an update; one message is handled once.
        if self.store.group_scan_seen(chat, mid).unwrap_or(true) {
            return;
        }
        let t_start = Instant::now();
        let now = now_ms();
        let name = doc.file_name.clone().unwrap_or_else(|| "file".into());
        let shown = safe_display_name(&name);
        let uid = doc.file_unique_id.as_deref();
        let size = doc.file_size.unwrap_or(0);
        let incomplete_note = |why: String| {
            if g.report_incomplete {
                let _ = self.post_report(g, &format!("m{mid}"), format!("<b>{shown}</b> {why} It was <b>not checked</b> and is not known to be safe."), false);
            }
        };

        if !allow(&self.groups.scans, chat, SCANS_PER_MIN, Duration::from_secs(60)) {
            let _ = self.store.group_record_scan(chat, mid, uid, "", size, "UNABLE_TO_VERIFY", false, "skipped_rate", None, now);
            if self.notice_due(chat, "scan_rate", Duration::from_secs(60)) {
                let _ = self.post_report(g, &format!("rate:{}", u.update_id), "Too many files at once. Some were <b>skipped and not checked</b>.".into(), false);
            }
            return;
        }
        if size > MAX_BOT_DOWNLOAD {
            let _ = self.store.group_record_scan(chat, mid, uid, "", size, "UNABLE_TO_VERIFY", false, "skipped_size", None, now);
            return incomplete_note("is larger than 20 MB, the most Telegram lets a bot download.".into());
        }
        self.start_placeholder(bot, g, mid, &shown, size);
        let (path, _) = match bot.get_file(&doc.file_id) {
            Ok(x) => x,
            Err(e) => {
                let _ = self.store.group_record_scan(chat, mid, uid, "", size, "UNABLE_TO_VERIFY", false, "unavailable", None, now);
                return incomplete_note(format!("could not be retrieved from Telegram ({}).", esc(&e.user_message())));
            }
        };
        let mut buf: Vec<u8> = Vec::new();
        let t_download = Instant::now();
        if let Err(e) = bot.download(&path, &mut buf, MAX_BOT_DOWNLOAD) {
            let _ = self.store.group_record_scan(chat, mid, uid, "", size, "UNABLE_TO_VERIFY", false, "unavailable", None, now);
            return incomplete_note(format!("could not be downloaded ({}).", esc(&e.user_message())));
        }
        let title: String = g.title.chars().filter(|c| !c.is_control()).take(60).collect();
        let origin = format!("Telegram group: {title}");
        let download_ms = t_download.elapsed().as_millis() as u64;
        let t_scan = Instant::now();
        match self.scan_ephemeral(&origin, &name, &mut buf.as_slice(), MAX_BOT_DOWNLOAD) {
            Ok(r) => {
                let scan_ms = t_scan.elapsed().as_millis() as u64;
                self.finish_document(bot, me, chat, mid, uid, &shown, &r);
                self.hooks.on_group_scan(&crate::service::GroupScanTiming { size: buf.len() as u64, download_ms, scan_ms, total_ms: t_start.elapsed().as_millis() as u64, verdict: verdict_code(r.verdict) });
            }
            Err(e) => {
                let _ = self.store.group_record_scan(chat, mid, uid, "", size, "UNABLE_TO_VERIFY", false, "error", None, now);
                incomplete_note(format!("could not be scanned ({}).", esc(&e)));
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_document(&self, bot: &BotClient, me: &BotInfo, chat: i64, mid: i64, uid: Option<&str>, shown: &str, r: &ScanReport) {
        let now = now_ms();
        // Read the settings again: an administrator may have changed them while this file was being scanned.
        let Ok(Some(g)) = self.store.group_get(chat) else { return };
        let code = verdict_code(r.verdict);
        let mut action: Option<String> = None;
        let mut action_line = String::new();

        if r.verdict == Verdict::Malicious && g.auto_delete && g.delete_consent_at.is_some() {
            // Deleting is destructive, so check the permission at the moment of use and never claim success without Telegram's "ok".
            match bot.get_chat_member(chat, me.id) {
                Ok(m) if m.may_delete() => match bot.delete_message(chat, mid) {
                    Ok(()) => {
                        action = Some("deleted".into());
                        action_line = "\nAction: <b>the message was deleted</b>.".into();
                    }
                    Err(e) => {
                        action = Some("delete_failed".into());
                        action_line = format!("\nAction: <b>could not delete the message</b> ({}). Remove it manually.", esc(&e.user_message()));
                        self.event("group_delete_failed", "warning", "A malicious file was found in a group but its message could not be deleted.");
                    }
                },
                _ => {
                    action = Some("delete_failed".into());
                    action_line = "\nAction: <b>could not delete the message</b>, I no longer have the Delete messages permission. Remove it manually.".into();
                    self.event("group_delete_failed", "warning", "A malicious file was found in a group but the bot lacks the Delete messages permission.");
                }
            }
        }

        let _ = self.store.group_record_scan(chat, mid, uid, &r.file.sha256, r.file.size, code, r.complete, "scanned", action.as_deref(), now);
        self.hooks.on_report(r);

        let sigs: Vec<String> = r.findings.iter().filter(|f| f.kind == FindingKind::Signature).map(|f| esc(&f.name)).take(3).collect();
        let hash = if r.file.sha256.len() >= 16 { format!("\nSHA-256: <code>{}…</code>", &r.file.sha256[..16]) } else { String::new() };
        let (text, urgent, post) = match r.verdict {
            Verdict::Malicious => (
                format!("<b>SENTRIX: MALICIOUS file</b>\n<b>{shown}</b>\nDetection: {}{hash}{action_line}\n{}Do not open it.", if sigs.is_empty() { "positively identified by the scanner".into() } else { sigs.join(", ") }, crate::notify::threat_lines(r)),
                true,
                true,
            ),
            Verdict::Suspicious => (format!("<b>SENTRIX: SUSPICIOUS file</b>\n<b>{shown}</b>\nIndicators were found that deserve a closer look. This is not proof of malware. Be careful before opening it.{hash}\n{}", crate::notify::threat_lines(r)), false, true),
            Verdict::Clean => (format!("<b>SENTRIX: no known threat</b>\n<b>{shown}</b>\nThe checks that ran found nothing. That is not a guarantee."), false, g.report_clean),
            Verdict::UnableToVerify | Verdict::Pending => (format!("<b>SENTRIX: could not be fully checked</b>\n<b>{shown}</b>\n{}\nNot known to be safe.", esc(&r.summary)), false, g.report_incomplete),
        };
        if post {
            let _ = self.post_report(&g, &format!("m{mid}"), text, urgent);
        }
    }
}
