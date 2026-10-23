//! The shared SENTRIX bot: what a person sees when they find the bot, press Start and choose what to protect.
//!
//! One bot token, many people. The rules that keep them apart:
//!  * Everything a person can change is checked against their Telegram user id, never against message text.
//!  * A group is linked only with a one-time code made for that person, used by that person, in a group where Telegram says
//!    they are an administrator.
//!  * Scan reports go to the private chat of the person who linked the group. They are never posted in the group.
//!  * The bot can only write to people who pressed Start. Anyone else is told how to, and nothing is switched on for them.
//!
//! Account protection is NOT done here. It runs on the person's own computer (the desktop app); this module only issues
//! the code that links that app to the person's chat (see `relay.rs`). The bot never sees a Telegram login.

use crate::group::allow;
use crate::hosted_store::CodeKind;
use crate::queue::{now_ms, Group};
use crate::service::Inner;
use crate::telegram::{esc, safe_display_name, BotClient, BotInfo, Button, Callback, Incoming};
use rand::RngCore;
use std::time::Duration;

pub const GROUP_CODE_TTL_MS: i64 = 30 * 60 * 1000;
pub const DEVICE_CODE_TTL_MS: i64 = 10 * 60 * 1000;
/// Messages one person may send the bot per minute before it stops answering for a moment.
pub const PRIVATE_PER_MIN: usize = 30;

#[derive(Clone, Debug, Default)]
pub struct HostedConfig {
    /// Where people get the desktop app. Empty: the bot says to ask the SENTRIX contact.
    pub download_url: String,
}

/// `g_` + 20 hex digits. Lowercase on purpose: commands arrive lowercased.
pub fn new_group_code() -> String {
    let mut b = [0u8; 10];
    rand::thread_rng().fill_bytes(&mut b);
    format!("g_{}", hex::encode(b))
}

/// Eight characters from an alphabet without look-alikes (no 0/O, 1/I), shown as `ABCD-EFGH`.
pub fn new_device_code() -> String {
    const A: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut r = rand::thread_rng();
    (0..8).map(|_| A[(r.next_u32() % 32) as usize] as char).collect()
}

pub fn show_device_code(c: &str) -> String {
    format!("{}-{}", &c[..4], &c[4..])
}

/// What a person typed or pasted, reduced to the code itself.
pub fn normalize_device_code(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_uppercase()).collect()
}

fn main_menu() -> Vec<Vec<Button>> {
    vec![
        vec![Button::callback("Protect a group", "m:group")],
        vec![Button::callback("Protect my account", "m:account")],
        vec![Button::callback("My protection", "m:mine"), Button::callback("How it works", "m:help")],
    ]
}

fn back() -> Vec<Button> {
    vec![Button::callback("Back to menu", "m:main")]
}

const HOW_IT_WORKS: &str = "<b>How SENTRIX works</b>\nI check files for malware and tell you what I find, here, privately.\n\n<b>The app comes first.</b> I only work for people who have the SENTRIX app installed and linked to me. Without it I do not check anything, for groups or for your account. Keep the app installed: if it is not seen for 14 days, protection pauses until you open it again.\n\n<b>Groups.</b> You add me to as many groups as you like, as long as you are in them. I check documents people post there (up to 20 MB). The results go to your <b>Scan History</b> group(s), never into the protected group. Files are checked and deleted straight away.\n\n<b>Your account.</b> The SENTRIX app on your own computer checks files that reach your Telegram account. Your Telegram login stays on your computer. The app sends me only the result to pass on to you.\n\n<b>Limits.</b> I cannot see secret chats, photos and videos are not checked, and files over 20 MB in groups are not checked. \"Not checked\" never means safe. No antivirus catches everything.";

impl Inner {
    fn hosted_download_url(&self) -> String {
        self.cfg.read().unwrap().hosted.as_ref().map(|h| h.download_url.clone()).unwrap_or_default()
    }

    /// Direct, immediate reply to a person who just wrote to the bot. Failures are noted, never fatal.
    fn private_say(&self, bot: &BotClient, user: i64, text: &str, rows: &[Vec<Button>]) {
        let r = if rows.is_empty() { bot.send_reply(user, text, None).map(|_| ()) } else { bot.send_buttons(user, text, rows).map(|_| ()) };
        if let Err(e) = r {
            self.event("hosted_send_failed", "warning", &format!("A reply to someone could not be sent: {}", e.user_message()));
        }
    }

    /// Every message to the bot in a private chat (shared-bot mode).
    pub(crate) fn handle_hosted_private(&self, bot: &BotClient, me: &BotInfo, u: &Incoming) {
        let Some(uid) = u.from_id else { return };
        // Private chat id and user id are the same number. Anything else is not a person talking to us.
        if u.chat_id != uid {
            return;
        }
        let now = now_ms();
        // The person blocked or unblocked the bot. Reports to a blocked person would only fail.
        if let Some(mc) = &u.member_change {
            match mc.new_status.as_str() {
                "kicked" | "left" => self.store.user_set_blocked(uid, true),
                "member" => self.store.user_set_blocked(uid, false),
                _ => {}
            }
            return;
        }
        if !allow(&self.groups.private, uid, PRIVATE_PER_MIN, Duration::from_secs(60)) {
            if let Some(cb) = &u.callback {
                let _ = bot.answer_callback(&cb.id, Some("One moment, please."));
            }
            return;
        }
        let first = u.from_name.as_deref().unwrap_or("");
        let _ = self.store.user_started(uid, first, now);
        if let Some(cb) = &u.callback {
            self.hosted_callback(bot, me, uid, cb);
            return;
        }
        let text = u.text.as_deref().unwrap_or("").trim();
        let cmd = text.split_whitespace().next().unwrap_or("").split('@').next().unwrap_or("").to_ascii_lowercase();
        match cmd.as_str() {
            // The app opens the bot with `?start=account`, so the code is waiting the moment the person presses Start.
            "/start" if text.split_whitespace().nth(1) == Some("account") => self.show_account(bot, me, uid),
            "/start" if text.split_whitespace().nth(1) == Some("group") => self.show_group_steps(bot, me, uid),
            "/start" | "/menu" => self.show_welcome(bot, uid, first),
            "/help" => self.private_say(bot, uid, HOW_IT_WORKS, &[back()]),
            "/groups" | "/mine" => self.show_mine(bot, uid),
            "/account" => self.show_account(bot, me, uid),
            _ => {
                if self.need_app(bot, uid) {
                    return;
                }
                let hint = if u.document.is_some() || u.other_media { "I check files in groups you protect and in your SENTRIX app, not files sent here. Choose what to protect:" } else { "Choose what to protect:" };
                self.private_say(bot, uid, hint, &main_menu());
            }
        }
    }

    fn show_welcome(&self, bot: &BotClient, uid: i64, first: &str) {
        let name: String = first.chars().filter(|c| !c.is_control()).take(40).collect();
        let hello = if name.trim().is_empty() { "<b>Welcome.</b>".to_string() } else { format!("<b>Welcome, {}.</b>", safe_display_name(&name)) };
        if !self.store.app_active(uid, now_ms()) {
            return self.show_app_required(bot, uid, &hello);
        }
        self.private_say(bot, uid, &format!("{hello}\nI am SENTRIX. I check files for malware and tell you what I find, here, privately.\n\nWhat do you want to protect?"), &main_menu());
    }

    /// Everything the bot does needs the SENTRIX app on the person's computer. If this person has none that is linked and
    /// recently seen, say so (with the download and a code to link it) and return `true`; the caller must stop.
    fn need_app(&self, bot: &BotClient, uid: i64) -> bool {
        if self.store.app_active(uid, now_ms()) {
            return false;
        }
        self.show_app_required(bot, uid, "");
        true
    }

    /// The only thing a person without the app can do here: get it, and link it with a one-time code.
    fn show_app_required(&self, bot: &BotClient, uid: i64, hello: &str) {
        let code = new_device_code();
        if self.store.code_issue(CodeKind::Device, uid, &code, now_ms() + DEVICE_CODE_TTL_MS).is_err() {
            return self.private_say(bot, uid, "Something went wrong on my side. Please try again.", &[]);
        }
        let url = self.hosted_download_url();
        let get = if url.is_empty() { "1. Get the SENTRIX app from the person who gave you this bot.".to_string() } else { format!("1. Download and install the SENTRIX app: {}", esc(&url)) };
        let lead = if hello.is_empty() { String::new() } else { format!("{hello}\nI am SENTRIX. I check files for malware and tell you what I find, here, privately.\n\n") };
        self.private_say(
            bot,
            uid,
            &format!("{lead}<b>Install the SENTRIX app first.</b> I work only for people who use the SENTRIX app, so until it is installed and linked to me I cannot check anything for you, not groups and not your account. Your Telegram login stays on your computer and never reaches me.\n\n{get}\n2. In the app open <b>Telegram</b>, then <b>Your account</b>, and choose <b>Link to the bot</b>.\n3. Enter this code:\n\n<code>{}</code>\n\nThe code works once and for 10 minutes. As soon as the app is linked I unlock everything here.", show_device_code(&code)),
            &[vec![Button::callback("Get a new code", "m:account")], vec![Button::callback("How it works", "m:help")]],
        );
    }

    fn show_group_steps(&self, bot: &BotClient, me: &BotInfo, uid: i64) {
        if self.need_app(bot, uid) {
            return;
        }
        let Some(username) = me.username.as_deref() else {
            return self.private_say(bot, uid, "I cannot make the group link right now. Please try again later.", &[back()]);
        };
        let code = new_group_code();
        if self.store.code_issue(CodeKind::Group, uid, &code, now_ms() + GROUP_CODE_TTL_MS).is_err() {
            return self.private_say(bot, uid, "Something went wrong on my side. Please try again.", &[back()]);
        }
        let url = format!("https://t.me/{username}?startgroup={code}");
        self.private_say(
            bot,
            uid,
            "<b>Protect a group</b>\n1. Make a new group called <b>Scan History</b> and add me to it. I notice it by myself and start sending results there, so the group you protect stays quiet. You can add other people to it too: everyone in it can read the results. Make as many Scan History groups as you like, and every one gets every result.\n2. Press <b>Choose a group</b> below and pick the group to protect. Telegram adds me to it. You only need to be a member of it, not an administrator. Protect as many groups as you like: come back here and press the button again for each one.\n3. I confirm in your Scan History group as soon as it is ready.\n\nI check documents people post in the group (up to 20 MB) and delete them straight away. Until a Scan History group exists, results come to this chat.\n\nThe button works for 30 minutes.",
            &[vec![Button::url("Choose a group", &url)], back()],
        );
    }

    fn show_account(&self, bot: &BotClient, _me: &BotInfo, uid: i64) {
        if !self.store.app_active(uid, now_ms()) {
            return self.show_app_required(bot, uid, "");
        }
        let code = new_device_code();
        if self.store.code_issue(CodeKind::Device, uid, &code, now_ms() + DEVICE_CODE_TTL_MS).is_err() {
            return self.private_say(bot, uid, "Something went wrong on my side. Please try again.", &[back()]);
        }
        let url = self.hosted_download_url();
        let get = if url.is_empty() { "1. Get the SENTRIX app from the person who gave you this bot.".to_string() } else { format!("1. Get the SENTRIX app: {}", esc(&url)) };
        self.private_say(
            bot,
            uid,
            &format!("<b>Protect my account</b>\nAccount protection runs inside the SENTRIX app on your own computer, so your Telegram login never reaches me. The app checks files that reach your account and sends me only the result, which I pass on to you here.\n\n{get}\n2. In the app open <b>Telegram</b>, then <b>Your account</b>, and choose <b>Link to the bot</b>.\n3. Enter this code:\n\n<code>{}</code>\n\nThe code works once and for 10 minutes. Your computer must be on for protection to work.", show_device_code(&code)),
            &[vec![Button::callback("Get a new code", "m:account")], back()],
        );
    }

    /// How many protected groups one page of "My protection" lists. A person can protect any number of groups; the list pages.
    const MINE_PAGE: usize = 6;

    fn show_mine(&self, bot: &BotClient, uid: i64) {
        self.show_mine_page(bot, uid, 0)
    }

    fn show_mine_page(&self, bot: &BotClient, uid: i64, page: usize) {
        let groups: Vec<Group> = self.store.groups_list().unwrap_or_default().into_iter().filter(|g| g.enabled_by == Some(uid) && g.left_at.is_none()).collect();
        let devices = self.store.devices_of(uid);
        let mut t = String::from("<b>Your protection</b>\n");
        let history = self.store.history_rooms(uid);
        t += &match history.len() {
            0 => "Results come to this chat. Make a group called <b>Scan History</b> and add me to it to receive them there.\n".to_string(),
            1 => format!("Results go to your <b>{}</b> group.\n", safe_display_name(&history[0].title)),
            n => format!("You have {n} Scan History groups (#{}). Each protected group below reports to the one you chose.\n", history.iter().map(|h| h.num.to_string()).collect::<Vec<_>>().join(", #")),
        };
        let pages = groups.len().div_ceil(Self::MINE_PAGE).max(1);
        let page = page.min(pages - 1);
        let mut rows: Vec<Vec<Button>> = vec![];
        t += &format!("\n<b>Groups</b>{}\n", if groups.len() > Self::MINE_PAGE { format!(" ({} in total, page {} of {pages})", groups.len(), page + 1) } else { String::new() });
        if groups.is_empty() {
            t += "None yet. Choose <b>Protect a group</b> to add one. There is no limit.\n";
        }
        let rooms = self.store.history_rooms(uid);
        for g in groups.iter().skip(page * Self::MINE_PAGE).take(Self::MINE_PAGE) {
            let short_name: String = g.title.chars().filter(|c| !c.is_control()).take(14).collect();
            let day = self.store.group_stats(g.chat_id, now_ms() - 86_400_000).unwrap_or_default();
            let name = safe_display_name(&g.title);
            t += &format!("{}: {}. Today {} checked, {} threat{}.\n", name, if g.enabled { "protected" } else { "paused" }, day.scans, day.threats, if day.threats == 1 { "" } else { "s" });
            let short: String = g.title.chars().filter(|c| !c.is_control()).take(18).collect();
            if rooms.len() > 1 {
                let to = match self.store.report_choice_get(g.chat_id).and_then(|h| rooms.iter().find(|r| r.chat_id == h)) {
                    Some(r) => format!("Reports to: Scan History #{}", r.num),
                    None => "Reports to: all Scan History groups".to_string(),
                };
                t += &format!("   {to}\n");
                rows.push(vec![Button::callback(&format!("Change where {short_name} reports"), &format!("r:{}", g.chat_id))]);
            }
            let mut row = vec![if g.enabled { Button::callback(&format!("Pause {short}"), &format!("g:off:{}", g.chat_id)) } else { Button::callback(&format!("Resume {short}"), &format!("g:on:{}", g.chat_id)) }];
            row.push(Button::callback("Remove", &format!("g:rm:{}", g.chat_id)));
            rows.push(row);
        }
        if pages > 1 {
            let mut nav = vec![];
            if page > 0 {
                nav.push(Button::callback("Previous groups", &format!("m:mine:{}", page - 1)));
            }
            if page + 1 < pages {
                nav.push(Button::callback("More groups", &format!("m:mine:{}", page + 1)));
            }
            rows.push(nav);
        }
        t += "\n<b>Your computers</b>\n";
        if devices.is_empty() {
            t += "None linked. Choose <b>Protect my account</b>.\n";
        }
        for d in &devices {
            t += &format!("{}: linked.\n", safe_display_name(&d.name));
            let short: String = d.name.chars().filter(|c| !c.is_control()).take(18).collect();
            rows.push(vec![Button::callback(&format!("Unlink {short}"), &format!("d:rm:{}", d.id))]);
        }
        rows.push(back());
        self.private_say(bot, uid, &t, &rows);
    }

    fn hosted_callback(&self, bot: &BotClient, me: &BotInfo, uid: i64, cb: &Callback) {
        let now = now_ms();
        let mut note: Option<&str> = None;
        let parts: Vec<&str> = cb.data.split(':').collect();
        // Switching protection on, or changing where reports go, needs the app. Pausing, removing and unlinking never do.
        if matches!(parts.as_slice(), ["g", "on", _] | ["r", ..]) && self.need_app(bot, uid) {
            let _ = bot.answer_callback(&cb.id, None);
            return;
        }
        match parts.as_slice() {
            ["m", "main"] => self.show_welcome(bot, uid, ""),
            ["m", "group"] => self.show_group_steps(bot, me, uid),
            ["m", "account"] => self.show_account(bot, me, uid),
            ["m", "mine"] => self.show_mine(bot, uid),
            ["m", "mine", p] => self.show_mine_page(bot, uid, p.parse().unwrap_or(0)),
            ["m", "help"] => self.private_say(bot, uid, HOW_IT_WORKS, &[back()]),
            ["g", act @ ("off" | "on" | "rm"), id] => {
                let Some(chat) = id.parse::<i64>().ok() else { return };
                // Only the person who linked a group may touch it. Telegram's own record, not the button, decides.
                let mine = matches!(self.store.group_get(chat), Ok(Some(g)) if g.enabled_by == Some(uid) && g.left_at.is_none());
                if !mine {
                    note = Some("That group is not yours to change.");
                } else {
                    match *act {
                        "off" => {
                            let _ = self.store.group_set_enabled(chat, false, uid, now);
                            let _ = self.store.group_set_auto_delete(chat, false, uid, now);
                            self.event("group_disabled", "info", "A group was paused by the person who protects it.");
                        }
                        "on" => match bot.get_chat_member(chat, uid) {
                            Ok(m) if m.is_member() => {
                                let _ = self.store.group_set_enabled(chat, true, uid, now);
                            }
                            _ => note = Some("You are no longer in that group, so it cannot be resumed."),
                        },
                        _ => {
                            let _ = bot.leave_chat(chat);
                            let _ = self.store.group_forget(chat);
                            self.event("group_removed", "info", "A group was removed by the person who protected it. The bot left.");
                        }
                    }
                }
                self.show_mine(bot, uid);
            }
            ["r", id] => {
                let Some(chat) = id.parse::<i64>().ok() else { return };
                if matches!(self.store.group_get(chat), Ok(Some(g)) if g.enabled_by == Some(uid) && g.left_at.is_none()) {
                    self.ask_where_to_report(bot, uid, chat);
                } else {
                    note = Some("That group is not yours to change.");
                }
            }
            ["r", id, dest] => {
                let Some(chat) = id.parse::<i64>().ok() else { return };
                let mine = matches!(self.store.group_get(chat), Ok(Some(g)) if g.enabled_by == Some(uid) && g.left_at.is_none());
                let rooms = self.store.history_rooms(uid);
                let choice = if *dest == "all" { Some(None) } else { dest.parse::<i64>().ok().filter(|d| rooms.iter().any(|r| r.chat_id == *d)).map(Some) };
                match (mine, choice) {
                    (true, Some(c)) => {
                        self.store.report_choice_set(chat, c);
                        note = Some("Saved.");
                        self.show_mine(bot, uid);
                    }
                    _ => note = Some("That choice is not available any more."),
                }
            }
            ["d", "rm", id] => {
                if !self.store.device_revoke(uid, id, now) {
                    note = Some("That computer is not linked to you.");
                }
                self.show_mine(bot, uid);
            }
            _ => {}
        }
        let _ = bot.answer_callback(&cb.id, note);
    }

    /// "Which Scan History group should this protected group report to?" One button per room, plus all of them.
    pub(crate) fn ask_where_to_report(&self, bot: &BotClient, uid: i64, group_chat: i64) {
        let rooms = self.store.history_rooms(uid);
        let current = self.store.report_choice_get(group_chat);
        let name = self.store.group_get(group_chat).ok().flatten().map(|g| safe_display_name(&g.title)).unwrap_or_else(|| "this group".into());
        let mut rows: Vec<Vec<Button>> = rooms
            .iter()
            .map(|r| {
                let mark = if current == Some(r.chat_id) { "✓ " } else { "" };
                vec![Button::callback(&format!("{mark}Scan History #{}", r.num), &format!("r:{group_chat}:{}", r.chat_id))]
            })
            .collect();
        rows.push(vec![Button::callback(&format!("{}All of them", if current.is_none() { "✓ " } else { "" }), &format!("r:{group_chat}:all"))]);
        rows.push(back());
        self.private_say(bot, uid, &format!("<b>Where should reports from {name} go?</b>\nEach Scan History group has a number, shown at the top of its welcome message. Many protected groups can report to the same one."), &rows);
    }

    /// `/start g_<code>` posted in a group by the person who pressed "Choose a group". This is the only way a group gets
    /// linked to someone's private chat in shared-bot mode.
    pub(crate) fn hosted_link_group(&self, bot: &BotClient, me: &BotInfo, u: &Incoming, code: &str) {
        let chat = u.chat_id;
        let now = now_ms();
        let say = |tag: &str, body: String| {
            let _ = self.say(chat, u.message_id, &format!("{tag}:{}", u.update_id), "group_reply", body, false);
        };
        if u.anonymous_admin {
            return say("anon", "I cannot tell who you are while you post anonymously. Turn off \"Remain anonymous\" and try the link again.".into());
        }
        let Some(owner) = self.store.code_peek(CodeKind::Group, code, now) else {
            return say("code", "This link has expired or was already used. Open the SENTRIX bot privately and choose Protect a group again.".into());
        };
        if u.from_id != Some(owner) {
            return say("who", "This link was made for someone else. Open the SENTRIX bot privately and make your own.".into());
        }
        // The code is not used up, so the same link works once the app is linked (within its 30 minutes).
        if !self.store.app_active(owner, now) {
            return say("app", "I cannot protect this group yet: the SENTRIX app must be installed and linked first. Open the SENTRIX bot privately for the download and your link code, then use the link again.".into());
        }
        // Any member of the group can set up protection, not only administrators. Telegram, not the message, says who is in it.
        match bot.get_chat_member(chat, owner) {
            Ok(m) if m.is_admin() => {}
            Ok(m) if m.is_member() => {
                // A member may protect a group nobody protects yet. Taking over a group someone else already protects needs
                // an administrator, so a member cannot quietly redirect another person's reports.
                let taken = matches!(self.store.group_get(chat), Ok(Some(g)) if g.enabled && g.left_at.is_none() && g.enabled_by.is_some_and(|o| o != owner));
                if taken {
                    return say("taken", "Someone else already protects this group. A group administrator can take it over.".into());
                }
            }
            Ok(_) => return say("admin", "You are not a member of this group, so you cannot protect it.".into()),
            Err(_) => return say("admin", "I could not verify that you are in this group, so nothing was changed.".into()),
        }
        if !self.store.user_reachable(owner) {
            return say("start", "Open the SENTRIX bot privately and press Start first, so I can send you the results.".into());
        }
        if self.store.code_take(CodeKind::Group, code, now).is_none() {
            return say("code", "This link was already used.".into());
        }
        let _ = self.store.group_set_enabled(chat, true, owner, now);
        let _ = self.store.group_set_report(chat, Some(true), None);
        self.event("group_linked", "info", "A group was linked to a person's private chat and protection was turned on.");
        let own = bot.get_chat_member(chat, me.id).ok();
        let blind = me.can_read_all_group_messages == Some(false) && !own.as_ref().is_some_and(|m| m.is_admin());
        let title = safe_display_name(u.chat_title.as_deref().unwrap_or("your group"));
        let mut t = format!("<b>{title}</b> is now protected. Results will arrive here.");
        if blind {
            t += "\n\n<b>One more step.</b> Telegram is hiding the group's files from me. Make me an administrator of the group (no special rights needed) so I can see them.";
        }
        match self.store.history_get(owner) {
            Some(_) if self.store.history_rooms(owner).len() > 1 => {
                // Several Scan History groups: ask which one this group reports to (until answered, all of them get it).
                let _ = self.store.report_choice_set(chat, None);
                self.private_say(bot, owner, &format!("{t}\n\nYou have more than one Scan History group, so tell me where this group's results should go."), &[]);
                self.ask_where_to_report(bot, owner, chat);
            }
            Some((h, _)) => {
                let _ = self.store.enqueue_notification_to(&format!("linked:{chat}:{}", u.update_id), "hosted_notice", &t, now, Some(h), None);
            }
            None => {
                let t2 = format!("{t}\n\nOne more thing: make a group called <b>Scan History</b> and add me to it. From then on, results go there instead of this chat.");
                let _ = self.store.enqueue_notification_to(&format!("linked:{chat}:{}", u.update_id), "hosted_notice", &t2, now, Some(owner), None);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_have_the_expected_shape_and_never_repeat_quickly() {
        let g = new_group_code();
        assert!(g.starts_with("g_") && g.len() == 22 && g[2..].chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()), "{g}");
        let d = new_device_code();
        assert_eq!(d.len(), 8);
        assert!(d.chars().all(|c| "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".contains(c)));
        assert_ne!(new_group_code(), new_group_code());
        assert_eq!(show_device_code("ABCD2345"), "ABCD-2345");
    }

    #[test]
    fn what_a_person_types_is_reduced_to_the_code() {
        assert_eq!(normalize_device_code(" abcd-2345 \n"), "ABCD2345");
        assert_eq!(normalize_device_code("ab cd 23 45"), "ABCD2345");
    }
}
