//! Where a person's own SENTRIX app posts the result of each file it checks, with no bot and no server involved.
//!
//! The app is signed in to the person's own Telegram account (QR sign-in). When it checks a file from a chat, it posts the
//! result as a message from that same account, into:
//!  * a group the person made called "Scan History" (any number of them; they can add other people to read the results), or
//!  * their own "Saved Messages" when they have no Scan History group yet, and only for results that need attention
//!    (a stream of "clean" notes in Saved Messages would just be noise).
//!
//! Each protected group can be pointed at one Scan History group; with no choice made it reports to all of them. A Scan
//! History group is never itself checked.

use crate::telegram::is_deceptive;
use crate::types::{ScanReport, Verdict};
use std::collections::{BTreeSet, HashMap};

/// Scan History groups used at once. Only a guard against absurd numbers.
pub const MAX_ROOMS: usize = 25;
/// Telegram allows 4096 characters per message.
const MAX_TEXT: usize = 3500;

#[derive(Default)]
pub struct Routing {
    /// The person's own user id: their "Saved Messages" chat has the same id.
    pub me: Option<i64>,
    /// Groups and supergroups the person is in (not channels, not Scan History groups).
    pub groups: HashMap<i64, String>,
    /// Scan History groups.
    pub rooms: BTreeSet<i64>,
    /// Protected group -> the Scan History group it reports to.
    pub routes: HashMap<i64, i64>,
}

impl Routing {
    /// Where the result for a file seen in `chat` goes. Empty: nowhere to put it.
    pub fn destinations(&self, chat: i64, clean: bool) -> Vec<i64> {
        if !self.rooms.is_empty() {
            if let Some(room) = self.routes.get(&chat).filter(|r| self.rooms.contains(r)) {
                return vec![*room];
            }
            return self.rooms.iter().copied().collect();
        }
        if clean {
            return vec![];
        }
        self.me.into_iter().collect()
    }
}

fn tidy(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control() && !is_deceptive(*c)).take(max).collect()
}

/// The message posted for one result. Plain text: names come from other people and are never interpreted as formatting.
pub fn report_text(r: &ScanReport, source: &str) -> String {
    let mut t = format!("SENTRIX: {}\nFile: {}\nFrom: {}\n", r.verdict.label(), tidy(&r.file.name, 120), tidy(source, 100));
    t.push_str(&tidy(&r.summary, 300));
    t.push('\n');
    if let Some(th) = &r.threat {
        let how = if th.basis == "identified" { "" } else { " (looks like this from its behaviour; not proof)" };
        t.push_str(&format!("Type: {}{}\nWhat it does: {}\n", tidy(&th.title, 120), how, tidy(&th.goal, 220)));
    }
    for f in r.findings.iter().take(3) {
        t.push_str(&format!("- {}\n", tidy(&f.name, 120)));
    }
    if matches!(r.verdict, Verdict::Malicious | Verdict::Suspicious) {
        t.push_str("Do not open it.\n");
    }
    t.chars().take(MAX_TEXT).collect()
}

/// The first message posted into a new Scan History group, so the person (and anyone they add) knows what it is.
pub fn room_welcome(num: i64) -> String {
    format!("SENTRIX Scan History #{num}\nResults for the groups you protect appear here, one message per file checked. Everyone in this group can read them, so add only people who should.")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn routing() -> Routing {
        Routing { me: Some(5), ..Default::default() }
    }

    #[test]
    fn without_a_scan_history_group_only_results_that_need_attention_go_to_saved_messages() {
        let r = routing();
        assert_eq!(r.destinations(-100, false), vec![5]);
        assert!(r.destinations(-100, true).is_empty(), "clean results are not dumped into Saved Messages");
        assert!(Routing::default().destinations(-100, false).is_empty(), "no account id yet: nowhere to post");
    }

    #[test]
    fn with_scan_history_groups_everything_goes_there_and_never_to_saved_messages() {
        let mut r = routing();
        r.rooms.insert(-200);
        r.rooms.insert(-300);
        assert_eq!(r.destinations(-100, true), vec![-300, -200], "all of them by default (BTreeSet order)");
        assert_eq!(r.destinations(-100, false).len(), 2);
        assert!(!r.destinations(-100, false).contains(&5));
    }

    #[test]
    fn a_chosen_scan_history_group_wins_but_a_vanished_one_falls_back_to_all() {
        let mut r = routing();
        r.rooms.insert(-200);
        r.rooms.insert(-300);
        r.routes.insert(-100, -300);
        assert_eq!(r.destinations(-100, false), vec![-300]);
        assert_eq!(r.destinations(-101, false).len(), 2, "another group has no choice");
        r.rooms.remove(&-300);
        assert_eq!(r.destinations(-100, false), vec![-200], "the chosen room is gone: use what is left");
    }

    #[test]
    fn the_text_is_plain_bounded_and_free_of_control_and_direction_tricks() {
        let mut rep = crate::account::unverified_report("Telegram personal chat", "inv\u{202E}fdp.exe\u{7}", 10, "x");
        rep.summary = "s".repeat(10_000);
        let t = report_text(&rep, "group \"A\nB\"");
        assert!(t.chars().count() <= MAX_TEXT);
        assert!(!t.contains('\u{202E}') && !t.contains('\u{7}') && !t.contains("A\nB"), "{t}");
        assert!(t.starts_with("SENTRIX: UNABLE TO VERIFY"), "{t}");
    }

    #[test]
    fn a_dangerous_result_says_what_it_is_and_not_to_open_it() {
        let mut rep = crate::account::unverified_report("Telegram personal chat", "evil.exe", 10, "x");
        rep.verdict = Verdict::Malicious;
        rep.threat = Some(crate::types::ThreatInfo { family: "ransomware".into(), title: "Ransomware".into(), goal: "Locks your files and demands payment.".into(), arrives_via: vec![], attack: vec![], advice: String::new(), basis: "identified".into(), also: vec![] });
        let t = report_text(&rep, "a private chat");
        assert!(t.contains("Type: Ransomware\n") && t.contains("What it does: Locks") && t.contains("Do not open it."), "{t}");
    }

    #[test]
    fn the_welcome_names_the_room() {
        assert!(room_welcome(2).starts_with("SENTRIX Scan History #2"));
    }
}
