//! The shared SENTRIX bot: one bot for everyone, reports in each person's own private chat.
//!
//! These tests run the real service and the real HTTP relay against a local TEST DOUBLE of the Telegram Bot API
//! (tests/common). They prove the protocol handling and the isolation rules. They are NOT a test of live Telegram.
mod common;

use common::*;
use sentrix_core::hosted::HostedConfig;
use sentrix_core::hosted_store::CodeKind;
use sentrix_core::quarantine::Quarantine;
use sentrix_core::queue::{now_ms, JobStore};
use sentrix_core::relay::{self, RelayClient, RelayServer};
use sentrix_core::service::{ProtectionService, ServiceConfig};
use sentrix_core::telegram::{BotClient, Courier};
use sentrix_core::{Limits, Scanner};
use std::sync::Arc;
use std::time::{Duration, Instant};

const A: i64 = -1001111111111; // a group
const B: i64 = -1002222222222; // another group
const SAM: i64 = 5001; // a customer
const KIM: i64 = 5002; // another customer
const MEMBER: i64 = 777; // an ordinary group member

fn until(secs: u64, mut f: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < end {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

struct Rig {
    svc: ProtectionService,
    store: Arc<JobStore>,
    mock: Mock,
    _dir: tempfile::TempDir,
}

fn rig() -> Rig {
    rig_with(Arc::new(Scanner::new(Limits::default(), None)))
}

fn rig_with(scanner: Arc<Scanner>) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(JobStore::open(&dir.path().join("botd.db")).unwrap());
    let q = Arc::new(Quarantine::open(dir.path().join("vault")).unwrap());
    let mut cfg = ServiceConfig::new(dir.path().join("tmp"));
    cfg.realtime = false;
    cfg.group_shield = true;
    cfg.hosted = Some(HostedConfig { download_url: "https://get.example/sentrix".into() });
    let mock = Mock::start();
    let svc = ProtectionService::new(scanner, q, store.clone(), Arc::new(Collect::default()), cfg);
    svc.set_bot(Some(Arc::new(BotClient::with_base(TOKEN, &mock.base).unwrap())));
    svc.start();
    Rig { svc, store, mock, _dir: dir }
}

fn code_in(text: &str, open: &str, close: &str) -> String {
    let a = text.find(open).expect("code start") + open.len();
    let b = text[a..].find(close).expect("code end") + a;
    text[a..b].to_string()
}

/// The person presses Start, then "Protect a group", and the group code comes back inside the link button.
fn group_code_for(r: &Rig, user: i64, n: &mut i64) -> String {
    r.mock.add_start(*n, user, "Sam");
    *n += 1;
    assert!(until(15, || r.mock.texts_in(user).iter().any(|t| t.contains("What do you want to protect"))));
    let before = r.mock.texts_in(user).len();
    r.mock.add_callback(*n, user, "m:group");
    *n += 1;
    assert!(until(15, || r.mock.texts_in(user).len() > before));
    let urls = r.mock.last_urls(user);
    let url = urls.first().expect("a link button").clone();
    assert!(url.starts_with("https://t.me/sentrix_test_bot?startgroup=g_"), "{url}");
    url.split("startgroup=").nth(1).unwrap().to_string()
}

/// A person links a group they administer, the way Telegram does it after "Choose a group".
fn link(r: &Rig, user: i64, chat: i64, n: &mut i64) {
    r.mock.add_group(chat, &[user], false, false);
    let code = group_code_for(r, user, n);
    r.mock.add_bot_joined(*n, chat, "Design team", user);
    *n += 1;
    r.mock.add_startgroup(*n, chat, *n, user, &code);
    *n += 1;
    assert!(until(15, || r.store.group_get(chat).ok().flatten().is_some_and(|g| g.enabled && g.enabled_by == Some(user))), "the group must be switched on for that person");
}

// ---- the front door ----------------------------------------------------------------------------------------------

#[test]
fn pressing_start_offers_the_two_choices_and_nothing_else_is_switched_on() {
    let r = rig();
    r.mock.add_start(1, SAM, "Sam");
    assert!(until(15, || r.mock.texts_in(SAM).iter().any(|t| t.contains("What do you want to protect"))));
    let t = r.mock.texts_in(SAM)[0].clone();
    assert!(t.contains("Welcome, Sam"), "{t}");
    let b: Vec<String> = r.mock.last_buttons(SAM).into_iter().map(|(label, _)| label).collect();
    assert!(b.contains(&"Protect a group".to_string()) && b.contains(&"Protect my account".to_string()), "{b:?}");
    assert!(r.store.user_reachable(SAM));
    assert!(r.store.groups_list().unwrap().is_empty() && r.store.devices_of(SAM).is_empty(), "choosing nothing protects nothing");
    r.svc.stop();
}

#[test]
fn a_file_sent_to_the_bot_privately_is_not_scanned_and_the_person_is_pointed_to_the_menu() {
    let r = rig();
    r.mock.add_start(1, SAM, "Sam");
    assert!(until(15, || r.mock.texts_in(SAM).len() >= 1));
    r.mock.add_document_update(2, SAM, SAM, "invoice.pdf", b"%PDF-1.4".to_vec());
    assert!(until(15, || r.mock.texts_in(SAM).len() >= 2));
    assert!(r.mock.texts_in(SAM)[1].contains("not files sent here"));
    assert_eq!(r.mock.called("getFile"), 0, "nothing is downloaded from a private chat");
    r.svc.stop();
}

#[test]
fn protect_my_account_gives_a_one_time_code_and_explains_that_the_login_stays_on_their_computer() {
    let r = rig();
    r.mock.add_start(1, SAM, "Sam");
    assert!(until(15, || r.mock.texts_in(SAM).len() >= 1));
    r.mock.add_callback(2, SAM, "m:account");
    assert!(until(15, || r.mock.texts_in(SAM).len() >= 2));
    let t = r.mock.texts_in(SAM)[1].clone();
    assert!(t.contains("never reaches me") && t.contains("https://get.example/sentrix"), "{t}");
    let shown = code_in(&t, "<code>", "</code>");
    assert_eq!(shown.len(), 9, "ABCD-EFGH");
    let code = shown.replace('-', "");
    assert_eq!(r.store.code_peek(CodeKind::Device, &code, now_ms()), Some(SAM));
    assert!(!t.to_lowercase().contains("phone number") && !t.to_lowercase().contains("password"), "the bot never asks for a Telegram login");
    r.svc.stop();
}

#[test]
fn opening_the_bot_from_the_app_shows_the_code_immediately_without_a_menu_step() {
    let r = rig();
    r.mock.add_private_text(1, SAM, "/start account");
    assert!(until(15, || r.mock.texts_in(SAM).iter().any(|t| t.contains("<code>"))), "{:?}", r.mock.texts_in(SAM));
    let t = r.mock.texts_in(SAM)[0].clone();
    assert!(t.contains("Protect my account") && t.contains("never reaches me"), "{t}");
    let code = code_in(&t, "<code>", "</code>").replace('-', "");
    assert_eq!(r.store.code_peek(CodeKind::Device, &code, now_ms()), Some(SAM));
    assert!(r.store.user_reachable(SAM), "pressing Start through the link still registers the person");
    r.mock.add_private_text(2, KIM, "/start group");
    assert!(until(15, || !r.mock.last_urls(KIM).is_empty()), "the group link is shown straight away too");
    r.svc.stop();
}

// ---- linking a group ---------------------------------------------------------------------------------------------

#[test]
fn choosing_a_group_links_it_and_every_report_goes_to_the_persons_private_chat_never_the_group() {
    let r = rig();
    let mut n = 1;
    link(&r, SAM, A, &mut n);
    // The person is told in their private chat, and the group is told only that protection started.
    assert!(until(15, || r.mock.texts_in(SAM).iter().any(|t| t.contains("is now protected"))));
    assert!(r.store.group_get(A).unwrap().unwrap().report_clean, "a group protected through the shared bot reports clean results too, so a person testing sees every file");
    std::thread::sleep(Duration::from_secs(2));
    assert!(r.mock.texts_in(A).is_empty(), "the protected group stays completely quiet: {:?}", r.mock.texts_in(A));
    // Someone in the group posts a file. No engine here, so the honest result is UNABLE TO VERIFY.
    r.mock.add_group_document(n, A, 50, MEMBER, "invoice.pdf", b"%PDF-1.4 hello".to_vec(), None);
    assert!(until(20, || r.mock.texts_in(SAM).iter().any(|t| t.contains("invoice.pdf"))), "the report must reach the person who protects the group");
    let msg = r.mock.texts_in(SAM).into_iter().find(|t| t.contains("invoice.pdf")).unwrap();
    assert!(msg.contains("Group:") && msg.contains("Design team"), "the private report says which group: {msg}");
    assert!(msg.contains("Scan History"), "with no Scan History group yet, the report reminds the person to make one: {msg}");
    assert!(msg.contains("could not be fully checked") && !msg.to_lowercase().contains("no known threat"), "{msg}");
    std::thread::sleep(Duration::from_secs(2));
    assert!(!r.mock.texts_in(A).iter().any(|t| t.contains("invoice.pdf")), "the file and its result are never posted in the group");
    r.svc.stop();
}

#[test]
fn a_link_only_works_for_the_person_it_was_made_for_in_a_group_they_administer_and_only_once() {
    let r = rig();
    let mut n = 1;
    let code = group_code_for(&r, SAM, &mut n);
    // Kim (an administrator of the group) tries to use Sam's link.
    r.mock.add_group(A, &[KIM], false, false);
    r.mock.add_bot_joined(n, A, "Design team", KIM);
    n += 1;
    r.mock.add_startgroup(n, A, n, KIM, &code);
    n += 1;
    assert!(until(15, || r.mock.texts_in(A).iter().any(|t| t.contains("made for someone else"))));
    assert!(r.store.group_get(A).unwrap().is_some_and(|g| !g.enabled));
    // Sam is only a member of this other group: Telegram, not the message, decides who is an administrator.
    r.mock.add_group(B, &[KIM], false, false);
    r.mock.add_bot_joined(n, B, "Other", SAM);
    n += 1;
    r.mock.add_startgroup(n, B, n, SAM, &code);
    n += 1;
    assert!(until(15, || r.mock.texts_in(B).iter().any(|t| t.contains("Only a group administrator"))));
    assert!(r.store.group_get(B).unwrap().is_some_and(|g| !g.enabled));
    // Sam finally uses it in a group Sam administers: works. A second use does not.
    r.mock.add_group(-1003333333333, &[SAM], false, false);
    r.mock.add_bot_joined(n, -1003333333333, "Mine", SAM);
    n += 1;
    r.mock.add_startgroup(n, -1003333333333, n, SAM, &code);
    n += 1;
    assert!(until(15, || r.store.group_get(-1003333333333).ok().flatten().is_some_and(|g| g.enabled)));
    r.mock.add_group(A, &[KIM, SAM], false, false);
    r.mock.add_startgroup(n, A, n, SAM, &code);
    assert!(until(15, || r.mock.texts_in(A).iter().any(|t| t.contains("expired or was already used"))), "a code works once");
    assert!(r.store.group_get(A).unwrap().is_some_and(|g| !g.enabled));
    r.svc.stop();
}

#[test]
fn an_anonymous_administrator_and_an_unknown_code_change_nothing() {
    let r = rig();
    r.mock.add_group(A, &[SAM], false, false);
    r.mock.add_bot_joined(1, A, "Design team", SAM);
    r.mock.add_startgroup(2, A, 2, SAM, "g_00000000000000000000");
    assert!(until(15, || r.mock.texts_in(A).iter().any(|t| t.contains("expired or was already used"))));
    r.mock.add_anonymous_group_text(3, A, 3, "/start@sentrix_test_bot g_00000000000000000000");
    assert!(until(15, || r.mock.texts_in(A).iter().any(|t| t.contains("anonymously"))));
    assert!(r.store.group_get(A).unwrap().is_some_and(|g| !g.enabled));
    r.svc.stop();
}

#[test]
fn an_administrator_who_never_pressed_start_cannot_switch_a_group_on_because_nobody_could_be_told() {
    let r = rig();
    r.mock.add_group(A, &[SAM], false, false);
    r.mock.add_group_text(1, A, 10, SAM, "/setup on");
    assert!(until(15, || r.mock.texts_in(A).iter().any(|t| t.contains("press Start first"))));
    assert!(r.store.group_get(A).unwrap().is_some_and(|g| !g.enabled), "nothing is scanned when no report could be delivered");
    r.svc.stop();
}

#[test]
fn a_file_in_a_group_where_protection_was_never_turned_on_is_not_checked_and_the_group_is_told_how_to_fix_it() {
    let r = rig();
    // Someone just added the bot to the group by hand. Nobody linked it.
    r.mock.add_group(A, &[SAM], false, false);
    r.mock.add_bot_joined(1, A, "Design team", SAM);
    r.mock.add_group_document(2, A, 10, MEMBER, "invoice.pdf", b"%PDF-1.4".to_vec(), None);
    assert!(until(15, || r.mock.texts_in(A).iter().any(|t| t.contains("protection is not on"))));
    let t = r.mock.texts_in(A).into_iter().find(|t| t.contains("protection is not on")).unwrap();
    assert!(t.contains("Protect a group") && !t.contains("invoice.pdf"), "it explains the fix and says nothing about the file: {t}");
    assert_eq!(r.mock.called("getFile"), 0, "the file is not downloaded or checked");
    // A second file within the hour does not repeat the notice.
    r.mock.add_group_document(3, A, 11, MEMBER, "second.pdf", b"%PDF-1.4".to_vec(), None);
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(r.mock.texts_in(A).iter().filter(|t| t.contains("protection is not on")).count(), 1);
    assert!(r.mock.texts_in(SAM).iter().all(|t| !t.contains("invoice.pdf")), "no report exists for a file that was not checked");
    r.svc.stop();
}

#[test]
fn groups_linked_before_the_default_changed_are_corrected_once_and_a_later_choice_is_kept() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(JobStore::open(&dir.path().join("botd.db")).unwrap());
    store.group_joined(A, "Old group", "supergroup", "member", 1).unwrap();
    store.group_set_enabled(A, true, SAM, 2).unwrap();
    assert!(!store.group_get(A).unwrap().unwrap().report_clean, "the old default");
    let mk = |store: Arc<JobStore>| {
        let q = Arc::new(Quarantine::open(dir.path().join("vault")).unwrap());
        let mut cfg = ServiceConfig::new(dir.path().join("tmp"));
        cfg.realtime = false;
        cfg.group_shield = true;
        cfg.hosted = Some(HostedConfig::default());
        let svc = ProtectionService::new(Arc::new(Scanner::new(Limits::default(), None)), q, store, Arc::new(Collect::default()), cfg);
        svc.start();
        svc
    };
    mk(store.clone()).stop();
    assert!(store.group_get(A).unwrap().unwrap().report_clean, "corrected on the first start");
    // The person turns it off on purpose; a later restart must not undo that.
    store.group_set_report(A, Some(false), None).unwrap();
    mk(store.clone()).stop();
    assert!(!store.group_get(A).unwrap().unwrap().report_clean, "the choice is kept");
}

// ---- reliability -------------------------------------------------------------------------------------------------

#[test]
fn a_conflict_with_another_program_is_named_in_the_log_and_the_bot_recovers_by_itself() {
    let r = rig();
    // Another program (a second copy, or an app with this same bot) is reading the messages.
    r.mock.conflict_next_polls(1);
    r.mock.add_start(1, SAM, "Sam");
    assert!(until(10, || r.store.recent_events(20).unwrap().iter().any(|e| e.kind == "telegram_poll" && e.message.contains("Another program"))), "the conflict must be named, not silent");
    assert!(r.store.kv_get("tg_poll_error").is_some(), "the heartbeat records why it is not receiving");
    // The other program stops: the bot is answering again within about half a minute, with no restart.
    assert!(until(45, || r.mock.texts_in(SAM).iter().any(|t| t.contains("What do you want to protect"))), "the bot must recover on its own");
    assert!(until(5, || r.store.kv_get("tg_poll_error").is_none()), "and the heartbeat clears");
    assert!(r.store.kv_get("tg_poll_ok_at").is_some());
    r.svc.stop();
}

// ---- the Scan History group ----------------------------------------------------------------------------------------

const H: i64 = -1004444444444; // Sam's Scan History group
const H2: i64 = -1005555555555; // Kim's

fn make_history(r: &Rig, chat: i64, owner: i64, n: &mut i64) {
    r.mock.add_group(chat, &[owner], false, false);
    r.mock.add_bot_joined(*n, chat, "Scan History", owner);
    *n += 1;
    assert!(until(15, || r.store.history_get(owner).is_some_and(|h| h.0 == chat)), "adding the bot to a group called Scan History must link it automatically");
}

#[test]
fn adding_the_bot_to_a_group_called_scan_history_links_it_automatically_and_it_is_never_protected_itself() {
    let r = rig();
    let mut n = 1;
    make_history(&r, H, SAM, &mut n);
    assert!(until(15, || r.mock.texts_in(H).iter().any(|t| t.contains("Reports for the groups this person protects"))));
    assert!(r.mock.texts_in(H).iter().any(|t| t.contains("Everyone in this group can read them")), "the group is told that everyone in it sees the reports");
    assert!(r.store.group_get(H).unwrap().is_none(), "a report room is not a protected group");
    // A file posted there is not scanned.
    r.mock.add_group_document(n, H, 5, MEMBER, "x.zip", b"PK".to_vec(), None);
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(r.mock.called("getFile"), 0);
    r.svc.stop();
}

#[test]
fn the_name_is_forgiving_about_capitals_spaces_and_the_plural_but_not_about_look_alikes() {
    use sentrix_core::group::is_history_title as ok;
    for yes in ["Scan History", "scan history", "  SCAN   HISTORY ", "Scans History", "scans history"] {
        assert!(ok(yes), "{yes:?}");
    }
    for no in ["Scan History 2", "My Scan History", "Scan Histor", "ScanHistory", "Scan  Hist0ry", "Scans Histories", ""] {
        assert!(!ok(no), "{no:?} must not count");
    }
}

#[test]
fn every_report_goes_to_the_scan_history_group_and_the_protected_group_stays_silent() {
    let r = rig();
    let mut n = 1;
    link(&r, SAM, A, &mut n);
    make_history(&r, H, SAM, &mut n);
    let history_msgs = r.mock.texts_in(H).len();
    r.mock.add_group_document(n, A, 50, MEMBER, "invoice.pdf", b"%PDF-1.4 hello".to_vec(), None);
    assert!(until(25, || r.mock.texts_in(H).iter().any(|t| t.contains("invoice.pdf"))), "the report must reach the Scan History group");
    let msg = r.mock.texts_in(H).into_iter().find(|t| t.contains("invoice.pdf")).unwrap();
    assert!(msg.contains("Group:") && msg.contains("Design team") && !msg.contains("Tip:"), "labelled with the group, and no reminder once a Scan History group exists: {msg}");
    assert!(r.mock.texts_in(H).len() > history_msgs);
    std::thread::sleep(Duration::from_secs(2));
    assert!(r.mock.texts_in(A).is_empty(), "the protected group never sees a scan, an alert or a notice: {:?}", r.mock.texts_in(A));
    assert!(!r.mock.texts_in(SAM).iter().any(|t| t.contains("invoice.pdf")), "and it is not duplicated into the private chat");
    r.svc.stop();
}

#[test]
fn two_people_each_get_reports_only_in_their_own_scan_history_group() {
    let r = rig();
    let mut n = 1;
    link(&r, SAM, A, &mut n);
    link(&r, KIM, B, &mut n);
    make_history(&r, H, SAM, &mut n);
    make_history(&r, H2, KIM, &mut n);
    r.mock.add_group_document(n, A, 50, MEMBER, "sams-file.zip", b"PK".to_vec(), None);
    r.mock.add_group_document(n + 1, B, 51, MEMBER, "kims-file.zip", b"PK".to_vec(), None);
    assert!(until(30, || r.mock.texts_in(H).iter().any(|t| t.contains("sams-file.zip")) && r.mock.texts_in(H2).iter().any(|t| t.contains("kims-file.zip"))));
    assert!(!r.mock.texts_in(H).iter().any(|t| t.contains("kims-file.zip")), "Kim's results never reach Sam's Scan History");
    assert!(!r.mock.texts_in(H2).iter().any(|t| t.contains("sams-file.zip")), "Sam's results never reach Kim's Scan History");
    r.svc.stop();
}

#[test]
fn a_group_with_the_right_name_is_not_used_by_someone_who_is_not_in_it() {
    let r = rig();
    let mut n = 1;
    r.mock.add_group(H, &[KIM], false, false);
    r.mock.set_not_in_group(H, SAM);
    // Sam claims a group Telegram says Sam is not in.
    r.mock.add_group_text_titled(n, H, 5, SAM, "Scan History", "/link");
    assert!(until(15, || r.mock.texts_in(H).iter().any(|t| t.contains("not a member"))));
    assert!(r.store.history_get(SAM).is_none());
    n += 1;
    // Kim, who is in it, can link it with /link even if the bot was added before the name was set.
    r.mock.add_group_text_titled(n, H, 6, KIM, "Scan History", "/link");
    assert!(until(15, || r.store.history_get(KIM).is_some_and(|h| h.0 == H)));
    assert!(r.store.history_get(SAM).is_none(), "linking for Kim does not link Sam");
    r.svc.stop();
}

#[test]
fn removing_or_renaming_the_scan_history_group_falls_back_to_the_private_chat_without_losing_reports() {
    let r = rig();
    let mut n = 1;
    link(&r, SAM, A, &mut n);
    make_history(&r, H, SAM, &mut n);
    // Renamed: the next thing said there no longer counts as a Scan History group.
    r.mock.add_group_text_titled(n, H, 7, SAM, "Old reports", "hello");
    n += 1;
    assert!(until(15, || r.store.history_get(SAM).is_none()), "a renamed group stops receiving reports");
    r.mock.add_group_document(n, A, 60, MEMBER, "late.zip", b"PK".to_vec(), None);
    n += 1;
    assert!(until(25, || r.mock.texts_in(SAM).iter().any(|t| t.contains("late.zip"))), "the report is not lost: it comes to the private chat");
    assert!(!r.mock.texts_in(H).iter().any(|t| t.contains("late.zip")));
    // Removing the bot from a real Scan History group clears it too.
    make_history(&r, H2, SAM, &mut n);
    r.mock.add_bot_removed(n, H2, "Scan History");
    assert!(until(15, || r.store.history_get(SAM).is_none()));
    r.svc.stop();
}

#[test]
fn the_report_command_goes_to_the_scan_history_group_too() {
    let r = rig();
    let mut n = 1;
    link(&r, SAM, A, &mut n);
    make_history(&r, H, SAM, &mut n);
    r.mock.add_group_text(n, A, 30, SAM, "/report");
    assert!(until(20, || r.mock.texts_in(H).iter().any(|t| t.contains("Security report"))), "{:?}", r.mock.texts_in(H));
    assert!(!r.mock.texts_in(A).iter().any(|t| t.contains("Security report")), "never posted in the protected group");
    r.svc.stop();
}

// ---- isolation ---------------------------------------------------------------------------------------------------

#[test]
fn two_people_two_groups_each_report_goes_only_to_its_own_person() {
    let r = rig();
    let mut n = 1;
    link(&r, SAM, A, &mut n);
    link(&r, KIM, B, &mut n);
    r.mock.add_group_document(n, A, 50, MEMBER, "sams-file.zip", b"PK".to_vec(), None);
    r.mock.add_group_document(n + 1, B, 51, MEMBER, "kims-file.zip", b"PK".to_vec(), None);
    assert!(until(25, || r.mock.texts_in(SAM).iter().any(|t| t.contains("sams-file.zip")) && r.mock.texts_in(KIM).iter().any(|t| t.contains("kims-file.zip"))));
    assert!(!r.mock.texts_in(SAM).iter().any(|t| t.contains("kims-file.zip")), "Sam must never see Kim's results");
    assert!(!r.mock.texts_in(KIM).iter().any(|t| t.contains("sams-file.zip")), "Kim must never see Sam's results");
    r.svc.stop();
}

#[test]
fn nobody_can_pause_remove_or_even_list_someone_elses_group() {
    let r = rig();
    let mut n = 1;
    link(&r, SAM, A, &mut n);
    r.mock.add_start(n, KIM, "Kim");
    n += 1;
    assert!(until(15, || r.mock.texts_in(KIM).len() >= 1));
    for act in ["off", "rm", "on"] {
        r.mock.add_callback(n, KIM, &format!("g:{act}:{A}"));
        n += 1;
    }
    assert!(until(15, || r.mock.state.lock().unwrap().answered.len() >= 3));
    assert!(r.store.group_get(A).unwrap().is_some_and(|g| g.enabled && g.left_at.is_none() && g.enabled_by == Some(SAM)), "Sam's group is untouched");
    let shown = r.mock.texts_in(KIM).join("\n");
    assert!(!shown.contains("Design team"), "Kim's menu never lists Sam's group: {shown}");
    r.svc.stop();
}

#[test]
fn the_owner_can_pause_resume_and_remove_their_group_from_the_menu() {
    let r = rig();
    let mut n = 1;
    link(&r, SAM, A, &mut n);
    r.mock.add_callback(n, SAM, &format!("g:off:{A}"));
    n += 1;
    assert!(until(15, || r.store.group_get(A).unwrap().is_some_and(|g| !g.enabled)));
    r.mock.add_callback(n, SAM, &format!("g:on:{A}"));
    n += 1;
    assert!(until(15, || r.store.group_get(A).unwrap().is_some_and(|g| g.enabled)), "an administrator may resume");
    r.mock.add_callback(n, SAM, &format!("g:rm:{A}"));
    assert!(until(15, || r.store.group_get(A).unwrap().is_none()), "removing erases the group's record");
    r.svc.stop();
}

#[test]
fn someone_who_is_no_longer_an_administrator_cannot_resume_a_paused_group() {
    let r = rig();
    let mut n = 1;
    link(&r, SAM, A, &mut n);
    r.mock.add_callback(n, SAM, &format!("g:off:{A}"));
    n += 1;
    assert!(until(15, || r.store.group_get(A).unwrap().is_some_and(|g| !g.enabled)));
    r.mock.add_group(A, &[KIM], false, false); // Sam was demoted
    r.mock.add_callback(n, SAM, &format!("g:on:{A}"));
    assert!(until(15, || r.mock.state.lock().unwrap().answered.len() >= 3));
    assert!(r.store.group_get(A).unwrap().is_some_and(|g| !g.enabled));
    r.svc.stop();
}

// ---- reachability ------------------------------------------------------------------------------------------------

#[test]
fn a_person_who_blocks_the_bot_is_marked_unreachable_and_the_gap_is_recorded_not_hidden() {
    let r = rig();
    let mut n = 1;
    link(&r, SAM, A, &mut n);
    r.mock.add_user_blocks_bot(n, SAM);
    n += 1;
    assert!(until(15, || !r.store.user_reachable(SAM)));
    r.mock.add_group_document(n, A, 60, MEMBER, "x.zip", b"PK".to_vec(), None);
    assert!(until(20, || r.store.recent_events(50).unwrap().iter().any(|e| e.kind == "group_report_undeliverable")), "a report that cannot be delivered is an event, not silence");
    assert!(!r.mock.texts_in(A).iter().any(|t| t.contains("x.zip")), "and it is still not dumped into the group");
    // Pressing Start again restores delivery.
    r.mock.add_start(n + 1, SAM, "Sam");
    assert!(until(15, || r.store.user_reachable(SAM)));
    r.svc.stop();
}

// ---- the relay: the app on the person's computer reports through the bot ----------------------------------------

fn relay_url(s: &RelayServer) -> String {
    format!("http://{}", s.addr)
}

fn issue_code(store: &JobStore, user: i64) -> String {
    store.user_started(user, "Sam", now_ms()).unwrap();
    let code = sentrix_core::hosted::new_device_code();
    store.code_issue(CodeKind::Device, user, &code, now_ms() + 600_000).unwrap();
    code
}

#[test]
fn an_app_linked_with_the_bots_code_delivers_its_reports_to_that_persons_chat_and_only_that_chat() {
    let r = rig();
    r.mock.add_start(1, SAM, "Sam");
    r.mock.add_start(2, KIM, "Kim");
    let server = RelayServer::start("127.0.0.1:0", r.store.clone(), false).unwrap();
    let base = relay_url(&server);
    let code = issue_code(&r.store, SAM);
    let linked = relay::link(&base, &sentrix_core::hosted::show_device_code(&code), "Sam's laptop").expect("link");
    assert_eq!(linked.token.len(), 64);
    assert_eq!(linked.user_name, "Sam");
    assert!(until(15, || r.mock.texts_in(SAM).iter().any(|t| t.contains("SENTRIX app linked") && t.contains("Sam&amp;#39;s") || t.contains("SENTRIX app linked"))), "the person is told the app was linked");
    let client = RelayClient::new(&base, &linked.token).unwrap();
    assert_eq!(client.status().unwrap(), (true, true));
    client.send_reply(0, "<b>SENTRIX SECURITY REPORT</b>\nStatus: MALICIOUS\nFile: bad.exe", None).unwrap();
    assert!(until(20, || r.mock.texts_in(SAM).iter().any(|t| t.contains("Status: MALICIOUS"))), "the report reaches the person's chat");
    assert!(!r.mock.texts_in(KIM).iter().any(|t| t.contains("MALICIOUS")), "and nobody else's");
    server.stop();
    r.svc.stop();
}

#[test]
fn a_code_works_once_and_wrong_codes_are_rate_limited() {
    let r = rig();
    let server = RelayServer::start("127.0.0.1:0", r.store.clone(), false).unwrap();
    let base = relay_url(&server);
    let code = issue_code(&r.store, SAM);
    assert!(relay::link(&base, &code, "one").is_ok());
    assert!(relay::link(&base, &code, "two").unwrap_err().contains("wrong, expired or already used"));
    let mut limited = false;
    for i in 0..15 {
        let e = relay::link(&base, &format!("AAAA{:04}", i), "guess").unwrap_err();
        if e.contains("Too many attempts") {
            limited = true;
        }
    }
    assert!(limited, "guessing codes must be stopped");
    server.stop();
    r.svc.stop();
}

#[test]
fn an_unlinked_or_unknown_app_is_refused_and_the_request_cannot_name_another_chat() {
    let r = rig();
    r.mock.add_start(1, SAM, "Sam");
    r.mock.add_start(2, KIM, "Kim");
    let server = RelayServer::start("127.0.0.1:0", r.store.clone(), false).unwrap();
    let base = relay_url(&server);
    let linked = relay::link(&base, &issue_code(&r.store, SAM), "Sam's laptop").unwrap();
    // A made-up token is refused.
    assert_eq!(RelayClient::new(&base, &"a".repeat(64)).unwrap().status().unwrap(), (false, false));
    assert!(RelayClient::new(&base, &"a".repeat(64)).unwrap().send_reply(0, "x", None).is_err());
    // A raw request that tries to aim at Kim's chat still lands in Sam's.
    let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).build().into();
    let resp = agent.post(&format!("{base}/v1/report")).header("Authorization", &format!("Bearer {}", linked.token)).send_json(serde_json::json!({"text": "for-kim-attempt", "chat_id": KIM, "chatId": KIM})).unwrap();
    assert_eq!(resp.status().as_u16(), 202);
    assert!(until(20, || r.mock.texts_in(SAM).iter().any(|t| t.contains("for-kim-attempt"))));
    assert!(!r.mock.texts_in(KIM).iter().any(|t| t.contains("for-kim-attempt")), "a device can only ever write to the person it was issued to");
    // Unlinking works, and then the token is dead.
    let client = RelayClient::new(&base, &linked.token).unwrap();
    assert!(client.unlink());
    assert_eq!(client.status().unwrap(), (false, false));
    assert!(client.send_reply(0, "after", None).is_err());
    server.stop();
    r.svc.stop();
}

#[test]
fn the_person_can_unlink_a_computer_from_the_bot_menu_and_it_stops_working() {
    let r = rig();
    r.mock.add_start(1, SAM, "Sam");
    let server = RelayServer::start("127.0.0.1:0", r.store.clone(), false).unwrap();
    let base = relay_url(&server);
    let linked = relay::link(&base, &issue_code(&r.store, SAM), "Sam's laptop").unwrap();
    let id = r.store.devices_of(SAM)[0].id.clone();
    r.mock.add_callback(5, KIM, &format!("d:rm:{id}"));
    assert!(until(15, || r.mock.state.lock().unwrap().answered.len() >= 1));
    assert_eq!(r.store.devices_of(SAM).len(), 1, "Kim cannot unlink Sam's computer");
    r.mock.add_callback(6, SAM, &format!("d:rm:{id}"));
    assert!(until(15, || r.store.devices_of(SAM).is_empty()));
    assert_eq!(RelayClient::new(&base, &linked.token).unwrap().status().unwrap(), (false, false));
    server.stop();
    r.svc.stop();
}

#[test]
fn report_text_from_an_app_cannot_inject_links_or_scripts_and_floods_are_limited() {
    let r = rig();
    r.mock.add_start(1, SAM, "Sam");
    let server = RelayServer::start("127.0.0.1:0", r.store.clone(), false).unwrap();
    let base = relay_url(&server);
    let linked = relay::link(&base, &issue_code(&r.store, SAM), "Sam's laptop").unwrap();
    let c = RelayClient::new(&base, &linked.token).unwrap();
    c.send_reply(0, "<a href=\"https://evil.example\">click here</a> <b>ok</b>", None).unwrap();
    assert!(until(20, || r.mock.texts_in(SAM).iter().any(|t| t.contains("click here"))));
    let t = r.mock.texts_in(SAM).into_iter().find(|t| t.contains("click here")).unwrap();
    assert!(!t.contains("<a ") && t.contains("&lt;a href"), "links are shown as text, never active: {t}");
    let mut refused = 0;
    for i in 0..10 {
        if c.send_reply(0, &format!("flood {i}"), None).is_err() {
            refused += 1;
        }
    }
    assert!(refused >= 3, "a flood is refused so the person's chat is not buried: refused {refused}");
    server.stop();
    r.svc.stop();
}

#[test]
fn a_relay_report_for_someone_who_never_started_the_bot_is_refused_with_a_clear_reason() {
    let r = rig();
    let server = RelayServer::start("127.0.0.1:0", r.store.clone(), false).unwrap();
    let base = relay_url(&server);
    let linked = relay::link(&base, &issue_code(&r.store, SAM), "Sam's laptop").unwrap();
    r.store.user_set_blocked(SAM, true);
    let e = RelayClient::new(&base, &linked.token).unwrap().send_reply(0, "hello", None).unwrap_err();
    assert!(e.to_string().contains("Start"), "{e}");
    server.stop();
    r.svc.stop();
}

// ---- real engine -------------------------------------------------------------------------------------------------

fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write;
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (n, d) in entries {
        w.start_file(*n, zip::write::SimpleFileOptions::default()).unwrap();
        w.write_all(d).unwrap();
    }
    w.finish().unwrap().into_inner()
}

/// EICAR inside a zip (Defender removes a bare EICAR file). Run with:
///   SENTRIX_CLAMAV_DIR=... SENTRIX_DATA_DIR=... cargo test -p sentrix-core --test hosted -- --ignored --nocapture
#[test]
#[ignore = "needs real ClamAV: see the command above"]
fn real_engine_a_malicious_file_in_a_linked_group_alerts_only_the_owner_privately() {
    let clam = Arc::new(sentrix_core::clamav::ClamEngine::new(std::env::var_os("SENTRIX_CLAMAV_DIR").expect("SENTRIX_CLAMAV_DIR"), std::env::var_os("SENTRIX_DATA_DIR").expect("SENTRIX_DATA_DIR")));
    clam.start().expect("clamd");
    let r = rig_with(Arc::new(Scanner::new(Limits::default(), Some(clam))));
    let mut n = 1;
    link(&r, SAM, A, &mut n);
    r.mock.add_start(n, KIM, "Kim");
    n += 1;
    let zip = make_zip(&[("a.txt", b"hello"), ("inner/e.com", &sentrix_core::eicar::eicar_bytes())]);
    r.mock.add_group_document(n, A, 500, MEMBER, "invoice.zip", zip, None);
    assert!(until(90, || r.mock.texts_in(SAM).iter().any(|t| t.contains("MALICIOUS"))), "{:?}", r.mock.texts_in(SAM));
    let alert = r.mock.texts_in(SAM).into_iter().find(|t| t.contains("MALICIOUS")).unwrap();
    assert!(alert.contains("Eicar") && alert.contains("Do not open it") && alert.contains("Design team"), "{alert}");
    assert!(!r.mock.texts_in(A).iter().any(|t| t.contains("MALICIOUS") || t.contains("invoice.zip")), "nothing is posted in the group");
    assert!(!r.mock.texts_in(KIM).iter().any(|t| t.contains("MALICIOUS")), "nobody else is told");
    assert!(r.mock.deleted().is_empty(), "deletion stays off unless an administrator agreed to it");
    r.svc.stop();
    println!("[ok] real engine, shared bot: private alert, group silent, no cross-person leak");
}

/// The case that looked like "nothing happens": an ordinary, clean file posted in a protected group.
#[test]
#[ignore = "needs real ClamAV: see the command above"]
fn real_engine_an_ordinary_clean_file_is_reported_in_scan_history() {
    let clam = Arc::new(sentrix_core::clamav::ClamEngine::new(std::env::var_os("SENTRIX_CLAMAV_DIR").expect("SENTRIX_CLAMAV_DIR"), std::env::var_os("SENTRIX_DATA_DIR").expect("SENTRIX_DATA_DIR")));
    clam.start().expect("clamd");
    let r = rig_with(Arc::new(Scanner::new(Limits::default(), Some(clam))));
    let mut n = 1;
    link(&r, SAM, A, &mut n);
    make_history(&r, H, SAM, &mut n);
    r.mock.add_group_document(n, A, 700, MEMBER, "How to climb up tower.pdf", b"%PDF-1.4 a harmless document
".to_vec(), None);
    assert!(until(60, || r.mock.texts_in(H).iter().any(|t| t.contains("climb up tower"))), "{:?}", r.mock.texts_in(H));
    let msg = r.mock.texts_in(H).into_iter().find(|t| t.contains("climb up tower")).unwrap();
    assert!(msg.contains("no known threat") && msg.contains("not a guarantee") && msg.contains("Design team"), "{msg}");
    assert!(r.mock.texts_in(A).is_empty(), "the protected group stays silent");
    r.svc.stop();
}

