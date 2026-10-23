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
    cfg.hosted = Some(HostedConfig { download_url: "https://get.example/sentrix".into(), ..Default::default() });
    let mock = Mock::start();
    let svc = ProtectionService::new(scanner, q, store.clone(), Arc::new(Collect::default()), cfg);
    svc.set_bot(Some(Arc::new(BotClient::with_base(TOKEN, &mock.base).unwrap())));
    svc.start();
    Rig { svc, store, mock, _dir: dir }
}

/// The person has the SENTRIX app installed and linked (what the bot now requires before it does anything for them).
fn give_app(store: &JobStore, user: i64) {
    if store.devices_of(user).is_empty() {
        store.device_create(user, "Test computer", &sentrix_core::hosted_store::token_hash(&format!("tok-{user}")), now_ms()).unwrap();
    }
}

fn code_in(text: &str, open: &str, close: &str) -> String {
    let a = text.find(open).expect("code start") + open.len();
    let b = text[a..].find(close).expect("code end") + a;
    text[a..b].to_string()
}

/// The person presses Start, then "Protect a group", and the group code comes back inside the link button.
fn group_code_for(r: &Rig, user: i64, n: &mut i64) -> String {
    give_app(&r.store, user);
    r.mock.add_start(*n, user, "Sam");
    *n += 1;
    assert!(until(15, || r.mock.texts_in(user).iter().any(|t| t.contains("What do you want to protect"))));
    let steps = |r: &Rig| r.mock.texts_in(user).iter().filter(|t| t.contains("Make a new group called")).count();
    let before = steps(r);
    r.mock.add_callback(*n, user, "m:group");
    *n += 1;
    assert!(until(15, || steps(r) > before));
    // The newest group link in the whole chat: a "now protected" notice from the previous group may land after this message.
    let urls = r.mock.all_urls(user);
    let url = urls.last().expect("a link button").clone();
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
    give_app(&r.store, SAM);
    r.mock.add_start(1, SAM, "Sam");
    assert!(until(15, || r.mock.texts_in(SAM).iter().any(|t| t.contains("What do you want to protect"))));
    let t = r.mock.texts_in(SAM)[0].clone();
    assert!(t.contains("Welcome, Sam"), "{t}");
    let b: Vec<String> = r.mock.last_buttons(SAM).into_iter().map(|(label, _)| label).collect();
    assert!(b.contains(&"Protect a group".to_string()) && b.contains(&"Protect my account".to_string()), "{b:?}");
    assert!(r.store.user_reachable(SAM));
    assert!(r.store.groups_list().unwrap().is_empty(), "choosing nothing protects nothing");
    r.svc.stop();
}

#[test]
fn a_file_sent_to_the_bot_privately_is_not_scanned_and_the_person_is_pointed_to_the_menu() {
    let r = rig();
    give_app(&r.store, SAM);
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
    give_app(&r.store, SAM);
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
    give_app(&r.store, SAM);
    give_app(&r.store, KIM);
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
fn a_link_only_works_for_the_person_it_was_made_for_in_a_group_they_are_in_and_only_once() {
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
    // Telegram, not the message, decides who is in a group: here it says Sam is not in it.
    r.mock.add_group(B, &[KIM], false, false);
    r.mock.set_not_in_group(B, SAM);
    r.mock.add_bot_joined(n, B, "Other", SAM);
    n += 1;
    r.mock.add_startgroup(n, B, n, SAM, &code);
    n += 1;
    assert!(until(15, || r.mock.texts_in(B).iter().any(|t| t.contains("not a member of this group"))));
    assert!(r.store.group_get(B).unwrap().is_some_and(|g| !g.enabled));
    // Sam finally uses it in a group Sam is in: works. A second use does not.
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
fn an_ordinary_member_can_protect_a_group_but_cannot_take_over_one_someone_else_protects() {
    let r = rig();
    let mut n = 1;
    // Sam is NOT an administrator of A (Kim is), just a member. That is enough to set up protection.
    r.mock.add_group(A, &[KIM], false, false);
    let code = group_code_for(&r, SAM, &mut n);
    r.mock.add_bot_joined(n, A, "Design team", SAM);
    n += 1;
    r.mock.add_startgroup(n, A, n, SAM, &code);
    n += 1;
    assert!(until(15, || r.store.group_get(A).ok().flatten().is_some_and(|g| g.enabled && g.enabled_by == Some(SAM))), "a member can protect a group");
    // Lee is also just a member and cannot take it over from Sam.
    const LEE: i64 = 5003;
    let code2 = group_code_for(&r, LEE, &mut n);
    r.mock.add_startgroup(n, A, n, LEE, &code2);
    n += 1;
    assert!(until(15, || r.mock.texts_in(A).iter().any(|t| t.contains("Someone else already protects"))));
    assert_eq!(r.store.group_get(A).unwrap().unwrap().enabled_by, Some(SAM));
    // Kim, an administrator, can.
    let code3 = group_code_for(&r, KIM, &mut n);
    r.mock.add_startgroup(n, A, n, KIM, &code3);
    assert!(until(15, || r.store.group_get(A).unwrap().is_some_and(|g| g.enabled_by == Some(KIM))), "an administrator may take over");
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

#[test]
fn a_big_file_gets_a_checking_message_at_once_that_is_replaced_by_the_result_not_followed_by_a_second_one() {
    let r = rig();
    let mut n = 1;
    link(&r, SAM, A, &mut n);
    make_history(&r, H, SAM, &mut n);
    std::thread::sleep(Duration::from_secs(2));
    // 2 MB: above the threshold. No scan engine here, so the honest result is "could not be fully checked".
    r.mock.add_group_document(n, A, 80, MEMBER, "big-design.zip", vec![7u8; 2_000_000], None);
    assert!(until(25, || r.mock.texts_in(H).iter().any(|t| t.contains("could not be fully checked"))), "{:?}", r.mock.texts_in(H));
    let about: Vec<String> = r.mock.texts_in(H).into_iter().filter(|t| t.contains("big-design.zip")).collect();
    assert_eq!(about.len(), 1, "one message about the file, edited in place: {about:?}");
    assert!(!about[0].contains("Checking this file now"), "the placeholder was replaced: {}", about[0]);
    assert!(!r.mock.state.lock().unwrap().edited.is_empty(), "it was edited, not re-sent");
    assert!(r.mock.texts_in(A).is_empty(), "the protected group never sees any of it");
    r.svc.stop();
}

#[test]
fn a_small_file_gets_no_checking_message_just_the_result() {
    let r = rig();
    let mut n = 1;
    link(&r, SAM, A, &mut n);
    make_history(&r, H, SAM, &mut n);
    std::thread::sleep(Duration::from_secs(2));
    r.mock.add_group_document(n, A, 81, MEMBER, "small.pdf", b"%PDF-1.4".to_vec(), None);
    assert!(until(20, || r.mock.texts_in(H).iter().any(|t| t.contains("small.pdf"))));
    assert!(r.mock.state.lock().unwrap().edited.is_empty(), "nothing to replace");
    r.svc.stop();
}

#[test]
fn files_posted_in_different_groups_at_once_do_not_wait_for_each_other() {
    let r = rig();
    let mut n = 1;
    link(&r, SAM, A, &mut n);
    link(&r, KIM, B, &mut n);
    std::thread::sleep(Duration::from_secs(2));
    let t = Instant::now();
    for i in 0..6 {
        r.mock.add_group_document(n + i, if i % 2 == 0 { A } else { B }, 200 + i, MEMBER, &format!("f{i}.pdf"), b"%PDF-1.4".to_vec(), None);
    }
    assert!(until(30, || (0..6).all(|i| r.mock.texts_in(if i % 2 == 0 { SAM } else { KIM }).iter().any(|t| t.contains(&format!("f{i}.pdf"))))), "all six results must arrive");
    assert!(t.elapsed() < Duration::from_secs(12), "six small files from two groups took {:?}", t.elapsed());
    r.svc.stop();
}

// ---- reliability -------------------------------------------------------------------------------------------------

#[test]
fn a_conflict_with_another_program_is_named_in_the_log_and_the_bot_recovers_by_itself() {
    let r = rig();
    give_app(&r.store, SAM);
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
    give_app(&r.store, owner);
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

const H3: i64 = -1006666666666; // a second Scan History group of Sam's

#[test]
fn a_person_can_have_many_scan_history_groups_and_every_one_gets_every_report() {
    let r = rig();
    let mut n = 1;
    link(&r, SAM, A, &mut n);
    make_history(&r, H, SAM, &mut n);
    std::thread::sleep(Duration::from_millis(50)); // distinct link times
    make_history(&r, H3, SAM, &mut n);
    assert_eq!(r.store.history_all(SAM).len(), 2, "the second one is added, not a replacement");
    r.mock.add_group_document(n, A, 70, MEMBER, "both.pdf", b"%PDF-1.4 hello".to_vec(), None);
    assert!(until(30, || r.mock.texts_in(H).iter().any(|t| t.contains("both.pdf")) && r.mock.texts_in(H3).iter().any(|t| t.contains("both.pdf"))), "H: {:?} H3: {:?}", r.mock.texts_in(H), r.mock.texts_in(H3));
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(r.mock.texts_in(H).iter().filter(|t| t.contains("both.pdf")).count(), 1, "once per room");
    assert!(r.mock.texts_in(A).is_empty() && !r.mock.texts_in(SAM).iter().any(|t| t.contains("both.pdf")));
    // Removing one leaves the other working.
    r.mock.add_bot_removed(n + 1, H3, "Scan History");
    assert!(until(15, || r.store.history_all(SAM).len() == 1));
    assert_eq!(r.store.history_get(SAM).unwrap().0, H);
    r.svc.stop();
}

#[test]
fn the_bot_asks_which_scan_history_group_each_protected_group_reports_to_and_the_choice_is_respected() {
    let r = rig();
    let mut n = 1;
    r.mock.add_start(n, SAM, "Sam");
    n += 1;
    make_history(&r, H, SAM, &mut n);
    std::thread::sleep(Duration::from_millis(50));
    make_history(&r, H3, SAM, &mut n);
    assert_eq!(r.store.history_rooms(SAM).iter().map(|h| h.num).collect::<Vec<_>>(), vec![1, 2], "the rooms are numbered so they can be told apart");
    assert!(until(15, || r.mock.texts_in(H3).iter().any(|t| t.contains("Scan History #2"))), "{:?}", r.mock.texts_in(H3));
    // With two rooms, protecting a group makes the bot ask, privately.
    link(&r, SAM, A, &mut n);
    assert!(until(15, || r.mock.texts_in(SAM).iter().any(|t| t.contains("Where should reports from"))), "{:?}", r.mock.texts_in(SAM));
    let b: Vec<(String, String)> = r.mock.last_buttons(SAM);
    assert!(b.iter().any(|(l, _)| l == "Scan History #1") && b.iter().any(|(l, _)| l == "Scan History #2") && b.iter().any(|(l, _)| l.ends_with("All of them")), "{b:?}");
    // Sam picks #1 for group A.
    let pick = b.iter().find(|(l, _)| l == "Scan History #1").unwrap().1.clone();
    assert_eq!(pick, format!("r:{A}:{H}"));
    r.mock.add_callback(n, SAM, &pick);
    n += 1;
    assert!(until(15, || r.store.report_choice_get(A) == Some(H)));
    // A second protected group goes to #2.
    link(&r, SAM, B, &mut n);
    r.mock.add_callback(n, SAM, &format!("r:{B}:{H3}"));
    n += 1;
    assert!(until(15, || r.store.report_choice_get(B) == Some(H3)));
    r.mock.add_group_document(n, A, 90, MEMBER, "from-a.pdf", b"%PDF-1.4 a".to_vec(), None);
    r.mock.add_group_document(n + 1, B, 91, MEMBER, "from-b.pdf", b"%PDF-1.4 b".to_vec(), None);
    assert!(until(30, || r.mock.texts_in(H).iter().any(|t| t.contains("from-a.pdf")) && r.mock.texts_in(H3).iter().any(|t| t.contains("from-b.pdf"))));
    std::thread::sleep(Duration::from_secs(1));
    assert!(!r.mock.texts_in(H).iter().any(|t| t.contains("from-b.pdf")) && !r.mock.texts_in(H3).iter().any(|t| t.contains("from-a.pdf")), "each group reports only where it was told to");
    // Many protected groups can report to the same room: send B to #1 as well.
    r.mock.add_callback(n + 2, SAM, &format!("r:{B}:{H}"));
    assert!(until(15, || r.store.report_choice_get(B) == Some(H)));
    r.mock.add_group_document(n + 3, B, 92, MEMBER, "b-again.pdf", b"%PDF-1.4 c".to_vec(), None);
    assert!(until(30, || r.mock.texts_in(H).iter().any(|t| t.contains("b-again.pdf"))));
    // Someone else cannot change Sam's choice.
    r.mock.add_start(n + 4, KIM, "Kim");
    r.mock.add_callback(n + 5, KIM, &format!("r:{B}:all"));
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(r.store.report_choice_get(B), Some(H), "Kim cannot touch Sam's group");
    // "All of them" clears the choice.
    r.mock.add_callback(n + 6, SAM, &format!("r:{B}:all"));
    assert!(until(15, || r.store.report_choice_get(B).is_none()));
    r.svc.stop();
}

#[test]
fn a_person_can_protect_many_groups_and_the_list_pages() {
    let r = rig();
    let mut n = 1;
    let ids: Vec<i64> = (0..9).map(|i| -1001000000100 - i).collect();
    for &g in &ids {
        link(&r, SAM, g, &mut n);
    }
    assert_eq!(r.store.groups_list().unwrap().iter().filter(|g| g.enabled && g.enabled_by == Some(SAM)).count(), 9, "there is no limit of one");
    r.mock.add_callback(n, SAM, "m:mine");
    n += 1;
    assert!(until(15, || r.mock.texts_in(SAM).iter().any(|t| t.contains("9 in total, page 1 of 2"))), "{:?}", r.mock.texts_in(SAM));
    let b: Vec<String> = r.mock.last_buttons(SAM).into_iter().map(|(l, _)| l).collect();
    assert!(b.contains(&"More groups".to_string()), "{b:?}");
    r.mock.add_callback(n, SAM, "m:mine:1");
    assert!(until(15, || r.mock.texts_in(SAM).iter().any(|t| t.contains("page 2 of 2"))));
    let b: Vec<String> = r.mock.last_buttons(SAM).into_iter().map(|(l, _)| l).collect();
    assert!(b.contains(&"Previous groups".to_string()) && !b.contains(&"More groups".to_string()), "{b:?}");
    r.svc.stop();
}

#[test]
fn a_group_with_the_right_name_is_not_used_by_someone_who_is_not_in_it() {
    let r = rig();
    let mut n = 1;
    give_app(&r.store, KIM);
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
fn someone_who_has_left_the_group_cannot_resume_a_paused_group() {
    let r = rig();
    let mut n = 1;
    link(&r, SAM, A, &mut n);
    r.mock.add_callback(n, SAM, &format!("g:off:{A}"));
    n += 1;
    assert!(until(15, || r.store.group_get(A).unwrap().is_some_and(|g| !g.enabled)));
    r.mock.set_not_in_group(A, SAM); // Sam left the group
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

// ---- the app comes first -----------------------------------------------------------------------------------------

/// Every way a person could try to get something done through the bot without having the app.
#[test]
fn without_the_app_the_bot_offers_only_the_download_and_a_link_code() {
    let r = rig();
    r.mock.add_start(1, SAM, "Sam");
    assert!(until(15, || r.mock.texts_in(SAM).iter().any(|t| t.contains("Install the SENTRIX app first"))), "{:?}", r.mock.texts_in(SAM));
    let t = r.mock.texts_in(SAM)[0].clone();
    assert!(t.contains("Welcome, Sam") && t.contains("https://get.example/sentrix"), "the download comes with the first message: {t}");
    let code = code_in(&t, "<code>", "</code>").replace('-', "");
    assert_eq!(r.store.code_peek(CodeKind::Device, &code, now_ms()), Some(SAM), "and so does the code that links the app");
    let labels: Vec<String> = r.mock.last_buttons(SAM).into_iter().map(|(l, _)| l).collect();
    assert!(!labels.contains(&"Protect a group".to_string()) && !labels.contains(&"Protect my account".to_string()), "no feature is offered: {labels:?}");
    // Pressing the old buttons, typing, sending a file, or using the deep links changes nothing.
    let before = r.mock.texts_in(SAM).len();
    r.mock.add_callback(2, SAM, "m:group");
    r.mock.add_callback(3, SAM, "m:main");
    r.mock.add_private_text(4, SAM, "hello");
    r.mock.add_private_text(5, SAM, "/start group");
    r.mock.add_private_text(6, SAM, "/menu");
    r.mock.add_document_update(7, SAM, SAM, "invoice.pdf", b"%PDF-1.4".to_vec());
    assert!(until(20, || r.mock.texts_in(SAM).len() >= before + 6), "{:?}", r.mock.texts_in(SAM));
    std::thread::sleep(Duration::from_secs(1));
    let after = r.mock.texts_in(SAM);
    assert!(after[before..].iter().all(|t| t.contains("Install the SENTRIX app first")), "every attempt gets the same answer: {:?}", &after[before..]);
    assert!(r.mock.last_urls(SAM).iter().all(|u| !u.contains("startgroup")), "no group link is ever issued");
    assert!(r.store.groups_list().unwrap().is_empty());
    assert_eq!(r.mock.called("getFile"), 0);
    r.svc.stop();
}

#[test]
fn linking_the_app_unlocks_the_bot() {
    let r = rig();
    let server = RelayServer::start("127.0.0.1:0", r.store.clone(), false).unwrap();
    let base = relay_url(&server);
    r.mock.add_start(1, SAM, "Sam");
    assert!(until(15, || r.mock.texts_in(SAM).iter().any(|t| t.contains("Install the SENTRIX app first"))));
    let code = code_in(&r.mock.texts_in(SAM)[0], "<code>", "</code>");
    assert!(!r.store.app_active(SAM, now_ms()));
    relay::link(&base, &code, "Sam's laptop").expect("the app links with the code the bot showed");
    assert!(r.store.app_active(SAM, now_ms()));
    r.mock.add_start(2, SAM, "Sam");
    assert!(until(15, || r.mock.texts_in(SAM).iter().any(|t| t.contains("What do you want to protect"))), "{:?}", r.mock.texts_in(SAM));
    let b: Vec<String> = r.mock.last_buttons(SAM).into_iter().map(|(l, _)| l).collect();
    assert!(b.contains(&"Protect a group".to_string()), "{b:?}");
    // And nobody else is unlocked by it.
    r.mock.add_start(3, KIM, "Kim");
    assert!(until(15, || r.mock.texts_in(KIM).iter().any(|t| t.contains("Install the SENTRIX app first"))));
    server.stop();
    r.svc.stop();
}

#[test]
fn a_group_cannot_be_protected_without_the_app_and_the_same_link_works_once_the_app_is_linked() {
    let r = rig();
    r.mock.add_start(1, SAM, "Sam");
    assert!(until(15, || r.store.user_reachable(SAM)));
    // A link made before this rule existed (or by hand) still cannot switch anything on.
    let code = sentrix_core::hosted::new_group_code();
    r.store.code_issue(CodeKind::Group, SAM, &code, now_ms() + 600_000).unwrap();
    r.mock.add_group(A, &[SAM], false, false);
    r.mock.add_bot_joined(2, A, "Design team", SAM);
    r.mock.add_startgroup(3, A, 3, SAM, &code);
    assert!(until(15, || r.mock.texts_in(A).iter().any(|t| t.contains("app must be installed and linked first"))), "{:?}", r.mock.texts_in(A));
    assert!(r.store.group_get(A).unwrap().is_some_and(|g| !g.enabled));
    assert_eq!(r.store.code_peek(CodeKind::Group, &code, now_ms()), Some(SAM), "the link is not used up");
    // /setup on is refused the same way.
    r.mock.add_group_text(4, A, 4, SAM, "/setup on");
    assert!(until(15, || r.mock.texts_in(A).iter().filter(|t| t.contains("app must be installed and linked first")).count() >= 2), "{:?}", r.mock.texts_in(A));
    assert!(r.store.group_get(A).unwrap().is_some_and(|g| !g.enabled));
    // Once the app is linked, the very same link works.
    give_app(&r.store, SAM);
    r.mock.add_startgroup(5, A, 5, SAM, &code);
    assert!(until(15, || r.store.group_get(A).unwrap().is_some_and(|g| g.enabled && g.enabled_by == Some(SAM))));
    r.svc.stop();
}

#[test]
fn a_scan_history_group_is_not_linked_without_the_app() {
    let r = rig();
    r.mock.add_start(1, SAM, "Sam");
    assert!(until(15, || r.store.user_reachable(SAM)));
    r.mock.add_group(H, &[SAM], false, false);
    r.mock.add_bot_joined(2, H, "Scan History", SAM);
    assert!(until(15, || r.mock.texts_in(SAM).iter().any(|t| t.contains("cannot use this group as your Scan History yet"))), "the person is told privately: {:?}", r.mock.texts_in(SAM));
    assert!(r.store.history_get(SAM).is_none());
    // Typing /link in the group is answered in the group.
    r.mock.add_group_text_titled(3, H, 3, SAM, "Scan History", "/link");
    assert!(until(15, || r.mock.texts_in(H).iter().any(|t| t.contains("SENTRIX app must be installed"))), "{:?}", r.mock.texts_in(H));
    assert!(r.store.history_get(SAM).is_none());
    // With the app linked, /link works.
    give_app(&r.store, SAM);
    r.mock.add_group_text_titled(4, H, 4, SAM, "Scan History", "/link");
    assert!(until(15, || r.store.history_get(SAM).is_some_and(|h| h.0 == H)));
    r.svc.stop();
}

#[test]
fn files_are_not_checked_while_the_owner_has_no_working_app_and_the_owner_is_told_once_privately() {
    let r = rig();
    let mut n = 1;
    link(&r, SAM, A, &mut n);
    // The app has not been seen for 15 days (uninstalled, or the computer is gone).
    let id = r.store.devices_of(SAM)[0].id.clone();
    r.store.device_touch(&id, now_ms() - 15 * 24 * 3600 * 1000);
    assert!(!r.store.app_active(SAM, now_ms()));
    r.mock.add_group_document(n, A, 90, MEMBER, "one.pdf", b"%PDF-1.4".to_vec(), None);
    n += 1;
    r.mock.add_group_document(n, A, 91, MEMBER, "two.pdf", b"%PDF-1.4".to_vec(), None);
    n += 1;
    assert!(until(20, || r.mock.texts_in(SAM).iter().any(|t| t.contains("not being checked"))), "{:?}", r.mock.texts_in(SAM));
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(r.mock.called("getFile"), 0, "nothing is downloaded or checked");
    assert_eq!(r.mock.texts_in(SAM).iter().filter(|t| t.contains("not being checked")).count(), 1, "told once, not per file");
    assert!(!r.mock.texts_in(SAM).iter().any(|t| t.contains("one.pdf") || t.contains("two.pdf")), "no report exists for a file nobody checked");
    assert!(r.mock.texts_in(A).is_empty(), "the group itself stays silent: {:?}", r.mock.texts_in(A));
    // The app checks in again (it does so every minute while it runs): protection resumes by itself.
    r.store.device_touch(&id, now_ms());
    r.mock.add_group_document(n, A, 92, MEMBER, "three.pdf", b"%PDF-1.4".to_vec(), None);
    assert!(until(20, || r.mock.texts_in(SAM).iter().any(|t| t.contains("three.pdf"))), "{:?}", r.mock.texts_in(SAM));
    r.svc.stop();
}

#[test]
fn the_relay_status_check_keeps_a_working_app_counted_as_in_use() {
    let r = rig();
    let server = RelayServer::start("127.0.0.1:0", r.store.clone(), false).unwrap();
    let base = relay_url(&server);
    let linked = relay::link(&base, &issue_code(&r.store, SAM), "Sam's laptop").unwrap();
    let id = r.store.devices_of(SAM)[0].id.clone();
    r.store.device_touch(&id, now_ms() - 13 * 24 * 3600 * 1000);
    assert!(r.store.app_active(SAM, now_ms()));
    r.store.device_touch(&id, now_ms() - 15 * 24 * 3600 * 1000);
    assert!(!r.store.app_active(SAM, now_ms()), "silent for 15 days");
    assert!(RelayClient::new(&base, &linked.token).unwrap().status().unwrap().0);
    assert!(r.store.app_active(SAM, now_ms()), "one check-in from the app and it counts again");
    server.stop();
    r.svc.stop();
}

// ---- checking on the customer's own computer ---------------------------------------------------------------------

use sentrix_core::edge::{self, EdgeJob, EdgeResult};
use sentrix_core::telegram::MAX_BOT_DOWNLOAD;
use sentrix_core::types::{ScanReport, Verdict};

/// The shared bot in its normal mode: the server hands files to the owner's app and scans nothing itself.
fn rig_edge(wait_ms: i64) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(JobStore::open(&dir.path().join("botd.db")).unwrap());
    let q = Arc::new(Quarantine::open(dir.path().join("vault")).unwrap());
    let mut cfg = ServiceConfig::new(dir.path().join("tmp"));
    cfg.realtime = false;
    cfg.group_shield = true;
    cfg.hosted = Some(HostedConfig { download_url: "https://get.example/sentrix".into(), edge: true, edge_wait_ms: wait_ms });
    let mock = Mock::start();
    let svc = ProtectionService::new(Arc::new(Scanner::new(Limits::default(), None)), q, store.clone(), Arc::new(Collect::default()), cfg);
    svc.set_bot(Some(Arc::new(BotClient::with_base(TOKEN, &mock.base).unwrap())));
    svc.start();
    Rig { svc, store, mock, _dir: dir }
}

/// A relay that can hand out files (like the real bot service), and an app linked to it for `user`.
fn relay_with_files(r: &Rig) -> RelayServer {
    let bot: Arc<dyn edge::FileSource> = Arc::new(BotClient::with_base(TOKEN, &r.mock.base).unwrap());
    RelayServer::start_with_files("127.0.0.1:0", r.store.clone(), false, Some(bot)).unwrap()
}

fn app_for(r: &Rig, base: &str, user: i64) -> RelayClient {
    let linked = relay::link(base, &issue_code(&r.store, user), "Test computer").unwrap();
    RelayClient::new(base, &linked.token).unwrap()
}

/// What an app would send back for a file, without needing a scan engine in the test.
fn verdict_report(v: Verdict, complete: bool, sigs: &[&str]) -> ScanReport {
    let job = EdgeJob { id: "x".into(), owner: 0, group_chat: 0, message_id: 0, file_id: "f".into(), file_unique_id: None, name: "x".into(), size: 1, state: "done".into(), result: None, created_at: 0 };
    let res = EdgeResult {
        verdict: v,
        complete,
        sha256: "ab".repeat(32),
        size: 1,
        summary: if complete { "checked".into() } else { "the engine was not available".into() },
        signatures: sigs.iter().map(|s| s.to_string()).collect(),
        threat_title: sigs.first().map(|_| "Test file".to_string()),
        threat_goal: sigs.first().map(|_| "Nothing, this is a test signature.".to_string()),
        threat_basis: sigs.first().map(|_| "identified".to_string()),
    };
    edge::report_from_result(&job, &res)
}

#[test]
fn edge_the_server_neither_downloads_nor_scans_a_file_posted_in_a_protected_group() {
    let r = rig_edge(0);
    let mut n = 1;
    link(&r, SAM, A, &mut n);
    r.mock.add_group_document(n, A, 50, MEMBER, "invoice.pdf", b"%PDF-1.4 hello".to_vec(), None);
    assert!(until(15, || r.store.edge_waiting(SAM) == 1), "the file is recorded as a job for Sam's computer");
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(r.mock.called("getFile"), 0, "the server did not fetch the file");
    assert!(!r.mock.texts_in(SAM).iter().any(|t| t.contains("invoice.pdf")), "and there is no report yet: nobody has checked it");
    assert!(r.mock.texts_in(A).is_empty(), "the group stays silent");
    r.svc.stop();
}

#[test]
fn edge_the_owners_app_fetches_checks_and_answers_and_the_report_reaches_the_owner() {
    let r = rig_edge(0);
    let mut n = 1;
    link(&r, SAM, A, &mut n);
    make_history(&r, H, SAM, &mut n);
    let server = relay_with_files(&r);
    let base = relay_url(&server);
    let app = app_for(&r, &base, SAM);
    let content = b"MZ-not-really-a-program, but bytes the app must receive exactly".to_vec();
    r.mock.add_group_document(n, A, 51, MEMBER, "setup.exe", content.clone(), None);
    assert!(until(15, || r.store.edge_waiting(SAM) == 1));
    let seen = std::sync::Mutex::new(Vec::<(String, String, Vec<u8>)>::new());
    let scan = |origin: &str, name: &str, bytes: &[u8]| -> Result<ScanReport, String> {
        seen.lock().unwrap().push((origin.into(), name.into(), bytes.to_vec()));
        Ok(verdict_report(Verdict::Malicious, true, &["Test.Signature.A"]))
    };
    assert_eq!(edge::run_once(&app, &scan).unwrap(), 1);
    {
        let s = seen.lock().unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].1, "setup.exe");
        assert!(s[0].0.contains("Design team"), "the app is told which group: {}", s[0].0);
        assert_eq!(s[0].2, content, "the app received exactly the bytes that were posted");
    }
    assert!(until(20, || r.mock.texts_in(H).iter().any(|t| t.contains("MALICIOUS") && t.contains("setup.exe"))), "{:?}", r.mock.texts_in(H));
    let msg = r.mock.texts_in(H).into_iter().find(|t| t.contains("MALICIOUS")).unwrap();
    assert!(msg.contains("Test.Signature.A") && msg.contains("Design team"), "{msg}");
    assert_eq!(r.mock.called("getFile"), 1, "the file crossed the server once, on its way to the owner's computer");
    assert_eq!(r.store.edge_waiting(SAM), 0);
    assert!(r.mock.texts_in(A).is_empty(), "the group never sees any of it: {:?}", r.mock.texts_in(A));
    // Nothing is offered twice.
    assert_eq!(edge::run_once(&app, &scan).unwrap(), 0);
    server.stop();
    r.svc.stop();
}

#[test]
fn edge_a_clean_result_is_reported_and_an_incomplete_clean_is_never_believed() {
    let r = rig_edge(0);
    let mut n = 1;
    link(&r, SAM, A, &mut n);
    make_history(&r, H, SAM, &mut n);
    let server = relay_with_files(&r);
    let app = app_for(&r, &relay_url(&server), SAM);
    r.mock.add_group_document(n, A, 52, MEMBER, "ok.pdf", b"%PDF-1.4".to_vec(), None);
    r.mock.add_group_document(n + 1, A, 53, MEMBER, "dodgy.pdf", b"%PDF-1.4".to_vec(), None);
    assert!(until(15, || r.store.edge_waiting(SAM) == 2));
    let scan = |_: &str, name: &str, _: &[u8]| -> Result<ScanReport, String> {
        // A careless or dishonest app says "clean" for a file whose check did not finish.
        Ok(if name == "ok.pdf" { verdict_report(Verdict::Clean, true, &[]) } else { verdict_report(Verdict::Clean, false, &[]) })
    };
    assert_eq!(edge::run_once(&app, &scan).unwrap(), 2);
    assert!(until(20, || r.mock.texts_in(H).iter().any(|t| t.contains("ok.pdf")) && r.mock.texts_in(H).iter().any(|t| t.contains("dodgy.pdf"))), "{:?}", r.mock.texts_in(H));
    let ok = r.mock.texts_in(H).into_iter().find(|t| t.contains("ok.pdf")).unwrap();
    let bad = r.mock.texts_in(H).into_iter().find(|t| t.contains("dodgy.pdf")).unwrap();
    assert!(ok.contains("no known threat"), "{ok}");
    assert!(bad.contains("could not be fully checked") && !bad.contains("no known threat"), "{bad}");
    server.stop();
    r.svc.stop();
}

#[test]
fn edge_a_real_local_scan_without_an_engine_says_it_could_not_check_never_clean() {
    let r = rig_edge(0);
    let mut n = 1;
    link(&r, SAM, A, &mut n);
    make_history(&r, H, SAM, &mut n);
    let server = relay_with_files(&r);
    let app = app_for(&r, &relay_url(&server), SAM);
    r.mock.add_group_document(n, A, 54, MEMBER, "notes.txt", b"just some notes".to_vec(), None);
    assert!(until(15, || r.store.edge_waiting(SAM) == 1));
    // The app's own scanner (here the test's, with no antivirus engine installed).
    let local = Arc::new(Scanner::new(Limits::default(), None));
    let dir = tempfile::tempdir().unwrap();
    let svc = ProtectionService::new(local, Arc::new(Quarantine::open(dir.path().join("vault")).unwrap()), Arc::new(JobStore::open_in_memory().unwrap()), Arc::new(Collect::default()), ServiceConfig::new(dir.path().join("tmp")));
    let scan = |o: &str, n: &str, b: &[u8]| svc.scan_ephemeral(o, n, &mut &b[..], MAX_BOT_DOWNLOAD);
    assert_eq!(edge::run_once(&app, &scan).unwrap(), 1);
    assert!(until(20, || r.mock.texts_in(H).iter().any(|t| t.contains("notes.txt"))), "{:?}", r.mock.texts_in(H));
    let msg = r.mock.texts_in(H).into_iter().find(|t| t.contains("notes.txt")).unwrap();
    assert!(!msg.contains("no known threat"), "an unchecked file is never called safe: {msg}");
    server.stop();
    r.svc.stop();
}

#[test]
fn edge_another_persons_app_cannot_list_fetch_or_answer_someones_files() {
    let r = rig_edge(0);
    let mut n = 1;
    link(&r, SAM, A, &mut n);
    let server = relay_with_files(&r);
    let base = relay_url(&server);
    let sam = app_for(&r, &base, SAM);
    let kim = app_for(&r, &base, KIM);
    r.mock.add_group_document(n, A, 55, MEMBER, "private.docx", b"PK secret".to_vec(), None);
    assert!(until(15, || r.store.edge_waiting(SAM) == 1));
    assert!(kim.jobs().unwrap().is_empty(), "Kim's app is offered nothing");
    let job = sam.jobs().unwrap().remove(0);
    assert_eq!(job.name, "private.docx");
    assert!(kim.fetch_job_file(&job.id).is_err(), "Kim's app cannot download Sam's file");
    let lie = edge::EdgeSubmit { ok: true, error: None, result: Some(EdgeResult { verdict: Verdict::Clean, complete: true, sha256: String::new(), size: 0, summary: String::new(), signatures: vec![], threat_title: None, threat_goal: None, threat_basis: None }) };
    let _ = kim.submit_job_result(&job.id, &lie);
    let j = r.store.edge_get(&job.id).unwrap();
    assert!(j.state == "leased" && j.result.is_none(), "Kim's answer changed nothing: {j:?}");
    // A made-up id, and a made-up token, get nothing either.
    assert!(sam.fetch_job_file("00000000-0000-0000-0000-000000000000").is_err());
    assert!(RelayClient::new(&base, &"a".repeat(64)).unwrap().jobs().is_err());
    // Sam's own app still can, and only once.
    assert_eq!(sam.fetch_job_file(&job.id).unwrap(), b"PK secret".to_vec());
    sam.submit_job_result(&job.id, &lie).unwrap();
    assert!(r.store.edge_get(&job.id).unwrap().state == "done");
    server.stop();
    r.svc.stop();
}

#[test]
fn edge_a_file_nobody_picks_up_is_reported_as_not_checked_and_never_as_safe() {
    let r = rig_edge(1_500);
    let mut n = 1;
    link(&r, SAM, A, &mut n);
    make_history(&r, H, SAM, &mut n);
    r.mock.add_group_document(n, A, 56, MEMBER, "waiting.zip", b"PK".to_vec(), None);
    assert!(until(20, || r.mock.texts_in(H).iter().any(|t| t.contains("waiting.zip") && t.contains("did not pick it up"))), "{:?}", r.mock.texts_in(H));
    let msg = r.mock.texts_in(H).into_iter().find(|t| t.contains("waiting.zip")).unwrap();
    assert!(msg.contains("not checked") && !msg.contains("no known threat"), "{msg}");
    assert_eq!(r.store.edge_waiting(SAM), 0);
    assert_eq!(r.mock.called("getFile"), 0, "and the server still never touched the file");
    r.svc.stop();
}

#[test]
fn edge_when_the_file_cannot_be_fetched_the_owner_is_told_it_was_not_checked() {
    let r = rig_edge(0);
    let mut n = 1;
    link(&r, SAM, A, &mut n);
    make_history(&r, H, SAM, &mut n);
    // A relay that has no way to reach Telegram.
    let server = RelayServer::start("127.0.0.1:0", r.store.clone(), false).unwrap();
    let app = app_for(&r, &relay_url(&server), SAM);
    r.mock.add_group_document(n, A, 57, MEMBER, "gone.zip", b"PK".to_vec(), None);
    assert!(until(15, || r.store.edge_waiting(SAM) == 1));
    let scan = |_: &str, _: &str, _: &[u8]| -> Result<ScanReport, String> { panic!("nothing to scan") };
    assert_eq!(edge::run_once(&app, &scan).unwrap(), 1);
    assert!(until(20, || r.mock.texts_in(H).iter().any(|t| t.contains("gone.zip") && t.contains("could not be checked on your computer"))), "{:?}", r.mock.texts_in(H));
    server.stop();
    r.svc.stop();
}

#[test]
fn edge_a_crash_in_the_apps_scan_is_contained_and_reported_not_clean() {
    let r = rig_edge(0);
    let mut n = 1;
    link(&r, SAM, A, &mut n);
    make_history(&r, H, SAM, &mut n);
    let server = relay_with_files(&r);
    let app = app_for(&r, &relay_url(&server), SAM);
    r.mock.add_group_document(n, A, 58, MEMBER, "boom.pdf", b"%PDF".to_vec(), None);
    assert!(until(15, || r.store.edge_waiting(SAM) == 1));
    let scan = |_: &str, _: &str, _: &[u8]| -> Result<ScanReport, String> { panic!("scanner bug") };
    assert_eq!(edge::run_once(&app, &scan).unwrap(), 1, "the app survives and answers");
    assert!(until(20, || r.mock.texts_in(H).iter().any(|t| t.contains("boom.pdf") && t.contains("not checked"))), "{:?}", r.mock.texts_in(H));
    server.stop();
    r.svc.stop();
}

#[test]
fn edge_an_unlinked_app_is_given_no_work() {
    let r = rig_edge(0);
    let mut n = 1;
    link(&r, SAM, A, &mut n);
    let server = relay_with_files(&r);
    let app = app_for(&r, &relay_url(&server), SAM);
    assert!(app.jobs().unwrap().is_empty());
    assert!(app.unlink());
    assert!(app.jobs().is_err(), "once unlinked from the bot, the computer gets no files");
    server.stop();
    r.svc.stop();
}

#[test]
fn edge_without_a_working_app_nothing_is_queued_for_that_person() {
    let r = rig_edge(0);
    let mut n = 1;
    link(&r, SAM, A, &mut n);
    let id = r.store.devices_of(SAM)[0].id.clone();
    r.store.device_touch(&id, now_ms() - 15 * 24 * 3600 * 1000);
    r.mock.add_group_document(n, A, 59, MEMBER, "x.pdf", b"%PDF".to_vec(), None);
    assert!(until(20, || r.mock.texts_in(SAM).iter().any(|t| t.contains("not being checked"))), "{:?}", r.mock.texts_in(SAM));
    assert_eq!(r.store.edge_waiting(SAM), 0, "no job is kept for an owner whose app is gone");
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

/// Measurement, not a pass/fail test: how long from "file posted" to "report in Scan History", real engine, local Telegram double
/// (so no internet latency). Run with: cargo test --release -p sentrix-core --test hosted latency -- --ignored --nocapture
#[test]
#[ignore = "measurement; needs real ClamAV"]
fn latency_posted_file_to_report() {
    let clam = Arc::new(sentrix_core::clamav::ClamEngine::new(std::env::var_os("SENTRIX_CLAMAV_DIR").expect("SENTRIX_CLAMAV_DIR"), std::env::var_os("SENTRIX_DATA_DIR").expect("SENTRIX_DATA_DIR")));
    clam.start().expect("clamd");
    let r = rig_with(Arc::new(Scanner::new(Limits::default(), Some(clam))));
    let mut n = 1;
    link(&r, SAM, A, &mut n);
    make_history(&r, H, SAM, &mut n);
    std::thread::sleep(Duration::from_secs(3)); // let the link notices drain
    let mut random = vec![0u8; 6 * 1024 * 1024];
    let mut x: u64 = 0x9E3779B97F4A7C15;
    for b in random.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = x as u8;
    }
    let zip = make_zip(&[("big.bin", &random)]);
    let cases: Vec<(&str, Vec<u8>)> = vec![("small.pdf", b"%PDF-1.4 a harmless document
".repeat(6000)), ("6mb.zip", zip), ("small2.pdf", b"%PDF-1.4 another one
".repeat(6000))];
    for (i, (name, bytes)) in cases.into_iter().enumerate() {
        let before = r.mock.texts_in(H).len();
        let t = Instant::now();
        r.mock.add_group_document(n, A, 900 + i as i64, MEMBER, name, bytes.clone(), None);
        n += 1;
        let ok = until(60, || r.mock.texts_in(H).len() > before);
        println!("LATENCY {name} ({} KB): {:.2}s to the report {}", bytes.len() / 1024, t.elapsed().as_secs_f64(), if ok { "" } else { "(TIMED OUT)" });
    }
    // Two files at once: does the second wait for the first?
    let before = r.mock.texts_in(H).len();
    let t = Instant::now();
    r.mock.add_group_document(n, A, 950, MEMBER, "a.pdf", b"%PDF-1.4 a
".repeat(6000), None);
    r.mock.add_group_document(n + 1, A, 951, MEMBER, "b.pdf", b"%PDF-1.4 b
".repeat(6000), None);
    let ok = until(60, || r.mock.texts_in(H).len() >= before + 2);
    println!("LATENCY two small files posted together: {:.2}s until both reports {}", t.elapsed().as_secs_f64(), if ok { "" } else { "(TIMED OUT)" });
    r.svc.stop();
}

/// Where the time goes inside one scan of a 6 MB zip. Measurement only.
#[test]
#[ignore = "measurement; needs real ClamAV"]
fn latency_inside_one_scan() {
    let clam = Arc::new(sentrix_core::clamav::ClamEngine::new(std::env::var_os("SENTRIX_CLAMAV_DIR").expect("SENTRIX_CLAMAV_DIR"), std::env::var_os("SENTRIX_DATA_DIR").expect("SENTRIX_DATA_DIR")));
    clam.start().expect("clamd");
    let scanner = Scanner::new(Limits::default(), Some(clam.clone()));
    let mut random = vec![0u8; 6 * 1024 * 1024];
    let mut x: u64 = 0x9E3779B97F4A7C15;
    for b in random.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = x as u8;
    }
    let zip = make_zip(&[("big.bin", &random)]);
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("6mb.zip");
    let t = Instant::now();
    std::fs::write(&f, &zip).unwrap();
    println!("TIMING write temp file: {:.2}s", t.elapsed().as_secs_f64());
    let t = Instant::now();
    let out = clam.scan_stream(&mut &zip[..], &|| false);
    println!("TIMING clamd stream of the whole zip: {:.2}s ({:?})", t.elapsed().as_secs_f64(), out.is_ok());
    for i in 0..2 {
        let t = Instant::now();
        let rep = scanner.scan_file(&f, &sentrix_core::ScanOptions { use_cache: false, ..Default::default() });
        println!("TIMING full scan_file #{i}: {:.2}s verdict {:?}", t.elapsed().as_secs_f64(), rep.verdict);
        for c in &rep.checks {
            println!("   check {} {:?}", c.id, c.status);
        }
    }
    let t = Instant::now();
    let _ = zip.iter().fold(0u64, |a, b| a.wrapping_add(*b as u64));
    println!("TIMING (baseline) touch every byte: {:.3}s", t.elapsed().as_secs_f64());
}

/// Which kinds of file are slow inside the engine? Every sample has distinct content, so no cache can answer. Measurement only.
#[test]
#[ignore = "measurement; needs real ClamAV"]
fn latency_by_file_kind() {
    let clam = Arc::new(sentrix_core::clamav::ClamEngine::new(std::env::var_os("SENTRIX_CLAMAV_DIR").expect("SENTRIX_CLAMAV_DIR"), std::env::var_os("SENTRIX_DATA_DIR").expect("SENTRIX_DATA_DIR")));
    clam.start().expect("clamd");
    let rnd = |seed: u64, n: usize| {
        let mut v = vec![0u8; n];
        let mut x: u64 = 0x9E3779B97F4A7C15 ^ seed;
        for b in v.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = x as u8;
        }
        v
    };
    let mut time = |label: &str, bytes: Vec<u8>| {
        let t = Instant::now();
        let ok = clam.scan_stream(&mut &bytes[..], &|| false).is_ok();
        println!("KIND {label:<34} {:>6} KB  {:.2}s  ok={ok}", bytes.len() / 1024, t.elapsed().as_secs_f64());
    };
    time("warm-up (tiny text)", b"hello warm up
".to_vec());
    time("6 MB raw random", rnd(1, 6 << 20));
    time("6 MB raw random #2", rnd(2, 6 << 20));
    time("6 MB zip, stored random", make_zip(&[("a.bin", &rnd(3, 6 << 20))]));
    time("6 MB zip, stored random #2", make_zip(&[("a.bin", &rnd(4, 6 << 20))]));
    let text: Vec<u8> = (0..400_000).flat_map(|i| format!("line {i} of some ordinary document text
").into_bytes()).take(6 << 20).collect();
    time("6 MB of text", text.clone());
    time("zip of text (compresses well)", make_zip(&[("doc.txt", &text)]));
    time("170 KB pdf-like", rnd(5, 170 * 1024));
    time("30 MB raw random", rnd(6, 30 << 20));
}

/// Which engine setting makes archives slow? Starts the engine once per setting. Measurement only.
#[test]
#[ignore = "measurement; needs real ClamAV"]
fn latency_engine_settings() {
    let rnd = |seed: u64, n: usize| {
        let mut v = vec![0u8; n];
        let mut x: u64 = 0x9E3779B97F4A7C15 ^ seed;
        for b in v.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = x as u8;
        }
        v
    };
    let settings = ["", "ScanArchive no", "ScanPE no;ScanELF no;ScanOLE2 no;ScanPDF no;ScanHTML no;ScanMail no;ScanSWF no;ScanXMLDOCS no;ScanHWP3 no", "Bytecode no", "HeuristicAlerts no", "AlertEncrypted no;AlertExceedsMax no;MaxRecursion 4"];
    for (k, extra) in settings.iter().enumerate() {
        std::env::set_var("SENTRIX_CLAMD_EXTRA", extra);
        let clam = sentrix_core::clamav::ClamEngine::new(std::env::var_os("SENTRIX_CLAMAV_DIR").unwrap(), std::env::var_os("SENTRIX_DATA_DIR").unwrap());
        clam.start().expect("clamd");
        let _ = clam.scan_stream(&mut &b"warm"[..], &|| false);
        let z = make_zip(&[("a.bin", &rnd(100 + k as u64, 6 << 20))]);
        let t = Instant::now();
        let ok = clam.scan_stream(&mut &z[..], &|| false).is_ok();
        println!("SETTING [{extra}] 6 MB stored zip: {:.2}s ok={ok}", t.elapsed().as_secs_f64());
        clam.stop();
    }
    std::env::remove_var("SENTRIX_CLAMD_EXTRA");
}
