//! Group Shield tests.
//!
//!  * Tests without `#[ignore]` use no antivirus engine: they prove authorization, isolation, rate limiting, duplicate
//!    handling and, above all, that a file which could not be checked is never reported as clean.
//!  * The `#[ignore]`d tests run the whole flow against real ClamAV (EICAR inside a zip, because Defender removes EICAR files):
//!      SENTRIX_CLAMAV_DIR=… SENTRIX_DATA_DIR=… cargo test -p sentrix-core --test groups -- --ignored --nocapture
//!
//! Telegram is a local test double (tests/common). These tests prove the protocol handling and the policy, not live Telegram.
mod common;

use common::*;
use sentrix_core::clamav::ClamEngine;
use sentrix_core::eicar::eicar_bytes;
use sentrix_core::quarantine::Quarantine;
use sentrix_core::queue::{now_ms, JobStore};
use sentrix_core::service::{ProtectionService, ServiceConfig};
use sentrix_core::telegram::BotClient;
use sentrix_core::{Limits, Scanner};
use std::sync::Arc;
use std::time::{Duration, Instant};

const A: i64 = -1001111111111; // group A
const B: i64 = -1002222222222; // group B
const ADMIN_A: i64 = 900; // administrator of A only
const ADMIN_B: i64 = 901; // administrator of B only
const MEMBER: i64 = 777; // ordinary member of both

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

fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write;
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (n, d) in entries {
        w.start_file(*n, zip::write::SimpleFileOptions::default()).unwrap();
        w.write_all(d).unwrap();
    }
    w.finish().unwrap().into_inner()
}

struct Rig {
    svc: ProtectionService,
    hooks: Arc<Collect>,
    store: Arc<JobStore>,
    mock: Mock,
    _dir: tempfile::TempDir,
}

fn rig(scanner: Arc<Scanner>, shield: bool) -> Rig {
    rig_with(scanner, shield, false)
}

/// `submissions` = the owner also uses private-chat submissions, which keeps the bot worker running even with Group Shield off.
fn rig_with(scanner: Arc<Scanner>, shield: bool, submissions: bool) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(JobStore::open(&dir.path().join("protection.db")).unwrap());
    let q = Arc::new(Quarantine::open(dir.path().join("vault")).unwrap());
    let hooks = Arc::new(Collect::default());
    let mut cfg = ServiceConfig::new(dir.path().join("tmp"));
    cfg.realtime = false;
    cfg.chat_id = Some(CHAT);
    cfg.group_shield = shield;
    cfg.accept_submissions = submissions;
    let mock = Mock::start();
    let svc = ProtectionService::new(scanner, q, store.clone(), hooks.clone(), cfg);
    svc.set_bot(Some(Arc::new(BotClient::with_base(TOKEN, &mock.base).unwrap())));
    svc.start();
    Rig { svc, hooks, store, mock, _dir: dir }
}

fn no_engine() -> Arc<Scanner> {
    Arc::new(Scanner::new(Limits::default(), None))
}

fn enabled(r: &Rig, chat: i64) -> bool {
    r.store.group_get(chat).unwrap().is_some_and(|g| g.enabled)
}

/// Register a group and have its administrator switch protection on, through the real command path.
fn protect(r: &Rig, chat: i64, admin: i64, uid: i64) -> i64 {
    r.mock.add_group_text(uid, chat, uid, admin, "/setup on");
    assert!(until(15, || enabled(r, chat)), "the administrator's /setup on must enable protection");
    uid + 1
}

// ---- registration and authorization ------------------------------------------------------------------------

#[test]
fn adding_the_bot_registers_the_group_switched_off_and_says_how_to_start() {
    let r = rig(no_engine(), true);
    r.mock.add_group(A, &[ADMIN_A], false, false);
    r.mock.add_bot_joined(1, A, "Team chat", ADMIN_A);
    assert!(until(15, || r.store.group_get(A).unwrap().is_some()));
    let g = r.store.group_get(A).unwrap().unwrap();
    assert!(!g.enabled && !g.auto_delete, "a newly added bot must scan nothing until an administrator says so");
    assert!(r.mock.wait_for_messages_in(A, 1, 15));
    assert!(r.mock.texts_in(A)[0].contains("/setup on"));
    r.svc.stop();
}

#[test]
fn only_a_telegram_confirmed_administrator_can_change_settings() {
    let r = rig(no_engine(), true);
    r.mock.add_group(A, &[ADMIN_A], false, false);
    r.mock.add_group_text(1, A, 10, MEMBER, "/setup on");
    assert!(r.mock.wait_for_messages_in(A, 1, 15));
    assert!(r.mock.texts_in(A)[0].contains("Only group administrators"));
    assert!(!enabled(&r, A), "a member must not be able to switch protection on");
    // The administrator of a *different* group has no say here either.
    r.mock.add_group(B, &[ADMIN_B], false, false);
    r.mock.add_group_text(2, A, 11, ADMIN_B, "/setup on");
    assert!(until(15, || r.mock.texts_in(A).len() >= 2));
    assert!(!enabled(&r, A), "being an administrator elsewhere grants nothing");
    protect(&r, A, ADMIN_A, 3);
    assert!(enabled(&r, A));
    r.svc.stop();
}

#[test]
fn report_is_for_administrators_only_counts_only_and_never_mixes_groups() {
    let r = rig(no_engine(), true);
    r.mock.add_group(A, &[ADMIN_A], false, false);
    r.mock.add_group(B, &[ADMIN_B], false, false);
    protect(&r, A, ADMIN_A, 1);
    let n = protect(&r, B, ADMIN_B, 50) + 10;
    r.store.group_record_scan(B, 900, Some("uniq"), "ab", 5, "MALICIOUS", true, "scanned", None, now_ms()).unwrap();
    // Let the replies to the two /setup commands leave first: delivery is fast now, so the count must be taken after them.
    std::thread::sleep(Duration::from_secs(2));
    let before = r.mock.texts_in(A).len();
    // A member is refused.
    r.mock.add_group_text(n, A, 20, MEMBER, "/report");
    assert!(until(15, || r.mock.texts_in(A).len() > before));
    assert!(r.mock.texts_in(A).last().unwrap().contains("Only group administrators"));
    // An administrator of another group is refused too.
    let mid = r.mock.texts_in(A).len();
    r.mock.add_group_text(n + 1, A, 21, ADMIN_B, "/report");
    assert!(until(15, || r.mock.texts_in(A).len() > mid));
    assert!(r.mock.texts_in(A).last().unwrap().contains("Only group administrators"));
    // This group's administrator gets this group's numbers only.
    let last_private = r.mock.texts_in(CHAT).len();
    let last = r.mock.texts_in(A).len();
    r.mock.add_group_text(n + 2, A, 22, ADMIN_A, "/report");
    assert!(until(15, || r.mock.texts_in(CHAT).len() > last_private), "the summary goes to the owner's private chat");
    assert!(until(15, || r.mock.texts_in(A).len() > last));
    assert!(r.mock.texts_in(A).last().unwrap().contains("sent to you privately"), "the group only learns that it was sent privately");
    let t = r.mock.texts_in(CHAT).last().unwrap().clone();
    assert!(t.contains("Security report") && t.contains("this group only"), "{t}");
    assert!(t.contains("All time: 0 scanned, 0 malicious"), "group B's malicious scan must not appear in group A's report: {t}");
    assert!(!t.contains("invoice") && !t.contains(".exe"), "counts only: no file names");
    r.svc.stop();
}

#[test]
fn an_anonymous_administrator_cannot_be_identified_and_changes_nothing() {
    let r = rig(no_engine(), true);
    r.mock.add_group(A, &[ADMIN_A], false, false);
    r.mock.add_anonymous_group_text(1, A, 10, "/setup on");
    assert!(r.mock.wait_for_messages_in(A, 1, 15));
    assert!(r.mock.texts_in(A)[0].contains("anonymous"));
    assert!(!enabled(&r, A));
    r.svc.stop();
}

#[test]
fn commands_addressed_to_another_bot_are_ignored() {
    let r = rig(no_engine(), true);
    r.mock.add_group(A, &[ADMIN_A], false, false);
    r.mock.add_group_text(1, A, 10, ADMIN_A, "/setup@some_other_bot on");
    r.mock.add_group_text(2, A, 11, ADMIN_A, "/status@sentrix_test_bot");
    assert!(r.mock.wait_for_messages_in(A, 1, 15));
    let t = r.mock.texts_in(A);
    assert_eq!(t.len(), 1, "only the command addressed to this bot gets an answer: {t:?}");
    assert!(t[0].contains("Protection"));
    assert!(!enabled(&r, A));
    r.svc.stop();
}

#[test]
fn with_the_owners_master_switch_off_groups_are_not_scanned_and_are_told_why() {
    let r = rig_with(no_engine(), false, true);
    r.mock.add_group(A, &[ADMIN_A], false, false);
    r.mock.add_group_text(1, A, 10, ADMIN_A, "/setup on");
    r.mock.add_group_text(2, A, 11, MEMBER, "/status");
    assert!(r.mock.wait_for_messages_in(A, 1, 15));
    std::thread::sleep(Duration::from_secs(2));
    let t = r.mock.texts_in(A);
    assert_eq!(t.len(), 1, "one explanation, not one per command: {t:?}");
    assert!(t[0].contains("turned off in the SENTRIX app"));
    assert!(!enabled(&r, A));
    r.svc.stop();
}

#[test]
fn removing_the_bot_turns_protection_off() {
    let r = rig(no_engine(), true);
    r.mock.add_group(A, &[ADMIN_A], false, false);
    let n = protect(&r, A, ADMIN_A, 1);
    r.mock.add_bot_removed(n, A, "Team chat");
    assert!(until(15, || !enabled(&r, A)));
    assert!(r.store.group_get(A).unwrap().unwrap().left_at.is_some());
    r.svc.stop();
}

// ---- scanning policy ---------------------------------------------------------------------------------------

#[test]
fn a_file_in_an_unprotected_group_is_ignored_and_never_downloaded() {
    let r = rig(no_engine(), true);
    r.mock.add_group(A, &[ADMIN_A], false, false);
    r.mock.add_group_text(1, A, 10, MEMBER, "/status"); // registers the group, protection stays off
    r.mock.add_group_document(2, A, 11, MEMBER, "x.zip", b"data".to_vec(), None);
    assert!(r.mock.wait_for_messages_in(A, 1, 15));
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(r.mock.called("getFile"), 0, "a file in an unprotected group must not even be fetched");
    assert_eq!(r.store.group_stats(A, 0).unwrap().scans, 0);
    r.svc.stop();
}

#[test]
fn a_file_that_could_not_be_checked_is_never_reported_as_clean() {
    // No engine is available, so the scan cannot complete. The only honest result is UNABLE TO VERIFY.
    let r = rig(no_engine(), true);
    r.mock.add_group(A, &[ADMIN_A], false, false);
    let n = protect(&r, A, ADMIN_A, 1);
    r.mock.add_group_document(n, A, 50, MEMBER, "invoice.pdf", b"%PDF-1.4 hello".to_vec(), None);
    assert!(until(20, || r.mock.texts_in(CHAT).iter().any(|t| t.contains("invoice.pdf"))));
    let msg = r.mock.texts_in(CHAT).into_iter().find(|t| t.contains("invoice.pdf")).unwrap();
    assert!(msg.contains("could not be fully checked") && msg.contains("Not known to be safe"), "{msg}");
    assert!(!msg.to_lowercase().contains("no known threat") && !msg.contains("CLEAN"), "an unchecked file must not look safe: {msg}");
    assert!(!r.mock.texts_in(A).iter().any(|t| t.contains("invoice.pdf")), "scan results are never posted in the group");
    assert!(msg.contains("Group:"), "the private report says which group it is about: {msg}");
    let st = r.store.group_stats(A, 0).unwrap();
    assert_eq!((st.threats, st.unverified), (0, 1));
    r.svc.stop();
}

#[test]
fn oversized_and_inaccessible_files_are_reported_as_unchecked() {
    let r = rig(no_engine(), true);
    r.mock.add_group(A, &[ADMIN_A], false, false);
    let n = protect(&r, A, ADMIN_A, 1);
    // Telegram's own size field says it is bigger than a bot may download: it must not be downloaded at all.
    r.mock.add_group_document(n, A, 60, MEMBER, "huge.iso", b"x".to_vec(), Some(21 * 1024 * 1024));
    // Telegram refuses to serve this one.
    r.mock.add_group_document_gone(n + 1, A, 61, MEMBER, "expired.zip");
    assert!(until(20, || r.mock.texts_in(CHAT).iter().any(|t| t.contains("huge.iso")) && r.mock.texts_in(CHAT).iter().any(|t| t.contains("expired.zip"))));
    let huge = r.mock.texts_in(CHAT).into_iter().find(|t| t.contains("huge.iso")).unwrap();
    let gone = r.mock.texts_in(CHAT).into_iter().find(|t| t.contains("expired.zip")).unwrap();
    assert!(huge.contains("larger than 20 MB") && huge.contains("not checked"));
    assert!(gone.contains("could not be retrieved") && gone.contains("not checked"));
    assert!(!r.mock.texts_in(A).iter().any(|t| t.contains("huge.iso") || t.contains("expired.zip")), "nothing about these files is posted in the group");
    let st = r.store.group_stats(A, 0).unwrap();
    assert_eq!((st.skipped, st.errors, st.scans), (1, 1, 0), "{st:?}");
    r.svc.stop();
}

#[test]
fn redelivered_messages_are_handled_once() {
    let r = rig(no_engine(), true);
    r.mock.add_group(A, &[ADMIN_A], false, false);
    let n = protect(&r, A, ADMIN_A, 1);
    // Telegram can deliver the same message under a new update id (e.g. after a webhook/poller handover).
    r.mock.add_group_document(n, A, 70, MEMBER, "dup.zip", b"PK".to_vec(), None);
    r.mock.add_group_document(n + 1, A, 70, MEMBER, "dup.zip", b"PK".to_vec(), None);
    assert!(until(20, || r.mock.texts_in(CHAT).iter().any(|t| t.contains("dup.zip"))));
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(r.mock.texts_in(CHAT).iter().filter(|t| t.contains("dup.zip")).count(), 1, "one message, one result");
    let rows: i64 = r.store.group_stats(A, 0).unwrap().unverified;
    assert_eq!(rows, 1);
    r.svc.stop();
}

#[test]
fn a_flood_of_files_is_rate_limited_and_the_skipped_ones_are_declared() {
    let r = rig(no_engine(), true);
    r.mock.add_group(A, &[ADMIN_A], false, false);
    let n = protect(&r, A, ADMIN_A, 1);
    for i in 0..14 {
        r.mock.add_group_document(n + i, A, 100 + i, MEMBER, &format!("f{i}.zip"), b"PK".to_vec(), None);
    }
    assert!(until(60, || {
        let s = r.store.group_stats(A, 0).unwrap();
        s.scans + s.skipped + s.errors >= 14
    }));
    let s = r.store.group_stats(A, 0).unwrap();
    assert!(s.skipped >= 4, "files beyond the per-minute limit must be skipped, not silently queued: {s:?}");
    // Delivery is paced by the outbox (about one message a second), so give it time to reach the group.
    assert!(until(40, || r.mock.texts_in(CHAT).iter().any(|t| t.contains("skipped and not checked"))), "the owner must be told that some files were not checked");
    r.svc.stop();
}

// ---- isolation ---------------------------------------------------------------------------------------------

#[test]
fn groups_cannot_see_or_change_each_others_settings_or_history() {
    let r = rig(no_engine(), true);
    r.mock.add_group(A, &[ADMIN_A], false, false);
    r.mock.add_group(B, &[ADMIN_B], false, false);
    let n = protect(&r, A, ADMIN_A, 1);
    let n = protect(&r, B, ADMIN_B, n);
    r.mock.add_group_document(n, A, 5, MEMBER, "only-in-a.zip", b"PK".to_vec(), None);
    assert!(until(20, || r.store.group_stats(A, 0).unwrap().unverified == 1));

    // B's numbers know nothing about A's file, and A's administrator cannot switch B off.
    assert_eq!(r.store.group_stats(B, 0).unwrap().unverified, 0);
    r.mock.add_group_text(n + 1, B, 6, ADMIN_A, "/setup off");
    r.mock.add_group_text(n + 2, B, 7, MEMBER, "/scanstatus");
    assert!(until(20, || r.mock.texts_in(B).iter().any(|t| t.contains("Scan status"))));
    assert!(enabled(&r, B), "A's administrator must not be able to change group B");
    let b_status = r.mock.texts_in(B).into_iter().find(|t| t.contains("Scan status")).unwrap();
    assert!(b_status.contains("0 scanned"), "{b_status}");
    assert!(!b_status.contains("only-in-a"));
    // Removing A's local data leaves B untouched.
    r.store.group_forget(A).unwrap();
    assert!(r.store.group_get(B).unwrap().is_some());
    r.svc.stop();
}

// ---- automatic deletion consent ----------------------------------------------------------------------------

#[test]
fn automatic_deletion_needs_the_same_named_administrator_to_confirm() {
    let r = rig(no_engine(), true);
    r.mock.add_group(A, &[ADMIN_A, 902], true, true);
    let mut n = protect(&r, A, ADMIN_A, 1);
    let say = |n: i64, who: i64, text: &str| {
        r.mock.add_group_text(n, A, n, who, text);
        assert!(until(15, || r.mock.texts_in(A).len() >= r.mock.texts_in(A).len())); // no-op, keeps the helper symmetrical
    };
    let auto = || r.store.group_get(A).unwrap().unwrap().auto_delete;

    // Asking is not consenting.
    say(n, ADMIN_A, "/setup autodelete on");
    n += 1;
    assert!(until(15, || r.mock.texts_in(A).iter().any(|t| t.contains("Please confirm"))));
    assert!(!auto(), "turning deletion on needs a second, explicit step");

    // Neither another administrator nor a member can complete someone else's consent.
    say(n, 902, "/setup autodelete confirm");
    n += 1;
    say(n, MEMBER, "/setup autodelete confirm");
    n += 1;
    assert!(until(15, || r.mock.texts_in(A).iter().filter(|t| t.contains("nothing to confirm") || t.contains("Only group administrators")).count() >= 2));
    assert!(!auto());

    // The administrator who asked confirms: now it is on, with who/when recorded.
    say(n, ADMIN_A, "/setup autodelete confirm");
    assert!(until(15, auto));
    let g = r.store.group_get(A).unwrap().unwrap();
    assert!(g.delete_consent_at.is_some());
    r.svc.stop();
}

#[test]
fn automatic_deletion_cannot_be_enabled_without_the_delete_permission() {
    let r = rig(no_engine(), true);
    r.mock.add_group(A, &[ADMIN_A], true, false); // bot is admin but may not delete
    let n = protect(&r, A, ADMIN_A, 1);
    r.mock.add_group_text(n, A, n, ADMIN_A, "/setup autodelete on");
    assert!(until(15, || r.mock.texts_in(A).iter().any(|t| t.contains("cannot delete messages"))));
    assert!(!r.store.group_get(A).unwrap().unwrap().auto_delete);
    r.svc.stop();
}

#[test]
fn an_anonymous_administrator_cannot_grant_deletion_consent() {
    let r = rig(no_engine(), true);
    r.mock.add_group(A, &[ADMIN_A], true, true);
    let n = protect(&r, A, ADMIN_A, 1);
    r.mock.add_anonymous_group_text(n, A, n, "/setup autodelete on");
    assert!(until(15, || r.mock.texts_in(A).iter().any(|t| t.contains("anonymous") || t.contains("Remain anonymous"))));
    assert!(!r.store.group_get(A).unwrap().unwrap().auto_delete);
    r.svc.stop();
}

// ---- real engine -------------------------------------------------------------------------------------------

fn real_scanner() -> Arc<Scanner> {
    let clam = Arc::new(ClamEngine::new(std::env::var_os("SENTRIX_CLAMAV_DIR").expect("SENTRIX_CLAMAV_DIR"), std::env::var_os("SENTRIX_DATA_DIR").expect("SENTRIX_DATA_DIR")));
    clam.start().expect("clamd");
    Arc::new(Scanner::new(Limits::default(), Some(clam)))
}

fn turn_on_deletion(r: &Rig, chat: i64, admin: i64, mut n: i64) -> i64 {
    r.mock.add_group_text(n, chat, n, admin, "/setup autodelete on");
    n += 1;
    assert!(until(20, || r.mock.texts_in(chat).iter().any(|t| t.contains("Please confirm"))));
    r.mock.add_group_text(n, chat, n, admin, "/setup autodelete confirm");
    n += 1;
    assert!(until(20, || r.store.group_get(chat).unwrap().unwrap().auto_delete));
    n
}

#[test]
#[ignore = "needs real ClamAV: see file header"]
fn real_engine_malicious_file_alert_and_consented_deletion() {
    let r = rig(real_scanner(), true);
    r.mock.add_group(A, &[ADMIN_A], true, true);
    r.mock.add_group(B, &[ADMIN_B], true, true);
    let zip = make_zip(&[("a.txt", b"hello"), ("inner/e.com", &eicar_bytes())]);

    // Group A: protection on, deletion NOT on -> the threat is reported, nothing is deleted.
    let mut n = protect(&r, A, ADMIN_A, 1);
    r.mock.add_group_document(n, A, 500, MEMBER, "invoice.zip", zip.clone(), None);
    n += 1;
    assert!(until(60, || r.mock.texts_in(CHAT).iter().any(|t| t.contains("MALICIOUS"))), "{:?}", r.mock.texts_in(CHAT));
    let alert = r.mock.texts_in(CHAT).into_iter().find(|t| t.contains("MALICIOUS")).unwrap();
    assert!(alert.contains("Eicar") && alert.contains("Do not open it"), "{alert}");
    assert!(alert.contains("Group:"), "the private alert names the group: {alert}");
    assert!(!r.mock.texts_in(A).iter().any(|t| t.contains("MALICIOUS")), "the alert is never posted in the group itself");
    assert!(r.mock.deleted().is_empty(), "deletion is off by default");
    assert_eq!(r.store.group_stats(A, 0).unwrap().threats, 1);

    // The owner is told too, through the normal report hook (which marks it as coming from a group).
    assert!(r.hooks.wait_for(1, 5));
    assert!(r.hooks.reports.lock().unwrap()[0].origin.as_deref().unwrap_or("").starts_with("Telegram group:"));

    // Group B never enabled protection: the same file is left completely alone.
    r.mock.add_group_text(n, B, n, MEMBER, "/status");
    n += 1;
    r.mock.add_group_document(n, B, 501, MEMBER, "invoice.zip", zip.clone(), None);
    n += 1;
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(r.store.group_stats(B, 0).unwrap().scans, 0);
    assert!(!r.mock.deleted().iter().any(|(c, _)| *c == B));

    // Consent, then the same file is deleted and the alert says so.
    n = turn_on_deletion(&r, A, ADMIN_A, n);
    r.mock.add_group_document(n, A, 502, MEMBER, "invoice2.zip", zip.clone(), None);
    n += 1;
    assert!(until(60, || r.mock.deleted().contains(&(A, 502))), "after explicit consent the malicious message must be deleted");
    assert!(until(20, || r.mock.texts_in(CHAT).iter().any(|t| t.contains("invoice2.zip") && t.contains("was deleted"))));

    // The permission disappears: the deletion fails, and the alert says so instead of claiming success.
    r.mock.set_bot_can_delete(A, false);
    r.mock.add_group_document(n, A, 503, MEMBER, "invoice3.zip", zip, None);
    assert!(until(60, || r.mock.texts_in(CHAT).iter().any(|t| t.contains("invoice3.zip") && t.contains("could not delete"))), "{:?}", r.mock.texts_in(CHAT));
    assert!(!r.mock.deleted().contains(&(A, 503)));
    r.svc.stop();
    println!("[ok] real engine: alert, deletion off by default, B untouched, consented deletion, failure reported honestly");
}

#[test]
#[ignore = "needs real ClamAV: see file header"]
fn real_engine_clean_file_is_clean_only_when_the_engine_completed() {
    let r = rig(real_scanner(), true);
    r.mock.add_group(A, &[ADMIN_A], false, false);
    let n = protect(&r, A, ADMIN_A, 1);
    r.mock.add_group_text(n, A, n, ADMIN_A, "/setup clean on");
    let n = n + 1;
    r.mock.add_group_document(n, A, 600, MEMBER, "notes.txt", b"meeting notes\n".to_vec(), None);
    assert!(until(60, || r.mock.texts_in(CHAT).iter().any(|t| t.contains("notes.txt"))), "{:?}", r.mock.texts_in(CHAT));
    let msg = r.mock.texts_in(CHAT).into_iter().find(|t| t.contains("notes.txt")).unwrap();
    assert!(msg.contains("no known threat") && msg.contains("not a guarantee"), "{msg}");
    assert!(r.mock.deleted().is_empty());
    let _ = now_ms();
    r.svc.stop();
}
