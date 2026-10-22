//! Telegram Bot API client + delivery pipeline against a local TEST DOUBLE (see common/mod.rs). Not a live-Telegram test.
mod common;

use common::*;
use sentrix_core::notify::{deliver_due_at, format_report, NotifyPrefs};
use sentrix_core::queue::{now_ms, JobStore};
use sentrix_core::telegram::{BotClient, TgError};
use sentrix_core::{FileInfo, FindingKind, ScanReport, Severity, Verdict};
use std::io::Cursor;
use std::path::PathBuf;
use std::time::Duration;

fn client(m: &Mock) -> BotClient {
    BotClient::with_base(TOKEN, &m.base).unwrap()
}

fn report(verdict: Verdict, name: &str, sha: &str) -> ScanReport {
    let mut r = ScanReport {
        id: uuid::Uuid::new_v4(),
        file: FileInfo { path: PathBuf::from(format!("C:\\x\\{name}")), name: name.into(), size: 1, sha256: sha.repeat(64).chars().take(64).collect(), detected_type: "PE".into(), declared_extension: None, type_mismatch: false, signature: None, modified: None, source: None },
        verdict,
        complete: true,
        checks: vec![],
        findings: vec![],
        summary: String::new(),
        recommended_action: String::new(),
        started_at: chrono::Utc::now(),
        finished_at: chrono::Utc::now(),
        quarantined: false,
        blocked: false,
        cached: false,
        origin: Some("Telegram Desktop".into()),
        threat: None,
    };
    if verdict == Verdict::Malicious {
        r.findings.push(sentrix_core::Finding::new("clamav", "Eicar-Test-Signature", FindingKind::Signature, Severity::High, "e"));
    }
    r
}

#[test]
fn valid_credentials_connect_and_invalid_ones_are_explained() {
    let m = Mock::start();
    let me = client(&m).get_me().unwrap();
    assert_eq!((me.id, me.username.as_deref()), (123456789, Some("sentrix_test_bot")));

    let wrong = BotClient::with_base("987654321:ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", &m.base).unwrap();
    let e = wrong.get_me().unwrap_err();
    assert!(matches!(e, TgError::Api { code: 401, .. }), "{e:?}");
    assert!(e.user_message().contains("rejected the bot token"));
    assert!(!e.is_retryable(), "a revoked token must not be retried forever");
}

#[test]
fn a_message_reaches_the_chat_and_a_wrong_chat_is_explained() {
    let m = Mock::start();
    let c = client(&m);
    assert!(c.send_message(CHAT, "hello <b>there</b>").is_ok());
    assert_eq!(m.sent_texts(), vec!["hello <b>there</b>".to_string()]);
    let e = c.send_message(999, "x").unwrap_err();
    assert!(e.user_message().contains("cannot find that chat"), "{}", e.user_message());
}

#[test]
fn network_errors_never_leak_the_token() {
    // Nothing listens on this port, so the error text comes from the HTTP stack and includes the request URL.
    let c = BotClient::with_base(TOKEN, "http://127.0.0.1:9").unwrap();
    for e in [c.get_me().unwrap_err(), c.send_message(1, "x").unwrap_err(), c.get_updates(None, 1, 1).unwrap_err(), c.get_file("f").unwrap_err(), c.download("docs/x", &mut Vec::new(), 10).unwrap_err()] {
        let shown = format!("{e} | {e:?} | {}", e.user_message());
        assert!(!shown.contains(TOKEN) && !shown.contains("AAHkq3Zr"), "token leaked: {shown}");
        assert!(e.is_retryable());
    }
}

#[test]
fn delivery_retries_after_failures_and_never_duplicates() {
    let m = Mock::start();
    let store = JobStore::open_in_memory().unwrap();
    let c = client(&m);
    let o = format_report(&report(Verdict::Malicious, "bad.exe", "a"), &NotifyPrefs::default(), now_ms()).unwrap();
    assert!(store.enqueue_notification(&o.dedupe_key, &o.kind, &o.text, 0).unwrap());
    assert!(!store.enqueue_notification(&o.dedupe_key, &o.kind, &o.text, 0).unwrap(), "same event twice");

    // Telegram is down, then recovers.
    m.state.lock().unwrap().send_failures.extend([Fail::Status(502), Fail::Drop]);
    let d1 = deliver_due_at(&store, &c, CHAT, 5, Duration::ZERO, 0);
    assert_eq!((d1.sent, d1.retrying), (0, 1));
    assert_eq!(deliver_due_at(&store, &c, CHAT, 5, Duration::ZERO, 1_000).sent, 0, "not due again yet");
    let d2 = deliver_due_at(&store, &c, CHAT, 5, Duration::ZERO, 1_000_000);
    assert_eq!((d2.sent, d2.retrying), (0, 1), "dropped connection is a retryable failure too");
    let d3 = deliver_due_at(&store, &c, CHAT, 5, Duration::ZERO, 2_000_000);
    assert_eq!(d3.sent, 1);
    assert_eq!(m.sent_texts().len(), 1, "exactly one copy reached Telegram despite two failures");
    assert!(m.sent_texts()[0].contains("Eicar-Test-Signature"));
    let st = store.outbox_stats(2_000_000).unwrap();
    assert_eq!((st.pending, st.dead), (0, 0));
    assert_eq!(st.last_sent_at, Some(2_000_000));
}

#[test]
fn telegram_rate_limits_are_honoured() {
    let m = Mock::start();
    let store = JobStore::open_in_memory().unwrap();
    let c = client(&m);
    for i in 0..3 {
        store.enqueue_notification(&format!("k{i}"), "malicious", &format!("m{i}"), 0).unwrap();
    }
    m.state.lock().unwrap().send_failures.push_back(Fail::RateLimit(30));
    let d = deliver_due_at(&store, &c, CHAT, 5, Duration::ZERO, 0);
    assert_eq!((d.sent, d.retrying), (0, 1), "stop hammering after a 429");
    assert_eq!(m.state.lock().unwrap().calls.iter().filter(|c| *c == "sendMessage").count(), 1, "no further sends after a 429");
    assert_eq!(deliver_due_at(&store, &c, CHAT, 5, Duration::ZERO, 29_000).sent, 2, "the two untouched messages are still due; the limited one waits");
    let later = deliver_due_at(&store, &c, CHAT, 5, Duration::ZERO, 32_000);
    assert_eq!(later.sent, 1, "the rate-limited message goes out after retry_after");
}

#[test]
fn permanent_failures_are_not_retried_and_are_visible() {
    let m = Mock::start();
    let store = JobStore::open_in_memory().unwrap();
    let c = BotClient::with_base("987654321:ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", &m.base).unwrap(); // revoked/wrong token
    store.enqueue_notification("k", "malicious", "m", 0).unwrap();
    let d = deliver_due_at(&store, &c, CHAT, 5, Duration::ZERO, 0);
    assert_eq!((d.sent, d.dead), (0, 1));
    assert_eq!(deliver_due_at(&store, &c, CHAT, 5, Duration::ZERO, 10_000_000).dead, 0, "dead messages are not retried");
    let st = store.outbox_stats(0).unwrap();
    assert_eq!(st.dead, 1);
    assert!(st.last_error.unwrap().contains("401"));
    assert!(store.recent_events(5).unwrap().iter().any(|e| e.kind == "telegram_delivery" && e.message.contains("rejected the bot token")));
}

#[test]
fn a_notification_failure_never_changes_what_the_scan_found() {
    let store = JobStore::open_in_memory().unwrap();
    let r = report(Verdict::Malicious, "bad.exe", "b");
    let o = format_report(&r, &NotifyPrefs::default(), 0).unwrap();
    store.enqueue_notification(&o.dedupe_key, &o.kind, &o.text, 0).unwrap();
    let dead = BotClient::with_base(TOKEN, "http://127.0.0.1:9").unwrap();
    for t in 0..12 {
        deliver_due_at(&store, &dead, CHAT, 5, Duration::ZERO, t * 10_000_000);
    }
    assert_eq!(r.verdict, Verdict::Malicious);
    assert_eq!(store.outbox_stats(0).unwrap().dead, 1);
    assert!(o.text.contains("MALICIOUS"), "the stored report text still says what the scan found");
}

#[test]
fn downloads_are_size_capped_even_when_the_server_lies() {
    let m = Mock::start();
    let c = client(&m);
    m.state.lock().unwrap().files.insert("BIG".into(), vec![7u8; 200_000]);
    m.state.lock().unwrap().lie_about_size.insert("BIG".into(), 10);
    let (path, advertised) = c.get_file("BIG").unwrap();
    assert_eq!(advertised, Some(10), "the server claims a tiny file");
    let mut sink = Cursor::new(Vec::new());
    let e = c.download(&path, &mut sink, 50_000).unwrap_err();
    assert!(matches!(e, TgError::TooLarge(_)), "{e:?}");
    assert!(sink.get_ref().len() <= 50_000 + 64 * 1024, "must stop writing soon after the cap");
    let mut ok = Vec::new();
    m.state.lock().unwrap().files.insert("SMALL".into(), b"hello".to_vec());
    let (p2, _) = c.get_file("SMALL").unwrap();
    assert_eq!(c.download(&p2, &mut ok, 1000).unwrap(), 5);
    assert_eq!(ok, b"hello");
}

#[test]
fn updates_are_parsed_and_acknowledged_by_offset() {
    let m = Mock::start();
    m.add_text_update(10, CHAT, CHAT, "/start");
    m.add_document_update(11, CHAT, CHAT, "a.exe", vec![1, 2, 3]);
    let c = client(&m);
    let all = c.get_updates(None, 0, 10).unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all[1].document.as_ref().unwrap().file_name.as_deref(), Some("a.exe"));
    let after = c.get_updates(Some(12), 0, 10).unwrap();
    assert!(after.is_empty(), "acknowledged updates are not delivered again");
}
