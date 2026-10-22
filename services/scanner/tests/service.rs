//! End-to-end tests of the background protection service.
//!
//!  * Tests without `#[ignore]` run anywhere (no antivirus engine): they prove the failure-path guarantees.
//!  * `pipeline_with_real_engine` is `#[ignore]` and runs the whole pipeline against real ClamAV:
//!      SENTRIX_CLAMAV_DIR=… SENTRIX_DATA_DIR=… cargo test -p sentrix-core --test service -- --ignored --nocapture
//!
//! Telegram is a local test double (tests/common): these tests do not talk to the real Telegram.
mod common;

use common::*;
use sentrix_core::account::{AccountPrefs, AttachmentGate, ChatKind, IncomingAttachment, IngestError};
use sentrix_core::clamav::ClamEngine;
use sentrix_core::eicar::eicar_bytes;
use sentrix_core::guard;
use sentrix_core::notify::NotifyPrefs;
use sentrix_core::quarantine::Quarantine;
use sentrix_core::queue::JobStore;
use sentrix_core::service::{ProtectionService, ServiceConfig, WatchRoot};
use sentrix_core::telegram::BotClient;
use sentrix_core::{Limits, Scanner, Verdict};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
    watch: PathBuf,
    tmp: PathBuf,
    _dir: tempfile::TempDir,
}

fn rig(scanner: Arc<Scanner>, label: &str, tweak: impl FnOnce(&mut ServiceConfig)) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    rig_in(dir, scanner, label, tweak)
}

fn rig_in(dir: tempfile::TempDir, scanner: Arc<Scanner>, label: &str, tweak: impl FnOnce(&mut ServiceConfig)) -> Rig {
    let watch = dir.path().join("watched");
    std::fs::create_dir_all(&watch).unwrap();
    let tmp = dir.path().join("tmp");
    let store = Arc::new(JobStore::open(&dir.path().join("protection.db")).unwrap());
    let q = Arc::new(Quarantine::open(dir.path().join("vault")).unwrap());
    let hooks = Arc::new(Collect::default());
    let mut cfg = ServiceConfig::new(tmp.clone());
    cfg.realtime = true;
    cfg.roots = vec![WatchRoot { path: watch.clone(), label: label.into() }];
    tweak(&mut cfg);
    let svc = ProtectionService::new(scanner, q, store.clone(), hooks.clone(), cfg);
    Rig { svc, hooks, store, watch, tmp, _dir: dir }
}

fn no_engine() -> Arc<Scanner> {
    Arc::new(Scanner::new(Limits::default(), None))
}

// ---- failure-path guarantees (no engine needed) ------------------------------------------------------------

#[test]
fn without_an_engine_nothing_is_recorded_as_clean_and_the_work_is_retried_not_lost() {
    let r = rig(no_engine(), "Downloads folder", |_| {});
    r.svc.start();
    std::fs::write(r.watch.join("report.pdf"), b"%PDF-1.4 hello").unwrap();
    // The file is detected, settles, is scanned, finds no engine: that is a *retry*, never a verdict.
    assert!(until(15, || r.store.stats(sentrix_core::queue::now_ms()).unwrap().queued == 1 && r.store.recent_events(5).unwrap().is_empty() || r.store.stats(sentrix_core::queue::now_ms()).unwrap().queued == 1));
    std::thread::sleep(Duration::from_secs(5));
    let st = r.store.stats(sentrix_core::queue::now_ms()).unwrap();
    assert_eq!(st.queued + st.scanning, 1, "the job must still exist: {st:?}");
    assert_eq!(r.hooks.count(), 0, "no result may be published for a scan that could not run");
    assert_eq!(st.files_scanned, 0, "and nothing may be remembered as scanned/clean");
    r.svc.stop();
}

#[test]
fn files_that_arrived_while_sentrix_was_off_are_found_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let watch = dir.path().join("watched");
    std::fs::create_dir_all(&watch).unwrap();
    let fresh = watch.join("arrived-while-off.exe");
    std::fs::write(&fresh, b"MZ fresh").unwrap();
    let old = watch.join("old-download.exe");
    std::fs::write(&old, b"MZ old").unwrap();
    let thirty_days = std::time::SystemTime::now() - Duration::from_secs(30 * 86_400);
    std::fs::File::options().write(true).open(&old).unwrap().set_modified(thirty_days).unwrap();
    std::fs::write(watch.join("movie.mp4.crdownload"), b"partial").unwrap(); // an in-progress download

    let r = rig_in(dir, no_engine(), "Downloads folder", |_| {});
    assert_eq!(r.store.stats(0).unwrap().queued, 0);
    r.svc.start(); // the reconciler runs shortly after start
    assert!(until(10, || r.store.stats(sentrix_core::queue::now_ms()).unwrap().queued + r.store.stats(sentrix_core::queue::now_ms()).unwrap().scanning >= 1), "the file that arrived while SENTRIX was off must be queued");
    std::thread::sleep(Duration::from_millis(500));
    let ev = r.store.recent_events(10).unwrap();
    assert!(ev.iter().any(|e| e.kind == "reconciled"), "{ev:?}");
    let st = r.store.stats(sentrix_core::queue::now_ms()).unwrap();
    assert_eq!(st.queued + st.scanning, 1, "only the recent file: the 30-day-old one and the .crdownload are skipped");
    r.svc.stop();
}

#[test]
fn health_reports_real_state_per_folder() {
    let r = rig(no_engine(), "Telegram Desktop", |c| c.roots.push(WatchRoot { path: PathBuf::from("Z:\\unplugged-drive\\Downloads"), label: "Removable drive".into() }));
    r.svc.start();
    let h = r.svc.health();
    assert!(h.realtime_enabled);
    assert!(until(5, || r.svc.health().monitor_running), "monitor must be running for the folder that exists");
    let h = r.svc.health();
    let ok = h.roots.iter().find(|x| x.label == "Telegram Desktop").unwrap();
    assert!(ok.exists && ok.watching && ok.error.is_none(), "{ok:?}");
    let missing = h.roots.iter().find(|x| x.label == "Removable drive").unwrap();
    assert!(!missing.exists && !missing.watching && missing.error.is_some(), "an unavailable drive must be shown as a problem: {missing:?}");
    r.svc.stop();
    assert!(!r.svc.health().monitor_running, "stopped means stopped");
}

#[test]
fn disabling_realtime_stops_watching() {
    let r = rig(no_engine(), "Downloads folder", |_| {});
    r.svc.start();
    assert!(until(5, || r.svc.health().monitor_running));
    let mut cfg = ServiceConfig::new(r.tmp.clone());
    cfg.realtime = false;
    r.svc.set_config(cfg);
    assert!(!r.svc.health().monitor_running);
    std::fs::write(r.watch.join("later.exe"), b"MZ").unwrap();
    std::thread::sleep(Duration::from_secs(4));
    assert_eq!(r.store.stats(sentrix_core::queue::now_ms()).unwrap().queued, 0, "nothing is queued while protection is off");
    r.svc.stop();
}

// ---- bot submissions: sender validation, limits, cleanup (no engine needed) --------------------------------

fn bot_rig(m: &Mock, accept: bool) -> Rig {
    let r = rig(no_engine(), "Downloads folder", |c| {
        c.realtime = false;
        c.chat_id = Some(CHAT);
        c.accept_submissions = accept;
    });
    r.svc.set_bot(Some(Arc::new(BotClient::with_base(TOKEN, &m.base).unwrap())));
    r.svc.start();
    r
}

#[test]
fn only_the_configured_owner_can_submit_files_to_the_bot() {
    let m = Mock::start();
    let r = bot_rig(&m, true);
    m.add_document_update(1, 777, 777, "stranger.exe", b"MZ".to_vec()); // someone else's private chat
    m.add_document_update(2, CHAT, 555, "wrong-sender.exe", b"MZ".to_vec()); // right chat id, different sender id
    m.state.lock().unwrap().updates.push(serde_json::json!({"update_id": 3, "message": {"chat": {"id": CHAT, "type": "group"}, "from": {"id": CHAT}, "document": {"file_id": "FILE1", "file_name": "group.exe", "file_size": 2}}}));
    // Two private-chat strangers are rejected and counted. The group message is not an owner submission either: it takes the
    // Group Shield path, which (switched off here) ignores it. In every case nothing is scanned and nobody gets a reply.
    assert!(until(15, || r.svc.health().rejected_submissions >= 2 && r.store.kv_get("tg_offset").as_deref() == Some("4")), "rejected: {} | events: {:?} | telegram calls: {:?}", r.svc.health().rejected_submissions, r.store.recent_events(10).unwrap(), m.state.lock().unwrap().calls);
    std::thread::sleep(Duration::from_secs(2));
    assert!(r.store.groups_list().unwrap().iter().all(|g| !g.enabled), "a group message must never switch protection on");
    assert!(m.sent_texts().is_empty(), "strangers get no reply and nothing is scanned: {:?}", m.sent_texts());
    assert!(!r.tmp.exists() || std::fs::read_dir(&r.tmp).unwrap().count() == 0);
    assert_eq!(r.hooks.count(), 0);
    r.svc.stop();
}

#[test]
fn owner_submission_is_scanned_answered_and_cleaned_up() {
    let m = Mock::start();
    let r = bot_rig(&m, true);
    m.add_document_update(10, CHAT, CHAT, "my<doc>\u{202E}fdp.pdf", b"%PDF-1.4 not malware".to_vec());
    assert!(m.wait_for_messages(1, 25), "the owner must get an answer");
    let reply = m.sent_texts().remove(0);
    // Without an engine the honest answer is "could not verify", never "clean".
    assert!(reply.contains("UNABLE TO VERIFY"), "{reply}");
    assert!(!reply.contains("Status:</b> CLEAN"));
    assert!(!reply.contains('\u{202E}') && reply.contains("my&lt;doc&gt;"), "untrusted name must be neutralised: {reply}");
    assert!(until(5, || r.hooks.count() == 1));
    let rep = r.hooks.reports.lock().unwrap()[0].clone();
    assert_eq!(rep.origin.as_deref(), Some("Telegram bot submission"));
    assert!(!rep.file.path.exists(), "no real path is exposed for a temp file");
    assert!(until(5, || !r.tmp.exists() || std::fs::read_dir(&r.tmp).unwrap().count() == 0), "the isolated temp folder must be removed");
    r.svc.stop();
}

#[test]
fn submissions_are_limited_by_size_rate_and_media_type() {
    let m = Mock::start();
    let r = bot_rig(&m, true);
    // Advertised as too big: refused without downloading.
    m.state.lock().unwrap().updates.push(serde_json::json!({"update_id": 20, "message": {"chat": {"id": CHAT, "type": "private"}, "from": {"id": CHAT}, "document": {"file_id": "HUGE", "file_name": "big.iso", "file_size": 30_000_000u64}}}));
    // A photo: Telegram recompresses these.
    m.state.lock().unwrap().updates.push(serde_json::json!({"update_id": 21, "message": {"chat": {"id": CHAT, "type": "private"}, "from": {"id": CHAT}, "photo": [{}]}}));
    assert!(m.wait_for_messages(2, 25));
    let texts = m.sent_texts().join("\n");
    assert!(texts.contains("larger than the 20 MB") && texts.contains("recompresses photos"), "{texts}");
    assert!(!m.state.lock().unwrap().calls.contains(&"getFile".to_string()), "oversized files must not even be requested");
    // Rate limit: 5 files per minute, the 6th is refused.
    for i in 0..6 {
        m.add_document_update(100 + i, CHAT, CHAT, &format!("f{i}.txt"), b"x".to_vec());
    }
    assert!(m.wait_for_messages(2 + 6, 60));
    let all = m.sent_texts().join("\n");
    assert!(all.contains("Too many files at once"), "{all}");
    r.svc.stop();
}

#[test]
fn bot_submissions_are_ignored_unless_the_user_enabled_them() {
    let m = Mock::start();
    let r = bot_rig(&m, false);
    m.add_document_update(1, CHAT, CHAT, "a.exe", b"MZ".to_vec());
    std::thread::sleep(Duration::from_secs(4));
    assert!(!m.state.lock().unwrap().calls.contains(&"getUpdates".to_string()), "the bot must not even poll when submissions are off");
    assert!(m.sent_texts().is_empty());
    r.svc.stop();
}

// ---- account attachment gate -------------------------------------------------------------------------------

#[test]
fn account_attachments_respect_category_size_backpressure_and_leave_nothing_behind() {
    let r = rig(no_engine(), "Downloads folder", |c| c.realtime = false);
    r.svc.start();
    let gate = AttachmentGate::new(AccountPrefs::default(), 2);
    let att = |kind, size| IncomingAttachment { chat_kind: kind, display_name: "invoice.pdf".into(), size };
    assert_eq!(gate.ingest(&r.svc, &att(ChatKind::Group, 10), &mut &b"x"[..]).unwrap_err(), IngestError::CategoryDisabled, "groups are opt-in");
    assert_eq!(gate.ingest(&r.svc, &att(ChatKind::Channel, 10), &mut &b"x"[..]).unwrap_err(), IngestError::CategoryDisabled);
    assert_eq!(gate.ingest(&r.svc, &att(ChatKind::Private, 500 * 1024 * 1024), &mut &b"x"[..]).unwrap_err(), IngestError::TooLarge);
    let rep = gate.ingest(&r.svc, &att(ChatKind::Private, 10), &mut &b"%PDF-1.4 x"[..]).unwrap();
    assert_eq!(rep.origin.as_deref(), Some("Telegram personal chat"));
    assert_ne!(rep.verdict, Verdict::Clean, "no engine, so never clean");
    assert_eq!(gate.in_flight(), 0);
    assert!(until(5, || !r.tmp.exists() || std::fs::read_dir(&r.tmp).unwrap().count() == 0));

    // Backpressure: with every slot busy, the next attachment is pushed back instead of queued without bound.
    struct Slow;
    impl std::io::Read for Slow {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            std::thread::sleep(Duration::from_millis(600));
            buf[0] = b'x';
            Ok(1)
        }
    }
    let gate = Arc::new(AttachmentGate::new(AccountPrefs { max_bytes: 3, ..Default::default() }, 2));
    let svc = Arc::new(r.svc);
    let busy: Vec<_> = (0..2)
        .map(|_| {
            let (g, s) = (gate.clone(), svc.clone());
            std::thread::spawn(move || g.ingest(&s, &IncomingAttachment { chat_kind: ChatKind::Private, display_name: "slow.bin".into(), size: 3 }, &mut Slow))
        })
        .collect();
    assert!(until(3, || gate.in_flight() == 2));
    assert_eq!(gate.ingest(&svc, &IncomingAttachment { chat_kind: ChatKind::Private, display_name: "third.bin".into(), size: 1 }, &mut &b"x"[..]).unwrap_err(), IngestError::Busy);
    for b in busy {
        let _ = b.join();
    }
    assert_eq!(gate.in_flight(), 0, "slots are always released");
    svc.stop();
}

// ---- the full pipeline against REAL ClamAV -----------------------------------------------------------------

fn write_slowly(path: &Path, chunks: usize, pause: Duration) {
    let mut f = std::fs::File::create(path).unwrap();
    for i in 0..chunks {
        f.write_all(format!("chunk {i} of a download in progress\n").as_bytes()).unwrap();
        f.flush().unwrap();
        std::thread::sleep(pause);
    }
}

#[test]
#[ignore = "needs real ClamAV: see file header"]
fn pipeline_with_real_engine() {
    let clam = Arc::new(ClamEngine::new(std::env::var_os("SENTRIX_CLAMAV_DIR").expect("SENTRIX_CLAMAV_DIR"), std::env::var_os("SENTRIX_DATA_DIR").expect("SENTRIX_DATA_DIR")));
    clam.start().expect("clamd");
    let scanner = Arc::new(Scanner::new(Limits::default(), Some(clam.clone())));
    let ms = || sentrix_core::queue::now_ms();

    // ---- 1. malicious file in a watched folder: detected automatically, reported, guarded, and Telegram told ----
    {
        let m = Mock::start();
        let r = rig(scanner.clone(), "Telegram Desktop", |c| {
            c.chat_id = Some(CHAT);
            c.auto_quarantine = false;
            c.execution_guard = true;
        });
        r.svc.set_bot(Some(Arc::new(BotClient::with_base(TOKEN, &m.base).unwrap())));
        r.svc.start();
        let zip = r.watch.join("invoice.zip");
        std::fs::write(&zip, make_zip(&[("a.txt", b"hello"), ("inner/e.com", &eicar_bytes())])).unwrap();
        assert!(r.hooks.wait_for(1, 40), "the new file must be scanned with no user action");
        let rep = r.hooks.reports.lock().unwrap()[0].clone();
        assert_eq!(rep.verdict, Verdict::Malicious);
        assert_eq!(rep.origin.as_deref(), Some("Telegram Desktop"), "source label comes from the watched folder");
        assert!(rep.blocked && guard::is_blocked(&zip), "quarantine is off, so the execution guard must have been applied and verified");
        assert!(zip.exists(), "the file is left in place when only the guard is enabled");
        assert!(m.wait_for_messages(1, 30), "the user's bot must receive the report");
        let text = m.sent_texts().remove(0);
        for must in ["Status:</b> MALICIOUS", "Source:</b> Telegram Desktop", "invoice.zip", "Eicar-Test-Signature", "Execution blocked by SENTRIX"] {
            assert!(text.contains(must), "missing {must:?}:\n{text}");
        }
        guard::allow_execution(&zip).unwrap();
        r.svc.stop();
        println!("[ok] malicious zip in the Telegram Desktop folder: scanned, guarded, reported to the bot");
    }

    // ---- 2. quarantine policy removes it instead ----
    {
        let r = rig(scanner.clone(), "Downloads folder", |c| c.auto_quarantine = true);
        r.svc.start();
        let zip = r.watch.join("payload.zip");
        std::fs::write(&zip, make_zip(&[("e.com", &eicar_bytes())])).unwrap();
        assert!(r.hooks.wait_for(1, 40));
        assert!(r.hooks.reports.lock().unwrap()[0].quarantined);
        assert!(until(5, || !zip.exists()), "the original must be gone after quarantine");
        r.svc.stop();
        println!("[ok] auto-quarantine moves confirmed malware into the vault");
    }

    // ---- 3. clean file: CLEAN only because the engine completed; reported only if the user wants clean reports ----
    {
        let m = Mock::start();
        let r = rig(scanner.clone(), "Downloads folder", |c| {
            c.chat_id = Some(CHAT);
            c.notify = NotifyPrefs { clean_scans: true, ..Default::default() };
        });
        r.svc.set_bot(Some(Arc::new(BotClient::with_base(TOKEN, &m.base).unwrap())));
        r.svc.start();
        let t0 = std::time::Instant::now();
        std::fs::write(r.watch.join("notes.txt"), b"meeting notes\n").unwrap();
        assert!(r.hooks.wait_for(1, 40));
        let t_report = t0.elapsed();
        let rep = r.hooks.reports.lock().unwrap()[0].clone();
        assert_eq!((rep.verdict, rep.complete), (Verdict::Clean, true));
        assert!(m.wait_for_messages(1, 30));
        // Real measurement. Telegram is a local test double, so this excludes real network latency; it includes the settle delay.
        println!("[measure] file written -> report available: {} ms; -> delivered to the Bot API double: {} ms", t_report.as_millis(), t0.elapsed().as_millis());
        assert!(m.sent_texts()[0].contains("Status:</b> CLEAN"));
        r.svc.stop();
        println!("[ok] clean file → CLEAN (engine completed) → optional clean report");
    }

    // ---- 4. partial download: nothing is scanned until it stops growing; exactly one result for the final content ----
    {
        let r = rig(scanner.clone(), "Downloads folder", |_| {});
        r.svc.start();
        let p = r.watch.join("big-download.bin");
        write_slowly(&p, 12, Duration::from_millis(450)); // ~5.4 s of continuous writing
        assert_eq!(r.hooks.count(), 0, "a file still being written must not be reported (least of all as clean)");
        assert!(r.hooks.wait_for(1, 40));
        std::thread::sleep(Duration::from_secs(3));
        assert_eq!(r.hooks.count(), 1, "exactly one result for one download");
        let rep = r.hooks.reports.lock().unwrap()[0].clone();
        assert_eq!(rep.file.size, std::fs::metadata(&p).unwrap().len(), "the result describes the FINISHED file");
        r.svc.stop();
        println!("[ok] partial download not scanned early; one result for the final file");
    }

    // ---- 5. duplicate events: a burst of touches is one job and one result ----
    {
        let r = rig(scanner.clone(), "Downloads folder", |_| {});
        r.svc.start();
        let p = r.watch.join("burst.txt");
        for i in 0..40 {
            std::fs::write(&p, b"same content").unwrap();
            if i % 10 == 0 {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        assert!(r.hooks.wait_for(1, 40));
        std::thread::sleep(Duration::from_secs(4));
        assert_eq!(r.hooks.count(), 1, "duplicate filesystem events must not create duplicate scans");
        r.svc.stop();
        println!("[ok] 40 write events → 1 scan");
    }

    // ---- 6. replaced after scanning: the old verdict is stale and the new content is scanned ----
    {
        let r = rig(scanner.clone(), "Downloads folder", |_| {});
        r.svc.start();
        let p = r.watch.join("swap.txt");
        std::fs::write(&p, b"first version").unwrap();
        assert!(r.hooks.wait_for(1, 40));
        std::thread::sleep(Duration::from_secs(2));
        std::fs::write(&p, b"second, different version").unwrap();
        assert!(r.hooks.wait_for(2, 40), "a changed file must be scanned again");
        let reps = r.hooks.reports.lock().unwrap().clone();
        assert_ne!(reps[0].file.sha256, reps[1].file.sha256);
        assert_eq!(reps[1].file.sha256, sentrix_core::hash::sha256_file(&p).unwrap());
        r.svc.stop();
        println!("[ok] file replaced after scan → rescanned with the new hash");
    }

    // ---- 7. locked file: no result while unreadable, retried, then scanned once released ----
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        let r = rig(scanner.clone(), "Downloads folder", |_| {});
        r.svc.start();
        let p = r.watch.join("locked.txt");
        let mut f = std::fs::OpenOptions::new().write(true).create(true).share_mode(0).open(&p).unwrap(); // exclusive
        f.write_all(b"held by another program").unwrap();
        f.flush().unwrap();
        std::thread::sleep(Duration::from_secs(7));
        assert_eq!(r.hooks.count(), 0, "an unreadable file must not produce a verdict");
        let st = r.store.stats(ms()).unwrap();
        assert_eq!(st.queued + st.scanning, 1, "it is waiting for a retry, not lost: {st:?}");
        drop(f); // the other program lets go
        assert!(r.hooks.wait_for(1, 60), "after release the file must be scanned");
        assert_eq!(r.hooks.reports.lock().unwrap()[0].verdict, Verdict::Clean);
        r.svc.stop();
        println!("[ok] locked file → retried with backoff → scanned after release");
    }

    // ---- 8. restart: a file dropped while the service is stopped is picked up by the next run ----
    {
        let dir = tempfile::tempdir().unwrap();
        let first = rig_in(dir, scanner.clone(), "Downloads folder", |_| {});
        first.svc.start();
        std::fs::write(first.watch.join("before.txt"), b"seen while running").unwrap();
        assert!(first.hooks.wait_for(1, 40));
        first.svc.stop();
        std::fs::write(first.watch.join("while-off.txt"), b"arrived while SENTRIX was not running").unwrap();
        // "Reboot": a brand-new service over the same database.
        let q = Arc::new(Quarantine::open(first._dir.path().join("vault")).unwrap());
        let hooks2 = Arc::new(Collect::default());
        let mut cfg = ServiceConfig::new(first.tmp.clone());
        cfg.realtime = true;
        cfg.roots = vec![WatchRoot { path: first.watch.clone(), label: "Downloads folder".into() }];
        let second = ProtectionService::new(scanner.clone(), q, first.store.clone(), hooks2.clone(), cfg);
        second.start();
        assert!(hooks2.wait_for(1, 60), "the file that arrived while off must be scanned after restart");
        std::thread::sleep(Duration::from_secs(2));
        let names: Vec<String> = hooks2.reports.lock().unwrap().iter().map(|r| r.file.name.clone()).collect();
        assert_eq!(names, vec!["while-off.txt".to_string()], "already-scanned files are not rescanned");
        second.stop();
        println!("[ok] restart → missed file reconciled, scanned files not repeated");
    }

    // ---- 9. owner submits a malicious file to their bot ----
    {
        let m = Mock::start();
        let r = rig(scanner.clone(), "Downloads folder", |c| {
            c.realtime = false;
            c.chat_id = Some(CHAT);
            c.accept_submissions = true;
        });
        r.svc.set_bot(Some(Arc::new(BotClient::with_base(TOKEN, &m.base).unwrap())));
        r.svc.start();
        m.add_document_update(1, CHAT, CHAT, "sent-by-friend.zip", make_zip(&[("e.com", &eicar_bytes())]));
        assert!(m.wait_for_messages(1, 40));
        let t = m.sent_texts().remove(0);
        assert!(t.contains("Status:</b> MALICIOUS") && t.contains("Telegram bot submission") && t.contains("Eicar-Test-Signature"), "{t}");
        assert!(until(5, || !r.tmp.exists() || std::fs::read_dir(&r.tmp).unwrap().count() == 0), "temp copy removed");
        r.svc.stop();
        println!("[ok] malicious file sent to the user's own bot → scanned locally → MALICIOUS reply → temp copy deleted");
    }

    // ---- 10. account attachment (through the privacy-minimal gate) ----
    {
        let r = rig(scanner.clone(), "Downloads folder", |c| c.realtime = false);
        r.svc.start();
        let gate = AttachmentGate::new(AccountPrefs::default(), 2);
        let att = IncomingAttachment { chat_kind: ChatKind::Private, display_name: "photo-album.zip".into(), size: 100 };
        let rep = gate.ingest(&r.svc, &att, &mut make_zip(&[("e.com", &eicar_bytes())]).as_slice()).unwrap();
        assert_eq!((rep.verdict, rep.origin.as_deref()), (Verdict::Malicious, Some("Telegram personal chat")));
        assert!(until(5, || !r.tmp.exists() || std::fs::read_dir(&r.tmp).unwrap().count() == 0));
        r.svc.stop();
        println!("[ok] account attachment path scans with the real engine and leaves nothing behind");
    }

    clam.stop();
}
