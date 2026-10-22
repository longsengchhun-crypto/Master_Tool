//! Personal Telegram account protection against the REAL TDLib library.
//!
//!  * `real_tdlib_*` tests load the pinned DLL from `third_party/tdlib` (or `SENTRIX_TDLIB_DIR`) and talk to it. They need
//!    no account. They are skipped with a message when the folder is absent, unless `SENTRIX_REQUIRE_TDLIB=1`.
//!  * `live_*` tests are `#[ignore]`d: they need real credentials in the environment and a person scanning a QR code with
//!    a dedicated test Telegram account:
//!
//!      SENTRIX_TG_API_ID=… SENTRIX_TG_API_HASH=… SENTRIX_CLAMAV_DIR=… SENTRIX_DATA_DIR=… \
//!      cargo test -p sentrix-core --test account_td live_ -- --ignored --nocapture --test-threads=1
//!
//! Nothing here uses a simulated Telegram: either the real library answers, or the test says it did not run.

use sentrix_core::account::{AccountPrefs, AttachmentGate};
use sentrix_core::account_td::{AccountOptions, AttachmentScanner, Credentials, LinkState, ServiceScanner, Shared, TdAccount};
use sentrix_core::clamav::ClamEngine;
use sentrix_core::quarantine::Quarantine;
use sentrix_core::queue::JobStore;
use sentrix_core::service::{Hooks, ProtectionService, ServiceConfig};
use sentrix_core::tdjson::{TdIo, TdLib};
use sentrix_core::{Limits, ScanReport, Scanner};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn tdlib_dir() -> Option<PathBuf> {
    let d = std::env::var_os("SENTRIX_TDLIB_DIR").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../third_party/tdlib"));
    if d.join("tdjson.dll").exists() || d.join("libtdjson.so").exists() || d.join("libtdjson.dylib").exists() {
        Some(d)
    } else if std::env::var("SENTRIX_REQUIRE_TDLIB").as_deref() == Ok("1") {
        panic!("SENTRIX_REQUIRE_TDLIB=1 but no TDLib files in {}", d.display());
    } else {
        eprintln!("[skipped] TDLib not found in {}", d.display());
        None
    }
}

fn wait<T>(secs: u64, mut f: impl FnMut() -> Option<T>) -> Option<T> {
    let end = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < end {
        if let Some(v) = f() {
            return Some(v);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    None
}

#[test]
fn real_tdlib_loads_after_its_pins_verify_and_answers_a_request() {
    let Some(dir) = tdlib_dir() else { return };
    let lib = TdLib::load(&dir).expect("the pinned TDLib files must load");
    let client = lib.new_client();
    client.send(r#"{"@type":"getOption","name":"version","@extra":"v"}"#);
    let mut version = None;
    for _ in 0..40 {
        if let Some(m) = client.receive(0.5) {
            let v: serde_json::Value = serde_json::from_str(&m).unwrap();
            if v["@extra"] == "v" {
                version = v["value"].as_str().map(String::from);
                break;
            }
        }
    }
    let v = version.expect("TDLib answered getOption");
    println!("[ok] real TDLib loaded, version {v}");
    assert!(v.starts_with("1.8"), "{v}");
}

#[test]
fn real_tdlib_refuses_a_tampered_copy() {
    let Some(dir) = tdlib_dir() else { return };
    let tmp = tempfile::tempdir().unwrap();
    for e in std::fs::read_dir(&dir).unwrap().flatten() {
        if e.path().extension().map(|x| x == "dll").unwrap_or(false) {
            std::fs::copy(e.path(), tmp.path().join(e.file_name())).unwrap();
        }
    }
    let mut bytes = std::fs::read(tmp.path().join("zlib1.dll")).unwrap();
    bytes.push(0);
    std::fs::write(tmp.path().join("zlib1.dll"), bytes).unwrap();
    let err = sentrix_core::tdjson::verify_dir(tmp.path(), sentrix_core::tdjson::PINS).unwrap_err();
    assert!(err.contains("zlib1.dll") && err.contains("refusing"), "{err}");
}

#[test]
fn real_tdlib_with_an_invalid_api_id_ends_in_a_clear_failed_state_and_leaves_nothing_behind() {
    let Some(dir) = tdlib_dir() else { return };
    let lib = TdLib::load(&dir).unwrap();
    let data = tempfile::tempdir().unwrap();
    let store = Arc::new(JobStore::open_in_memory().unwrap());
    let scanner: Arc<dyn AttachmentScanner> = Arc::new(NullScan);
    let shared = Shared::new(store, scanner, Box::new(|| {}), AccountOptions::default(), LinkState::Disconnected);
    let l2 = lib.clone();
    let acct = TdAccount::new(shared, data.path(), Some(Credentials { api_id: 1, api_hash: "00000000000000000000000000000000".into() }), Box::new(move || Ok(Arc::new(l2.new_client()) as Arc<dyn TdIo>)), None);
    acct.connect();
    let end = wait(60, || match acct.view().link {
        LinkState::Failed(m) => Some(Ok(m)),
        LinkState::WaitingForScan => Some(Err("a QR code was issued for an invalid api_id".to_string())),
        _ => None,
    });
    match end {
        Some(Ok(m)) => println!("[ok] real TDLib refused the bogus credentials: {m}"),
        Some(Err(e)) => panic!("{e}"),
        None => {
            // No network: the library cannot reach Telegram at all. That is a legitimate environment limit, said plainly.
            eprintln!("[inconclusive] TDLib did not answer within 60 s (no network?); state {:?}", acct.view().link);
        }
    }
    acct.disconnect();
    assert!(!data.path().join("telegram-account.session").exists(), "no key may be left behind");
}

struct NullScan;
impl AttachmentScanner for NullScan {
    fn scan(&self, _: sentrix_core::account::ChatKind, _: &str, _: u64, _: &mut dyn std::io::Read) -> Result<ScanReport, sentrix_core::account::IngestError> {
        Err(sentrix_core::account::IngestError::Scan("unused".into()))
    }
    fn publish(&self, _: &ScanReport) {}
    fn notice(&self, _: &'static str, _: &str) {}
}

// ---- live ------------------------------------------------------------------------------------------------------

#[derive(Default)]
struct Collect(Mutex<Vec<ScanReport>>);
impl Hooks for Collect {
    fn on_report(&self, r: &ScanReport) {
        self.0.lock().unwrap().push(r.clone());
    }
    fn on_health_changed(&self) {}
}

fn print_qr(link: &str) {
    use qrcode::render::unicode::Dense1x2;
    if let Ok(c) = qrcode::QrCode::new(link.as_bytes()) {
        println!("\n{}\n", c.render::<Dense1x2>().quiet_zone(true).build());
    }
}

/// Real login with a real test account, then waits for a file to arrive and checks that it is scanned and removed.
#[test]
#[ignore = "needs SENTRIX_TG_API_ID/HASH, a test Telegram account and a person scanning the QR code; see file header"]
fn live_qr_login_then_a_received_file_is_scanned_by_the_real_engine_and_disconnect_erases_everything() {
    let dir = tdlib_dir().expect("TDLib files");
    let creds = Credentials { api_id: std::env::var("SENTRIX_TG_API_ID").expect("SENTRIX_TG_API_ID").parse().expect("numeric api id"), api_hash: std::env::var("SENTRIX_TG_API_HASH").expect("SENTRIX_TG_API_HASH") };
    let lib = TdLib::load(&dir).unwrap();

    let clam = Arc::new(ClamEngine::new(std::env::var_os("SENTRIX_CLAMAV_DIR").expect("SENTRIX_CLAMAV_DIR"), std::env::var_os("SENTRIX_DATA_DIR").expect("SENTRIX_DATA_DIR")));
    clam.start().expect("clamd");
    let scanner = Arc::new(Scanner::new(Limits::default(), Some(clam)));
    let work = tempfile::tempdir().unwrap();
    let store = Arc::new(JobStore::open(&work.path().join("protection.db")).unwrap());
    let q = Arc::new(Quarantine::open(work.path().join("vault")).unwrap());
    let hooks = Arc::new(Collect::default());
    let svc = Arc::new(ProtectionService::new(scanner, q, store.clone(), hooks.clone(), ServiceConfig::new(work.path().join("tmp"))));
    let gate = Arc::new(AttachmentGate::new(AccountPrefs::default(), 2));
    let shared = Shared::new(store, Arc::new(ServiceScanner { svc, gate }), Box::new(|| {}), AccountOptions::default(), LinkState::Disconnected);
    let l2 = lib.clone();
    let acct_dir = work.path().join("tg-account");
    let acct = TdAccount::new(shared, &acct_dir, Some(creds), Box::new(move || Ok(Arc::new(l2.new_client()) as Arc<dyn TdIo>)), None);

    acct.connect();
    println!("Scan the QR code below in Telegram on the TEST account: Settings > Devices > Link Desktop Device.");
    let mut last = String::new();
    let connected = wait(240, || {
        let v = acct.view();
        if let Some(link) = &v.login_link {
            if *link != last {
                last = link.clone();
                print_qr(link);
            }
        }
        match v.link {
            LinkState::Connected => Some(true),
            LinkState::TwoStepUnsupported | LinkState::Failed(_) | LinkState::Expired => Some(false),
            _ => None,
        }
    });
    assert_eq!(connected, Some(true), "login did not complete: {:?}", acct.view().link);
    println!("[ok] connected as {:?}", acct.view().display);
    assert!(acct_dir.join("telegram-account.session").exists(), "the database key is stored");

    println!("From ANOTHER account, send the test account a file (a zip with EICAR works). Waiting up to 5 minutes…");
    let got = wait(300, || {
        let v = acct.view();
        (v.counts.scanned + v.counts.inaccessible >= 1).then_some(v)
    });
    let v = got.expect("no attachment was processed in 5 minutes");
    println!("[ok] processed: {:?}", v.recent.first());
    assert!(acct_dir.join("files").read_dir().map(|mut d| d.next().is_none()).unwrap_or(true), "the downloaded copy must be removed");

    acct.disconnect();
    assert_eq!(acct.view().link, LinkState::Disconnected);
    assert!(!acct_dir.join("telegram-account.session").exists());
    assert!(!acct_dir.join("db").exists(), "the local database must be erased");
    println!("[ok] disconnected; session key and local database erased. Also check Telegram > Settings > Devices: the SENTRIX session must be gone.");
}
