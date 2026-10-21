//! End-to-end tests against a REAL ClamAV engine. These are #[ignore]d so they can never silently "pass" when the
//! engine is absent. Run with:
//!   SENTRIX_CLAMAV_DIR=<dir with clamd.exe> SENTRIX_DATA_DIR=<dir with clamav-db> cargo test -p sentrix-core --test engine -- --ignored --nocapture
//!
//! EICAR note: Windows Defender (or any real-time AV) may delete EICAR files the moment they are written. If a
//! step fails with "EICAR file vanished", that is the host AV doing its job, not a SENTRIX bug.

use sentrix_core::clamav::ClamEngine;
use sentrix_core::eicar::eicar_bytes;
use sentrix_core::quarantine::{Quarantine, RestoreOptions};
use sentrix_core::{CheckStatus, FindingKind, Limits, ScanOptions, Scanner, Verdict};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;

fn engine_dirs() -> (PathBuf, PathBuf) {
    let clam = std::env::var_os("SENTRIX_CLAMAV_DIR").expect("SENTRIX_CLAMAV_DIR must be set for engine tests");
    let data = std::env::var_os("SENTRIX_DATA_DIR").expect("SENTRIX_DATA_DIR must be set for engine tests");
    (clam.into(), data.into())
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, bytes).unwrap();
    p
}

fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (n, d) in entries {
        w.start_file(*n, zip::write::SimpleFileOptions::default()).unwrap();
        w.write_all(d).unwrap();
    }
    w.finish().unwrap().into_inner()
}

fn mz_pe() -> Vec<u8> {
    let mut b = vec![0u8; 0x400];
    b[0] = b'M';
    b[1] = b'Z';
    b[0x3c] = 0x80;
    b[0x80..0x84].copy_from_slice(b"PE\0\0");
    b
}

#[test]
#[ignore = "requires a real ClamAV install + signature database; see file header"]
fn real_engine_end_to_end() {
    let (clam_dir, data_dir) = engine_dirs();
    let clam = Arc::new(ClamEngine::new(clam_dir, data_dir));
    assert!(clam.is_installed(), "ClamAV binaries not found");
    assert!(clam.has_database(), "no signature database; run `sentrix-cli update-signatures` first");
    let scanner = Scanner::new(Limits::default(), Some(clam.clone()));
    let work = tempfile::tempdir().unwrap();
    let w = work.path();
    let opts = ScanOptions { use_cache: false, ..Default::default() };

    // 0. Engine comes up and reports an honest status.
    let t = std::time::Instant::now();
    clam.start().expect("clamd must start");
    println!("clamd started in {:?}; version = {}", t.elapsed(), clam.version().unwrap());
    let st = scanner.engine_status();
    assert_eq!(st.state, "running", "{st:?}");
    assert!(st.clamav_version.as_deref().unwrap_or("").contains("ClamAV"));

    // 1. A benign text file is CLEAN, and only because ClamAV completed.
    let p = write(w, "notes.txt", b"meeting notes: nothing to see\n");
    let r = scanner.scan_file(&p, &opts);
    assert_eq!(r.verdict, Verdict::Clean, "{r:#?}");
    assert!(r.complete);
    assert!(r.checks.iter().any(|c| c.id == "clamav" && c.status == CheckStatus::Completed));
    println!("[ok] benign text -> CLEAN");

    // 2a. ClamAV itself detects EICAR (streamed from memory, so no host AV can interfere).
    let direct = clam.scan_stream(&mut std::io::Cursor::new(eicar_bytes()), &|| false).unwrap();
    match &direct {
        sentrix_core::clamav::ClamOutcome::Found(n) => println!("[ok] ClamAV direct stream: EICAR -> FOUND ({n})"),
        other => panic!("ClamAV failed to detect EICAR: {other:?}"),
    }

    // 2b. EICAR on disk is MALICIOUS. On a machine with real-time AV (e.g. Defender) the OS may block the read
    //     (os error 225); SENTRIX then reports the host provider's detection. Either path must yield MALICIOUS.
    let e = write(w, "eicar.com", &eicar_bytes());
    let r = scanner.scan_file(&e, &opts);
    assert_eq!(r.verdict, Verdict::Malicious, "{r:#?}");
    if r.findings.iter().any(|f| f.source == "windows-security") {
        assert!(!r.complete, "a blocked read cannot be a complete scan");
        println!("[ok] EICAR on disk -> MALICIOUS via host security provider (access blocked, os error 225)");
    } else {
        assert!(r.findings.iter().any(|f| f.source == "clamav" && f.kind == FindingKind::Signature), "ClamAV must flag EICAR: {:#?}", r.findings);
        assert!(r.findings.iter().any(|f| f.source == "builtin-eicar"));
        println!("[ok] EICAR on disk -> MALICIOUS (clamav: {})", r.findings.iter().find(|f| f.source == "clamav").unwrap().name);
    }

    // 3. EICAR hidden in a nested archive is still found, without ever extracting to disk.
    let inner = make_zip(&[("payload/e.com", &eicar_bytes())]);
    let outer = make_zip(&[("docs/readme.txt", b"hi"), ("inner.zip", &inner)]);
    let z = write(w, "invoice.zip", &outer);
    let r = scanner.scan_file(&z, &opts);
    assert_eq!(r.verdict, Verdict::Malicious, "{r:#?}");
    assert!(r.findings.iter().any(|f| f.location.as_deref().is_some_and(|l| l.contains("inner.zip!"))), "nested location expected: {:#?}", r.findings);
    println!("[ok] nested-zip EICAR -> MALICIOUS with location");

    // 4. Misleading extension: a PE renamed .jpg is identified by content and flagged.
    let p = write(w, "holiday.jpg", &mz_pe());
    let r = scanner.scan_file(&p, &opts);
    assert!(r.file.type_mismatch);
    assert!(r.file.detected_type.contains("Windows executable"), "{}", r.file.detected_type);
    assert!(matches!(r.verdict, Verdict::Suspicious), "{:?} / {:#?}", r.verdict, r.findings);
    println!("[ok] exe renamed .jpg -> SUSPICIOUS ({})", r.file.detected_type);

    // 5. Corrupt archive fails closed.
    let p = write(w, "broken.zip", b"PK\x03\x04this is not really a zip file at all");
    let r = scanner.scan_file(&p, &opts);
    assert_ne!(r.verdict, Verdict::Clean, "corrupt archive must never be clean: {r:#?}");
    println!("[ok] corrupt zip -> {:?}", r.verdict);

    // 6. Oversized file is not declared clean.
    let tiny = Scanner::new(Limits { max_scan_bytes: 100, max_analyze_bytes: 50, ..Limits::default() }, Some(clam.clone()));
    let p = write(w, "big.bin", &vec![7u8; 4096]);
    let r = tiny.scan_file(&p, &opts);
    assert_eq!(r.verdict, Verdict::UnableToVerify, "{r:#?}");
    assert!(!r.complete);
    println!("[ok] over-limit file -> UNABLE TO VERIFY");

    // 7. Cancellation produces an incomplete, non-clean result.
    let cancel_opts = ScanOptions { use_cache: false, ..Default::default() };
    cancel_opts.cancel.store(true, Ordering::Relaxed);
    let p = write(w, "late.txt", b"x");
    let r = scanner.scan_file(&p, &cancel_opts);
    assert_ne!(r.verdict, Verdict::Clean);
    assert!(!r.complete);
    println!("[ok] cancelled scan -> {:?}, complete=false", r.verdict);

    // 8. Cache: same content + engine versions -> cached; changed content -> rescanned.
    let cached = ScanOptions::default();
    let p = write(w, "cache.txt", b"stable content");
    let a = scanner.scan_file(&p, &cached);
    let b = scanner.scan_file(&p, &cached);
    assert!(!a.cached && b.cached, "second scan of unchanged file must hit cache");
    std::fs::write(&p, b"changed content").unwrap();
    let c = scanner.scan_file(&p, &cached);
    assert!(!c.cached && c.file.sha256 != a.file.sha256, "changed file must be rescanned");
    println!("[ok] cache hit on unchanged file, miss after modification");

    // 9. Engine crash recovery: kill clamd; the next scan restarts it instead of reporting a false clean.
    clam.stop();
    assert!(clam.ping().is_err());
    let r = scanner.scan_file(&p, &opts);
    assert_eq!(r.verdict, Verdict::Clean, "engine should auto-restart: {:#?}", r.checks);
    println!("[ok] engine killed -> auto-restarted -> scan completed");

    // 10. Detect -> quarantine -> restore workflow on a real detection.
    //     The EICAR-carrying zip is used so host real-time AV does not block the file we need to read.
    let z2 = write(w, "attachment.zip", &make_zip(&[("eicar.com", &eicar_bytes())]));
    let r = scanner.scan_file(&z2, &opts);
    assert_eq!(r.verdict, Verdict::Malicious, "{r:#?}");
    let q = Quarantine::open(w.join("vault")).unwrap();
    let rec = q.quarantine(&z2, Some(&r.file.sha256), r.verdict, &r.summary, &r.file.detected_type).unwrap();
    assert!(!z2.exists(), "original must be gone after quarantine");
    let out = w.join("restored");
    std::fs::create_dir(&out).unwrap();
    let denied = q.restore(&rec.id.to_string(), &out, RestoreOptions { confirm_malicious: false, allow_suspicious: true });
    assert!(denied.is_err(), "restoring MALICIOUS without confirmation must fail");
    println!("[ok] detected archive quarantined, original removed, unconfirmed restore denied");
    // A confirmed restore re-creates the EICAR zip and may trigger host AV; round-trips are covered by the
    // quarantine unit tests with benign data.

    // 11. Folder scan reports what it could not scan instead of claiming completeness.
    let folder = w.join("folder");
    std::fs::create_dir(&folder).unwrap();
    write(&folder, "one.txt", b"1");
    write(&folder, "two.txt", b"2");
    let batch = scanner.scan_paths(&[folder.clone()], &opts, 2, &|_| {}, &|_| {});
    assert_eq!(batch.reports.len(), 2);
    assert!(batch.complete);
    #[cfg(windows)]
    {
        let real = w.join("elsewhere");
        std::fs::create_dir(&real).unwrap();
        write(&real, "hidden.txt", b"x");
        let st = std::process::Command::new("cmd").args(["/C", "mklink", "/J"]).arg(folder.join("jct")).arg(&real).output().unwrap();
        assert!(st.status.success());
        let batch = scanner.scan_paths(&[folder.clone()], &opts, 2, &|_| {}, &|_| {});
        assert_eq!(batch.reports.len(), 2, "junction target must not be followed");
        assert!(!batch.complete && batch.skipped.len() == 1, "{:?}", batch.skipped);
        println!("[ok] junction skipped and reported; batch marked incomplete");
    }

    scanner.clam().unwrap().stop();
}

#[test]
fn without_an_engine_nothing_is_ever_clean() {
    let scanner = Scanner::new(Limits::default(), None);
    let d = tempfile::tempdir().unwrap();
    let p = write(d.path(), "a.txt", b"harmless");
    let r = scanner.scan_file(&p, &ScanOptions::default());
    assert_eq!(r.verdict, Verdict::UnableToVerify);
    assert!(!r.complete);
    assert_eq!(scanner.engine_status().state, "unavailable");
}
