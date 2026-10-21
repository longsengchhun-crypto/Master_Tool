//! Cross-component test: the REAL desktop portal client against the REAL console and database.
//! Driven in three phases by apps/admin/tests/desktop-e2e.test.ts (which owns the server, schema and admin actions).
//! All tests are #[ignore]d so they cannot silently pass without that harness.
//!
//!   SENTRIX_E2E_URL, SENTRIX_E2E_DIR (shared between phases), SENTRIX_E2E_CODE (phase 1 only)

use sentrix_desktop_lib::portal::Portal;
use serde_json::json;
use std::path::PathBuf;

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| panic!("{k} must be set by the harness"))
}
fn dir() -> PathBuf {
    PathBuf::from(env("SENTRIX_E2E_DIR"))
}
fn heartbeat() -> serde_json::Value {
    json!({
        "appVersion": "0.1.0",
        "engineVersion": "ClamAV 1.5.4",
        "intelVersion": "28159",
        "intelUpdatedAt": chrono::Utc::now().to_rfc3339(),
        "protection": { "engineState": "running", "realtimeState": "active", "detail": "from the rust e2e test" }
    })
}

#[test]
#[ignore = "driven by apps/admin/tests/desktop-e2e.test.ts"]
fn phase1_enroll() {
    let p = Portal::open(&dir());
    assert!(!p.is_enrolled());

    // A wrong code is refused with the console's generic message and leaves the device unenrolled.
    let bad = p.enroll(&env("SENTRIX_E2E_URL"), "SX-AAAA-BBBB-CCCC-DDDD", "E2E-PC", Some("windows"), "0.1.0");
    assert!(bad.is_err());
    assert!(!p.is_enrolled());

    // A plain-http, non-loopback console is refused before any network traffic.
    assert!(p.enroll("http://console.example.com", &env("SENTRIX_E2E_CODE"), "E2E-PC", None, "0.1.0").is_err());

    let policy = p.enroll(&env("SENTRIX_E2E_URL"), &env("SENTRIX_E2E_CODE"), "E2E-PC", Some("windows"), "0.1.0").expect("enroll should succeed");
    assert!(policy["autoQuarantine"].is_string(), "policy must come back from the console: {policy}");
    let s = p.status();
    assert!(s.enrolled);
    assert!(s.org_name.is_some());
    assert_eq!(s.license.as_ref().unwrap().state, "valid");

    // The same code cannot be used twice, even by the same client.
    let p2 = Portal::open(&tempfile::tempdir().unwrap().path().to_path_buf());
    assert!(p2.enroll(&env("SENTRIX_E2E_URL"), &env("SENTRIX_E2E_CODE"), "E2E-PC-2", None, "0.1.0").is_err());

    // Heartbeat works and returns no jobs yet.
    let sync = p.heartbeat(&heartbeat()).expect("heartbeat");
    assert!(sync.jobs.is_empty());

    // The credential is persisted protected, not in clear text.
    let raw = std::fs::read_to_string(dir().join("enrollment.json")).unwrap();
    assert!(!raw.contains("dev_"), "device token must not be stored in clear text");
}

#[test]
#[ignore = "driven by apps/admin/tests/desktop-e2e.test.ts"]
fn phase2_job_roundtrip_after_restart() {
    // A brand-new Portal over the same directory simulates an app restart: the credential must survive.
    let p = Portal::open(&dir());
    assert!(p.is_enrolled(), "enrollment must survive a restart");
    let sync = p.heartbeat(&heartbeat()).expect("heartbeat after restart");
    let kinds: Vec<&str> = sync.jobs.iter().map(|j| j.kind.as_str()).collect();
    assert_eq!(kinds, vec!["intel_update"], "the console-requested job must arrive exactly once");
    p.job_result(&sync.jobs[0].id, true, "ok-from-rust");
    p.report_scan("file", chrono::Utc::now(), 1, 0, true, &[]);
    p.event("engine_degraded", "warning", "reported by the e2e test");
    // Delivered jobs are not delivered again.
    assert!(p.heartbeat(&heartbeat()).unwrap().jobs.is_empty());
}

#[test]
#[ignore = "driven by apps/admin/tests/desktop-e2e.test.ts"]
fn phase3_revoked_device_is_dropped() {
    let p = Portal::open(&dir());
    assert!(p.is_enrolled());
    let err = p.heartbeat(&heartbeat()).expect_err("a revoked device must be told so");
    assert!(err.to_lowercase().contains("removed"), "{err}");
    assert!(!p.is_enrolled(), "the credential must be discarded locally");
    assert!(!dir().join("enrollment.json").exists());
    // And it stays that way after a restart.
    assert!(!Portal::open(&dir()).is_enrolled());
}
