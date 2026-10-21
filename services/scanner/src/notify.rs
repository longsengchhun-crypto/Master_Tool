//! Turning scan results into Telegram reports, and delivering them reliably.
//!
//! Rules (tested):
//!  * every field comes from the real `ScanReport`; unavailable values are omitted, never invented;
//!  * an incomplete scan is never reported as CLEAN;
//!  * the user's notification preferences decide what is sent;
//!  * one report per (kind, file hash, day): repeated filesystem events cannot spam the user;
//!  * delivery problems affect only the outbox: they can never change a verdict or stop protection.

use crate::queue::{now_ms, JobStore, Retry};
use crate::telegram::{esc, safe_display_name, BotClient, TgError};
use crate::types::{CheckStatus, FindingKind, ScanReport, Severity, Verdict};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct NotifyPrefs {
    pub malicious: bool,
    pub suspicious: bool,
    pub unable_to_verify: bool,
    /// Completed, clean scans. Off by default: it is noisy.
    pub clean_scans: bool,
    pub quarantined: bool,
    pub engine_problems: bool,
    pub protection_stopped: bool,
    pub account_events: bool,
    pub include_hash: bool,
}

impl Default for NotifyPrefs {
    fn default() -> Self {
        NotifyPrefs { malicious: true, suspicious: true, unable_to_verify: false, clean_scans: false, quarantined: true, engine_problems: true, protection_stopped: true, account_events: true, include_hash: true }
    }
}

/// One message ready for the outbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    pub kind: String,
    pub dedupe_key: String,
    pub text: String,
}

fn day_bucket(ms: i64) -> i64 {
    ms / 86_400_000
}

/// What happened to the file as a result of this scan, in plain words (only real actions are named).
pub fn action_text(r: &ScanReport) -> String {
    match (r.quarantined, r.blocked) {
        (true, _) => "Moved to SENTRIX quarantine".into(),
        (false, true) => "Execution blocked by SENTRIX (the file was left in place)".into(),
        _ => "No automatic action was taken".into(),
    }
}

fn recommendation(r: &ScanReport) -> &'static str {
    match r.verdict {
        Verdict::Malicious => "Do not open or run this file. Review it in SENTRIX.",
        Verdict::Suspicious => "Do not open this file until you have verified where it came from. Review it in SENTRIX.",
        Verdict::UnableToVerify => "SENTRIX could not finish checking this file, so it is not known to be safe. Treat it with caution.",
        Verdict::Clean => "No threat was found by the checks that ran. This is not a guarantee of safety.",
        Verdict::Pending => "The scan is still running.",
    }
}

fn detection_text(r: &ScanReport) -> Option<String> {
    let sig: Vec<&str> = r.findings.iter().filter(|f| f.kind == FindingKind::Signature).map(|f| f.name.as_str()).collect();
    if !sig.is_empty() {
        return Some(sig.join(", "));
    }
    match r.verdict {
        Verdict::Suspicious => {
            let mut f: Vec<&crate::types::Finding> = r.findings.iter().filter(|f| f.severity >= Severity::Medium && f.kind != FindingKind::Coverage).collect();
            f.sort_by(|a, b| b.severity.cmp(&a.severity));
            let names: Vec<&str> = f.iter().take(3).map(|f| f.name.as_str()).collect();
            (!names.is_empty()).then(|| names.join("; "))
        }
        Verdict::UnableToVerify => r.checks.iter().find(|c| c.status.is_gap()).map(|c| format!("{}: {}", c.name, c.note.clone().unwrap_or_else(|| "could not be completed".into()))),
        _ => None,
    }
}

/// Decide whether this scan result produces a report under `prefs`, and build it. `now` is only used for the daily
/// de-duplication bucket.
pub fn format_report(r: &ScanReport, prefs: &NotifyPrefs, now: i64) -> Option<Outgoing> {
    let (kind, wanted): (&'static str, bool) = match r.verdict {
        Verdict::Malicious => ("malicious", prefs.malicious || (r.quarantined && prefs.quarantined)),
        Verdict::Suspicious => ("suspicious", prefs.suspicious || (r.quarantined && prefs.quarantined)),
        Verdict::UnableToVerify => ("unable_to_verify", prefs.unable_to_verify),
        // Never report an incomplete scan as clean, even if some code path produced Clean + incomplete.
        Verdict::Clean => ("clean", prefs.clean_scans && r.complete),
        Verdict::Pending => return None,
    };
    if !wanted {
        return None;
    }

    let mut t = String::from("<b>SENTRIX SECURITY REPORT</b>\n\n");
    t.push_str(&format!("<b>Status:</b> {}\n", r.verdict.label()));
    t.push_str(&format!("<b>File:</b> {}\n", safe_display_name(&r.file.name)));
    if let Some(o) = &r.origin {
        t.push_str(&format!("<b>Source:</b> {}\n", esc(o)));
    }
    if let Some(d) = detection_text(r) {
        t.push_str(&format!("<b>{}:</b> {}\n", if r.verdict == Verdict::UnableToVerify { "Reason" } else { "Detection" }, esc(&d.chars().take(300).collect::<String>())));
    }
    t.push_str(&format!("<b>Scan time:</b> {}\n", r.finished_at.format("%Y-%m-%d %H:%M UTC")));
    if !r.complete && r.verdict != Verdict::UnableToVerify {
        t.push_str("<b>Scan status:</b> Incomplete (some checks could not run)\n");
    }
    t.push_str(&format!("<b>Action:</b> {}\n", action_text(r)));
    if prefs.include_hash && !r.file.sha256.is_empty() {
        t.push_str(&format!("<b>SHA-256:</b> <code>{}</code>\n", r.file.sha256));
    }
    t.push_str(&format!("\n<b>Recommendation:</b> {}", recommendation(r)));

    let ident = if r.file.sha256.is_empty() { format!("path:{}", r.file.path.display()) } else { r.file.sha256.clone() };
    Some(Outgoing { kind: kind.to_string(), dedupe_key: format!("scan:{kind}:{ident}:{}", day_bucket(now)), text: t })
}

/// Health/system messages. De-duplicated per kind over a window so a flapping engine cannot flood the chat.
pub fn format_system(kind: &'static str, detail: &str, prefs: &NotifyPrefs, now: i64) -> Option<Outgoing> {
    let (title, wanted, window_ms): (&str, bool, i64) = match kind {
        "engine_unavailable" => ("Antivirus engine unavailable", prefs.engine_problems, 6 * 3_600_000),
        "signatures_outdated" => ("Signature database is outdated", prefs.engine_problems, 24 * 3_600_000),
        "protection_stopped" => ("Real-time protection stopped", prefs.protection_stopped, 3_600_000),
        "protection_restored" => ("Protection restored", prefs.protection_stopped, 3_600_000),
        "account_expired" => ("Telegram account authorization expired", prefs.account_events, 24 * 3_600_000),
        "test" => ("Connection test", true, 1),
        _ => return None,
    };
    if !wanted {
        return None;
    }
    let text = format!("<b>SENTRIX NOTICE</b>\n\n<b>{}</b>\n{}", esc(title), esc(&detail.chars().take(500).collect::<String>()));
    Some(Outgoing { kind: kind.to_string(), dedupe_key: format!("sys:{kind}:{}", now / window_ms.max(1)), text })
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct Delivery {
    pub sent: usize,
    pub retrying: usize,
    pub dead: usize,
}

/// Send what is due. Never panics and never touches scan state. `min_gap` paces sends (Telegram allows about one
/// message per second to a single chat). Stops early on a rate-limit so we do not hammer a 429.
pub fn deliver_due(store: &JobStore, client: &BotClient, chat_id: i64, max: usize, min_gap: Duration) -> Delivery {
    deliver_due_at(store, client, chat_id, max, min_gap, now_ms())
}

/// `deliver_due` with an explicit clock, so retry/backoff behaviour is testable without waiting.
pub fn deliver_due_at(store: &JobStore, client: &BotClient, chat_id: i64, max: usize, min_gap: Duration, now: i64) -> Delivery {
    let mut d = Delivery::default();
    let due = match store.claim_notifications(now, max) {
        Ok(v) => v,
        Err(_) => return d,
    };
    for (i, n) in due.iter().enumerate() {
        if i > 0 && !min_gap.is_zero() {
            std::thread::sleep(min_gap);
        }
        match client.send_message(chat_id, &n.text) {
            Ok(_) => {
                let _ = store.notification_sent(&n.id, now);
                d.sent += 1;
            }
            Err(e) => {
                let msg = e.to_string(); // already redacted by the client
                if e.is_retryable() {
                    match store.notification_failed(&n.id, &msg, e.retry_after_ms(), now) {
                        Ok(Retry::GaveUp) => {
                            d.dead += 1;
                            store.add_event("telegram_delivery", "warning", "A Telegram report could not be delivered after repeated attempts.", now);
                        }
                        _ => d.retrying += 1,
                    }
                    if matches!(e, TgError::Api { code: 429, .. }) {
                        break;
                    }
                } else {
                    let _ = store.notification_dead(&n.id, &msg, now);
                    store.add_event("telegram_delivery", "warning", &format!("Telegram refused a report: {}", e.user_message()), now);
                    d.dead += 1;
                }
            }
        }
    }
    d
}

/// Count of check gaps, used by callers deciding whether a "could not verify" message is warranted.
pub fn has_gap(r: &ScanReport) -> bool {
    r.checks.iter().any(|c| matches!(c.status, CheckStatus::Unavailable | CheckStatus::Failed | CheckStatus::Incomplete))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use chrono::Utc;
    use std::path::PathBuf;

    fn report(verdict: Verdict, complete: bool) -> ScanReport {
        ScanReport {
            id: uuid::Uuid::new_v4(),
            file: FileInfo { path: PathBuf::from("C:\\Users\\a\\Downloads\\bad<1>.exe"), name: "bad<1>.exe".into(), size: 10, sha256: "ab".repeat(32), detected_type: "PE".into(), declared_extension: Some("exe".into()), type_mismatch: false, signature: None, modified: None, source: None },
            verdict,
            complete,
            checks: vec![],
            findings: vec![],
            summary: String::new(),
            recommended_action: String::new(),
            started_at: Utc::now(),
            finished_at: Utc::now(),
            quarantined: false,
            blocked: false,
            cached: false,
            origin: Some("Telegram Desktop".into()),
        }
    }
    fn sig(name: &str) -> Finding {
        Finding::new("clamav", name, FindingKind::Signature, Severity::High, "e")
    }

    #[test]
    fn malicious_report_contains_only_real_fields() {
        let mut r = report(Verdict::Malicious, true);
        r.findings.push(sig("Win.Test.EICAR_HDB-1"));
        r.quarantined = true;
        let o = format_report(&r, &NotifyPrefs::default(), 0).unwrap();
        assert_eq!(o.kind, "malicious");
        for must in ["SENTRIX SECURITY REPORT", "Status:</b> MALICIOUS", "Source:</b> Telegram Desktop", "Detection:</b> Win.Test.EICAR_HDB-1", "Moved to SENTRIX quarantine", &"ab".repeat(32), "Do not open or run this file"] {
            assert!(o.text.contains(must), "missing {must:?} in:\n{}", o.text);
        }
        assert!(o.text.contains("bad&lt;1&gt;.exe"), "file name must be HTML-escaped");
        assert!(!o.text.contains("bad<1>"));
    }

    #[test]
    fn unavailable_values_are_omitted_not_invented() {
        let mut r = report(Verdict::Malicious, true);
        r.findings.push(sig("X"));
        r.origin = None;
        r.file.sha256 = String::new();
        let t = format_report(&r, &NotifyPrefs::default(), 0).unwrap().text;
        assert!(!t.contains("Source:") && !t.contains("SHA-256:"), "{t}");
        assert!(t.contains("No automatic action was taken"));
    }

    #[test]
    fn clean_is_never_reported_for_an_incomplete_scan() {
        let prefs = NotifyPrefs { clean_scans: true, ..Default::default() };
        assert!(format_report(&report(Verdict::Clean, false), &prefs, 0).is_none(), "incomplete + clean must stay silent");
        assert!(format_report(&report(Verdict::Clean, true), &prefs, 0).is_some());
        assert!(format_report(&report(Verdict::Clean, true), &NotifyPrefs::default(), 0).is_none(), "clean reports are opt-in");
    }

    #[test]
    fn unable_to_verify_says_why_and_is_opt_in() {
        let mut r = report(Verdict::UnableToVerify, false);
        r.checks.push(Check { id: "clamav".into(), name: "Malware signatures (ClamAV)".into(), status: CheckStatus::Unavailable, engine_version: None, note: Some("ClamAV is not installed".into()), retryable: true });
        assert!(format_report(&r, &NotifyPrefs::default(), 0).is_none());
        let t = format_report(&r, &NotifyPrefs { unable_to_verify: true, ..Default::default() }, 0).unwrap().text;
        assert!(t.contains("Reason:</b> Malware signatures (ClamAV): ClamAV is not installed"), "{t}");
        assert!(t.contains("not known to be safe"));
    }

    #[test]
    fn preferences_control_what_is_sent() {
        let mut r = report(Verdict::Suspicious, true);
        r.findings.push(Finding::new("heuristic.pe", "Process-injection API combination", FindingKind::Heuristic, Severity::Medium, "e"));
        assert!(format_report(&r, &NotifyPrefs::default(), 0).unwrap().text.contains("Process-injection API combination"));
        assert!(format_report(&r, &NotifyPrefs { suspicious: false, ..Default::default() }, 0).is_none());
        // A quarantined suspicious file still reports if the user wants quarantine notices.
        r.quarantined = true;
        assert!(format_report(&r, &NotifyPrefs { suspicious: false, quarantined: true, ..Default::default() }, 0).is_some());
        assert!(format_report(&r, &NotifyPrefs { suspicious: false, quarantined: false, ..Default::default() }, 0).is_none());
        assert!(format_report(&report(Verdict::Pending, false), &NotifyPrefs::default(), 0).is_none());
    }

    #[test]
    fn hash_can_be_left_out() {
        let mut r = report(Verdict::Malicious, true);
        r.findings.push(sig("X"));
        let t = format_report(&r, &NotifyPrefs { include_hash: false, ..Default::default() }, 0).unwrap().text;
        assert!(!t.contains(&"ab".repeat(32)));
    }

    #[test]
    fn same_file_same_day_dedupes_but_a_new_day_or_new_content_does_not() {
        let mut r = report(Verdict::Malicious, true);
        r.findings.push(sig("X"));
        let p = NotifyPrefs::default();
        let a = format_report(&r, &p, 1_000).unwrap().dedupe_key;
        assert_eq!(a, format_report(&r, &p, 5_000_000).unwrap().dedupe_key);
        assert_ne!(a, format_report(&r, &p, 3 * 86_400_000).unwrap().dedupe_key);
        r.file.sha256 = "cd".repeat(32);
        assert_ne!(a, format_report(&r, &p, 1_000).unwrap().dedupe_key);
    }

    #[test]
    fn spoofed_names_cannot_reach_the_message() {
        let mut r = report(Verdict::Malicious, true);
        r.findings.push(sig("X"));
        r.file.name = "photo\u{202E}gpj.exe".into();
        assert!(!format_report(&r, &NotifyPrefs::default(), 0).unwrap().text.contains('\u{202E}'));
    }

    #[test]
    fn system_notices_respect_preferences_and_dedupe_windows() {
        let p = NotifyPrefs::default();
        let a = format_system("engine_unavailable", "ClamAV is not installed.", &p, 0).unwrap();
        let b = format_system("engine_unavailable", "ClamAV is not installed.", &p, 3_600_000).unwrap();
        assert_eq!(a.dedupe_key, b.dedupe_key, "within the 6 h window");
        assert_ne!(a.dedupe_key, format_system("engine_unavailable", "x", &p, 7 * 3_600_000).unwrap().dedupe_key);
        assert!(format_system("engine_unavailable", "x", &NotifyPrefs { engine_problems: false, ..Default::default() }, 0).is_none());
        assert!(format_system("nonsense", "x", &p, 0).is_none());
    }

    #[test]
    fn long_text_is_truncated_to_telegrams_limit_by_the_client_not_here() {
        let mut r = report(Verdict::UnableToVerify, false);
        r.checks.push(Check { id: "x".into(), name: "n".into(), status: CheckStatus::Failed, engine_version: None, note: Some("y".repeat(5000)), retryable: false });
        let t = format_report(&r, &NotifyPrefs { unable_to_verify: true, ..Default::default() }, 0).unwrap().text;
        assert!(t.chars().count() < crate::telegram::MAX_MESSAGE_CHARS, "{}", t.chars().count());
    }
}
