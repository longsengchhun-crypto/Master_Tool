//! Plain-language report rendering. Only states what actually ran; checks that did not run are listed as such.

use crate::types::*;
use std::fmt::Write;

fn status_word(s: CheckStatus) -> &'static str {
    match s {
        CheckStatus::Completed => "completed",
        CheckStatus::NotApplicable => "not applicable to this file type",
        CheckStatus::Unavailable => "NOT AVAILABLE",
        CheckStatus::Failed => "FAILED",
        CheckStatus::Incomplete => "PARTIAL",
    }
}

fn sev_word(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
    }
}

pub fn to_text(r: &ScanReport) -> String {
    let mut o = String::new();
    let _ = writeln!(o, "SENTRIX FILE SECURITY REPORT");
    let _ = writeln!(o, "============================");
    let _ = writeln!(o, "File:        {}", r.file.name);
    let _ = writeln!(o, "Location:    {}", r.file.path.display());
    let _ = writeln!(o, "Type:        {}", r.file.detected_type);
    let _ = writeln!(o, "Size:        {} bytes", r.file.size);
    let _ = writeln!(o, "SHA-256:     {}", if r.file.sha256.is_empty() { "(file could not be read)" } else { &r.file.sha256 });
    let _ = writeln!(o, "Scanned:     {}", r.finished_at.to_rfc3339());
    let _ = writeln!(o, "Verdict:     {}", r.verdict.label());
    let _ = writeln!(o, "Scan status: {}", if r.complete { "complete" } else { "INCOMPLETE (see checks below)" });
    if r.cached {
        let _ = writeln!(o, "Note:        reused a previous result for identical content and engine versions");
    }
    let _ = writeln!(o, "Quarantined: {}", if r.quarantined { "yes" } else { "no" });
    let _ = writeln!(o, "Blocked:     {}", if r.blocked { "yes" } else { "no (SENTRIX scans and warns; it does not enforce execution blocking)" });
    let _ = writeln!(o);
    let _ = writeln!(o, "What this means");
    let _ = writeln!(o, "  {}", r.summary);
    let _ = writeln!(o);
    let _ = writeln!(o, "Recommended action");
    let _ = writeln!(o, "  {}", r.recommended_action);
    if r.file.type_mismatch {
        let _ = writeln!(o);
        let _ = writeln!(o, "Name check: the file name's extension does not match what the file actually is.");
    }
    let _ = writeln!(o);
    let _ = writeln!(o, "What we checked");
    for c in &r.checks {
        let ver = c.engine_version.as_deref().map(|v| format!(" [{v}]")).unwrap_or_default();
        let note = c.note.as_deref().map(|n| format!(" - {n}")).unwrap_or_default();
        let _ = writeln!(o, "  - {}{}: {}{}", c.name, ver, status_word(c.status), note);
    }
    if !r.findings.is_empty() {
        let _ = writeln!(o);
        let _ = writeln!(o, "Findings");
        for f in &r.findings {
            let loc = f.location.as_deref().map(|l| format!(" in {l}")).unwrap_or_default();
            let _ = writeln!(o, "  - [{}] {}{}", sev_word(f.severity), f.name, loc);
            let _ = writeln!(o, "      source: {}{}", f.source, f.engine_version.as_deref().map(|v| format!(" ({v})")).unwrap_or_default());
            let _ = writeln!(o, "      {}", f.evidence);
        }
    }
    let _ = writeln!(o);
    let _ = writeln!(o, "A CLEAN result means the checks that ran found nothing; it is not a guarantee of safety.");
    o
}

pub fn to_json(r: &ScanReport) -> String {
    serde_json::to_string_pretty(r).unwrap_or_else(|_| "{}".into())
}
