//! Verdict aggregation. These rules are the product's honesty contract (see docs/DETECTION.md):
//!
//!  1. MALICIOUS  only when a signature engine matched (ClamAV, or the EICAR test detector).
//!                Heuristics alone can never produce MALICIOUS.
//!  2. SUSPICIOUS when heuristic/integrity evidence reaches the documented score (>=3, or any High).
//!  3. CLEAN      only when a real signature engine (ClamAV) COMPLETED and no applicable check had a gap.
//!  4. otherwise  UNABLE_TO_VERIFY. A missing engine, partial coverage, parser failure, or cancellation
//!                can never be reported as clean.

use crate::types::{Check, CheckStatus, Finding, FindingKind, Severity, Verdict};

pub const SUSPICIOUS_SCORE: u32 = 3;

pub struct Decision {
    pub verdict: Verdict,
    pub complete: bool,
    pub summary: String,
    pub recommended_action: String,
}

pub fn heuristic_score(findings: &[Finding]) -> u32 {
    findings
        .iter()
        .filter(|f| matches!(f.kind, FindingKind::Heuristic | FindingKind::Integrity))
        .map(|f| f.severity.weight())
        .sum()
}

pub fn decide(checks: &[Check], findings: &[Finding]) -> Decision {
    let complete = !checks.iter().any(|c| c.status.is_gap());
    let signature_engine_ran = checks.iter().any(|c| c.id == "clamav" && c.status == CheckStatus::Completed);
    let malicious = findings.iter().any(|f| f.kind == FindingKind::Signature);
    let score = heuristic_score(findings);
    let suspicious = score >= SUSPICIOUS_SCORE || findings.iter().any(|f| f.severity == Severity::High && f.kind != FindingKind::Signature);

    let gaps: Vec<String> = checks
        .iter()
        .filter(|c| c.status.is_gap())
        .map(|c| match &c.note {
            Some(n) => format!("{}: {}", c.name, n),
            None => format!("{} could not be completed", c.name),
        })
        .collect();

    let (verdict, summary, action) = if malicious {
        let names: Vec<&str> = findings.iter().filter(|f| f.kind == FindingKind::Signature).map(|f| f.name.as_str()).collect();
        (
            Verdict::Malicious,
            format!("A malware detection engine identified this file as {}.", names.join(", ")),
            "Do not open this file. Quarantine it, then delete it if you do not need it. If you believe this is a mistake, keep it quarantined and check the source.".to_string(),
        )
    } else if suspicious {
        (
            Verdict::Suspicious,
            "This file contains indicators that deserve a closer look. They are not proof of malware; legitimate software can show the same traits.".to_string(),
            "Do not open this file until you have confirmed where it came from and that it is authentic. Quarantine it if you are unsure.".to_string(),
        )
    } else if !signature_engine_ran || !complete {
        let why = if !signature_engine_ran {
            "No malware-signature engine was available to check this file".to_string()
        } else {
            "The scan was only partial".to_string()
        };
        (
            Verdict::UnableToVerify,
            format!("{why}, so SENTRIX cannot say whether this file is safe."),
            "Treat the file with caution. Fix the issue listed under 'Checks not completed' (for example update protection) and scan again.".to_string(),
        )
    } else {
        (
            Verdict::Clean,
            "The checks that ran found no threat. This is not a guarantee: no scanner detects everything.".to_string(),
            "No action needed from this scan. Keep the file only if you trust its source.".to_string(),
        )
    };

    let mut summary = summary;
    if !gaps.is_empty() && verdict != Verdict::UnableToVerify {
        summary.push_str(" Some checks could not be completed; see details.");
    }
    Decision { verdict, complete, summary, recommended_action: action }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(id: &str, s: CheckStatus) -> Check {
        Check { id: id.into(), name: id.into(), status: s, engine_version: None, note: None, retryable: false }
    }
    fn heur(sev: Severity) -> Finding {
        Finding::new("heuristic.x", "x", FindingKind::Heuristic, sev, "e")
    }
    fn sig() -> Finding {
        Finding::new("clamav", "Win.Test.EICAR_HDB-1", FindingKind::Signature, Severity::High, "e")
    }

    #[test]
    fn clean_requires_signature_engine_completed() {
        let d = decide(&[check("clamav", CheckStatus::Completed), check("static", CheckStatus::Completed)], &[]);
        assert_eq!(d.verdict, Verdict::Clean);
        assert!(d.complete);
    }

    #[test]
    fn missing_engine_is_never_clean() {
        let d = decide(&[check("clamav", CheckStatus::Unavailable), check("static", CheckStatus::Completed)], &[]);
        assert_eq!(d.verdict, Verdict::UnableToVerify);
        assert!(!d.complete);
    }

    #[test]
    fn partial_scan_is_never_clean() {
        let d = decide(&[check("clamav", CheckStatus::Completed), check("archive", CheckStatus::Incomplete)], &[]);
        assert_eq!(d.verdict, Verdict::UnableToVerify);
    }

    #[test]
    fn not_applicable_does_not_block_clean() {
        let d = decide(&[check("clamav", CheckStatus::Completed), check("static", CheckStatus::NotApplicable)], &[]);
        assert_eq!(d.verdict, Verdict::Clean);
    }

    #[test]
    fn signature_match_is_malicious_even_if_incomplete() {
        let d = decide(&[check("clamav", CheckStatus::Unavailable)], &[sig()]);
        assert_eq!(d.verdict, Verdict::Malicious);
        assert!(!d.complete);
    }

    #[test]
    fn heuristics_alone_cap_at_suspicious() {
        let d = decide(&[check("clamav", CheckStatus::Completed)], &[heur(Severity::High), heur(Severity::High), heur(Severity::High)]);
        assert_eq!(d.verdict, Verdict::Suspicious);
    }

    #[test]
    fn low_signals_below_threshold_stay_clean() {
        let d = decide(&[check("clamav", CheckStatus::Completed)], &[heur(Severity::Low), heur(Severity::Low)]);
        assert_eq!(d.verdict, Verdict::Clean);
    }

    #[test]
    fn single_medium_is_suspicious() {
        let d = decide(&[check("clamav", CheckStatus::Completed)], &[heur(Severity::Medium)]);
        assert_eq!(d.verdict, Verdict::Suspicious);
    }
}
