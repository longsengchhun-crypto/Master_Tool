//! Shared data model. Serialised verbatim to the UI, to exported reports, and (hashes only) to the control plane.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Ordered by severity so the aggregate verdict can use `max`-style reasoning where appropriate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    Pending,
    UnableToVerify,
    Clean,
    Suspicious,
    Malicious,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Pending => "PENDING",
            Verdict::UnableToVerify => "UNABLE TO VERIFY",
            Verdict::Clean => "CLEAN",
            Verdict::Suspicious => "SUSPICIOUS",
            Verdict::Malicious => "MALICIOUS",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    /// Ran to completion.
    Completed,
    /// Does not apply to this file type (distinct from "could not run").
    NotApplicable,
    /// The engine or capability is not present/configured on this machine.
    Unavailable,
    /// Ran but errored (I/O error, parser failure, timeout).
    Failed,
    /// Ran but hit a resource limit, so coverage is partial.
    Incomplete,
}

impl CheckStatus {
    /// A status that prevents a CLEAN verdict when the check was required.
    pub fn is_gap(self) -> bool {
        matches!(self, CheckStatus::Unavailable | CheckStatus::Failed | CheckStatus::Incomplete)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Check {
    pub id: String,
    pub name: String,
    pub status: CheckStatus,
    pub engine_version: Option<String>,
    pub note: Option<String>,
    /// The failure is likely temporary (locked file, engine not running) so the queue may retry it later.
    /// Structural problems (corrupt or oversized files, unsupported formats) are never retryable.
    #[serde(default)]
    pub retryable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    /// Documented heuristic weights; see docs/DETECTION.md. Not a calibrated probability.
    pub fn weight(self) -> u32 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 3,
            Severity::High => 5,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// A malware-signature engine matched.
    Signature,
    /// Static heuristic evidence (never proof on its own).
    Heuristic,
    /// Digital-signature / integrity observation.
    Integrity,
    /// Coverage problem surfaced as a finding (e.g. encrypted archive).
    Coverage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Detecting engine or analyzer id, e.g. "clamav", "builtin-eicar", "heuristic.pe".
    pub source: String,
    pub engine_version: Option<String>,
    pub name: String,
    pub kind: FindingKind,
    pub severity: Severity,
    /// Human-readable evidence. Never contains file contents beyond short indicators.
    pub evidence: String,
    /// Path inside an archive, if the finding concerns a nested entry.
    pub location: Option<String>,
    pub detected_at: DateTime<Utc>,
    /// The threat family this behaviour belongs to (see `threat_kb`), when the rule that found it knows one.
    #[serde(default)]
    pub family: Option<String>,
    /// MITRE ATT&CK technique ids for the behaviour (reference labels, not proof it happened).
    #[serde(default)]
    pub attack: Vec<String>,
}

impl Finding {
    pub fn new(source: &str, name: &str, kind: FindingKind, severity: Severity, evidence: impl Into<String>) -> Self {
        Finding {
            source: source.to_string(),
            engine_version: None,
            name: name.to_string(),
            kind,
            severity,
            evidence: evidence.into(),
            location: None,
            detected_at: Utc::now(),
            family: None,
            attack: Vec::new(),
        }
    }
    pub fn with_family(mut self, family: &str, attack: &[&str]) -> Self {
        self.family = Some(family.to_string());
        self.attack = attack.iter().map(|a| a.to_string()).collect();
        self
    }
    pub fn at(mut self, loc: impl Into<String>) -> Self {
        self.location = Some(loc.into());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInfo {
    /// "signed_trusted" | "signed_untrusted" | "signed_invalid" | "unsigned" | "unknown"
    pub state: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub path: PathBuf,
    pub name: String,
    pub size: u64,
    pub sha256: String,
    pub detected_type: String,
    pub declared_extension: Option<String>,
    pub type_mismatch: bool,
    pub signature: Option<SignatureInfo>,
    pub modified: Option<DateTime<Utc>>,
    /// Where the file came from, when Windows recorded it ("Mark of the Web"): host name and zone only, never the
    /// full URL (query strings can carry tokens). `None` when unknown.
    #[serde(default)]
    pub source: Option<String>,
}

/// A plain-language explanation of what kind of threat a file is, when it is one. See `threat_kb`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ThreatInfo {
    pub family: String,
    pub title: String,
    /// What the attacker wants.
    pub goal: String,
    /// How it usually reaches people.
    pub arrives_via: Vec<String>,
    pub attack: Vec<String>,
    pub advice: String,
    /// "identified": the malware engine named it. "suggested": behaviour resembles it; evidence, not proof.
    pub basis: String,
    /// Other families the behaviour also resembles.
    pub also: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub id: uuid::Uuid,
    pub file: FileInfo,
    pub verdict: Verdict,
    /// True only if every check that applies to this file completed.
    pub complete: bool,
    pub checks: Vec<Check>,
    pub findings: Vec<Finding>,
    pub summary: String,
    pub recommended_action: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub quarantined: bool,
    /// True only when the execution guard (a deny-execute ACL, see `guard.rs`) was applied AND read back successfully.
    /// SENTRIX has no kernel driver, so this is never claimed for any other reason.
    pub blocked: bool,
    pub cached: bool,
    /// What triggered the scan: "Telegram Desktop", "Downloads folder", "Browser download", "Custom folder",
    /// "Removable drive", "Telegram bot submission", "Telegram personal chat" / "Telegram group" / "Telegram channel" (account protection), "Manual scan". `None` for old reports.
    #[serde(default)]
    pub origin: Option<String>,
    /// What kind of threat this is and what it wants, in plain words. Only for findings that are one.
    #[serde(default)]
    pub threat: Option<ThreatInfo>,
}

/// Hard resource limits applied to every scan. Exceeding one yields `Incomplete`, never a clean verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Limits {
    /// Largest file loaded into memory for static analysis.
    pub max_analyze_bytes: u64,
    /// Largest file that is sent to the signature engine.
    pub max_scan_bytes: u64,
    pub archive_max_depth: u32,
    pub archive_max_entries: usize,
    /// Total bytes decompressed from one archive across all entries.
    pub archive_max_total_bytes: u64,
    pub archive_max_entry_bytes: u64,
    /// Per-entry compression ratio above which an entry is treated as a decompression bomb.
    pub archive_max_ratio: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_analyze_bytes: 128 * 1024 * 1024,
            max_scan_bytes: 512 * 1024 * 1024,
            archive_max_depth: 3,
            archive_max_entries: 10_000,
            archive_max_total_bytes: 256 * 1024 * 1024,
            archive_max_entry_bytes: 128 * 1024 * 1024,
            archive_max_ratio: 200,
        }
    }
}
