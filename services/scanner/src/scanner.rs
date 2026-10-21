//! Scan orchestration: identify â†’ hash â†’ signature check â†’ signature engine â†’ static analysis â†’ archive
//! inspection â†’ verdict. The file is opened once and every layer reads from that handle, so a file swapped on disk
//! mid-scan cannot make different layers inspect different content.

use crate::archive;
use crate::clamav::{classify_signature, ClamClass, ClamEngine, ClamError, ClamOutcome};
use crate::eicar;
use crate::heuristics;
use crate::identify::{self, FileKind};
use crate::signature;
use crate::types::*;
use crate::verdict;
use crate::ENGINE_VERSION;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, UNIX_EPOCH};

#[derive(Clone)]
pub struct ScanOptions {
    pub cancel: Arc<AtomicBool>,
    /// Reuse a prior result when the same content was scanned with the same engine + signature versions.
    pub use_cache: bool,
    /// Folders skipped silently during folder walks (SENTRIX's own data). Intentional, so not counted as a gap.
    pub exclude: Vec<PathBuf>,
    /// Memory bound for batch scans: once more than this many reports accumulate, clean complete ones are dropped
    /// from the returned list (they are still counted).
    pub max_retained_reports: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions { cancel: Arc::new(AtomicBool::new(false)), use_cache: true, exclude: Vec::new(), max_retained_reports: 500 }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Progress {
    pub done: usize,
    /// Files found so far. Discovery runs concurrently with scanning, so this grows until `discovering` is false.
    pub discovered: usize,
    pub discovering: bool,
    pub current: PathBuf,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct BatchCounts {
    pub total: usize,
    pub clean: usize,
    pub suspicious: usize,
    pub malicious: usize,
    pub unable_to_verify: usize,
    /// Reports whose scan was not complete (any verdict).
    pub incomplete: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BatchResult {
    /// All reports for small batches; for large batches only those that are not "clean and complete".
    pub reports: Vec<ScanReport>,
    pub reports_truncated: bool,
    pub counts: BatchCounts,
    /// Items that were not scanned at all (links, unreadable folders), capped for display. Any item makes the batch incomplete.
    pub skipped: Vec<(PathBuf, String)>,
    pub skipped_total: usize,
    pub complete: bool,
    pub cancelled: bool,
}

const MAX_SKIPPED_KEPT: usize = 1000;
const MAX_FLAGGED_KEPT: usize = 5000;

#[derive(Default)]
struct Acc {
    reports: Vec<ScanReport>,
    truncated: bool,
    counts: BatchCounts,
    skipped: Vec<(PathBuf, String)>,
    skipped_total: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct EngineStatus {
    pub core_version: String,
    pub clamav_installed: bool,
    pub clamav_database_present: bool,
    pub clamav_running: bool,
    pub clamav_version: Option<String>,
    pub database_age_hours: Option<u64>,
    /// "running" | "degraded" | "stopped" | "unavailable"
    pub state: String,
    pub detail: String,
}

pub struct Scanner {
    limits: RwLock<Limits>,
    max_intel_age_hours: std::sync::atomic::AtomicU64,
    clam: Option<Arc<ClamEngine>>,
    start_lock: Mutex<()>,
    cache: Mutex<HashMap<String, ScanReport>>,
    stat_cache: Mutex<HashMap<(PathBuf, u64, i64), String>>,
    version_cache: Mutex<Option<(Option<String>, Instant)>>,
}

impl Scanner {
    pub fn new(limits: Limits, clam: Option<Arc<ClamEngine>>) -> Self {
        Scanner {
            limits: RwLock::new(limits),
            max_intel_age_hours: std::sync::atomic::AtomicU64::new(72),
            clam,
            start_lock: Mutex::new(()),
            cache: Mutex::new(HashMap::new()),
            stat_cache: Mutex::new(HashMap::new()),
            version_cache: Mutex::new(None),
        }
    }

    pub fn limits(&self) -> Limits {
        self.limits.read().unwrap().clone()
    }

    /// Limits apply to scans that start after this call; cached results from older limits stay valid only for the same content.
    pub fn set_limits(&self, l: Limits) {
        *self.limits.write().unwrap() = l;
        self.cache.lock().unwrap().clear();
    }

    /// How old the signature database may be before protection is reported as degraded (default 72 h).
    pub fn set_max_intel_age_hours(&self, h: u64) {
        self.max_intel_age_hours.store(h.clamp(1, 24 * 90), Ordering::Relaxed);
    }

    pub fn clam(&self) -> Option<&Arc<ClamEngine>> {
        self.clam.as_ref()
    }

    pub fn clear_cache(&self) {
        self.cache.lock().unwrap().clear();
        self.stat_cache.lock().unwrap().clear();
        *self.version_cache.lock().unwrap() = None;
    }

    /// Honest, real-time view of the signature engine for the dashboard.
    pub fn engine_status(&self) -> EngineStatus {
        let core_version = ENGINE_VERSION.to_string();
        let Some(c) = &self.clam else {
            return EngineStatus { core_version, clamav_installed: false, clamav_database_present: false, clamav_running: false, clamav_version: None, database_age_hours: None, state: "unavailable".into(), detail: "No malware-signature engine is configured. Files can be inspected but cannot be declared clean.".into() };
        };
        let installed = c.is_installed();
        let db = c.has_database();
        let running = c.ping().is_ok();
        let version = if running { c.version().ok() } else { None };
        let age = c.database_age().map(|d| d.as_secs() / 3600);
        let (state, detail) = if !installed {
            ("unavailable", "ClamAV is not installed. Install the bundled engine or set its location in Settings.".to_string())
        } else if !db {
            ("unavailable", "No signature database yet. Run a protection update.".to_string())
        } else if !running {
            ("stopped", "The detection engine is not running. It will be restarted on the next scan.".to_string())
        } else if age.map_or(true, |h| h > self.max_intel_age_hours.load(Ordering::Relaxed)) {
            ("degraded", format!("Signatures are {} hours old. Update protection.", age.map(|h| h.to_string()).unwrap_or_else(|| "?".into())))
        } else {
            ("running", "Detection engine is running with current signatures.".to_string())
        };
        EngineStatus { core_version, clamav_installed: installed, clamav_database_present: db, clamav_running: running, clamav_version: version, database_age_hours: age, state: state.into(), detail }
    }

    fn clam_version(&self) -> Option<String> {
        let c = self.clam.as_ref()?;
        {
            let g = self.version_cache.lock().unwrap();
            if let Some((v, at)) = g.as_ref() {
                if at.elapsed() < Duration::from_secs(60) && v.is_some() {
                    return v.clone();
                }
            }
        }
        let v = c.version().ok();
        *self.version_cache.lock().unwrap() = Some((v.clone(), Instant::now()));
        v
    }

    /// Restart-on-demand so an engine crash degrades one scan at worst.
    fn ensure_clam(&self) -> Result<&Arc<ClamEngine>, ClamError> {
        let c = self.clam.as_ref().ok_or(ClamError::NotInstalled)?;
        if c.ping().is_ok() {
            return Ok(c);
        }
        let _g = self.start_lock.lock().unwrap();
        if c.ping().is_ok() {
            return Ok(c);
        }
        c.start()?;
        Ok(c)
    }

    pub fn scan_file(&self, path: &Path, opts: &ScanOptions) -> ScanReport {
        let limits = self.limits();
        let started = Utc::now();
        let name = path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| path.to_string_lossy().into_owned());
        let ext = identify::extension_of(&name);
        let mut checks: Vec<Check> = Vec::new();
        let mut findings: Vec<Finding> = Vec::new();
        let cancelled = || opts.cancel.load(Ordering::Relaxed);

        let mut info = FileInfo {
            path: path.to_path_buf(),
            name: name.clone(),
            size: 0,
            sha256: String::new(),
            detected_type: FileKind::Unknown.label().to_string(),
            declared_extension: ext.clone(),
            type_mismatch: false,
            signature: None,
            modified: None,
            source: zone_source(path),
        };

        // 1. Refuse links: following attacker-controlled symlinks/junctions could redirect a scan (or later actions).
        match std::fs::symlink_metadata(path) {
            Ok(m) if is_link_like(&m) => {
                checks.push(chk("access", "File access", CheckStatus::Failed, None, Some("The path is a symbolic link or junction; SENTRIX does not follow links. Scan the real file instead.".into())));
                return finish(info, checks, findings, started, false);
            }
            Err(e) => {
                checks.push(chk("access", "File access", CheckStatus::Failed, None, Some(format!("Could not read the file: {e}"))));
                return finish(info, checks, findings, started, false);
            }
            _ => {}
        }

        // 2. Open once; all later reads use this handle.
        let mut file = match File::open(path) {
            Ok(f) => f,
            Err(e) => {
                record_access_failure(&e, &mut checks, &mut findings);
                return finish(info, checks, findings, started, false);
            }
        };
        let meta = match file.metadata() {
            Ok(m) if m.is_file() => m,
            Ok(_) => {
                checks.push(chk("access", "File access", CheckStatus::Failed, None, Some("Not a regular file.".into())));
                return finish(info, checks, findings, started, false);
            }
            Err(e) => {
                checks.push(chk("access", "File access", CheckStatus::Failed, None, Some(e.to_string())));
                return finish(info, checks, findings, started, false);
            }
        };
        info.size = meta.len();
        info.modified = meta.modified().ok().map(DateTime::<Utc>::from);
        let mtime_key = meta.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_nanos() as i64).unwrap_or(0);

        // Fast path for repeat events on an unchanged file (path + size + mtime), then confirm by engine fingerprint.
        let fingerprint = format!("{}|{}", ENGINE_VERSION, self.clam_version().unwrap_or_else(|| "no-signature-engine".into()));
        if opts.use_cache {
            let sha = self.stat_cache.lock().unwrap().get(&(path.to_path_buf(), info.size, mtime_key)).cloned();
            if let Some(sha) = sha {
                if let Some(hit) = self.cache.lock().unwrap().get(&format!("{sha}|{fingerprint}")).cloned() {
                    return rebrand_cached(hit, info, started);
                }
            }
        }

        // 3. Read head, then body (bounded) and hash.
        let mut head = vec![0u8; 0x9000.min(info.size as usize)];
        if let Err(e) = file.read_exact(&mut head) {
            record_access_failure(&e, &mut checks, &mut findings);
            return finish(info, checks, findings, started, false);
        }
        if file.seek(SeekFrom::Start(0)).is_err() {
            checks.push(chk("access", "File access", CheckStatus::Failed, None, Some("Could not rewind file.".into())));
            return finish(info, checks, findings, started, false);
        }
        let mut hasher = Sha256::new();
        let body: Option<Vec<u8>> = if info.size <= limits.max_analyze_bytes {
            let mut v = Vec::with_capacity(info.size as usize);
            if let Err(e) = (&mut file).take(limits.max_analyze_bytes + 1).read_to_end(&mut v) {
                record_access_failure(&e, &mut checks, &mut findings);
                return finish(info, checks, findings, started, false);
            }
            hasher.update(&v);
            Some(v)
        } else {
            let mut buf = vec![0u8; 1024 * 1024];
            loop {
                if cancelled() {
                    break;
                }
                match file.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => hasher.update(&buf[..n]),
                    Err(e) => {
                        record_access_failure(&e, &mut checks, &mut findings);
                        return finish(info, checks, findings, started, false);
                    }
                }
            }
            None
        };
        if cancelled() {
            checks.push(chk("cancel", "Scan", CheckStatus::Incomplete, None, Some("Cancelled before completion.".into())));
            return finish(info, checks, findings, started, false);
        }
        info.sha256 = hex::encode(hasher.finalize());
        self.stat_cache.lock().unwrap().insert((path.to_path_buf(), info.size, mtime_key), info.sha256.clone());

        if opts.use_cache {
            if let Some(hit) = self.cache.lock().unwrap().get(&format!("{}|{fingerprint}", info.sha256)).cloned() {
                return rebrand_cached(hit, info, started);
            }
        }

        // 4. Identify by content (Layer A).
        let mut kind = identify::identify(&head, ext.as_deref());
        if kind.zip_family() {
            if let Some(b) = &body {
                if let Ok(z) = zip::ZipArchive::new(Cursor::new(b.as_slice())) {
                    let names: Vec<String> = z.file_names().map(|s| s.to_string()).collect();
                    kind = identify::refine_zip(&names);
                }
            }
        }
        info.detected_type = kind.label().to_string();
        info.type_mismatch = identify::extension_mismatch(kind, ext.as_deref());
        checks.push(chk("identify", "File type identification", CheckStatus::Completed, None, if kind == FileKind::Unknown { Some("Format not recognised; only signature scanning applies.".into()) } else { None }));
        checks.push(chk("hash", "SHA-256 hash", CheckStatus::Completed, None, None));

        if info.type_mismatch {
            let sev = if kind.is_executable() { Severity::Medium } else { Severity::Low };
            findings.push(Finding::new("heuristic.identify", "File content does not match its extension", FindingKind::Heuristic, sev, format!("The content is {} but the name ends in .{}.", kind.label(), ext.clone().unwrap_or_default())));
        }
        if identify::double_extension(&name) {
            findings.push(Finding::new("heuristic.identify", "Double file extension", FindingKind::Heuristic, Severity::Medium, "A document-style extension is followed by an executable one, a common disguise."));
        }

        // 5. Digital signature (Windows PE).
        if kind == FileKind::Pe {
            let sig = signature::verify(path);
            let (sev, nm) = match sig.state.as_str() {
                "signed_invalid" => (Severity::High, "Digital signature is invalid or the file was altered"),
                "signed_untrusted" => (Severity::Low, "Signed with a certificate that is not trusted"),
                "signed_trusted" => (Severity::Info, "Valid digital signature"),
                "unsigned" => (Severity::Info, "Not digitally signed"),
                _ => (Severity::Info, "Digital signature status unknown"),
            };
            findings.push(Finding::new("authenticode", nm, FindingKind::Integrity, sev, sig.detail.clone().unwrap_or_default()));
            checks.push(chk("signature", "Digital signature", if sig.state == "unknown" { CheckStatus::Failed } else { CheckStatus::Completed }, None, sig.detail.clone().filter(|_| sig.state == "unknown")));
            info.signature = Some(sig);
        } else {
            checks.push(chk("signature", "Digital signature", CheckStatus::NotApplicable, None, None));
        }

        // 6. EICAR test detector (validates the workflow; never counts as a signature engine).
        {
            let hit = body.as_deref().is_some_and(eicar::is_eicar_file);
            if hit {
                let mut f = Finding::new("builtin-eicar", "EICAR-Test-File", FindingKind::Signature, Severity::High, "The file is the standard EICAR anti-malware test file. It is harmless by design.");
                f.engine_version = Some(ENGINE_VERSION.to_string());
                findings.push(f);
            }
            checks.push(chk("builtin-eicar", "EICAR test-file detector", CheckStatus::Completed, Some(ENGINE_VERSION.to_string()), Some("Test-file detector only; not a malware engine.".into())));
        }

        // 7. Signature engine (Layer B).
        self.run_clam(&mut file, body.as_deref(), info.size, opts, &mut checks, &mut findings);
        if cancelled() {
            checks.push(chk("cancel", "Scan", CheckStatus::Incomplete, None, Some("Cancelled before completion.".into())));
            return finish(info, checks, findings, started, false);
        }

        // 8. Static heuristics (Layer C) and archive inspection.
        if kind.has_static_analyzer() {
            match &body {
                Some(b) if !kind.zip_family() => {
                    let b: &[u8] = b;
                    match std::panic::catch_unwind(|| heuristics::analyze(kind, b)) {
                        Ok(f) => {
                            findings.extend(f);
                            checks.push(chk("static", "Static analysis", CheckStatus::Completed, Some(ENGINE_VERSION.to_string()), None));
                        }
                        Err(_) => checks.push(chk("static", "Static analysis", CheckStatus::Failed, None, Some("The analyzer crashed on this file; it was contained and the file was not analysed.".into()))),
                    }
                }
                Some(b) => {
                    let r = archive::inspect_zip(b, &limits, &cancelled);
                    findings.extend(r.findings);
                    checks.push(chk("archive", "Archive contents", r.status, Some(ENGINE_VERSION.to_string()), r.note));
                    // Container-level indicators (macros in OOXML).
                    if kind == FileKind::Ooxml {
                        checks.push(chk("static", "Document analysis", CheckStatus::Completed, Some(ENGINE_VERSION.to_string()), None));
                        findings.extend(ooxml_macro_findings(b));
                    }
                }
                None => checks.push(chk("static", "Static analysis", CheckStatus::Incomplete, None, Some(format!("File is larger than the {} MiB analysis limit; only the signature engine inspected it.", limits.max_analyze_bytes / 1024 / 1024)))),
            }
        } else {
            let note = if kind.is_archive() { "Contents of this archive type are inspected by the signature engine's unpacker only." } else { "No in-house analyzer for this format; signature engine only." };
            checks.push(chk("static", "Static analysis", CheckStatus::NotApplicable, None, Some(note.into())));
        }

        let report = finish(info, checks, findings, started, false);
        if report.verdict != Verdict::Pending && !cancelled() {
            self.cache.lock().unwrap().insert(format!("{}|{fingerprint}", report.file.sha256), report.clone());
        }
        report
    }

    fn run_clam(&self, file: &mut File, body: Option<&[u8]>, size: u64, opts: &ScanOptions, checks: &mut Vec<Check>, findings: &mut Vec<Finding>) {
        let limits = self.limits();
        let name = "Malware signatures (ClamAV)";
        if size > limits.max_scan_bytes {
            checks.push(chk("clamav", name, CheckStatus::Incomplete, None, Some(format!("File exceeds the {} MiB scan limit and was not sent to the engine.", limits.max_scan_bytes / 1024 / 1024))));
            return;
        }
        let clam = match self.ensure_clam() {
            Ok(c) => c,
            Err(e) => {
                // The engine may simply not be running yet or still downloading signatures: worth retrying later.
                checks.push(retryable(chk("clamav", name, CheckStatus::Unavailable, None, Some(e.to_string()))));
                return;
            }
        };
        let cancel = || opts.cancel.load(Ordering::Relaxed);
        let outcome = match body {
            Some(b) => clam.scan_stream(&mut Cursor::new(b), &cancel),
            None => file.seek(SeekFrom::Start(0)).map_err(ClamError::from).and_then(|_| clam.scan_stream(file, &cancel)),
        };
        let version = self.clam_version();
        match outcome {
            Ok(ClamOutcome::Clean) => checks.push(chk("clamav", name, CheckStatus::Completed, version, None)),
            Ok(ClamOutcome::Found(sig)) => {
                match classify_signature(&sig) {
                    ClamClass::Malicious => {
                        let mut f = Finding::new("clamav", &sig, FindingKind::Signature, Severity::High, format!("ClamAV signature match: {sig}"));
                        f.engine_version = version.clone();
                        findings.push(f);
                        checks.push(chk("clamav", name, CheckStatus::Completed, version, None));
                    }
                    ClamClass::Suspicious => {
                        let mut f = Finding::new("clamav", &sig, FindingKind::Heuristic, Severity::Medium, format!("ClamAV heuristic detection: {sig}. This is an indicator, not a confirmed malware identification."));
                        f.engine_version = version.clone();
                        findings.push(f);
                        checks.push(chk("clamav", name, CheckStatus::Completed, version, None));
                    }
                    ClamClass::CoverageGap => {
                        findings.push(Finding::new("clamav", &sig, FindingKind::Coverage, Severity::Low, "ClamAV could not fully inspect this file (encrypted content or limits exceeded)."));
                        checks.push(chk("clamav", name, CheckStatus::Incomplete, version, Some("Part of the file could not be inspected (encrypted or over engine limits).".into())));
                    }
                }
            }
            Ok(ClamOutcome::Error(e)) if e == "cancelled" => checks.push(chk("clamav", name, CheckStatus::Incomplete, version, Some("Cancelled.".into()))),
            Ok(ClamOutcome::Error(e)) => checks.push(retryable(chk("clamav", name, CheckStatus::Failed, version, Some(e)))),
            Err(e) => checks.push(retryable(chk("clamav", name, CheckStatus::Failed, version, Some(e.to_string())))),
        }
    }

    /// Scan files and folders. Discovery streams into the workers through a bounded queue, so memory stays flat even
    /// for a whole-disk scan. Folders are walked without following links; anything not scanned is reported.
    ///
    /// `on_report` sees every report (and may amend it, e.g. to record an automatic quarantine) before it is counted.
    pub fn scan_paths(&self, paths: &[PathBuf], opts: &ScanOptions, workers: usize, on_report: &(dyn Fn(&mut ScanReport) + Sync), on_progress: &(dyn Fn(Progress) + Sync)) -> BatchResult {
        let (tx, rx) = std::sync::mpsc::sync_channel::<PathBuf>(2048);
        let rx = Mutex::new(rx);
        let discovered = AtomicUsize::new(0);
        let discovering = AtomicBool::new(true);
        let done = AtomicUsize::new(0);
        let acc = Mutex::new(Acc::default());
        let cap = opts.max_retained_reports;

        std::thread::scope(|s| {
            let (discovered, discovering, acc) = (&discovered, &discovering, &acc);
            s.spawn(move || {
                let mut send = |mut p: PathBuf| -> bool {
                    discovered.fetch_add(1, Ordering::Relaxed);
                    loop {
                        match tx.try_send(p) {
                            Ok(()) => return true,
                            Err(std::sync::mpsc::TrySendError::Full(v)) => {
                                if opts.cancel.load(Ordering::Relaxed) {
                                    return false;
                                }
                                p = v;
                                std::thread::sleep(Duration::from_millis(4));
                            }
                            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => return false,
                        }
                    }
                };
                let mut skip = |p: PathBuf, why: String| {
                    let mut a = acc.lock().unwrap();
                    a.skipped_total += 1;
                    if a.skipped.len() < MAX_SKIPPED_KEPT {
                        a.skipped.push((p, why));
                    }
                };
                walk(paths, &opts.cancel, &opts.exclude, &mut send, &mut skip);
                discovering.store(false, Ordering::Relaxed);
                // `tx` drops here, which ends the workers' recv loop once the queue drains.
            });

            for _ in 0..workers.clamp(1, 8) {
                s.spawn(|| loop {
                    if opts.cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    let p = match rx.lock().unwrap().recv_timeout(Duration::from_millis(200)) {
                        Ok(p) => p,
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    };
                    let mut r = self.scan_file(&p, opts);
                    on_report(&mut r);
                    {
                        let mut a = acc.lock().unwrap();
                        a.counts.total += 1;
                        match r.verdict {
                            Verdict::Clean => a.counts.clean += 1,
                            Verdict::Suspicious => a.counts.suspicious += 1,
                            Verdict::Malicious => a.counts.malicious += 1,
                            _ => a.counts.unable_to_verify += 1,
                        }
                        if !r.complete {
                            a.counts.incomplete += 1;
                        }
                        let flagged = !(r.verdict == Verdict::Clean && r.complete);
                        if a.reports.len() >= cap && !a.truncated {
                            a.truncated = true;
                            a.reports.retain(|x| !(x.verdict == Verdict::Clean && x.complete));
                        }
                        if flagged {
                            if a.reports.len() < MAX_FLAGGED_KEPT {
                                a.reports.push(r);
                            } else {
                                a.truncated = true;
                            }
                        } else if !a.truncated {
                            a.reports.push(r);
                        }
                    }
                    let d = done.fetch_add(1, Ordering::Relaxed) + 1;
                    on_progress(Progress { done: d, discovered: discovered.load(Ordering::Relaxed), discovering: discovering.load(Ordering::Relaxed), current: p });
                });
            }
        });

        let a = acc.into_inner().unwrap();
        let cancelled = opts.cancel.load(Ordering::Relaxed);
        let complete = !cancelled && a.skipped_total == 0 && a.counts.incomplete == 0;
        BatchResult { reports: a.reports, reports_truncated: a.truncated, counts: a.counts, skipped: a.skipped, skipped_total: a.skipped_total, complete, cancelled }
    }
}

fn is_excluded(p: &Path, exclude: &[PathBuf]) -> bool {
    if exclude.is_empty() {
        return false;
    }
    #[cfg(windows)]
    {
        // Windows paths are case-insensitive.
        let lp = p.to_string_lossy().to_lowercase();
        exclude.iter().any(|e| {
            let le = e.to_string_lossy().to_lowercase();
            lp == le || lp.starts_with(&format!("{}\\", le.trim_end_matches('\\')))
        })
    }
    #[cfg(not(windows))]
    {
        exclude.iter().any(|e| p.starts_with(e))
    }
}

/// Depth-first walk that never follows symbolic links or junctions. Unreadable entries go to `on_skip`, never
/// silently ignored. `on_file` returning false stops the walk (cancelled or consumer gone).
pub fn walk(roots: &[PathBuf], cancel: &AtomicBool, exclude: &[PathBuf], on_file: &mut dyn FnMut(PathBuf) -> bool, on_skip: &mut dyn FnMut(PathBuf, String)) {
    let mut stack: Vec<PathBuf> = roots.iter().rev().cloned().collect();
    while let Some(p) = stack.pop() {
        if cancel.load(Ordering::Relaxed) {
            return;
        }
        if is_excluded(&p, exclude) {
            continue;
        }
        let m = match std::fs::symlink_metadata(&p) {
            Ok(m) => m,
            Err(e) => {
                on_skip(p, e.to_string());
                continue;
            }
        };
        if is_link_like(&m) {
            on_skip(p, "symbolic link or junction (not followed)".into());
        } else if m.is_dir() {
            match std::fs::read_dir(&p) {
                Ok(rd) => {
                    let mut kids: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
                    kids.sort();
                    stack.extend(kids.into_iter().rev());
                }
                Err(e) => on_skip(p, format!("cannot read folder: {e}")),
            }
        } else if m.is_file() && !on_file(p) {
            return;
        }
    }
}

#[cfg(windows)]
fn is_link_like(m: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    m.file_type().is_symlink() || m.file_attributes() & 0x400 != 0 // FILE_ATTRIBUTE_REPARSE_POINT
}
#[cfg(not(windows))]
fn is_link_like(m: &std::fs::Metadata) -> bool {
    m.file_type().is_symlink()
}

/// Windows returns ERROR_VIRUS_INFECTED (225) / ERROR_VIRUS_DELETED (226) when the installed security provider
/// (Microsoft Defender or a third-party AV) blocks access because it classified the file as malicious or unwanted.
fn blocked_by_host_security(e: &std::io::Error) -> bool {
    matches!(e.raw_os_error(), Some(225) | Some(226))
}

/// A blocked read is a detection by a trusted engine (the OS security provider), so it is reported as one.
/// Any other failure is a coverage gap and can never become a clean verdict.
fn record_access_failure(e: &std::io::Error, checks: &mut Vec<Check>, findings: &mut Vec<Finding>) {
    if blocked_by_host_security(e) {
        findings.push(Finding::new(
            "windows-security",
            "Blocked by your computer's security software",
            FindingKind::Signature,
            Severity::High,
            "The operating system's security provider refused access because it classified this file as a virus or unwanted software. SENTRIX could not read the file itself.",
        ));
        checks.push(chk("access", "File access", CheckStatus::Failed, None, Some("Access was blocked by your security software, so SENTRIX could not scan the contents itself.".into())));
    } else {
        let c = chk("access", "File access", CheckStatus::Failed, None, Some(access_hint(e)));
        checks.push(if io_is_transient(e) { retryable(c) } else { c });
    }
}

/// Read the NTFS `Zone.Identifier` stream written by browsers/mail clients and describe the origin. Only the host and
/// zone are kept: the full URL may contain tokens or personal data.
#[cfg(windows)]
pub fn zone_source(path: &Path) -> Option<String> {
    let mut f = File::open(format!("{}:Zone.Identifier", path.display())).ok()?;
    let mut buf = Vec::new();
    (&mut f).take(4096).read_to_end(&mut buf).ok()?;
    parse_zone_identifier(&String::from_utf8_lossy(&buf))
}
#[cfg(not(windows))]
pub fn zone_source(_path: &Path) -> Option<String> {
    None
}

pub fn parse_zone_identifier(text: &str) -> Option<String> {
    let get = |key: &str| text.lines().find_map(|l| l.trim().strip_prefix(key).and_then(|r| r.strip_prefix('=')).map(|v| v.trim().to_string()));
    let zone = match get("ZoneId")?.as_str() {
        "0" => "this computer",
        "1" => "local network",
        "2" => "trusted site",
        "3" => "the Internet",
        "4" => "an untrusted site",
        _ => "an unknown zone",
    };
    let host = get("HostUrl").or_else(|| get("ReferrerUrl")).and_then(|u| {
        let rest = u.split("://").nth(1)?;
        let authority = rest.split(['/', '?', '#']).next()?;
        let host = authority.rsplit('@').next()?; // drop any user:password@
        (!host.is_empty() && host.len() < 120).then(|| host.to_string())
    });
    Some(match host {
        Some(h) => format!("Downloaded from {h} ({zone})"),
        None => format!("Marked as coming from {zone}"),
    })
}

fn access_hint(e: &std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::PermissionDenied => "Permission denied. The file may be locked by another program or require elevated rights.".into(),
        std::io::ErrorKind::NotFound => "The file no longer exists.".into(),
        _ => format!("Could not read the file: {e}"),
    }
}

fn chk(id: &str, name: &str, status: CheckStatus, engine_version: Option<String>, note: Option<String>) -> Check {
    Check { id: id.into(), name: name.into(), status, engine_version, note, retryable: false }
}

/// Mark a failed check as worth retrying later (locked file, engine not running).
fn retryable(mut c: Check) -> Check {
    c.retryable = true;
    c
}

/// Locked or momentarily inaccessible files are retried; a file that is gone is not.
fn io_is_transient(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    // 32 = ERROR_SHARING_VIOLATION, 33 = ERROR_LOCK_VIOLATION, 5 = ERROR_ACCESS_DENIED (an AV or a writer holding the file)
    matches!(e.kind(), PermissionDenied | WouldBlock | Interrupted | TimedOut) || matches!(e.raw_os_error(), Some(32) | Some(33) | Some(5))
}

fn finish(info: FileInfo, checks: Vec<Check>, findings: Vec<Finding>, started: DateTime<Utc>, cached: bool) -> ScanReport {
    let d = verdict::decide(&checks, &findings);
    ScanReport {
        id: uuid::Uuid::new_v4(),
        file: info,
        verdict: d.verdict,
        complete: d.complete,
        checks,
        findings,
        summary: d.summary,
        recommended_action: d.recommended_action,
        started_at: started,
        finished_at: Utc::now(),
        quarantined: false,
        blocked: false,
        cached,
        origin: None,
    }
}

fn rebrand_cached(mut hit: ScanReport, info: FileInfo, started: DateTime<Utc>) -> ScanReport {
    hit.id = uuid::Uuid::new_v4();
    hit.file.path = info.path;
    hit.file.name = info.name;
    hit.file.modified = info.modified;
    hit.file.size = info.size;
    hit.file.declared_extension = info.declared_extension;
    hit.file.source = info.source;
    hit.started_at = started;
    hit.finished_at = Utc::now();
    hit.cached = true;
    hit.quarantined = false;
    hit
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn tree(n: usize) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        for i in 0..n {
            let sub = d.path().join(format!("d{}", i % 7));
            std::fs::create_dir_all(&sub).unwrap();
            std::fs::write(sub.join(format!("f{i}.txt")), format!("file {i}")).unwrap();
        }
        d
    }

    fn no_engine() -> Scanner {
        Scanner::new(Limits::default(), None)
    }

    #[test]
    fn counts_every_file_and_never_calls_anything_clean_without_an_engine() {
        let d = tree(120);
        let b = no_engine().scan_paths(&[d.path().to_path_buf()], &ScanOptions::default(), 4, &|_| {}, &|_| {});
        assert_eq!(b.counts.total, 120);
        assert_eq!(b.counts.clean, 0);
        assert_eq!(b.counts.unable_to_verify, 120);
        assert!(!b.complete, "no engine means the batch cannot be complete");
        assert_eq!(b.reports.len(), 120);
    }

    #[test]
    fn excluded_folders_are_skipped_silently() {
        let d = tree(14);
        let ex = d.path().join("d0");
        let opts = ScanOptions { exclude: vec![ex], ..Default::default() };
        let b = no_engine().scan_paths(&[d.path().to_path_buf()], &opts, 2, &|_| {}, &|_| {});
        assert_eq!(b.counts.total, 12, "two files live under d0");
        assert_eq!(b.skipped_total, 0, "an intentional exclusion is not a gap");
    }

    #[test]
    fn cancelling_mid_scan_returns_promptly_without_deadlock() {
        // More files than the bounded queue holds (2048), so the producer is blocked on a full queue when we cancel.
        let d = tree(6000);
        let opts = ScanOptions::default();
        let cancel = opts.cancel.clone();
        let seen = AtomicUsize::new(0);
        let (tx, rx) = std::sync::mpsc::channel();
        let root = d.path().to_path_buf();
        let h = std::thread::spawn(move || {
            let b = no_engine().scan_paths(&[root], &opts, 2, &|_| {}, &|_| {
                if seen.fetch_add(1, Ordering::Relaxed) == 20 {
                    cancel.store(true, Ordering::Relaxed);
                }
            });
            tx.send((b.cancelled, b.counts.total, b.complete)).unwrap();
        });
        let (cancelled, total, complete) = rx.recv_timeout(Duration::from_secs(20)).expect("scan_paths deadlocked after cancel");
        h.join().unwrap();
        assert!(cancelled && !complete);
        assert!(total < 6000, "should stop early, scanned {total}");
    }

    #[test]
    fn zone_identifier_keeps_only_host_and_zone() {
        let s = parse_zone_identifier("[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://a.example/\r\nHostUrl=https://user:pw@files.evil.example/dl/x.exe?token=SECRET#frag\r\n").unwrap();
        assert_eq!(s, "Downloaded from files.evil.example (the Internet)");
        assert!(!s.contains("SECRET") && !s.contains("pw"));
        assert_eq!(parse_zone_identifier("[ZoneTransfer]\r\nZoneId=3\r\n").unwrap(), "Marked as coming from the Internet");
        assert_eq!(parse_zone_identifier("[ZoneTransfer]\r\nZoneId=4\r\nHostUrl=about:internet\r\n").unwrap(), "Marked as coming from an untrusted site");
        assert!(parse_zone_identifier("no zone here").is_none());
    }

    #[cfg(windows)]
    #[test]
    fn real_alternate_data_stream_is_read() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("dl.bin");
        std::fs::write(&p, b"x").unwrap();
        std::fs::write(format!("{}:Zone.Identifier", p.display()), "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://cdn.example/f?sig=abc\r\n").unwrap();
        let r = no_engine().scan_file(&p, &ScanOptions { use_cache: false, ..Default::default() });
        assert_eq!(r.file.source.as_deref(), Some("Downloaded from cdn.example (the Internet)"));
        let plain = d.path().join("plain.bin");
        std::fs::write(&plain, b"y").unwrap();
        assert!(no_engine().scan_file(&plain, &ScanOptions::default()).file.source.is_none());
    }

    #[test]
    fn unreadable_roots_are_reported_not_ignored() {
        let b = no_engine().scan_paths(&[PathBuf::from("Z:/definitely/missing")], &ScanOptions::default(), 1, &|_| {}, &|_| {});
        assert_eq!(b.skipped_total, 1);
        assert!(!b.complete);
    }

    #[test]
    fn on_report_can_amend_reports_before_they_are_counted() {
        let d = tree(5);
        let b = no_engine().scan_paths(&[d.path().to_path_buf()], &ScanOptions::default(), 2, &|r| r.quarantined = true, &|_| {});
        assert!(b.reports.iter().all(|r| r.quarantined));
    }

    #[test]
    fn walk_does_not_visit_the_same_file_twice_and_is_ordered() {
        let d = tree(30);
        let mut seen = Vec::new();
        walk(&[d.path().to_path_buf()], &AtomicBool::new(false), &[], &mut |p| { seen.push(p); true }, &mut |_, _| {});
        let mut uniq = seen.clone();
        uniq.sort();
        uniq.dedup();
        assert_eq!(seen.len(), 30);
        assert_eq!(uniq.len(), 30);
    }
}

fn ooxml_macro_findings(zip_bytes: &[u8]) -> Vec<Finding> {
    let Ok(mut z) = zip::ZipArchive::new(Cursor::new(zip_bytes)) else { return Vec::new() };
    let mut out = Vec::new();
    let names: Vec<String> = z.file_names().map(|s| s.to_string()).collect();
    if names.iter().any(|n| n.to_ascii_lowercase().ends_with("vbaproject.bin")) {
        out.push(Finding::new("heuristic.document", "Contains VBA macros", FindingKind::Heuristic, Severity::Low, "Macros can run code when enabled. Their behaviour was not analysed."));
    }
    // Remote template injection / external relationships.
    for n in names.iter().filter(|n| n.ends_with(".rels")) {
        if let Ok(f) = z.by_name(n) {
            let mut s = String::new();
            if f.take(1024 * 1024).read_to_string(&mut s).is_ok() {
                let l = s.to_ascii_lowercase();
                if l.contains("targetmode=\"external\"") && (l.contains("attachedtemplate") || l.contains("oleobject")) && (l.contains("http://") || l.contains("https://") || l.contains("\\\\")) {
                    out.push(Finding::new("heuristic.document", "Loads external content when opened", FindingKind::Heuristic, Severity::Medium, "The document references a remote template or object, a technique used to fetch malicious content after delivery.").at(n.clone()));
                }
            }
        }
    }
    out
}
