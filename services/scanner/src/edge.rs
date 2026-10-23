//! Checking on the customer's own computer ("edge scanning").
//!
//! The shared bot used to download every file posted in a protected group and scan it on the bot's server. That makes the
//! server hold, scan and pay for everybody's files. Now the server only does the part that needs the bot's token:
//!
//!   1. A document is posted in a protected group. The bot records a small **job** (file name, size, Telegram file id, which
//!      group, whose group). It does not download or scan anything.
//!   2. The owner's SENTRIX app asks the relay for its jobs (`GET /v1/jobs`), fetches each file through the relay
//!      (`GET /v1/jobs/<id>/file`: the server hands the bytes from Telegram straight through memory, nothing is written to
//!      its disk), scans it with the engine on that computer, and sends back a short verdict (`POST /v1/jobs/<id>/result`).
//!   3. The server turns the verdict into the report the owner reads in Scan History, and does the one thing only the bot can
//!      do (deleting a confirmed-malicious message, if the group's administrators agreed to that).
//!
//! The bot stays in control: only a person with a linked, recently seen app gets jobs, only that person's app can fetch or
//! answer them, the app token can be revoked from the bot, and the server decides what is reported and where.
//!
//! The verdict comes from the owner's computer, so it is only as trustworthy as that computer. It can only affect the
//! owner's own reports and groups. A verdict that claims "clean" without a complete check is downgraded to "could not be
//! fully checked" before anyone reads it.

use crate::queue::{JobStore, StoreError};
use crate::relay::RelayClient;
use crate::telegram::{BotClient, MAX_BOT_DOWNLOAD};
use crate::types::{FileInfo, Finding, FindingKind, ScanReport, Severity, ThreatInfo, Verdict};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A job handed to an app that does not answer is offered again after this long.
pub const EDGE_LEASE_MS: i64 = 5 * 60 * 1000;
/// How long a file may wait for the owner's computer before it is reported as "not checked".
pub const EDGE_DEFAULT_WAIT_MS: i64 = 6 * 60 * 60 * 1000;
/// Files waiting for one person's computer. More than this are reported as skipped instead of piling up.
pub const EDGE_MAX_QUEUED_PER_OWNER: i64 = 200;
/// Jobs one app is given per request.
pub const EDGE_BATCH: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeJob {
    pub id: String,
    pub owner: i64,
    pub group_chat: i64,
    pub message_id: i64,
    pub file_id: String,
    pub file_unique_id: Option<String>,
    pub name: String,
    pub size: u64,
    pub state: String,
    pub result: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enqueued {
    Queued,
    /// The same message was already handed over.
    Duplicate,
    /// This person already has `EDGE_MAX_QUEUED_PER_OWNER` files waiting.
    Full,
}

/// What the app is told about a job. No Telegram file id, no chat ids.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EdgeJobInfo {
    pub id: String,
    pub name: String,
    pub size: u64,
    pub group: String,
}

/// The short verdict the app sends back. No paths, no file contents, no evidence text beyond the summary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EdgeResult {
    pub verdict: Verdict,
    pub complete: bool,
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub summary: String,
    /// Names the malware engine gave it (at most three are shown).
    #[serde(default)]
    pub signatures: Vec<String>,
    #[serde(default)]
    pub threat_title: Option<String>,
    #[serde(default)]
    pub threat_goal: Option<String>,
    /// "identified" (the engine named it) or "suggested" (behaviour only).
    #[serde(default)]
    pub threat_basis: Option<String>,
}

/// The body of `POST /v1/jobs/<id>/result`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeSubmit {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub result: Option<EdgeResult>,
}

/// Where the relay gets a file's bytes. The bot's server implements it with the Telegram Bot API.
pub trait FileSource: Send + Sync {
    fn fetch(&self, file_id: &str, max_bytes: u64) -> Result<Vec<u8>, String>;
}

impl FileSource for BotClient {
    fn fetch(&self, file_id: &str, max_bytes: u64) -> Result<Vec<u8>, String> {
        let (path, _) = self.get_file(file_id).map_err(|e| e.user_message())?;
        let mut buf = Vec::new();
        self.download(&path, &mut buf, max_bytes).map_err(|e| e.user_message())?;
        Ok(buf)
    }
}

fn row(r: &rusqlite::Row) -> rusqlite::Result<EdgeJob> {
    Ok(EdgeJob {
        id: r.get(0)?,
        owner: r.get(1)?,
        group_chat: r.get(2)?,
        message_id: r.get(3)?,
        file_id: r.get(4)?,
        file_unique_id: r.get(5)?,
        name: r.get(6)?,
        size: r.get::<_, i64>(7)?.max(0) as u64,
        state: r.get(8)?,
        result: r.get(9)?,
        created_at: r.get(10)?,
    })
}

const COLS: &str = "id, owner, group_chat, message_id, file_id, file_unique_id, name, size, state, result, created_at";

impl JobStore {
    #[allow(clippy::too_many_arguments)]
    pub fn edge_enqueue(&self, owner: i64, group_chat: i64, message_id: i64, file_id: &str, file_unique_id: Option<&str>, name: &str, size: u64, now: i64) -> Result<Enqueued, StoreError> {
        let c = self.conn.lock().unwrap();
        let waiting: i64 = c.query_row("SELECT count(*) FROM edge_jobs WHERE owner=?1 AND state IN ('queued','leased')", [owner], |r| r.get(0))?;
        if waiting >= EDGE_MAX_QUEUED_PER_OWNER {
            return Ok(Enqueued::Full);
        }
        let name: String = name.chars().filter(|c| !c.is_control()).take(200).collect();
        let n = c.execute(
            "INSERT OR IGNORE INTO edge_jobs(id, owner, group_chat, message_id, file_id, file_unique_id, name, size, state, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'queued',?9,?9)",
            params![uuid::Uuid::new_v4().to_string(), owner, group_chat, message_id, file_id, file_unique_id, name, size as i64, now],
        )?;
        Ok(if n > 0 { Enqueued::Queued } else { Enqueued::Duplicate })
    }

    /// Hand this person's waiting jobs (and any whose earlier hand-over went unanswered) to one of their apps.
    pub fn edge_claim(&self, owner: i64, limit: usize, now: i64) -> Vec<EdgeJob> {
        let c = self.conn.lock().unwrap();
        let sql = format!("SELECT {COLS} FROM edge_jobs WHERE owner=?1 AND (state='queued' OR (state='leased' AND leased_at<?2)) ORDER BY created_at, rowid LIMIT ?3");
        let Ok(mut st) = c.prepare(&sql) else { return vec![] };
        let jobs: Vec<EdgeJob> = st.query_map(params![owner, now - EDGE_LEASE_MS, limit as i64], row).map(|r| r.filter_map(Result::ok).collect()).unwrap_or_default();
        drop(st);
        for j in &jobs {
            let _ = c.execute("UPDATE edge_jobs SET state='leased', leased_at=?2, updated_at=?2 WHERE id=?1", params![j.id, now]);
        }
        jobs
    }

    pub fn edge_get(&self, id: &str) -> Option<EdgeJob> {
        let sql = format!("SELECT {COLS} FROM edge_jobs WHERE id=?1");
        self.conn.lock().unwrap().query_row(&sql, [id], row).optional().ok().flatten()
    }

    /// Record the app's answer. Only the job's owner, only while it is handed out, and only once.
    pub fn edge_finish(&self, id: &str, owner: i64, ok: bool, payload: &str, now: i64) -> bool {
        self.conn
            .lock()
            .unwrap()
            .execute("UPDATE edge_jobs SET state=?3, result=?4, updated_at=?5 WHERE id=?1 AND owner=?2 AND state='leased'", params![id, owner, if ok { "done" } else { "failed" }, payload, now])
            .map(|n| n > 0)
            .unwrap_or(false)
    }

    /// Answers waiting to be turned into reports.
    pub fn edge_finished(&self, limit: usize) -> Vec<EdgeJob> {
        let c = self.conn.lock().unwrap();
        let sql = format!("SELECT {COLS} FROM edge_jobs WHERE state IN ('done','failed') ORDER BY updated_at, rowid LIMIT ?1");
        let Ok(mut st) = c.prepare(&sql) else { return vec![] };
        st.query_map([limit as i64], row).map(|r| r.filter_map(Result::ok).collect()).unwrap_or_default()
    }

    pub fn edge_close(&self, id: &str, now: i64) {
        let _ = self.conn.lock().unwrap().execute("UPDATE edge_jobs SET state='closed', result=NULL, updated_at=?2 WHERE id=?1", params![id, now]);
    }

    /// Jobs nobody answered within `wait_ms` of being posted. They are marked expired and returned so the owner is told.
    pub fn edge_expire(&self, now: i64, wait_ms: i64) -> Vec<EdgeJob> {
        let c = self.conn.lock().unwrap();
        let sql = format!("SELECT {COLS} FROM edge_jobs WHERE state IN ('queued','leased') AND created_at<?1 ORDER BY created_at LIMIT 50");
        let Ok(mut st) = c.prepare(&sql) else { return vec![] };
        let jobs: Vec<EdgeJob> = st.query_map([now - wait_ms], row).map(|r| r.filter_map(Result::ok).collect()).unwrap_or_default();
        drop(st);
        for j in &jobs {
            let _ = c.execute("UPDATE edge_jobs SET state='expired', updated_at=?2 WHERE id=?1 AND state IN ('queued','leased')", params![j.id, now]);
        }
        // Finished bookkeeping rows are not kept for long.
        let _ = c.execute("DELETE FROM edge_jobs WHERE state IN ('closed','expired') AND updated_at<?1", [now - 24 * 3_600_000]);
        jobs
    }

    /// (files waiting for customers' computers, files answered in the last 24 hours). Counts only.
    pub fn edge_totals(&self) -> (i64, i64) {
        let c = self.conn.lock().unwrap();
        let waiting = c.query_row("SELECT count(*) FROM edge_jobs WHERE state IN ('queued','leased')", [], |r| r.get(0)).unwrap_or(0);
        let answered = c.query_row("SELECT count(*) FROM edge_jobs WHERE state IN ('done','failed','closed') AND updated_at > ?1", [crate::queue::now_ms() - 24 * 3_600_000], |r| r.get(0)).unwrap_or(0);
        (waiting, answered)
    }

    /// Files waiting for this person's computer (queued or handed out).
    pub fn edge_waiting(&self, owner: i64) -> i64 {
        self.conn.lock().unwrap().query_row("SELECT count(*) FROM edge_jobs WHERE owner=?1 AND state IN ('queued','leased')", [owner], |r| r.get(0)).unwrap_or(0)
    }
}

// ---- conversions ------------------------------------------------------------------------------------------------

fn clip(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control() || *c == '\n').take(max).collect()
}

/// What the app sends for a finished scan.
pub fn result_from_report(r: &ScanReport) -> EdgeResult {
    let flagged = matches!(r.verdict, Verdict::Malicious | Verdict::Suspicious);
    EdgeResult {
        verdict: r.verdict,
        complete: r.complete,
        sha256: r.file.sha256.clone(),
        size: r.file.size,
        summary: clip(&r.summary, 600),
        signatures: r.findings.iter().filter(|f| f.kind == FindingKind::Signature).map(|f| clip(&f.name, 80)).take(3).collect(),
        threat_title: r.threat.as_ref().filter(|_| flagged).map(|t| clip(&t.title, 80)),
        threat_goal: r.threat.as_ref().filter(|_| flagged).map(|t| clip(&t.goal, 240)),
        threat_basis: r.threat.as_ref().filter(|_| flagged).map(|t| clip(&t.basis, 20)),
    }
}

/// The server's view of an answer from an app: a report with only what is needed to write the message, every string
/// cut to a safe length. A "clean" that was not complete is never believed.
pub fn report_from_result(job: &EdgeJob, r: &EdgeResult) -> ScanReport {
    let now = chrono::Utc::now();
    let sha256 = if r.sha256.len() == 64 && r.sha256.chars().all(|c| c.is_ascii_hexdigit()) { r.sha256.to_ascii_lowercase() } else { String::new() };
    let mut verdict = r.verdict;
    let mut complete = r.complete;
    if matches!(verdict, Verdict::Clean) && !complete {
        verdict = Verdict::UnableToVerify;
    }
    if matches!(verdict, Verdict::Pending) {
        verdict = Verdict::UnableToVerify;
        complete = false;
    }
    let name = clip(&job.name, 120);
    let threat = match (&r.threat_title, &r.threat_goal) {
        (Some(t), Some(g)) if matches!(verdict, Verdict::Malicious | Verdict::Suspicious) => Some(ThreatInfo {
            family: String::new(),
            title: clip(t, 80),
            goal: clip(g, 240),
            arrives_via: vec![],
            attack: vec![],
            advice: String::new(),
            basis: if r.threat_basis.as_deref() == Some("identified") { "identified".into() } else { "suggested".into() },
            also: vec![],
        }),
        _ => None,
    };
    ScanReport {
        id: uuid::Uuid::new_v4(),
        file: FileInfo { path: PathBuf::from(format!("[Telegram group] {name}")), name: name.clone(), size: job.size, sha256, detected_type: String::new(), declared_extension: None, type_mismatch: false, signature: None, modified: None, source: None },
        verdict,
        complete,
        checks: vec![],
        findings: r.signatures.iter().take(3).map(|n| Finding::new("sentrix-app", &clip(n, 80), FindingKind::Signature, Severity::High, "")).collect(),
        summary: clip(&r.summary, 600),
        recommended_action: String::new(),
        started_at: now,
        finished_at: now,
        quarantined: false,
        blocked: false,
        cached: false,
        origin: Some("Telegram group".into()),
        threat,
    }
}

// ---- the app's side ---------------------------------------------------------------------------------------------

/// Ask the relay for this computer's jobs, check each file here, send back the verdicts. Returns how many were answered.
/// `scan(origin, file name, bytes)` is the app's own scan engine; nothing here ever scans on the server.
pub fn run_once(client: &RelayClient, scan: &dyn Fn(&str, &str, &[u8]) -> Result<ScanReport, String>) -> Result<usize, String> {
    let jobs = client.jobs()?;
    let mut answered = 0;
    for j in jobs {
        let outcome: Result<EdgeResult, String> = match client.fetch_job_file(&j.id) {
            Ok(bytes) if bytes.len() as u64 > MAX_BOT_DOWNLOAD => Err("the file is larger than 20 MB".into()),
            Ok(bytes) => {
                let origin = format!("Telegram group: {}", clip(&j.group, 60));
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| scan(&origin, &j.name, &bytes)))
                    .unwrap_or_else(|_| Err("the scan crashed on this computer".into()))
                    .map(|r| result_from_report(&r))
            }
            Err(e) => Err(format!("the file could not be fetched ({e})")),
        };
        let submit = match outcome {
            Ok(r) => EdgeSubmit { ok: true, error: None, result: Some(r) },
            Err(e) => EdgeSubmit { ok: false, error: Some(clip(&e, 200)), result: None },
        };
        client.submit_job_result(&j.id, &submit)?;
        answered += 1;
    }
    Ok(answered)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enq(s: &JobStore, owner: i64, mid: i64, now: i64) -> Enqueued {
        s.edge_enqueue(owner, -100, mid, "FILEID", Some("uniq"), "invoice.pdf", 10, now).unwrap()
    }

    #[test]
    fn a_message_is_queued_once_and_only_its_owner_can_claim_it() {
        let s = JobStore::open_in_memory().unwrap();
        assert_eq!(enq(&s, 7, 1, 100), Enqueued::Queued);
        assert_eq!(enq(&s, 7, 1, 101), Enqueued::Duplicate, "the same message is never queued twice");
        assert!(s.edge_claim(8, 3, 200).is_empty(), "another person's app gets nothing");
        let got = s.edge_claim(7, 3, 200);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "invoice.pdf");
        assert!(s.edge_claim(7, 3, 201).is_empty(), "handed out: not offered again straight away");
    }

    #[test]
    fn a_job_nobody_answers_is_offered_again_after_the_lease_and_expires_after_the_wait() {
        let s = JobStore::open_in_memory().unwrap();
        enq(&s, 7, 1, 1_000);
        let first = s.edge_claim(7, 3, 2_000);
        assert_eq!(first.len(), 1);
        assert!(s.edge_claim(7, 3, 2_000 + EDGE_LEASE_MS - 1).is_empty());
        assert_eq!(s.edge_claim(7, 3, 2_000 + EDGE_LEASE_MS + 1).len(), 1, "the app that took it went silent");
        assert!(s.edge_expire(1_000 + 10, 5_000).is_empty(), "still within its wait");
        let gone = s.edge_expire(1_000 + 6_000, 5_000);
        assert_eq!(gone.len(), 1);
        assert!(s.edge_claim(7, 3, 99_999_999).is_empty(), "an expired job is never offered again");
        assert!(s.edge_expire(1_000 + 7_000, 5_000).is_empty(), "and is reported only once");
    }

    #[test]
    fn only_the_owner_can_answer_and_only_once() {
        let s = JobStore::open_in_memory().unwrap();
        enq(&s, 7, 1, 100);
        let id = s.edge_claim(7, 1, 200)[0].id.clone();
        assert!(!s.edge_finish(&id, 8, true, "{}", 300), "someone else's app cannot answer it");
        assert!(s.edge_finish(&id, 7, true, "{\"x\":1}", 300));
        assert!(!s.edge_finish(&id, 7, true, "{\"x\":2}", 301), "a second answer is refused");
        let done = s.edge_finished(10);
        assert_eq!(done.len(), 1);
        assert_eq!(done[0].result.as_deref(), Some("{\"x\":1}"));
        s.edge_close(&id, 400);
        assert!(s.edge_finished(10).is_empty());
        assert!(s.edge_get(&id).unwrap().result.is_none(), "the verdict is not kept after it was used");
    }

    #[test]
    fn one_person_cannot_pile_up_unlimited_jobs() {
        let s = JobStore::open_in_memory().unwrap();
        for i in 0..EDGE_MAX_QUEUED_PER_OWNER {
            assert_eq!(enq(&s, 7, i, 1), Enqueued::Queued);
        }
        assert_eq!(enq(&s, 7, 9_999, 1), Enqueued::Full);
        assert_eq!(enq(&s, 8, 100_000, 1), Enqueued::Queued, "another person is not affected");
    }

    #[test]
    fn an_app_cannot_make_an_incomplete_check_look_clean_or_smuggle_markup() {
        let job = EdgeJob { id: "x".into(), owner: 7, group_chat: -1, message_id: 1, file_id: "f".into(), file_unique_id: None, name: "a\u{7}.pdf".into(), size: 10, state: "done".into(), result: None, created_at: 0 };
        let lie = EdgeResult { verdict: Verdict::Clean, complete: false, sha256: "é".repeat(40), size: 1, summary: "ok".into(), signatures: vec![], threat_title: None, threat_goal: None, threat_basis: None };
        let r = report_from_result(&job, &lie);
        assert_eq!(r.verdict, Verdict::UnableToVerify, "an incomplete clean is never believed");
        assert!(r.file.sha256.is_empty(), "a made-up hash is dropped (and cannot break the message layout)");
        assert_eq!(r.file.name, "a.pdf");
        let bad = EdgeResult { verdict: Verdict::Malicious, complete: true, sha256: "a".repeat(64), size: 10, summary: "x".repeat(5000), signatures: vec!["Eicar".into(); 9], threat_title: Some("T".into()), threat_goal: Some("G".into()), threat_basis: Some("whatever".into()) };
        let r = report_from_result(&job, &bad);
        assert_eq!(r.findings.len(), 3);
        assert!(r.summary.chars().count() <= 600);
        assert_eq!(r.threat.as_ref().unwrap().basis, "suggested", "only the two known bases exist");
    }
}
