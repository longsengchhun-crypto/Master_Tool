//! Durable protection state: scan-job queue, per-file scan state, notification outbox, protection events.
//!
//! Backed by SQLite (WAL) so that a crash, a power cut or a restart loses nothing and recovery is deterministic.
//!
//! Guarantees (each covered by tests below):
//!  * at most ONE active (queued/scanning) job per path: repeated file-system events coalesce;
//!  * an unchanged, completely scanned file is never rescanned; a changed file marks the old result STALE;
//!  * transient failures retry with backoff and give up after a bounded number of attempts: never silently;
//!  * jobs stuck in "scanning" after a crash are recovered on start-up;
//!  * the queue is bounded; overflow is refused and recorded, not absorbed;
//!  * the notification outbox de-duplicates by key and never influences scan results.

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use std::path::Path;
use std::sync::Mutex;

pub const MAX_QUEUED: i64 = 20_000;
pub const MAX_ATTEMPTS: i64 = 7;
pub const STUCK_AFTER_MS: i64 = 10 * 60 * 1000;
const EVENTS_KEPT: i64 = 1000;
const OUTBOX_MAX_PENDING: i64 = 1000;
const OUTBOX_KEEP_MS: i64 = 7 * 86_400_000;

pub fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// Windows paths are case-insensitive; the uniqueness key must be too.
pub fn path_key(p: &Path) -> String {
    let s = p.to_string_lossy().replace('/', "\\");
    if cfg!(windows) {
        s.to_lowercase()
    } else {
        p.to_string_lossy().into_owned()
    }
}

/// Retry delay after the Nth failed attempt (1-based): 5 s, 15 s, 1 min, 5 min, 15 min, 1 h.
pub fn backoff_ms(attempt: i64) -> i64 {
    const S: [i64; 6] = [5, 15, 60, 300, 900, 3600];
    S[(attempt.clamp(1, S.len() as i64) - 1) as usize] * 1000
}

#[derive(Debug, Clone, Serialize)]
pub struct Job {
    pub id: String,
    pub path: String,
    pub source: String,
    pub attempts: i64,
    pub enqueue_size: i64,
    pub enqueue_mtime: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Enq {
    Created(String),
    /// An active job for this path already exists; it was refreshed (and flagged to rescan if it was mid-scan).
    Coalesced(String),
    /// Same size and mtime as a completed, non-stale scan.
    SkippedUnchanged,
    /// The queue is full.
    Overflow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Retry {
    At(i64),
    GaveUp,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueueStats {
    pub queued: i64,
    pub scanning: i64,
    pub failed: i64,
    /// Jobs "scanning" for longer than STUCK_AFTER_MS (a worker died or hung).
    pub stuck: i64,
    pub oldest_queued_seconds: Option<i64>,
    pub files_scanned: i64,
    pub stale_results: i64,
    pub last_scan_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventRow {
    pub id: i64,
    pub ts: i64,
    pub kind: String,
    pub severity: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailedJob {
    pub id: String,
    pub path: String,
    pub source: String,
    pub attempts: i64,
    pub last_error: Option<String>,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboxRow {
    pub id: String,
    pub kind: String,
    pub text: String,
    pub state: String,
    pub attempts: i64,
    pub last_error: Option<String>,
    pub created_at: i64,
    pub sent_at: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboxStats {
    pub pending: i64,
    pub failed_24h: i64,
    pub dead: i64,
    pub last_sent_at: Option<i64>,
    pub last_error: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
}

pub struct JobStore {
    conn: Mutex<Connection>,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS scan_jobs(
  id TEXT PRIMARY KEY, path TEXT NOT NULL, key TEXT NOT NULL, source TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('queued','scanning','done','failed')),
  attempts INTEGER NOT NULL DEFAULT 0, dirty INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER NOT NULL, enqueue_size INTEGER NOT NULL, enqueue_mtime INTEGER NOT NULL,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, last_error TEXT, report_id TEXT, verdict TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS scan_jobs_one_active ON scan_jobs(key) WHERE state IN ('queued','scanning');
CREATE INDEX IF NOT EXISTS scan_jobs_due ON scan_jobs(state, next_attempt_at);
CREATE TABLE IF NOT EXISTS file_state(
  key TEXT PRIMARY KEY, path TEXT NOT NULL, size INTEGER NOT NULL, mtime INTEGER NOT NULL, sha256 TEXT,
  verdict TEXT, complete INTEGER NOT NULL, scanned_at INTEGER NOT NULL, report_id TEXT, stale INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS outbox(
  id TEXT PRIMARY KEY, dedupe_key TEXT NOT NULL UNIQUE, kind TEXT NOT NULL, text TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('pending','sent','dead')),
  attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER NOT NULL, last_error TEXT,
  created_at INTEGER NOT NULL, sent_at INTEGER, failed_at INTEGER
);
CREATE INDEX IF NOT EXISTS outbox_due ON outbox(state, next_attempt_at);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, kind TEXT NOT NULL, severity TEXT NOT NULL, message TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY, value TEXT NOT NULL);
"#;

impl JobStore {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let c = Connection::open(path)?;
        c.pragma_update(None, "journal_mode", "WAL")?;
        c.pragma_update(None, "synchronous", "NORMAL")?;
        c.busy_timeout(std::time::Duration::from_secs(5))?;
        c.execute_batch(SCHEMA)?;
        Ok(JobStore { conn: Mutex::new(c) })
    }

    pub fn open_in_memory() -> Result<Self, StoreError> {
        let c = Connection::open_in_memory()?;
        c.execute_batch(SCHEMA)?;
        Ok(JobStore { conn: Mutex::new(c) })
    }

    // ---- jobs ---------------------------------------------------------------------------------------------

    pub fn enqueue(&self, path: &Path, source: &str, size: u64, mtime_ms: i64, now: i64) -> Result<Enq, StoreError> {
        let mut c = self.conn.lock().unwrap();
        let tx = c.transaction()?;
        let key = path_key(path);

        let fs: Option<(i64, i64, i64, i64)> = tx.query_row("SELECT size, mtime, complete, stale FROM file_state WHERE key = ?1", [&key], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).optional()?;
        if let Some((s, m, complete, stale)) = fs {
            if s == size as i64 && m == mtime_ms && complete == 1 && stale == 0 {
                tx.commit()?;
                return Ok(Enq::SkippedUnchanged);
            }
            // The file differs from what was scanned: the stored verdict no longer describes it.
            tx.execute("UPDATE file_state SET stale = 1 WHERE key = ?1", [&key])?;
        }

        let active: Option<(String, String)> = tx.query_row("SELECT id, state FROM scan_jobs WHERE key = ?1 AND state IN ('queued','scanning')", [&key], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
        if let Some((id, state)) = active {
            if state == "queued" {
                tx.execute("UPDATE scan_jobs SET enqueue_size = ?2, enqueue_mtime = ?3, updated_at = ?4 WHERE id = ?1", params![id, size as i64, mtime_ms, now])?;
            } else {
                // Mid-scan: whatever the worker concludes describes the OLD content, so scan again afterwards.
                tx.execute("UPDATE scan_jobs SET dirty = 1, enqueue_size = ?2, enqueue_mtime = ?3, updated_at = updated_at WHERE id = ?1", params![id, size as i64, mtime_ms])?;
            }
            tx.commit()?;
            return Ok(Enq::Coalesced(id));
        }

        let queued: i64 = tx.query_row("SELECT count(*) FROM scan_jobs WHERE state = 'queued'", [], |r| r.get(0))?;
        if queued >= MAX_QUEUED {
            tx.commit()?;
            return Ok(Enq::Overflow);
        }
        let id = uuid::Uuid::new_v4().to_string();
        tx.execute(
            "INSERT INTO scan_jobs(id, path, key, source, state, next_attempt_at, enqueue_size, enqueue_mtime, created_at, updated_at) VALUES (?1,?2,?3,?4,'queued',?5,?6,?7,?5,?5)",
            params![id, path.to_string_lossy(), key, source, now, size as i64, mtime_ms],
        )?;
        tx.commit()?;
        Ok(Enq::Created(id))
    }

    /// Take up to `limit` due jobs and mark them as scanning.
    pub fn claim_due(&self, now: i64, limit: usize) -> Result<Vec<Job>, StoreError> {
        let mut c = self.conn.lock().unwrap();
        let tx = c.transaction()?;
        let jobs: Vec<Job> = {
            let mut st = tx.prepare("SELECT id, path, source, attempts, enqueue_size, enqueue_mtime FROM scan_jobs WHERE state = 'queued' AND next_attempt_at <= ?1 ORDER BY next_attempt_at, created_at LIMIT ?2")?;
            let rows = st.query_map(params![now, limit as i64], |r| Ok(Job { id: r.get(0)?, path: r.get(1)?, source: r.get(2)?, attempts: r.get(3)?, enqueue_size: r.get(4)?, enqueue_mtime: r.get(5)? }))?;
            rows.collect::<Result<_, _>>()?
        };
        for j in &jobs {
            tx.execute("UPDATE scan_jobs SET state = 'scanning', updated_at = ?2 WHERE id = ?1", params![j.id, now])?;
        }
        tx.commit()?;
        Ok(jobs)
    }

    /// Record a finished scan. If the file changed while it was being scanned (`dirty`), the result is marked stale and
    /// the job is queued again. Returns true if it was re-queued.
    #[allow(clippy::too_many_arguments)]
    pub fn complete(&self, job_id: &str, report_id: &str, verdict: &str, sha256: &str, size: u64, mtime_ms: i64, complete: bool, now: i64) -> Result<bool, StoreError> {
        let mut c = self.conn.lock().unwrap();
        let tx = c.transaction()?;
        let (path, key, dirty): (String, String, i64) = tx.query_row("SELECT path, key, dirty FROM scan_jobs WHERE id = ?1", [job_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        tx.execute(
            "INSERT INTO file_state(key, path, size, mtime, sha256, verdict, complete, scanned_at, report_id, stale) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
             ON CONFLICT(key) DO UPDATE SET path=?2, size=?3, mtime=?4, sha256=?5, verdict=?6, complete=?7, scanned_at=?8, report_id=?9, stale=?10",
            params![key, path, size as i64, mtime_ms, sha256, verdict, complete as i64, now, report_id, dirty],
        )?;
        if dirty == 1 {
            tx.execute("UPDATE scan_jobs SET state='queued', dirty=0, attempts=0, next_attempt_at=?2, updated_at=?2, report_id=?3, verdict=?4 WHERE id=?1", params![job_id, now, report_id, verdict])?;
        } else {
            tx.execute("UPDATE scan_jobs SET state='done', updated_at=?2, report_id=?3, verdict=?4, last_error=NULL WHERE id=?1", params![job_id, now, report_id, verdict])?;
        }
        tx.commit()?;
        Ok(dirty == 1)
    }

    /// A retryable failure. Backs off, and gives up (state `failed`) after MAX_ATTEMPTS: visibly, never silently.
    pub fn fail_transient(&self, job_id: &str, error: &str, now: i64) -> Result<Retry, StoreError> {
        let c = self.conn.lock().unwrap();
        let prior: i64 = c.query_row("SELECT attempts FROM scan_jobs WHERE id = ?1", [job_id], |r| r.get(0))?;
        let attempts = prior + 1;
        let err: String = error.chars().take(300).collect();
        if attempts >= MAX_ATTEMPTS {
            c.execute("UPDATE scan_jobs SET state='failed', attempts=?2, last_error=?3, updated_at=?4 WHERE id=?1", params![job_id, attempts, err, now])?;
            Ok(Retry::GaveUp)
        } else {
            let at = now + backoff_ms(attempts);
            c.execute("UPDATE scan_jobs SET state='queued', attempts=?2, next_attempt_at=?3, last_error=?4, updated_at=?5 WHERE id=?1", params![job_id, attempts, at, err, now])?;
            Ok(Retry::At(at))
        }
    }

    /// Not ready yet (a download is still being written): look again later WITHOUT counting a failed attempt.
    pub fn defer(&self, job_id: &str, until_ms: i64, now: i64) -> Result<(), StoreError> {
        self.conn.lock().unwrap().execute("UPDATE scan_jobs SET state='queued', next_attempt_at=?2, updated_at=?3 WHERE id=?1 AND state='scanning'", params![job_id, until_ms, now])?;
        Ok(())
    }

    /// The file vanished before it could be scanned (a temporary name that was renamed): nothing to report.
    pub fn discard(&self, job_id: &str, now: i64) -> Result<(), StoreError> {
        self.conn.lock().unwrap().execute("UPDATE scan_jobs SET state='done', updated_at=?2, last_error='file disappeared before it was scanned' WHERE id=?1", params![job_id, now])?;
        Ok(())
    }

    /// Terminal failure with no retry (e.g. the file is gone).
    pub fn fail_permanent(&self, job_id: &str, error: &str, now: i64) -> Result<(), StoreError> {
        let err: String = error.chars().take(300).collect();
        self.conn.lock().unwrap().execute("UPDATE scan_jobs SET state='failed', last_error=?2, updated_at=?3 WHERE id=?1", params![job_id, err, now])?;
        Ok(())
    }

    /// After a crash or restart: anything still "scanning" belongs to a worker that no longer exists.
    pub fn recover_stuck(&self, now: i64, older_than_ms: i64) -> Result<usize, StoreError> {
        let c = self.conn.lock().unwrap();
        let n = c.execute("UPDATE scan_jobs SET state='queued', next_attempt_at=?1, last_error='recovered after an interruption', updated_at=?1 WHERE state='scanning' AND updated_at <= ?2", params![now, now - older_than_ms])?;
        Ok(n)
    }

    pub fn stats(&self, now: i64) -> Result<QueueStats, StoreError> {
        let c = self.conn.lock().unwrap();
        let count = |sql: &str, p: &[&dyn rusqlite::ToSql]| -> rusqlite::Result<i64> { c.query_row(sql, p, |r| r.get(0)) };
        let oldest: Option<i64> = c.query_row("SELECT min(created_at) FROM scan_jobs WHERE state='queued'", [], |r| r.get(0))?;
        Ok(QueueStats {
            queued: count("SELECT count(*) FROM scan_jobs WHERE state='queued'", &[])?,
            scanning: count("SELECT count(*) FROM scan_jobs WHERE state='scanning'", &[])?,
            failed: count("SELECT count(*) FROM scan_jobs WHERE state='failed'", &[])?,
            stuck: count("SELECT count(*) FROM scan_jobs WHERE state='scanning' AND updated_at <= ?1", &[&(now - STUCK_AFTER_MS)])?,
            oldest_queued_seconds: oldest.map(|t| ((now - t) / 1000).max(0)),
            files_scanned: count("SELECT count(*) FROM file_state", &[])?,
            stale_results: count("SELECT count(*) FROM file_state WHERE stale=1", &[])?,
            last_scan_at: c.query_row("SELECT max(scanned_at) FROM file_state WHERE complete=1", [], |r| r.get(0))?,
        })
    }

    pub fn failed_jobs(&self, limit: usize) -> Result<Vec<FailedJob>, StoreError> {
        let c = self.conn.lock().unwrap();
        let mut st = c.prepare("SELECT id, path, source, attempts, last_error, updated_at FROM scan_jobs WHERE state='failed' ORDER BY updated_at DESC LIMIT ?1")?;
        let rows = st.query_map([limit as i64], |r| Ok(FailedJob { id: r.get(0)?, path: r.get(1)?, source: r.get(2)?, attempts: r.get(3)?, last_error: r.get(4)?, updated_at: r.get(5)? }))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// User-initiated retry of a failed job.
    pub fn retry_failed(&self, job_id: &str, now: i64) -> Result<bool, StoreError> {
        let c = self.conn.lock().unwrap();
        // The unique-active index protects against duplicates if a fresh job for the same path already exists.
        let r = c.execute("UPDATE scan_jobs SET state='queued', attempts=0, next_attempt_at=?2, updated_at=?2, last_error=NULL WHERE id=?1 AND state='failed' AND NOT EXISTS (SELECT 1 FROM scan_jobs j WHERE j.key = scan_jobs.key AND j.state IN ('queued','scanning'))", params![job_id, now]);
        Ok(matches!(r, Ok(n) if n > 0))
    }

    /// Is this file currently recorded as scanned, complete, unchanged and not stale?
    pub fn is_current(&self, path: &Path, size: u64, mtime_ms: i64) -> Result<bool, StoreError> {
        let c = self.conn.lock().unwrap();
        let r: Option<i64> = c
            .query_row("SELECT 1 FROM file_state WHERE key=?1 AND size=?2 AND mtime=?3 AND complete=1 AND stale=0", params![path_key(path), size as i64, mtime_ms], |r| r.get(0))
            .optional()?;
        Ok(r.is_some())
    }

    pub fn file_is_stale(&self, path: &Path) -> Result<bool, StoreError> {
        let c = self.conn.lock().unwrap();
        let r: Option<i64> = c.query_row("SELECT stale FROM file_state WHERE key=?1", [path_key(path)], |r| r.get(0)).optional()?;
        Ok(r == Some(1))
    }

    // ---- events -------------------------------------------------------------------------------------------

    pub fn add_event(&self, kind: &str, severity: &str, message: &str, now: i64) {
        let c = self.conn.lock().unwrap();
        let msg: String = message.chars().take(400).collect();
        let _ = c.execute("INSERT INTO events(ts, kind, severity, message) VALUES (?1,?2,?3,?4)", params![now, kind, severity, msg]);
        let _ = c.execute("DELETE FROM events WHERE id <= (SELECT max(id) FROM events) - ?1", [EVENTS_KEPT]);
    }

    pub fn recent_events(&self, limit: usize) -> Result<Vec<EventRow>, StoreError> {
        let c = self.conn.lock().unwrap();
        let mut st = c.prepare("SELECT id, ts, kind, severity, message FROM events ORDER BY id DESC LIMIT ?1")?;
        let rows = st.query_map([limit as i64], |r| Ok(EventRow { id: r.get(0)?, ts: r.get(1)?, kind: r.get(2)?, severity: r.get(3)?, message: r.get(4)? }))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    // ---- kv -----------------------------------------------------------------------------------------------

    pub fn kv_get(&self, key: &str) -> Option<String> {
        self.conn.lock().unwrap().query_row("SELECT value FROM kv WHERE key=?1", [key], |r| r.get(0)).optional().ok().flatten()
    }

    pub fn kv_set(&self, key: &str, value: &str) {
        let _ = self.conn.lock().unwrap().execute("INSERT INTO kv(key, value) VALUES (?1,?2) ON CONFLICT(key) DO UPDATE SET value=?2", params![key, value]);
    }

    pub fn kv_delete(&self, key: &str) {
        let _ = self.conn.lock().unwrap().execute("DELETE FROM kv WHERE key=?1", [key]);
    }

    // ---- outbox -------------------------------------------------------------------------------------------

    /// Queue a notification. `dedupe_key` makes a repeated event a no-op (returns false).
    pub fn enqueue_notification(&self, dedupe_key: &str, kind: &str, text: &str, now: i64) -> Result<bool, StoreError> {
        let (created, full) = {
            let c = self.conn.lock().unwrap();
            let pending: i64 = c.query_row("SELECT count(*) FROM outbox WHERE state='pending'", [], |r| r.get(0))?;
            if pending >= OUTBOX_MAX_PENDING {
                (0, true) // bounded: a Telegram outage must not grow storage without limit
            } else {
                let n = c.execute(
                    "INSERT OR IGNORE INTO outbox(id, dedupe_key, kind, text, state, next_attempt_at, created_at) VALUES (?1,?2,?3,?4,'pending',?5,?5)",
                    params![uuid::Uuid::new_v4().to_string(), dedupe_key, kind, text, now],
                )?;
                (n, false)
            }
        };
        if full {
            // Dropping must be visible, but not once per dropped message (that would flood the event log).
            let last = self.kv_get("outbox_full_at").and_then(|v| v.parse::<i64>().ok()).unwrap_or(i64::MIN);
            if now.saturating_sub(last) > 3_600_000 {
                self.kv_set("outbox_full_at", &now.to_string());
                self.add_event("outbox_full", "warning", "Telegram reports are not being delivered and the queue is full. New reports are being dropped until delivery resumes.", now);
            }
        }
        Ok(created > 0)
    }

    /// Delivered and abandoned messages are kept briefly for the status screen, then deleted: their text can name private files.
    pub fn prune_outbox(&self, now: i64) -> usize {
        self.conn.lock().unwrap().execute("DELETE FROM outbox WHERE state IN ('sent','dead') AND created_at < ?1", [now - OUTBOX_KEEP_MS]).unwrap_or(0)
    }

    pub fn claim_notifications(&self, now: i64, limit: usize) -> Result<Vec<OutboxRow>, StoreError> {
        let c = self.conn.lock().unwrap();
        let mut st = c.prepare("SELECT id, kind, text, state, attempts, last_error, created_at, sent_at FROM outbox WHERE state='pending' AND next_attempt_at <= ?1 ORDER BY created_at LIMIT ?2")?;
        let rows = st.query_map(params![now, limit as i64], outbox_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn notification_sent(&self, id: &str, now: i64) -> Result<(), StoreError> {
        self.conn.lock().unwrap().execute("UPDATE outbox SET state='sent', sent_at=?2, last_error=NULL, text='' WHERE id=?1", params![id, now])?;
        Ok(())
    }

    /// Delivery failed. `retry_after_ms` (Telegram 429) overrides the backoff. After 8 attempts it is marked dead.
    pub fn notification_failed(&self, id: &str, error: &str, retry_after_ms: Option<i64>, now: i64) -> Result<Retry, StoreError> {
        let c = self.conn.lock().unwrap();
        let prior: i64 = c.query_row("SELECT attempts FROM outbox WHERE id=?1", [id], |r| r.get(0))?;
        let attempts = prior + 1;
        let err: String = error.chars().take(300).collect();
        if attempts >= 8 {
            c.execute("UPDATE outbox SET state='dead', attempts=?2, last_error=?3, failed_at=?4 WHERE id=?1", params![id, attempts, err, now])?;
            Ok(Retry::GaveUp)
        } else {
            let at = now + retry_after_ms.unwrap_or_else(|| backoff_ms(attempts));
            c.execute("UPDATE outbox SET attempts=?2, next_attempt_at=?3, last_error=?4, failed_at=?5 WHERE id=?1", params![id, attempts, at, err, now])?;
            Ok(Retry::At(at))
        }
    }

    /// A failure that retrying cannot fix (revoked token, unknown chat): stop immediately and say so.
    pub fn notification_dead(&self, id: &str, error: &str, now: i64) -> Result<(), StoreError> {
        let err: String = error.chars().take(300).collect();
        self.conn.lock().unwrap().execute("UPDATE outbox SET state='dead', attempts=attempts+1, last_error=?2, failed_at=?3 WHERE id=?1", params![id, err, now])?;
        Ok(())
    }

    pub fn outbox_stats(&self, now: i64) -> Result<OutboxStats, StoreError> {
        let c = self.conn.lock().unwrap();
        Ok(OutboxStats {
            pending: c.query_row("SELECT count(*) FROM outbox WHERE state='pending'", [], |r| r.get(0))?,
            failed_24h: c.query_row("SELECT count(*) FROM outbox WHERE failed_at IS NOT NULL AND failed_at >= ?1", [now - 86_400_000], |r| r.get(0))?,
            dead: c.query_row("SELECT count(*) FROM outbox WHERE state='dead'", [], |r| r.get(0))?,
            last_sent_at: c.query_row("SELECT max(sent_at) FROM outbox WHERE state='sent'", [], |r| r.get(0))?,
            last_error: c.query_row("SELECT last_error FROM outbox WHERE last_error IS NOT NULL ORDER BY COALESCE(failed_at, created_at) DESC LIMIT 1", [], |r| r.get(0)).optional()?,
        })
    }

    pub fn recent_notifications(&self, limit: usize) -> Result<Vec<OutboxRow>, StoreError> {
        let c = self.conn.lock().unwrap();
        let mut st = c.prepare("SELECT id, kind, text, state, attempts, last_error, created_at, sent_at FROM outbox ORDER BY created_at DESC LIMIT ?1")?;
        let rows = st.query_map([limit as i64], outbox_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Remove every stored message text (used when the bot is disconnected: messages may name private files).
    pub fn clear_outbox(&self) {
        let _ = self.conn.lock().unwrap().execute("DELETE FROM outbox", []);
    }
}

fn outbox_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<OutboxRow> {
    Ok(OutboxRow { id: r.get(0)?, kind: r.get(1)?, text: r.get(2)?, state: r.get(3)?, attempts: r.get(4)?, last_error: r.get(5)?, created_at: r.get(6)?, sent_at: r.get(7)? })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }
    fn store() -> JobStore {
        JobStore::open_in_memory().unwrap()
    }

    #[test]
    fn repeated_events_for_one_path_make_one_job() {
        let s = store();
        let a = s.enqueue(&p("C:\\d\\a.exe"), "Downloads", 10, 1, 1000).unwrap();
        let Enq::Created(id) = a else { panic!("{a:?}") };
        for _ in 0..50 {
            assert_eq!(s.enqueue(&p("C:\\d\\a.exe"), "Downloads", 10, 1, 1001).unwrap(), Enq::Coalesced(id.clone()));
        }
        assert_eq!(s.stats(2000).unwrap().queued, 1);
    }

    #[test]
    fn path_identity_ignores_case_and_slashes_on_windows() {
        if !cfg!(windows) {
            return;
        }
        let s = store();
        assert!(matches!(s.enqueue(&p("C:\\Users\\X\\Downloads\\A.EXE"), "d", 1, 1, 0).unwrap(), Enq::Created(_)));
        assert!(matches!(s.enqueue(&p("c:/users/x/downloads/a.exe"), "d", 1, 1, 0).unwrap(), Enq::Coalesced(_)));
    }

    #[test]
    fn unchanged_complete_files_are_skipped_but_changed_ones_go_stale_and_requeue() {
        let s = store();
        let Enq::Created(id) = s.enqueue(&p("C:\\d\\f.bin"), "d", 10, 5, 0).unwrap() else { panic!() };
        let job = s.claim_due(0, 10).unwrap().remove(0);
        assert_eq!(job.id, id);
        assert!(!s.complete(&id, "r1", "CLEAN", &"a".repeat(64), 10, 5, true, 10).unwrap());
        assert_eq!(s.enqueue(&p("C:\\d\\f.bin"), "d", 10, 5, 20).unwrap(), Enq::SkippedUnchanged);
        assert!(s.is_current(&p("C:\\d\\f.bin"), 10, 5).unwrap());
        // The file is modified.
        assert!(matches!(s.enqueue(&p("C:\\d\\f.bin"), "d", 11, 6, 30).unwrap(), Enq::Created(_)));
        assert!(s.file_is_stale(&p("C:\\d\\f.bin")).unwrap(), "the previous CLEAN no longer describes the file");
        assert!(!s.is_current(&p("C:\\d\\f.bin"), 10, 5).unwrap());
        assert_eq!(s.stats(40).unwrap().stale_results, 1);
    }

    #[test]
    fn incomplete_results_are_never_treated_as_current() {
        let s = store();
        let Enq::Created(id) = s.enqueue(&p("C:\\d\\g.bin"), "d", 1, 1, 0).unwrap() else { panic!() };
        s.claim_due(0, 1).unwrap();
        s.complete(&id, "r", "UNABLE_TO_VERIFY", "", 1, 1, false, 5).unwrap();
        assert!(matches!(s.enqueue(&p("C:\\d\\g.bin"), "d", 1, 1, 10).unwrap(), Enq::Created(_)), "an incomplete scan must be retried, not skipped");
    }

    #[test]
    fn a_change_during_a_scan_requeues_it_and_marks_the_result_stale() {
        let s = store();
        let Enq::Created(id) = s.enqueue(&p("C:\\d\\h.exe"), "d", 10, 1, 0).unwrap() else { panic!() };
        s.claim_due(0, 1).unwrap();
        // The file is rewritten while the worker is scanning the old content.
        assert_eq!(s.enqueue(&p("C:\\d\\h.exe"), "d", 99, 2, 5).unwrap(), Enq::Coalesced(id.clone()));
        assert!(s.complete(&id, "r", "CLEAN", &"b".repeat(64), 10, 1, true, 10).unwrap(), "must be re-queued");
        assert!(s.file_is_stale(&p("C:\\d\\h.exe")).unwrap());
        let again = s.claim_due(10, 1).unwrap();
        assert_eq!(again.len(), 1);
        assert_eq!(again[0].enqueue_size, 99);
    }

    #[test]
    fn transient_failures_back_off_and_eventually_give_up_visibly() {
        let s = store();
        let Enq::Created(id) = s.enqueue(&p("C:\\d\\locked.bin"), "d", 1, 1, 0).unwrap() else { panic!() };
        let mut now = 0;
        for attempt in 1..MAX_ATTEMPTS {
            assert_eq!(s.claim_due(now, 1).unwrap().len(), 1, "attempt {attempt} must be due");
            let r = s.fail_transient(&id, "file is locked", now).unwrap();
            let Retry::At(at) = r else { panic!("gave up too early at {attempt}") };
            assert_eq!(at - now, backoff_ms(attempt));
            assert!(s.claim_due(now, 1).unwrap().is_empty(), "not due again before its backoff has passed");
            now = at;
        }
        assert_eq!(s.claim_due(now, 1).unwrap().len(), 1);
        assert_eq!(s.fail_transient(&id, "file is locked", now).unwrap(), Retry::GaveUp);
        let failed = s.failed_jobs(10).unwrap();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].last_error.as_deref(), Some("file is locked"));
        assert_eq!(s.stats(now).unwrap().failed, 1);
    }

    #[test]
    fn deferring_does_not_consume_attempts_and_discarding_leaves_no_failure() {
        let s = store();
        let Enq::Created(id) = s.enqueue(&p("C:\\d\\growing.bin"), "d", 1, 1, 0).unwrap() else { panic!() };
        for _ in 0..20 {
            assert_eq!(s.claim_due(1_000_000, 1).unwrap().len(), 1);
            s.defer(&id, 1_000_000, 1_000_000).unwrap();
        }
        let j = s.claim_due(1_000_000, 1).unwrap().remove(0);
        assert_eq!(j.attempts, 0, "waiting for a download to finish is not a failure");
        s.discard(&id, 5).unwrap();
        let st = s.stats(5).unwrap();
        assert_eq!((st.queued, st.scanning, st.failed), (0, 0, 0));
    }

    #[test]
    fn backoff_grows_and_is_capped() {
        assert!(backoff_ms(1) < backoff_ms(2) && backoff_ms(2) < backoff_ms(6));
        assert_eq!(backoff_ms(6), backoff_ms(50));
    }

    #[test]
    fn jobs_stuck_in_scanning_are_recovered_after_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("p.db");
        {
            let s = JobStore::open(&db).unwrap();
            s.enqueue(&p("C:\\d\\a.bin"), "d", 1, 1, 0).unwrap();
            s.enqueue(&p("C:\\d\\b.bin"), "d", 1, 1, 0).unwrap();
            assert_eq!(s.claim_due(0, 10).unwrap().len(), 2); // process "crashes" here with both mid-scan
        }
        let s = JobStore::open(&db).unwrap(); // restart
        assert_eq!(s.stats(1).unwrap().scanning, 2);
        assert_eq!(s.stats(STUCK_AFTER_MS + 5).unwrap().stuck, 2, "runtime watchdog sees them as stuck");
        assert_eq!(s.recover_stuck(100, 0).unwrap(), 2);
        let st = s.stats(100).unwrap();
        assert_eq!((st.queued, st.scanning), (2, 0));
        assert_eq!(s.claim_due(100, 10).unwrap().len(), 2);
    }

    #[test]
    fn the_queue_is_bounded() {
        let s = store();
        {
            let c = s.conn.lock().unwrap();
            let mut ins = c.prepare("INSERT INTO scan_jobs(id,path,key,source,state,next_attempt_at,enqueue_size,enqueue_mtime,created_at,updated_at) VALUES (?1,?1,?1,'d','queued',0,1,1,0,0)").unwrap();
            for i in 0..MAX_QUEUED {
                ins.execute([format!("p{i}")]).unwrap();
            }
        }
        assert_eq!(s.enqueue(&p("C:\\one-too-many.bin"), "d", 1, 1, 0).unwrap(), Enq::Overflow);
    }

    #[test]
    fn retry_failed_requeues_once_and_never_duplicates() {
        let s = store();
        let Enq::Created(id) = s.enqueue(&p("C:\\d\\x.bin"), "d", 1, 1, 0).unwrap() else { panic!() };
        s.claim_due(0, 1).unwrap();
        s.fail_permanent(&id, "gone", 1).unwrap();
        assert!(matches!(s.enqueue(&p("C:\\d\\x.bin"), "d", 1, 1, 2).unwrap(), Enq::Created(_)), "a new event creates a fresh job");
        assert!(!s.retry_failed(&id, 3).unwrap(), "must not resurrect a duplicate of an active job");
    }

    #[test]
    fn notifications_dedupe_retry_and_die_visibly() {
        let s = store();
        assert!(s.enqueue_notification("malicious:abc", "malicious", "text", 0).unwrap());
        assert!(!s.enqueue_notification("malicious:abc", "malicious", "text", 1).unwrap(), "same event must not be sent twice");
        let due = s.claim_notifications(0, 10).unwrap();
        assert_eq!(due.len(), 1);
        // A Telegram 429 with retry_after is honoured over the default backoff.
        assert_eq!(s.notification_failed(&due[0].id, "429", Some(30_000), 0).unwrap(), Retry::At(30_000));
        assert!(s.claim_notifications(29_999, 10).unwrap().is_empty());
        assert_eq!(s.claim_notifications(30_000, 10).unwrap().len(), 1);
        let mut now = 30_000;
        let mut gave_up = false;
        for _ in 0..10 {
            if s.notification_failed(&due[0].id, "network down", None, now).unwrap() == Retry::GaveUp {
                gave_up = true;
                break;
            }
            now += 10_000_000;
        }
        assert!(gave_up);
        let st = s.outbox_stats(now).unwrap();
        assert_eq!((st.pending, st.dead), (0, 1));
        assert_eq!(st.last_error.as_deref(), Some("network down"));
    }

    #[test]
    fn delivery_failures_never_touch_scan_state() {
        let s = store();
        let Enq::Created(id) = s.enqueue(&p("C:\\d\\m.exe"), "d", 1, 1, 0).unwrap() else { panic!() };
        s.claim_due(0, 1).unwrap();
        s.complete(&id, "r", "MALICIOUS", &"c".repeat(64), 1, 1, true, 1).unwrap();
        s.enqueue_notification("k", "malicious", "x", 1).unwrap();
        let n = s.claim_notifications(1, 1).unwrap();
        for _ in 0..8 {
            let _ = s.notification_failed(&n[0].id, "boom", None, 1);
        }
        let c = s.conn.lock().unwrap();
        let v: String = c.query_row("SELECT verdict FROM file_state WHERE key = ?1", [path_key(&p("C:\\d\\m.exe"))], |r| r.get(0)).unwrap();
        assert_eq!(v, "MALICIOUS");
    }

    #[test]
    fn outbox_is_bounded_and_clearable() {
        let s = store();
        let mut accepted = 0;
        for i in 0..1100 {
            if s.enqueue_notification(&format!("k{i}"), "malicious", "t", 0).unwrap() {
                accepted += 1;
            }
        }
        assert_eq!(accepted, 1000);
        s.clear_outbox();
        assert_eq!(s.outbox_stats(0).unwrap().pending, 0);
    }

    #[test]
    fn delivered_text_is_erased_and_old_rows_pruned() {
        let s = store();
        s.enqueue_notification("a", "malicious", "private-name.exe is malicious", 0).unwrap();
        let n = s.claim_notifications(0, 1).unwrap();
        s.notification_sent(&n[0].id, 1).unwrap();
        let text: String = s.conn.lock().unwrap().query_row("SELECT text FROM outbox", [], |r| r.get(0)).unwrap();
        assert_eq!(text, "", "a delivered message's text must not be kept");
        assert_eq!(s.prune_outbox(OUTBOX_KEEP_MS - 1), 0, "recent rows stay for the status screen");
        assert_eq!(s.prune_outbox(OUTBOX_KEEP_MS + 1), 1);
    }

    #[test]
    fn dropping_because_the_outbox_is_full_is_visible_once() {
        let s = store();
        for i in 0..(OUTBOX_MAX_PENDING + 20) {
            let _ = s.enqueue_notification(&format!("k{i}"), "malicious", "t", 5);
        }
        let n = s.recent_events(50).unwrap().iter().filter(|e| e.kind == "outbox_full").count();
        assert_eq!(n, 1);
    }

    #[test]
    fn events_are_capped_and_newest_first() {
        let s = store();
        for i in 0..1100 {
            s.add_event("k", "info", &format!("e{i}"), i);
        }
        let ev = s.recent_events(5).unwrap();
        assert_eq!(ev[0].message, "e1099");
        let n: i64 = s.conn.lock().unwrap().query_row("SELECT count(*) FROM events", [], |r| r.get(0)).unwrap();
        assert!(n <= EVENTS_KEPT + 1);
    }

    #[test]
    fn kv_roundtrip() {
        let s = store();
        assert_eq!(s.kv_get("a"), None);
        s.kv_set("a", "1");
        s.kv_set("a", "2");
        assert_eq!(s.kv_get("a").as_deref(), Some("2"));
        s.kv_delete("a");
        assert_eq!(s.kv_get("a"), None);
    }
}
