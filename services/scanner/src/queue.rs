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
    /// None means the owner's own chat; Some is a group the bot was added to.
    #[serde(skip)]
    pub chat_id: Option<i64>,
    #[serde(skip)]
    pub reply_to: Option<i64>,
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
    pub(crate) conn: Mutex<Connection>,
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
CREATE TABLE IF NOT EXISTS tg_groups(
  chat_id INTEGER PRIMARY KEY, title TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL DEFAULT 'group',
  enabled INTEGER NOT NULL DEFAULT 0, auto_delete INTEGER NOT NULL DEFAULT 0,
  report_clean INTEGER NOT NULL DEFAULT 0, report_incomplete INTEGER NOT NULL DEFAULT 1,
  enabled_by INTEGER, enabled_at INTEGER, delete_consent_by INTEGER, delete_consent_at INTEGER,
  bot_status TEXT NOT NULL DEFAULT 'member', joined_at INTEGER NOT NULL, left_at INTEGER
);
CREATE TABLE IF NOT EXISTS tg_group_scans(
  id INTEGER PRIMARY KEY AUTOINCREMENT, chat_id INTEGER NOT NULL, message_id INTEGER NOT NULL,
  file_unique_id TEXT, sha256 TEXT, size INTEGER, verdict TEXT NOT NULL, complete INTEGER NOT NULL,
  outcome TEXT NOT NULL, action TEXT, ts INTEGER NOT NULL, UNIQUE(chat_id, message_id)
);
CREATE INDEX IF NOT EXISTS tg_group_scans_chat ON tg_group_scans(chat_id, ts);
-- Shared (hosted) bot: people who pressed Start, one-time link codes, and desktop apps linked to a person's chat.
CREATE TABLE IF NOT EXISTS tg_users(
  user_id INTEGER PRIMARY KEY, first_name TEXT NOT NULL DEFAULT '', started_at INTEGER NOT NULL, blocked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS link_codes(
  code TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('group','device')), user_id INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, used_at INTEGER
);
CREATE TABLE IF NOT EXISTS relay_devices(
  id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, token_hash TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
  created_at INTEGER NOT NULL, last_seen_at INTEGER, revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS relay_devices_user ON relay_devices(user_id);
"#;

/// Columns added after the first release. Existing databases are upgraded in place.
fn migrate(c: &Connection) -> Result<(), StoreError> {
    let has = |table: &str, col: &str| -> Result<bool, StoreError> {
        let mut st = c.prepare(&format!("PRAGMA table_info({table})"))?;
        let names = st.query_map([], |r| r.get::<_, String>(1))?.collect::<Result<Vec<_>, _>>()?;
        Ok(names.iter().any(|n| n == col))
    };
    if !has("outbox", "chat_id")? {
        c.execute("ALTER TABLE outbox ADD COLUMN chat_id INTEGER", [])?;
    }
    if !has("outbox", "reply_to")? {
        c.execute("ALTER TABLE outbox ADD COLUMN reply_to INTEGER", [])?;
    }
    Ok(())
}

impl JobStore {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let c = Connection::open(path)?;
        c.pragma_update(None, "journal_mode", "WAL")?;
        c.pragma_update(None, "synchronous", "NORMAL")?;
        c.busy_timeout(std::time::Duration::from_secs(5))?;
        c.execute_batch(SCHEMA)?;
        migrate(&c)?;
        Ok(JobStore { conn: Mutex::new(c) })
    }

    pub fn open_in_memory() -> Result<Self, StoreError> {
        let c = Connection::open_in_memory()?;
        c.execute_batch(SCHEMA)?;
        migrate(&c)?;
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
        self.enqueue_notification_to(dedupe_key, kind, text, now, None, None)
    }

    /// Queue a message for the owner's chat (`chat_id` None) or for a group, optionally as a reply to `reply_to`.
    pub fn enqueue_notification_to(&self, dedupe_key: &str, kind: &str, text: &str, now: i64, chat_id: Option<i64>, reply_to: Option<i64>) -> Result<bool, StoreError> {
        let (created, full) = {
            let c = self.conn.lock().unwrap();
            let pending: i64 = c.query_row("SELECT count(*) FROM outbox WHERE state='pending'", [], |r| r.get(0))?;
            if pending >= OUTBOX_MAX_PENDING {
                (0, true) // bounded: a Telegram outage must not grow storage without limit
            } else {
                let n = c.execute(
                    "INSERT OR IGNORE INTO outbox(id, dedupe_key, kind, text, state, next_attempt_at, created_at, chat_id, reply_to) VALUES (?1,?2,?3,?4,'pending',?5,?5,?6,?7)",
                    params![uuid::Uuid::new_v4().to_string(), dedupe_key, kind, text, now, chat_id, reply_to],
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
        let mut st = c.prepare("SELECT id, kind, text, state, attempts, last_error, created_at, sent_at, chat_id, reply_to FROM outbox WHERE state='pending' AND next_attempt_at <= ?1 ORDER BY created_at LIMIT ?2")?;
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
        let mut st = c.prepare("SELECT id, kind, text, state, attempts, last_error, created_at, sent_at, chat_id, reply_to FROM outbox ORDER BY created_at DESC LIMIT ?1")?;
        let rows = st.query_map([limit as i64], outbox_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }


    // ---- Telegram groups (Group Shield) -------------------------------------------------------------------
    //
    // Everything here is keyed by the group's chat id and every query filters on it, so one group's settings, history and
    // counts can never be read or changed through another group. File names and message text are not stored: only the
    // file's hash, size, verdict and what was done about it.

    pub fn group_joined(&self, chat_id: i64, title: &str, kind: &str, bot_status: &str, now: i64) -> Result<(), StoreError> {
        let title: String = title.chars().filter(|c| !c.is_control()).take(120).collect();
        self.conn.lock().unwrap().execute(
            "INSERT INTO tg_groups(chat_id, title, kind, bot_status, joined_at) VALUES (?1,?2,?3,?4,?5)
             ON CONFLICT(chat_id) DO UPDATE SET title=?2, kind=?3, bot_status=?4, left_at=NULL",
            params![chat_id, title, kind, bot_status, now],
        )?;
        Ok(())
    }

    /// The bot was removed (or can no longer post). Settings are kept, but protection is switched off so re-adding the bot
    /// does not silently re-enable anything.
    pub fn group_left(&self, chat_id: i64, now: i64) -> Result<(), StoreError> {
        self.conn.lock().unwrap().execute("UPDATE tg_groups SET left_at=?2, enabled=0, auto_delete=0, bot_status='left' WHERE chat_id=?1", params![chat_id, now])?;
        Ok(())
    }

    pub fn group_set_status(&self, chat_id: i64, bot_status: &str) -> Result<(), StoreError> {
        self.conn.lock().unwrap().execute("UPDATE tg_groups SET bot_status=?2 WHERE chat_id=?1", params![chat_id, bot_status])?;
        Ok(())
    }

    pub fn group_get(&self, chat_id: i64) -> Result<Option<Group>, StoreError> {
        let c = self.conn.lock().unwrap();
        Ok(c.query_row(GROUP_SELECT_ONE, [chat_id], group_row).optional()?)
    }

    pub fn groups_list(&self) -> Result<Vec<Group>, StoreError> {
        let c = self.conn.lock().unwrap();
        let mut st = c.prepare(&format!("{GROUP_SELECT} ORDER BY title COLLATE NOCASE"))?;
        let rows = st.query_map([], group_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn group_set_enabled(&self, chat_id: i64, on: bool, by: i64, now: i64) -> Result<bool, StoreError> {
        let n = self.conn.lock().unwrap().execute(
            "UPDATE tg_groups SET enabled=?2, enabled_by=?3, enabled_at=?4, auto_delete = CASE WHEN ?2=0 THEN 0 ELSE auto_delete END WHERE chat_id=?1 AND left_at IS NULL",
            params![chat_id, on as i64, by, now],
        )?;
        Ok(n > 0)
    }

    /// Turning deletion on records who agreed and when; turning it off clears that consent.
    pub fn group_set_auto_delete(&self, chat_id: i64, on: bool, by: i64, now: i64) -> Result<bool, StoreError> {
        let c = self.conn.lock().unwrap();
        let n = if on {
            c.execute("UPDATE tg_groups SET auto_delete=1, delete_consent_by=?2, delete_consent_at=?3 WHERE chat_id=?1 AND enabled=1 AND left_at IS NULL", params![chat_id, by, now])?
        } else {
            c.execute("UPDATE tg_groups SET auto_delete=0, delete_consent_by=NULL, delete_consent_at=NULL WHERE chat_id=?1", params![chat_id])?
        };
        Ok(n > 0)
    }

    pub fn group_set_report(&self, chat_id: i64, clean: Option<bool>, incomplete: Option<bool>) -> Result<(), StoreError> {
        let c = self.conn.lock().unwrap();
        if let Some(v) = clean {
            c.execute("UPDATE tg_groups SET report_clean=?2 WHERE chat_id=?1", params![chat_id, v as i64])?;
        }
        if let Some(v) = incomplete {
            c.execute("UPDATE tg_groups SET report_incomplete=?2 WHERE chat_id=?1", params![chat_id, v as i64])?;
        }
        Ok(())
    }

    /// Has this message already been handled? (Telegram can redeliver updates.)
    pub fn group_scan_seen(&self, chat_id: i64, message_id: i64) -> Result<bool, StoreError> {
        let c = self.conn.lock().unwrap();
        Ok(c.query_row("SELECT 1 FROM tg_group_scans WHERE chat_id=?1 AND message_id=?2", params![chat_id, message_id], |_| Ok(())).optional()?.is_some())
    }

    /// Record the outcome for one message. Returns false if that message was already recorded.
    #[allow(clippy::too_many_arguments)]
    pub fn group_record_scan(&self, chat_id: i64, message_id: i64, file_unique_id: Option<&str>, sha256: &str, size: u64, verdict: &str, complete: bool, outcome: &str, action: Option<&str>, now: i64) -> Result<bool, StoreError> {
        let n = self.conn.lock().unwrap().execute(
            "INSERT OR IGNORE INTO tg_group_scans(chat_id, message_id, file_unique_id, sha256, size, verdict, complete, outcome, action, ts) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![chat_id, message_id, file_unique_id, sha256, size as i64, verdict, complete as i64, outcome, action, now],
        )?;
        Ok(n > 0)
    }

    pub fn group_stats(&self, chat_id: i64, since: i64) -> Result<GroupStats, StoreError> {
        let c = self.conn.lock().unwrap();
        let n = |sql: &str| -> Result<i64, StoreError> { Ok(c.query_row(sql, params![chat_id, since], |r| r.get(0))?) };
        Ok(GroupStats {
            scans: n("SELECT count(*) FROM tg_group_scans WHERE chat_id=?1 AND ts>=?2 AND outcome='scanned'")?,
            threats: n("SELECT count(*) FROM tg_group_scans WHERE chat_id=?1 AND ts>=?2 AND verdict='MALICIOUS'")?,
            suspicious: n("SELECT count(*) FROM tg_group_scans WHERE chat_id=?1 AND ts>=?2 AND verdict='SUSPICIOUS'")?,
            // Scanned but not completely checked. Skipped and failed files are counted separately, never twice.
            unverified: n("SELECT count(*) FROM tg_group_scans WHERE chat_id=?1 AND ts>=?2 AND outcome='scanned' AND verdict='UNABLE_TO_VERIFY'")?,
            skipped: n("SELECT count(*) FROM tg_group_scans WHERE chat_id=?1 AND ts>=?2 AND outcome IN ('skipped_size','skipped_rate')")?,
            errors: n("SELECT count(*) FROM tg_group_scans WHERE chat_id=?1 AND ts>=?2 AND outcome IN ('unavailable','error')")?,
            last_scan_at: c.query_row("SELECT max(ts) FROM tg_group_scans WHERE chat_id=?1 AND outcome='scanned'", [chat_id], |r| r.get(0))?,
        })
    }

    /// Counts across all groups, for the optional console heartbeat. Numbers only: no ids, titles or names.
    pub fn group_totals(&self, since: i64) -> Result<GroupTotals, StoreError> {
        let c = self.conn.lock().unwrap();
        let n = |sql: &str, p: &[&dyn rusqlite::ToSql]| -> Result<i64, StoreError> { Ok(c.query_row(sql, p, |r| r.get(0))?) };
        Ok(GroupTotals {
            registered: n("SELECT count(*) FROM tg_groups WHERE left_at IS NULL", &[])?,
            protected: n("SELECT count(*) FROM tg_groups WHERE left_at IS NULL AND enabled=1", &[])?,
            auto_delete: n("SELECT count(*) FROM tg_groups WHERE left_at IS NULL AND enabled=1 AND auto_delete=1", &[])?,
            scans: n("SELECT count(*) FROM tg_group_scans WHERE ts>=?1 AND outcome='scanned'", &[&since])?,
            threats: n("SELECT count(*) FROM tg_group_scans WHERE ts>=?1 AND verdict='MALICIOUS'", &[&since])?,
            errors: n("SELECT count(*) FROM tg_group_scans WHERE ts>=?1 AND outcome IN ('unavailable','error')", &[&since])?,
        })
    }

    pub fn group_forget(&self, chat_id: i64) -> Result<(), StoreError> {
        let c = self.conn.lock().unwrap();
        c.execute("DELETE FROM tg_group_scans WHERE chat_id=?1", [chat_id])?;
        c.execute("DELETE FROM tg_groups WHERE chat_id=?1", [chat_id])?;
        c.execute("DELETE FROM outbox WHERE chat_id=?1", [chat_id])?;
        Ok(())
    }

    /// Used when the bot is disconnected: nothing about the groups should outlive the credentials.
    pub fn groups_clear(&self) {
        let c = self.conn.lock().unwrap();
        let _ = c.execute("DELETE FROM tg_group_scans", []);
        let _ = c.execute("DELETE FROM tg_groups", []);
    }

    pub fn prune_group_scans(&self, now: i64) -> usize {
        self.conn.lock().unwrap().execute("DELETE FROM tg_group_scans WHERE ts < ?1", [now - 30 * 86_400_000]).unwrap_or(0)
    }

    /// Remove every stored message text (used when the bot is disconnected: messages may name private files).
    pub fn clear_outbox(&self) {
        let _ = self.conn.lock().unwrap().execute("DELETE FROM outbox", []);
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    #[serde(skip)]
    pub chat_id: i64,
    pub title: String,
    pub kind: String,
    pub enabled: bool,
    pub auto_delete: bool,
    pub report_clean: bool,
    pub report_incomplete: bool,
    #[serde(skip)]
    pub enabled_by: Option<i64>,
    pub enabled_at: Option<i64>,
    #[serde(skip)]
    pub delete_consent_by: Option<i64>,
    pub delete_consent_at: Option<i64>,
    /// What the bot is in that group: member, administrator, left.
    pub bot_status: String,
    pub joined_at: i64,
    pub left_at: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupStats {
    pub scans: i64,
    pub threats: i64,
    pub suspicious: i64,
    pub unverified: i64,
    pub skipped: i64,
    pub errors: i64,
    pub last_scan_at: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupTotals {
    pub registered: i64,
    pub protected: i64,
    pub auto_delete: i64,
    pub scans: i64,
    pub threats: i64,
    pub errors: i64,
}

const GROUP_SELECT: &str = "SELECT chat_id, title, kind, enabled, auto_delete, report_clean, report_incomplete, enabled_by, enabled_at, delete_consent_by, delete_consent_at, bot_status, joined_at, left_at FROM tg_groups";
const GROUP_SELECT_ONE: &str = "SELECT chat_id, title, kind, enabled, auto_delete, report_clean, report_incomplete, enabled_by, enabled_at, delete_consent_by, delete_consent_at, bot_status, joined_at, left_at FROM tg_groups WHERE chat_id = ?1";

fn group_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Group> {
    Ok(Group {
        chat_id: r.get(0)?,
        title: r.get(1)?,
        kind: r.get(2)?,
        enabled: r.get::<_, i64>(3)? == 1,
        auto_delete: r.get::<_, i64>(4)? == 1,
        report_clean: r.get::<_, i64>(5)? == 1,
        report_incomplete: r.get::<_, i64>(6)? == 1,
        enabled_by: r.get(7)?,
        enabled_at: r.get(8)?,
        delete_consent_by: r.get(9)?,
        delete_consent_at: r.get(10)?,
        bot_status: r.get(11)?,
        joined_at: r.get(12)?,
        left_at: r.get(13)?,
    })
}

fn outbox_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<OutboxRow> {
    Ok(OutboxRow { id: r.get(0)?, kind: r.get(1)?, text: r.get(2)?, state: r.get(3)?, attempts: r.get(4)?, last_error: r.get(5)?, created_at: r.get(6)?, sent_at: r.get(7)?, chat_id: r.get(8)?, reply_to: r.get(9)? })
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
