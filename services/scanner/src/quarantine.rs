//! Secure quarantine.
//!
//!  * Contents are encrypted (ChaCha20-Poly1305) into `<dir>/blobs/<uuid>.sxq`, so a quarantined file cannot be
//!    executed, opened by a shell association, or re-flagged by other scanners, and ordinary tools cannot read it.
//!  * The key lives in `<dir>/.key`, wrapped with Windows DPAPI (bound to the user account) on Windows.
//!  * Metadata (`<dir>/meta/<uuid>.json`) carries an HMAC so tampering is detected; tampered records can't be restored.
//!  * Every action is appended to a hash-chained audit log.
//!  * File names inside the vault are always generated UUIDs. Attacker-controlled names/paths are stored as data only
//!    and are sanitised before being used for a restore destination. Links are never followed.

use crate::types::Verdict;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

pub const MAX_QUARANTINE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum QuarantineError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("refusing to quarantine a symbolic link or junction")]
    IsLink,
    #[error("not a regular file")]
    NotAFile,
    #[error("file is too large to quarantine safely ({0} bytes)")]
    TooLarge(u64),
    #[error("the file changed after it was scanned; scan it again before quarantining")]
    ChangedSinceScan,
    #[error("quarantine record not found")]
    NotFound,
    #[error("quarantine record failed its integrity check and cannot be used")]
    Tampered,
    #[error("invalid quarantine id")]
    BadId,
    #[error("record is not active (state: {0:?})")]
    NotActive(State),
    #[error("restoring a file classified as MALICIOUS requires explicit confirmation")]
    NeedsConfirmation,
    #[error("restoring a SUSPICIOUS file is disabled by policy")]
    RestoreBlockedByPolicy,
    #[error("the vault copy failed verification; the original was left untouched")]
    VerifyFailed,
    #[error("the stored file failed its integrity check (SHA-256 mismatch or corruption)")]
    Corrupt,
    #[error("the destination folder is invalid or is a link")]
    BadDestination,
    #[error("could not remove the original file after copying it ({0}); nothing was quarantined")]
    CouldNotRemoveOriginal(String),
    #[error("key protection failed: {0}")]
    Key(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Quarantined,
    Restored,
    Deleted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub id: Uuid,
    pub original_path: PathBuf,
    pub original_name: String,
    pub sha256: String,
    pub size: u64,
    pub verdict: Verdict,
    pub reason: String,
    pub detected_type: String,
    pub quarantined_at: DateTime<Utc>,
    pub state: State,
}

#[derive(Serialize, Deserialize)]
struct StoredMeta {
    record: Record,
    mac: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListedRecord {
    #[serde(flatten)]
    pub record: Record,
    /// True if the metadata failed its HMAC check. Such entries are shown but can only be deleted.
    pub tampered: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct RestoreOptions {
    /// User explicitly confirmed (elevated confirmation) restoring a MALICIOUS file.
    pub confirm_malicious: bool,
    /// Policy: may users restore SUSPICIOUS files?
    pub allow_suspicious: bool,
}

pub struct Quarantine {
    dir: PathBuf,
    key: [u8; 32],
}

impl Quarantine {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, QuarantineError> {
        let dir = dir.into();
        fs::create_dir_all(dir.join("blobs"))?;
        fs::create_dir_all(dir.join("meta"))?;
        let key = load_or_create_key(&dir.join(".key"))?;
        Ok(Quarantine { dir, key })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn blob(&self, id: Uuid) -> PathBuf {
        self.dir.join("blobs").join(format!("{id}.sxq"))
    }
    fn meta(&self, id: Uuid) -> PathBuf {
        self.dir.join("meta").join(format!("{id}.json"))
    }

    fn mac_key(&self) -> [u8; 32] {
        let mut m = <HmacSha256 as Mac>::new_from_slice(&self.key).unwrap();
        m.update(b"sentrix-quarantine-meta-v1");
        m.finalize().into_bytes().into()
    }

    fn mac(&self, r: &Record) -> String {
        let mut m = <HmacSha256 as Mac>::new_from_slice(&self.mac_key()).unwrap();
        m.update(serde_json::to_string(r).unwrap().as_bytes());
        hex::encode(m.finalize().into_bytes())
    }

    fn verify_mac(&self, s: &StoredMeta) -> bool {
        let Ok(expect) = hex::decode(&s.mac) else { return false };
        let mut m = <HmacSha256 as Mac>::new_from_slice(&self.mac_key()).unwrap();
        m.update(serde_json::to_string(&s.record).unwrap().as_bytes());
        m.verify_slice(&expect).is_ok()
    }

    fn write_meta(&self, r: &Record) -> Result<(), QuarantineError> {
        let stored = StoredMeta { record: r.clone(), mac: self.mac(r) };
        let tmp = self.meta(r.id).with_extension("tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(&stored).unwrap())?;
        fs::rename(&tmp, self.meta(r.id))?;
        Ok(())
    }

    fn load(&self, id: Uuid) -> Result<(Record, bool), QuarantineError> {
        let bytes = fs::read(self.meta(id)).map_err(|e| if e.kind() == std::io::ErrorKind::NotFound { QuarantineError::NotFound } else { e.into() })?;
        let s: StoredMeta = serde_json::from_slice(&bytes).map_err(|_| QuarantineError::Tampered)?;
        let ok = s.record.id == id && self.verify_mac(&s);
        Ok((s.record, ok))
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::from_slice(&self.key))
    }

    /// Move a scanned file into the vault. `expected_sha256` (from the scan report) guards against a swap after scanning.
    pub fn quarantine(&self, path: &Path, expected_sha256: Option<&str>, verdict: Verdict, reason: &str, detected_type: &str) -> Result<Record, QuarantineError> {
        let lm = fs::symlink_metadata(path)?;
        if is_link_like(&lm) {
            return Err(QuarantineError::IsLink);
        }
        if !lm.is_file() {
            return Err(QuarantineError::NotAFile);
        }
        if lm.len() > MAX_QUARANTINE_BYTES {
            return Err(QuarantineError::TooLarge(lm.len()));
        }
        let mut f = File::open(path)?;
        let mut data = Vec::with_capacity(lm.len() as usize);
        (&mut f).take(MAX_QUARANTINE_BYTES + 1).read_to_end(&mut data)?;
        let sha = hex::encode(Sha256::digest(&data));
        if let Some(exp) = expected_sha256 {
            if !exp.eq_ignore_ascii_case(&sha) {
                return Err(QuarantineError::ChangedSinceScan);
            }
        }

        let id = Uuid::new_v4();
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ct = self
            .cipher()
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: &data, aad: id.as_bytes() })
            .map_err(|_| QuarantineError::VerifyFailed)?;
        {
            let mut out = OpenOptions::new().write(true).create_new(true).open(self.blob(id))?;
            out.write_all(&nonce)?;
            out.write_all(&ct)?;
            out.sync_all()?;
        }
        // Verify the vault copy before touching the original.
        match self.read_blob(id) {
            Ok(back) if hex::encode(Sha256::digest(&back)) == sha => {}
            _ => {
                let _ = fs::remove_file(self.blob(id));
                return Err(QuarantineError::VerifyFailed);
            }
        }

        let record = Record {
            id,
            original_path: path.to_path_buf(),
            original_name: path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default(),
            sha256: sha,
            size: data.len() as u64,
            verdict,
            reason: reason.chars().take(500).collect(),
            detected_type: detected_type.to_string(),
            quarantined_at: Utc::now(),
            state: State::Quarantined,
        };
        if let Err(e) = self.write_meta(&record) {
            let _ = fs::remove_file(self.blob(id));
            return Err(e);
        }
        drop(f);
        if let Err(e) = fs::remove_file(path) {
            // Do not leave a half-quarantined state: the user would see the file gone from the list but still on disk.
            let _ = fs::remove_file(self.blob(id));
            let _ = fs::remove_file(self.meta(id));
            return Err(QuarantineError::CouldNotRemoveOriginal(e.to_string()));
        }
        self.audit("quarantine", &record, "")?;
        Ok(record)
    }

    fn read_blob(&self, id: Uuid) -> Result<Vec<u8>, QuarantineError> {
        let raw = fs::read(self.blob(id))?;
        if raw.len() < 12 + 16 {
            return Err(QuarantineError::Corrupt);
        }
        let (nonce, ct) = raw.split_at(12);
        self.cipher().decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: id.as_bytes() }).map_err(|_| QuarantineError::Corrupt)
    }

    pub fn list(&self) -> Result<Vec<ListedRecord>, QuarantineError> {
        let mut out = Vec::new();
        for e in fs::read_dir(self.dir.join("meta"))?.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) != Some("json") {
                continue;
            }
            let Some(id) = p.file_stem().and_then(|s| s.to_str()).and_then(|s| Uuid::parse_str(s).ok()) else { continue };
            match self.load(id) {
                Ok((record, ok)) => out.push(ListedRecord { record, tampered: !ok }),
                Err(_) => continue,
            }
        }
        out.sort_by(|a, b| b.record.quarantined_at.cmp(&a.record.quarantined_at));
        Ok(out)
    }

    /// Restore into `dest_dir` (never overwriting). Returns the path written.
    pub fn restore(&self, id_str: &str, dest_dir: &Path, opts: RestoreOptions) -> Result<PathBuf, QuarantineError> {
        let id = Uuid::parse_str(id_str).map_err(|_| QuarantineError::BadId)?;
        let (mut rec, ok) = self.load(id)?;
        if !ok {
            return Err(QuarantineError::Tampered);
        }
        if rec.state != State::Quarantined {
            return Err(QuarantineError::NotActive(rec.state));
        }
        match rec.verdict {
            Verdict::Malicious if !opts.confirm_malicious => return Err(QuarantineError::NeedsConfirmation),
            Verdict::Suspicious if !opts.allow_suspicious => return Err(QuarantineError::RestoreBlockedByPolicy),
            _ => {}
        }
        let dm = fs::symlink_metadata(dest_dir).map_err(|_| QuarantineError::BadDestination)?;
        if !dm.is_dir() || is_link_like(&dm) {
            return Err(QuarantineError::BadDestination);
        }
        let data = self.read_blob(id)?;
        if hex::encode(Sha256::digest(&data)) != rec.sha256 {
            return Err(QuarantineError::Corrupt);
        }

        let safe = sanitize_filename(&rec.original_name);
        let mut target = dest_dir.join(&safe);
        let mut out = None;
        for attempt in 0..8 {
            // create_new fails if anything (file, symlink, junction) already exists at the path, so we cannot be
            // redirected through a pre-planted link and never overwrite user data.
            match OpenOptions::new().write(true).create_new(true).open(&target) {
                Ok(f) => {
                    out = Some(f);
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let suffix = format!("{}.restored-{}-{attempt}", safe, &rec.id.to_string()[..8]);
                    target = dest_dir.join(suffix);
                }
                Err(e) => return Err(e.into()),
            }
        }
        let mut out = out.ok_or(QuarantineError::BadDestination)?;
        out.write_all(&data)?;
        out.sync_all()?;
        drop(out);

        rec.state = State::Restored;
        self.write_meta(&rec)?;
        let _ = fs::remove_file(self.blob(id));
        self.audit("restore", &rec, &target.to_string_lossy())?;
        Ok(target)
    }

    /// Permanently delete the stored copy. The caller is responsible for obtaining user confirmation.
    pub fn delete(&self, id_str: &str) -> Result<(), QuarantineError> {
        let id = Uuid::parse_str(id_str).map_err(|_| QuarantineError::BadId)?;
        let (mut rec, ok) = self.load(id)?;
        if rec.state == State::Deleted {
            return Ok(());
        }
        let _ = fs::remove_file(self.blob(id));
        rec.state = State::Deleted;
        if ok {
            self.write_meta(&rec)?;
        } else {
            let _ = fs::remove_file(self.meta(id)); // a tampered record can only be purged
        }
        self.audit("delete", &rec, if ok { "" } else { "tampered-record-purged" })?;
        Ok(())
    }

    // ---- audit log ------------------------------------------------------------------------------------------

    fn audit(&self, action: &str, r: &Record, detail: &str) -> Result<(), QuarantineError> {
        let path = self.dir.join("audit.jsonl");
        let prev = fs::read_to_string(&path).ok().and_then(|s| s.lines().last().map(|l| l.to_string())).and_then(|l| serde_json::from_str::<serde_json::Value>(&l).ok()).and_then(|v| v["hash"].as_str().map(String::from)).unwrap_or_else(|| "0".repeat(64));
        let at = Utc::now().to_rfc3339();
        let body = serde_json::json!({ "at": at, "action": action, "id": r.id, "sha256": r.sha256, "name": r.original_name, "detail": detail, "prev": prev });
        let hash = hex::encode(Sha256::digest(body.to_string().as_bytes()));
        let mut line = body;
        line["hash"] = serde_json::Value::String(hash);
        let mut f = OpenOptions::new().create(true).append(true).open(path)?;
        writeln!(f, "{line}")?;
        Ok(())
    }

    /// Returns the 1-based line number of the first broken link, or None if the log is intact.
    pub fn verify_audit(&self) -> Option<usize> {
        let Ok(s) = fs::read_to_string(self.dir.join("audit.jsonl")) else { return None };
        let mut prev = "0".repeat(64);
        for (i, l) in s.lines().enumerate() {
            let Ok(mut v) = serde_json::from_str::<serde_json::Value>(l) else { return Some(i + 1) };
            let Some(h) = v.get("hash").and_then(|x| x.as_str()).map(String::from) else { return Some(i + 1) };
            v.as_object_mut().unwrap().remove("hash");
            if v["prev"].as_str() != Some(prev.as_str()) || hex::encode(Sha256::digest(v.to_string().as_bytes())) != h {
                return Some(i + 1);
            }
            prev = h;
        }
        None
    }
}

/// Keep only a safe leaf name: no separators, no drive prefixes, no reserved device names, no trailing dots/spaces.
pub fn sanitize_filename(name: &str) -> String {
    let leaf = name.rsplit(['\\', '/']).next().unwrap_or("");
    let mut s: String = leaf.chars().map(|c| if c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*') { '_' } else { c }).collect();
    s = s.trim_matches(|c| c == '.' || c == ' ').to_string();
    let stem = s.split('.').next().unwrap_or("").to_ascii_uppercase();
    let reserved = ["CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"];
    if s.is_empty() || reserved.contains(&stem.as_str()) {
        s = format!("restored-file-{}", &Uuid::new_v4().to_string()[..8]);
    }
    s.chars().take(200).collect()
}

#[cfg(windows)]
fn is_link_like(m: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    m.file_type().is_symlink() || m.file_attributes() & 0x400 != 0
}
#[cfg(not(windows))]
fn is_link_like(m: &fs::Metadata) -> bool {
    m.file_type().is_symlink()
}

// ---- key management ---------------------------------------------------------------------------------------

fn load_or_create_key(path: &Path) -> Result<[u8; 32], QuarantineError> {
    if let Ok(blob) = fs::read(path) {
        let raw = unwrap_key(&blob)?;
        return raw.try_into().map_err(|_| QuarantineError::Key("stored key has the wrong length".into()));
    }
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    let wrapped = wrap_key(&key)?;
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(&wrapped)?;
    f.sync_all()?;
    Ok(key)
}

fn wrap_key(key: &[u8]) -> Result<Vec<u8>, QuarantineError> {
    crate::secret::protect(key).map_err(|e| QuarantineError::Key(e.0))
}
fn unwrap_key(blob: &[u8]) -> Result<Vec<u8>, QuarantineError> {
    crate::secret::unprotect(blob).map_err(|e| QuarantineError::Key(e.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault() -> (tempfile::TempDir, Quarantine) {
        let d = tempfile::tempdir().unwrap();
        let q = Quarantine::open(d.path().join("vault")).unwrap();
        (d, q)
    }

    fn sample(d: &Path, name: &str, body: &[u8]) -> PathBuf {
        let p = d.join(name);
        fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn roundtrip_preserves_content_and_removes_original() {
        let (d, q) = vault();
        let p = sample(d.path(), "evil.exe", b"payload-bytes");
        let sha = hex::encode(Sha256::digest(b"payload-bytes"));
        let r = q.quarantine(&p, Some(&sha), Verdict::Suspicious, "test", "PE").unwrap();
        assert!(!p.exists());
        // The stored blob is not the plaintext.
        let raw = fs::read(q.blob(r.id)).unwrap();
        assert!(!raw.windows(13).any(|w| w == b"payload-bytes"));
        let out = d.path().join("out");
        fs::create_dir(&out).unwrap();
        let restored = q.restore(&r.id.to_string(), &out, RestoreOptions { confirm_malicious: false, allow_suspicious: true }).unwrap();
        assert_eq!(fs::read(restored).unwrap(), b"payload-bytes");
        assert!(q.verify_audit().is_none());
    }

    #[test]
    fn malicious_restore_needs_confirmation() {
        let (d, q) = vault();
        let p = sample(d.path(), "m.bin", b"x");
        let r = q.quarantine(&p, None, Verdict::Malicious, "t", "x").unwrap();
        let out = d.path().join("out");
        fs::create_dir(&out).unwrap();
        let no = RestoreOptions { confirm_malicious: false, allow_suspicious: true };
        assert!(matches!(q.restore(&r.id.to_string(), &out, no), Err(QuarantineError::NeedsConfirmation)));
        let yes = RestoreOptions { confirm_malicious: true, allow_suspicious: true };
        assert!(q.restore(&r.id.to_string(), &out, yes).is_ok());
    }

    #[test]
    fn suspicious_restore_respects_policy() {
        let (d, q) = vault();
        let p = sample(d.path(), "s.bin", b"x");
        let r = q.quarantine(&p, None, Verdict::Suspicious, "t", "x").unwrap();
        let out = d.path().join("out");
        fs::create_dir(&out).unwrap();
        let o = RestoreOptions { confirm_malicious: true, allow_suspicious: false };
        assert!(matches!(q.restore(&r.id.to_string(), &out, o), Err(QuarantineError::RestoreBlockedByPolicy)));
    }

    #[test]
    fn swapped_file_is_refused() {
        let (d, q) = vault();
        let p = sample(d.path(), "a.bin", b"new content");
        let wrong = hex::encode(Sha256::digest(b"old content"));
        assert!(matches!(q.quarantine(&p, Some(&wrong), Verdict::Malicious, "t", "x"), Err(QuarantineError::ChangedSinceScan)));
        assert!(p.exists(), "original must be untouched on failure");
    }

    #[test]
    fn metadata_tampering_is_detected() {
        let (d, q) = vault();
        let p = sample(d.path(), "a.bin", b"data");
        let r = q.quarantine(&p, None, Verdict::Malicious, "t", "x").unwrap();
        let mp = q.meta(r.id);
        let s = fs::read_to_string(&mp).unwrap().replace("\"malicious\"", "\"clean\"").replace("MALICIOUS", "CLEAN");
        fs::write(&mp, s).unwrap();
        let listed = q.list().unwrap();
        assert!(listed[0].tampered);
        let out = d.path().join("out");
        fs::create_dir(&out).unwrap();
        let o = RestoreOptions { confirm_malicious: true, allow_suspicious: true };
        assert!(matches!(q.restore(&r.id.to_string(), &out, o), Err(QuarantineError::Tampered)));
    }

    #[test]
    fn blob_tampering_is_detected() {
        let (d, q) = vault();
        let p = sample(d.path(), "a.bin", b"data data data");
        let r = q.quarantine(&p, None, Verdict::Suspicious, "t", "x").unwrap();
        let mut raw = fs::read(q.blob(r.id)).unwrap();
        let n = raw.len();
        raw[n - 1] ^= 0xff;
        fs::write(q.blob(r.id), raw).unwrap();
        let out = d.path().join("out");
        fs::create_dir(&out).unwrap();
        let o = RestoreOptions { confirm_malicious: true, allow_suspicious: true };
        assert!(matches!(q.restore(&r.id.to_string(), &out, o), Err(QuarantineError::Corrupt)));
    }

    #[test]
    fn path_traversal_ids_are_rejected() {
        let (d, q) = vault();
        let o = RestoreOptions { confirm_malicious: true, allow_suspicious: true };
        for bad in ["../../etc/passwd", "..\\..\\x", "", "not-a-uuid", "../meta/x"] {
            assert!(matches!(q.restore(bad, d.path(), o), Err(QuarantineError::BadId)), "{bad}");
            assert!(matches!(q.delete(bad), Err(QuarantineError::BadId)), "{bad}");
        }
    }

    #[test]
    fn hostile_original_names_cannot_escape_destination() {
        let (d, q) = vault();
        let p = sample(d.path(), "ok.bin", b"x");
        let mut r = q.quarantine(&p, None, Verdict::Suspicious, "t", "x").unwrap();
        // Forge a hostile name into a (re-MACed) record, as an attacker who controlled the original name could.
        r.original_name = "..\\..\\Windows\\System32\\evil.dll".into();
        q.write_meta(&r).unwrap();
        let out = d.path().join("out");
        fs::create_dir(&out).unwrap();
        let o = RestoreOptions { confirm_malicious: true, allow_suspicious: true };
        let written = q.restore(&r.id.to_string(), &out, o).unwrap();
        assert_eq!(written.parent().unwrap(), out);
        assert_eq!(written.file_name().unwrap(), "evil.dll");
    }

    #[test]
    fn restore_never_overwrites() {
        let (d, q) = vault();
        let p = sample(d.path(), "doc.bin", b"quarantined");
        let r = q.quarantine(&p, None, Verdict::Suspicious, "t", "x").unwrap();
        let out = d.path().join("out");
        fs::create_dir(&out).unwrap();
        fs::write(out.join("doc.bin"), b"user data").unwrap();
        let o = RestoreOptions { confirm_malicious: true, allow_suspicious: true };
        let w = q.restore(&r.id.to_string(), &out, o).unwrap();
        assert_ne!(w, out.join("doc.bin"));
        assert_eq!(fs::read(out.join("doc.bin")).unwrap(), b"user data");
    }

    #[test]
    fn restore_destination_that_is_a_file_is_rejected() {
        let (d, q) = vault();
        let p = sample(d.path(), "a.bin", b"x");
        let r = q.quarantine(&p, None, Verdict::Suspicious, "t", "x").unwrap();
        let notdir = sample(d.path(), "plain.txt", b"x");
        let o = RestoreOptions { confirm_malicious: true, allow_suspicious: true };
        assert!(matches!(q.restore(&r.id.to_string(), &notdir, o), Err(QuarantineError::BadDestination)));
    }

    #[test]
    fn symlink_source_is_refused() {
        let (d, q) = vault();
        let target = sample(d.path(), "real.bin", b"x");
        let link = d.path().join("link.bin");
        #[cfg(windows)]
        let made = std::os::windows::fs::symlink_file(&target, &link).is_ok();
        #[cfg(not(windows))]
        let made = std::os::unix::fs::symlink(&target, &link).is_ok();
        if !made {
            eprintln!("SKIPPED: this account cannot create symlinks (needs Developer Mode or admin on Windows)");
            return;
        }
        assert!(matches!(q.quarantine(&link, None, Verdict::Malicious, "t", "x"), Err(QuarantineError::IsLink)));
        assert!(target.exists());
    }

    /// Directory junctions need no privilege on Windows, so this exercises the reparse-point refusal everywhere we run.
    #[cfg(windows)]
    #[test]
    fn junction_destination_is_refused() {
        let (d, q) = vault();
        let p = sample(d.path(), "a.bin", b"x");
        let r = q.quarantine(&p, None, Verdict::Suspicious, "t", "x").unwrap();
        let real = d.path().join("real");
        fs::create_dir(&real).unwrap();
        let junction = d.path().join("junction");
        let st = std::process::Command::new("cmd").args(["/C", "mklink", "/J"]).arg(&junction).arg(&real).output().unwrap();
        assert!(st.status.success(), "mklink /J failed: {}", String::from_utf8_lossy(&st.stdout));
        let o = RestoreOptions { confirm_malicious: true, allow_suspicious: true };
        assert!(matches!(q.restore(&r.id.to_string(), &junction, o), Err(QuarantineError::BadDestination)));
        assert_eq!(fs::read_dir(&real).unwrap().count(), 0, "nothing may be written through the junction");
    }

    #[test]
    fn delete_removes_blob_and_is_audited() {
        let (d, q) = vault();
        let p = sample(d.path(), "a.bin", b"x");
        let r = q.quarantine(&p, None, Verdict::Malicious, "t", "x").unwrap();
        q.delete(&r.id.to_string()).unwrap();
        assert!(!q.blob(r.id).exists());
        assert_eq!(q.list().unwrap()[0].record.state, State::Deleted);
        assert!(q.verify_audit().is_none());
    }

    #[test]
    fn audit_tampering_is_detected() {
        let (d, q) = vault();
        let p = sample(d.path(), "a.bin", b"x");
        q.quarantine(&p, None, Verdict::Malicious, "t", "x").unwrap();
        let ap = q.dir().join("audit.jsonl");
        let s = fs::read_to_string(&ap).unwrap().replace("quarantine", "nothing");
        fs::write(&ap, s).unwrap();
        assert_eq!(q.verify_audit(), Some(1));
    }

    #[test]
    fn filename_sanitiser() {
        assert_eq!(sanitize_filename("a\\b\\c.txt"), "c.txt");
        assert!(sanitize_filename("CON").starts_with("restored-file-"));
        assert!(sanitize_filename("...").starts_with("restored-file-"));
        assert_eq!(sanitize_filename("bad:name?.exe"), "bad_name_.exe");
    }
}
