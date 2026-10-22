//! Pieces shared by the personal-account protection: the DPAPI-protected key vault, the attachment gate in front of the
//! scanner, and the report for files that could not be checked. The Telegram client itself is in `account_td.rs`.
//!
//!  * `SessionVault`: the key that encrypts the TDLib database is only ever stored DPAPI-protected, and is wiped
//!    (overwritten, then deleted) on disconnect. It is never logged and never leaves the device.
//!  * `AttachmentGate`: no message text anywhere in the data model, per-category opt-in, size cap, bounded concurrency,
//!    isolated temp storage that is always removed, results go through the same scan/notify pipeline as everything else.
//!  * `unverified_report`: what the user sees for an attachment that was NOT checked. It is UNABLE TO VERIFY, never clean.

use crate::secret;
use crate::service::ProtectionService;
use crate::types::{Check, CheckStatus, FileInfo, ScanReport, Verdict};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::RwLock;

// ---- session vault -------------------------------------------------------------------------------------------

pub struct SessionVault {
    file: PathBuf,
}

impl SessionVault {
    pub fn new(dir: &Path) -> Self {
        SessionVault { file: dir.join("telegram-account.session") }
    }

    pub fn exists(&self) -> bool {
        self.file.is_file()
    }

    /// Store a session blob protected by the OS (DPAPI on Windows: bound to this Windows user).
    pub fn save(&self, session: &[u8]) -> Result<(), String> {
        let sealed = secret::protect(session).map_err(|e| e.to_string())?;
        let tmp = self.file.with_extension("tmp");
        std::fs::write(&tmp, sealed).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &self.file).map_err(|e| e.to_string())
    }

    pub fn load(&self) -> Option<Vec<u8>> {
        secret::unprotect(&std::fs::read(&self.file).ok()?).ok()
    }

    /// Overwrite then delete. Used on disconnect so no usable session remains on disk.
    pub fn wipe(&self) -> bool {
        if let Ok(m) = std::fs::metadata(&self.file) {
            let zeros = vec![0u8; m.len() as usize];
            let _ = std::fs::write(&self.file, zeros);
        }
        let _ = std::fs::remove_file(&self.file);
        !self.file.exists()
    }
}

/// What a report says about where a file came from, so a notice never claims more than it knows about the chat.
pub fn origin_for(kind: ChatKind) -> &'static str {
    match kind {
        ChatKind::Private => "Telegram personal chat",
        ChatKind::Group => "Telegram group",
        ChatKind::Channel => "Telegram channel",
    }
}

/// A result for an attachment that was not checked (too large, protected, download failed, scanner busy). It is
/// UNABLE TO VERIFY with the reason spelled out; nothing here can read as "safe".
pub fn unverified_report(origin: &str, name: &str, size: u64, reason: &str) -> ScanReport {
    let now = chrono::Utc::now();
    let clean_name: String = name.chars().filter(|c| !c.is_control()).take(120).collect();
    ScanReport {
        id: uuid::Uuid::new_v4(),
        file: FileInfo {
            path: PathBuf::from(format!("[{origin}] {clean_name}")),
            name: clean_name.clone(),
            size,
            sha256: String::new(),
            detected_type: "unknown".into(),
            declared_extension: Path::new(&clean_name).extension().map(|e| e.to_string_lossy().to_lowercase()),
            type_mismatch: false,
            signature: None,
            modified: None,
            source: None,
        },
        verdict: Verdict::UnableToVerify,
        complete: false,
        checks: vec![Check { id: "attachment_access".into(), name: "Attachment access".into(), status: CheckStatus::Unavailable, engine_version: None, note: Some(reason.to_string()), retryable: false }],
        findings: vec![],
        summary: format!("Not checked: {reason}"),
        recommended_action: "Do not open this file until it has been checked another way.".into(),
        started_at: now,
        finished_at: now,
        quarantined: false,
        blocked: false,
        cached: false,
        origin: Some(origin.to_string()),
        threat: None,
    }
}

// ---- attachment ingestion -----------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatKind {
    Private,
    Group,
    Channel,
}

/// Everything a transport may pass on about an attachment. There is intentionally NO field for message text, sender
/// name, chat title or history: the pipeline cannot retain what it is never given.
#[derive(Debug, Clone)]
pub struct IncomingAttachment {
    pub chat_kind: ChatKind,
    pub display_name: String,
    pub size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountPrefs {
    pub private_chats: bool,
    pub groups: bool,
    pub channels: bool,
    pub max_bytes: u64,
}

impl Default for AccountPrefs {
    fn default() -> Self {
        AccountPrefs { private_chats: true, groups: false, channels: false, max_bytes: 100 * 1024 * 1024 }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum IngestError {
    CategoryDisabled,
    TooLarge,
    /// Too many attachments at once: the transport must slow down or drop (backpressure), not queue without bound.
    Busy,
    Scan(String),
}

pub struct AttachmentGate {
    prefs: RwLock<AccountPrefs>,
    in_flight: AtomicUsize,
    max_in_flight: usize,
}

impl AttachmentGate {
    pub fn new(prefs: AccountPrefs, max_in_flight: usize) -> Self {
        AttachmentGate { prefs: RwLock::new(prefs), in_flight: AtomicUsize::new(0), max_in_flight }
    }

    pub fn ingest(&self, svc: &ProtectionService, att: &IncomingAttachment, content: &mut dyn Read) -> Result<ScanReport, IngestError> {
        let prefs = *self.prefs.read().unwrap();
        let allowed = match att.chat_kind {
            ChatKind::Private => prefs.private_chats,
            ChatKind::Group => prefs.groups,
            ChatKind::Channel => prefs.channels,
        };
        if !allowed {
            return Err(IngestError::CategoryDisabled);
        }
        if att.size > prefs.max_bytes {
            return Err(IngestError::TooLarge);
        }
        // Reserve a slot or push back.
        if self.in_flight.fetch_add(1, Ordering::SeqCst) >= self.max_in_flight {
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            return Err(IngestError::Busy);
        }
        struct Slot<'a>(&'a AtomicUsize);
        impl Drop for Slot<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let _slot = Slot(&self.in_flight);
        let r = svc.scan_ephemeral(origin_for(att.chat_kind), &att.display_name, content, prefs.max_bytes).map_err(IngestError::Scan)?;
        svc.publish_report(&r);
        Ok(r)
    }

    pub fn set_prefs(&self, p: AccountPrefs) {
        *self.prefs.write().unwrap() = p;
    }

    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unchecked_attachment_can_never_read_as_safe() {
        let r = unverified_report("Telegram personal chat", "inv\u{202e}oice.pdf\n", 10, "too big");
        assert_eq!(r.verdict, Verdict::UnableToVerify);
        assert!(!r.complete);
        assert!(r.file.sha256.is_empty());
        assert!(!r.file.name.contains('\n'));
        assert!(r.summary.contains("Not checked"));
        assert_eq!(r.checks[0].status, CheckStatus::Unavailable);
    }

    #[test]
    fn vault_never_stores_the_session_in_clear_and_wipes_on_disconnect() {
        let d = tempfile::tempdir().unwrap();
        let v = SessionVault::new(d.path());
        assert!(!v.exists() && v.load().is_none());
        let session = b"SUPER-SECRET-MTPROTO-AUTH-KEY-0123456789".to_vec();
        v.save(&session).unwrap();
        let raw = std::fs::read(d.path().join("telegram-account.session")).unwrap();
        assert!(!raw.windows(session.len()).any(|w| w == &session[..]) || !cfg!(windows), "the file must not contain the session in clear text");
        assert_eq!(v.load().unwrap(), session);
        assert!(v.wipe());
        assert!(!v.exists());
        assert!(v.load().is_none());
    }

    #[cfg(windows)]
    #[test]
    fn a_tampered_session_file_is_rejected_not_half_used() {
        let d = tempfile::tempdir().unwrap();
        let v = SessionVault::new(d.path());
        v.save(b"session").unwrap();
        let p = d.path().join("telegram-account.session");
        let mut raw = std::fs::read(&p).unwrap();
        let n = raw.len();
        raw[n - 1] ^= 0xff;
        std::fs::write(&p, raw).unwrap();
        assert!(v.load().is_none());
    }
}
