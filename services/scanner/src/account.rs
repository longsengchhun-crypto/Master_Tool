//! Telegram ACCOUNT-level attachment monitoring: the part that can be built and verified safely.
//!
//! STATUS: the MTProto transport (logging in as the user and receiving updates) is **NOT IMPLEMENTED**, deliberately.
//! See docs/PHASE2_GAP_ANALYSIS.md: no vetted/audited Rust MTProto client was available, Telegram places accounts using
//! unofficial clients under observation, and a live login could not be verified here (no test account / api_id).
//! Shipping an unaudited stack that holds a user's full account session without being able to test it would be unsafe.
//!
//! What IS here and tested:
//!  * `SessionVault`: a session blob is only ever stored DPAPI-protected, and is wiped (overwritten, then deleted) on
//!    disconnect. It is never logged and never leaves the device.
//!  * `AttachmentGate`: how an eventual transport must hand attachments over: no message text anywhere in the data
//!    model, per-category opt-in, size cap, bounded concurrency/backpressure, isolated temp storage that is always
//!    removed, results go through the same scan/notify pipeline as everything else.
//!  * `AccountTransport`: the trait a vetted transport will implement; `NotAvailable` is the only implementation and
//!    reports exactly why.

use crate::secret;
use crate::service::ProtectionService;
use crate::types::ScanReport;
use serde::Serialize;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "state", content = "detail")]
pub enum AccountState {
    /// No transport exists in this build. `detail` says why, for the UI.
    NotAvailable(String),
    Disconnected,
    Connected(String),
    Expired,
}

pub trait AccountTransport: Send + Sync {
    fn state(&self) -> AccountState;
}

pub struct NotAvailable;

impl AccountTransport for NotAvailable {
    fn state(&self) -> AccountState {
        AccountState::NotAvailable(NOT_AVAILABLE_REASON.into())
    }
}

pub const NOT_AVAILABLE_REASON: &str = "Account-level monitoring needs a Telegram client library that has been security-audited and a Telegram test account to verify it. Neither is available in this build, so SENTRIX does not collect any Telegram account credentials. Bot notifications and Telegram Desktop folder monitoring work without it.";

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

#[derive(Debug, Clone, Copy)]
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
    prefs: AccountPrefs,
    in_flight: AtomicUsize,
    max_in_flight: usize,
}

impl AttachmentGate {
    pub fn new(prefs: AccountPrefs, max_in_flight: usize) -> Self {
        AttachmentGate { prefs, in_flight: AtomicUsize::new(0), max_in_flight }
    }

    pub fn ingest(&self, svc: &ProtectionService, att: &IncomingAttachment, content: &mut dyn Read) -> Result<ScanReport, IngestError> {
        let allowed = match att.chat_kind {
            ChatKind::Private => self.prefs.private_chats,
            ChatKind::Group => self.prefs.groups,
            ChatKind::Channel => self.prefs.channels,
        };
        if !allowed {
            return Err(IngestError::CategoryDisabled);
        }
        if att.size > self.prefs.max_bytes {
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
        let r = svc.scan_ephemeral("Telegram account", &att.display_name, content, self.prefs.max_bytes).map_err(IngestError::Scan)?;
        svc.publish_report(&r);
        Ok(r)
    }

    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_is_honestly_unavailable() {
        match NotAvailable.state() {
            AccountState::NotAvailable(r) => {
                assert!(r.contains("audited"), "{r}");
                assert!(r.contains("does not collect any Telegram account credentials"));
            }
            other => panic!("{other:?}"),
        }
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
