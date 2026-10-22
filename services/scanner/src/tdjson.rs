//! Runtime binding to TDLib (Telegram's official client library) through its JSON interface.
//!
//! Why this shape: the library is loaded from a folder we control, and every file in that folder must match the SHA-256
//! pinned in `tdlib.sha256` BEFORE it is loaded. A replaced or corrupted DLL is refused, not run. There is no generated
//! wrapper crate between SENTRIX and the library: the whole surface is five C functions and JSON text.
//!
//! Residual risk (stated in docs/TELEGRAM_ACCOUNT.md): the pinned development binary is a third-party build of TDLib, and
//! a check made just before loading cannot stop an attacker who can already write to the application folder.

use sha2::{Digest, Sha256};
use std::ffi::{c_char, c_double, c_int, CStr, CString};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

/// What the account worker needs from TDLib. A scripted fake implements it in tests.
pub trait TdIo: Send + Sync {
    /// Queue one request (JSON object with an `@type`).
    fn send(&self, request: &str);
    /// Wait up to `timeout_secs` for the next update or response (JSON), or `None` on timeout.
    fn receive(&self, timeout_secs: f64) -> Option<String>;
}

/// SHA-256 pins for the TDLib files this build accepts: `<hex> *<file name>` per line.
pub const PINS: &str = include_str!("../tdlib.sha256");

/// Check every pinned file in `dir`. All of them must exist and match.
pub fn verify_dir(dir: &Path, pins: &str) -> Result<(), String> {
    let mut checked = 0;
    for line in pins.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let (hex, name) = line.split_once(' ').ok_or("malformed pin line")?;
        let name = name.trim_start_matches('*').trim();
        if name.contains(['/', '\\']) || name.contains("..") {
            return Err("malformed pin line".into());
        }
        let bytes = std::fs::read(dir.join(name)).map_err(|e| format!("{name}: {e}"))?;
        let got = hex::encode(Sha256::digest(&bytes));
        if !got.eq_ignore_ascii_case(hex.trim()) {
            return Err(format!("{name} does not match the pinned SHA-256; refusing to load it"));
        }
        checked += 1;
    }
    if checked == 0 {
        return Err("no pinned files".into());
    }
    Ok(())
}

type CreateFn = unsafe extern "C" fn() -> c_int;
type SendFn = unsafe extern "C" fn(c_int, *const c_char);
type ReceiveFn = unsafe extern "C" fn(c_double) -> *const c_char;
type ExecuteFn = unsafe extern "C" fn(*const c_char) -> *const c_char;

pub struct TdLib {
    // Kept alive for the life of the process: unloading a library that still has threads running is not safe.
    _lib: libloading::Library,
    create: CreateFn,
    send: SendFn,
    receive: ReceiveFn,
    execute: ExecuteFn,
    recv_lock: Mutex<()>,
}

static LIB: OnceLock<Result<Arc<TdLib>, String>> = OnceLock::new();

impl TdLib {
    /// Verify the pinned files, then load `tdjson` from `dir`. Loaded once per process.
    pub fn load(dir: &Path) -> Result<Arc<TdLib>, String> {
        LIB.get_or_init(|| Self::load_inner(dir).map(Arc::new)).clone()
    }

    fn load_inner(dir: &Path) -> Result<TdLib, String> {
        verify_dir(dir, PINS)?;
        let file: PathBuf = dir.join(if cfg!(windows) { "tdjson.dll" } else if cfg!(target_os = "macos") { "libtdjson.dylib" } else { "libtdjson.so" });
        // SAFETY: the file was just verified against its pin. Loading runs its initialisers, which is why the check comes first.
        #[cfg(windows)]
        let lib: libloading::Library = unsafe {
            // LOAD_WITH_ALTERED_SEARCH_PATH: its dependencies (OpenSSL, zlib) are taken from the same verified folder.
            libloading::os::windows::Library::load_with_flags(&file, 0x0000_0008).map_err(|e| e.to_string())?.into()
        };
        #[cfg(not(windows))]
        let lib = unsafe { libloading::Library::new(&file).map_err(|e| e.to_string())? };
        unsafe {
            let create = *lib.get::<CreateFn>(b"td_create_client_id\0").map_err(|e| e.to_string())?;
            let send = *lib.get::<SendFn>(b"td_send\0").map_err(|e| e.to_string())?;
            let receive = *lib.get::<ReceiveFn>(b"td_receive\0").map_err(|e| e.to_string())?;
            let execute = *lib.get::<ExecuteFn>(b"td_execute\0").map_err(|e| e.to_string())?;
            let me = TdLib { _lib: lib, create, send, receive, execute, recv_lock: Mutex::new(()) };
            // Library logging off: it would otherwise write to the console and could mention account details.
            me.execute_json(r#"{"@type":"setLogVerbosityLevel","new_verbosity_level":0}"#);
            Ok(me)
        }
    }

    fn execute_json(&self, request: &str) {
        if let Ok(c) = CString::new(request) {
            // SAFETY: valid NUL-terminated string; the returned pointer is not used.
            unsafe {
                (self.execute)(c.as_ptr());
            }
        }
    }

    pub fn new_client(self: &Arc<Self>) -> TdClient {
        // SAFETY: plain call into the library.
        let id = unsafe { (self.create)() };
        TdClient { lib: self.clone(), id }
    }
}

pub struct TdClient {
    lib: Arc<TdLib>,
    id: c_int,
}

impl TdIo for TdClient {
    fn send(&self, request: &str) {
        if let Ok(c) = CString::new(request) {
            // SAFETY: valid NUL-terminated string, copied by the library before it returns.
            unsafe { (self.lib.send)(self.id, c.as_ptr()) }
        }
    }

    fn receive(&self, timeout_secs: f64) -> Option<String> {
        let _g = self.lib.recv_lock.lock().ok()?;
        // SAFETY: the returned pointer is valid until the next receive/execute call; it is copied immediately, under the lock.
        unsafe {
            let p = (self.lib.receive)(timeout_secs);
            if p.is_null() {
                None
            } else {
                Some(CStr::from_ptr(p).to_string_lossy().into_owned())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_modified_library_file_is_refused() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("tdjson.dll"), b"genuine").unwrap();
        let pin = format!("{} *tdjson.dll\n", hex::encode(Sha256::digest(b"genuine")));
        assert!(verify_dir(d.path(), &pin).is_ok());
        std::fs::write(d.path().join("tdjson.dll"), b"genuine + implant").unwrap();
        assert!(verify_dir(d.path(), &pin).unwrap_err().contains("refusing to load"));
    }

    #[test]
    fn a_missing_pinned_file_is_refused() {
        let d = tempfile::tempdir().unwrap();
        assert!(verify_dir(d.path(), &format!("{} *tdjson.dll\n", "0".repeat(64))).is_err());
        assert!(verify_dir(d.path(), "").is_err(), "an empty pin list must not pass");
    }

    #[test]
    fn pin_names_cannot_point_outside_the_folder() {
        let d = tempfile::tempdir().unwrap();
        assert!(verify_dir(d.path(), &format!("{} *..\\evil.dll\n", "0".repeat(64))).is_err());
    }
}
