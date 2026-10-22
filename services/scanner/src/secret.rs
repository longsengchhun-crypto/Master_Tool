//! Per-user secret protection. On Windows this wraps data with DPAPI (bound to the signed-in user account, so another
//! user or a copied file cannot decrypt it). On other platforms it is a pass-through until a keyring integration lands;
//! callers must keep the files in a user-only directory there.

#[derive(Debug, thiserror::Error)]
#[error("secret protection failed: {0}")]
pub struct SecretError(pub String);

#[cfg(windows)]
pub fn protect(data: &[u8]) -> Result<Vec<u8>, SecretError> {
    dpapi(data, true)
}
#[cfg(windows)]
pub fn unprotect(blob: &[u8]) -> Result<Vec<u8>, SecretError> {
    dpapi(blob, false)
}
#[cfg(not(windows))]
pub fn protect(data: &[u8]) -> Result<Vec<u8>, SecretError> {
    Ok(data.to_vec())
}
#[cfg(not(windows))]
pub fn unprotect(blob: &[u8]) -> Result<Vec<u8>, SecretError> {
    Ok(blob.to_vec())
}

#[cfg(windows)]
fn dpapi(data: &[u8], protect: bool) -> Result<Vec<u8>, SecretError> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB};
    unsafe {
        let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
        let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        let ok = if protect {
            CryptProtectData(&input, std::ptr::null(), std::ptr::null(), std::ptr::null(), std::ptr::null(), 0, &mut out)
        } else {
            CryptUnprotectData(&input, std::ptr::null_mut(), std::ptr::null(), std::ptr::null(), std::ptr::null(), 0, &mut out)
        };
        if ok == 0 {
            return Err(SecretError(std::io::Error::last_os_error().to_string()));
        }
        let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        LocalFree(out.pbData as *mut _);
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let p = protect(b"device-token").unwrap();
        assert_eq!(unprotect(&p).unwrap(), b"device-token");
    }

    #[cfg(windows)]
    #[test]
    fn protected_form_is_not_the_plaintext() {
        let p = protect(b"device-token-plaintext").unwrap();
        assert!(!p.windows(22).any(|w| w == b"device-token-plaintext"));
    }

    #[cfg(windows)]
    #[test]
    fn tampered_blob_is_rejected() {
        let mut p = protect(b"x").unwrap();
        let n = p.len();
        p[n - 1] ^= 0xff;
        assert!(unprotect(&p).is_err());
    }
}

/// A small secret kept in its own file, protected for this Windows user and overwritten before it is deleted.
/// Used for the relay device token. It is never logged and never returned to the web UI.
pub struct SecretFile {
    file: std::path::PathBuf,
}

impl SecretFile {
    pub fn new(dir: &std::path::Path, name: &str) -> Self {
        SecretFile { file: dir.join(name) }
    }

    pub fn exists(&self) -> bool {
        self.file.is_file()
    }

    pub fn save(&self, secret: &[u8]) -> Result<(), String> {
        let sealed = protect(secret).map_err(|e| e.to_string())?;
        let tmp = self.file.with_extension("tmp");
        std::fs::write(&tmp, sealed).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &self.file).map_err(|e| e.to_string())
    }

    pub fn load(&self) -> Option<Vec<u8>> {
        unprotect(&std::fs::read(&self.file).ok()?).ok()
    }

    /// Overwrite then delete. Returns true when nothing remains on disk.
    pub fn wipe(&self) -> bool {
        if let Ok(m) = std::fs::metadata(&self.file) {
            let _ = std::fs::write(&self.file, vec![0u8; m.len() as usize]);
        }
        let _ = std::fs::remove_file(&self.file);
        !self.file.exists()
    }
}

#[cfg(test)]
mod secret_file_tests {
    use super::*;

    #[test]
    fn a_secret_file_round_trips_is_not_plaintext_and_wipes() {
        let d = tempfile::tempdir().unwrap();
        let f = SecretFile::new(d.path(), "relay.token");
        assert!(!f.exists() && f.load().is_none());
        f.save(b"device-token-0123456789").unwrap();
        #[cfg(windows)]
        assert!(!std::fs::read(d.path().join("relay.token")).unwrap().windows(10).any(|w| w == b"0123456789"));
        assert_eq!(f.load().unwrap(), b"device-token-0123456789");
        assert!(f.wipe() && !f.exists() && f.load().is_none());
    }
}
