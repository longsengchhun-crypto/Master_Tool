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
