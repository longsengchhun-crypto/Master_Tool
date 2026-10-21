//! Digital-signature inspection. On Windows this calls WinVerifyTrust (embedded Authenticode) with revocation
//! checking disabled so that verifying a file never causes a network request that reveals what is being scanned.
//! Catalog-signed files (many Windows system binaries) report as "unsigned" here; the report explains this.

use crate::types::SignatureInfo;
use std::path::Path;

#[cfg(windows)]
pub fn verify(path: &Path) -> SignatureInfo {
    use std::ffi::c_void;
    use std::mem::{size_of, zeroed};
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::WinTrust::*;

    // {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
    let mut action = windows_sys::core::GUID {
        data1: 0x00aac56b,
        data2: 0xcd44,
        data3: 0x11d0,
        data4: [0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee],
    };
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();

    unsafe {
        let mut file: WINTRUST_FILE_INFO = zeroed();
        file.cbStruct = size_of::<WINTRUST_FILE_INFO>() as u32;
        file.pcwszFilePath = wide.as_ptr();

        let mut data: WINTRUST_DATA = zeroed();
        data.cbStruct = size_of::<WINTRUST_DATA>() as u32;
        data.dwUIChoice = WTD_UI_NONE;
        data.fdwRevocationChecks = WTD_REVOKE_NONE;
        data.dwUnionChoice = WTD_CHOICE_FILE;
        data.Anonymous.pFile = &mut file;
        data.dwStateAction = WTD_STATEACTION_VERIFY;
        data.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL;

        let hwnd = -1isize as *mut c_void; // INVALID_HANDLE_VALUE: no UI
        let status = WinVerifyTrust(hwnd, &mut action, &mut data as *mut _ as *mut c_void) as u32;

        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(hwnd, &mut action, &mut data as *mut _ as *mut c_void);

        classify(status)
    }
}

#[cfg(not(windows))]
pub fn verify(_path: &Path) -> SignatureInfo {
    SignatureInfo { state: "unknown".into(), detail: Some("Digital-signature verification is only implemented on Windows in this build.".into()) }
}

/// Map a WinVerifyTrust HRESULT. Split out so it is unit-testable on every platform.
pub fn classify(status: u32) -> SignatureInfo {
    let (state, detail) = match status {
        0 => ("signed_trusted", "The signature is valid and chains to a trusted root.".to_string()),
        0x800B_0100 => ("unsigned", "No embedded digital signature (system files may be catalog-signed instead).".to_string()),
        0x800B_0001 | 0x800B_0003 => ("unsigned", "This file type does not carry an embedded signature.".to_string()),
        0x8009_6010 | 0x8009_6011 | 0x8009_6012 => ("signed_invalid", "A signature is present but the file has been altered since it was signed, or the signature is corrupt.".to_string()),
        0x800B_0004 | 0x800B_0109 | 0x800B_0101 | 0x800B_0111 | 0x800B_0110 => ("signed_untrusted", "A signature is present but its certificate is expired, not trusted, or not valid for code signing.".to_string()),
        0x800B_0102 => ("signed_untrusted", "The signing certificate is not trusted.".to_string()),
        other => ("unknown", format!("Signature check returned 0x{other:08X}.")),
    };
    SignatureInfo { state: state.into(), detail: Some(detail) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_known_codes() {
        assert_eq!(classify(0).state, "signed_trusted");
        assert_eq!(classify(0x800B_0100).state, "unsigned");
        assert_eq!(classify(0x8009_6010).state, "signed_invalid");
        assert_eq!(classify(0x800B_0109).state, "signed_untrusted");
        assert_eq!(classify(0xDEAD_BEEF).state, "unknown");
    }
}
