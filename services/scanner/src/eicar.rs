//! Built-in detector for the EICAR anti-malware *test* string. It exists so the detect → report → quarantine
//! workflow can be validated end to end without handling live malware. It is NOT a malware engine and never
//! contributes to a CLEAN verdict.

/// The standard 68-byte EICAR test string, assembled at runtime so this source file does not itself trip scanners.
pub fn eicar_bytes() -> Vec<u8> {
    let parts = [
        r"X5O!P%@AP[4\PZX54(P^)7CC)7}$",
        "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!",
        "$H+H*",
    ];
    parts.concat().into_bytes()
}

/// EICAR rules: the file must *begin* with the 68-byte string and may be followed only by whitespace (max 128 bytes total).
pub fn is_eicar_file(data: &[u8]) -> bool {
    let sig = eicar_bytes();
    if data.len() < sig.len() || data.len() > 128 || !data.starts_with(&sig) {
        return false;
    }
    data[sig.len()..].iter().all(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n' | 0x1a))
}

/// Looser containment check used for archive entries and embedded payloads.
pub fn contains_eicar(data: &[u8]) -> bool {
    let sig = eicar_bytes();
    memchr::memmem::find(data, &sig).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_eicar_matches() {
        let mut d = eicar_bytes();
        assert_eq!(d.len(), 68);
        assert!(is_eicar_file(&d));
        d.extend_from_slice(b"\r\n");
        assert!(is_eicar_file(&d));
    }

    #[test]
    fn eicar_with_trailing_junk_is_not_a_standard_file() {
        let mut d = eicar_bytes();
        d.extend_from_slice(b"xxxx");
        assert!(!is_eicar_file(&d));
        assert!(contains_eicar(&d));
    }

    #[test]
    fn ordinary_text_is_not_eicar() {
        assert!(!is_eicar_file(b"hello"));
        assert!(!contains_eicar(b"hello"));
    }
}
