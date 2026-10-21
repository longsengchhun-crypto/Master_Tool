//! Update-integrity tests. The Tauri updater verifies minisign signatures with the `minisign-verify` crate against the
//! public key in tauri.conf.json before installing anything; these tests exercise exactly that verifier.

use base64::Engine;
use std::io::Cursor;

fn b64d(s: &str) -> String {
    String::from_utf8(base64::engine::general_purpose::STANDARD.decode(s.trim()).expect("base64")).expect("utf8")
}

/// Sign `data` with a fresh throwaway key; returns (public key text, signature text).
fn sign(data: &[u8]) -> (String, String) {
    let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
    let sig = minisign::sign(Some(&kp.pk), &kp.sk, Cursor::new(data), Some("test"), Some("test")).unwrap();
    (kp.pk.to_box().unwrap().to_string(), sig.to_string())
}

fn verify(pk_text: &str, sig_text: &str, data: &[u8]) -> bool {
    let Ok(pk) = minisign_verify::PublicKey::decode(pk_text) else { return false };
    let Ok(sig) = minisign_verify::Signature::decode(sig_text) else { return false };
    pk.verify(data, &sig, false).is_ok()
}

#[test]
fn genuine_update_verifies() {
    let installer = vec![7u8; 100_000];
    let (pk, sig) = sign(&installer);
    assert!(verify(&pk, &sig, &installer));
}

#[test]
fn a_single_flipped_byte_is_rejected() {
    let mut installer = vec![7u8; 100_000];
    let (pk, sig) = sign(&installer);
    for pos in [0usize, 50_000, 99_999] {
        installer[pos] ^= 1;
        assert!(!verify(&pk, &sig, &installer), "tampering at byte {pos} must be rejected");
        installer[pos] ^= 1;
    }
}

#[test]
fn appended_payload_is_rejected() {
    let installer = vec![7u8; 1000];
    let (pk, sig) = sign(&installer);
    let mut evil = installer.clone();
    evil.extend_from_slice(b"MZ-malware");
    assert!(!verify(&pk, &sig, &evil));
}

#[test]
fn truncated_download_is_rejected() {
    let installer = vec![7u8; 100_000];
    let (pk, sig) = sign(&installer);
    assert!(!verify(&pk, &sig, &installer[..99_000]));
    assert!(!verify(&pk, &sig, &[]));
}

#[test]
fn a_valid_signature_from_a_different_key_is_rejected() {
    // An attacker who controls the server can sign with their own key, but not with ours.
    let installer = vec![7u8; 5000];
    let (_our_pk, _our_sig) = sign(&installer);
    let (attacker_pk, attacker_sig) = sign(&installer);
    let (our_pk, _) = sign(b"unrelated");
    assert!(verify(&attacker_pk, &attacker_sig, &installer), "sanity: attacker's signature is valid for attacker's key");
    assert!(!verify(&our_pk, &attacker_sig, &installer), "but it must not verify under the app's key");
}

#[test]
fn missing_or_garbage_signatures_are_rejected() {
    let (pk, _) = sign(b"x");
    for bad in ["", "not a signature", "untrusted comment: x\nAAAA\ntrusted comment: y\nBBBB"] {
        assert!(!verify(&pk, bad, b"x"), "{bad:?}");
    }
}

/// Verifies the REAL built installer and its .sig against the public key compiled into the app.
///   SENTRIX_ARTIFACT=<path to SENTRIX_x.y.z_x64-setup.exe> cargo test -p sentrix-desktop --test update_signature -- --ignored
#[test]
#[ignore = "needs a built, signed installer: set SENTRIX_ARTIFACT"]
fn built_installer_verifies_against_the_key_in_tauri_conf() {
    let artifact = std::path::PathBuf::from(std::env::var("SENTRIX_ARTIFACT").expect("SENTRIX_ARTIFACT"));
    let data = std::fs::read(&artifact).unwrap();
    let sig_b64 = std::fs::read_to_string(artifact.with_extension("exe.sig")).expect("the .sig next to the installer");
    let conf: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tauri.conf.json")).unwrap()).unwrap();
    let pk_text = b64d(conf["plugins"]["updater"]["pubkey"].as_str().expect("pubkey in tauri.conf.json"));
    let sig_text = b64d(&sig_b64);
    assert!(verify(&pk_text, &sig_text, &data), "the shipped installer must verify against the key in the app");
    let mut tampered = data.clone();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0xff;
    assert!(!verify(&pk_text, &sig_text, &tampered), "a tampered installer must NOT verify");
}
