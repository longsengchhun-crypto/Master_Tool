//! The bot service keeps itself up to date.
//!
//! Every release publishes `botd-latest.json` next to the installer: `{version, url, sha256, signature, notes}`. The running
//! service fetches it, and when the version is newer it downloads the program, checks BOTH the SHA-256 and the minisign
//! signature (made with the same private key that signs the desktop app's updates), swaps the program file for the new one
//! and starts it again. Nothing that fails a check is ever installed, whoever served it: the feed, the download address
//! and the network are all untrusted; only the signature counts.
//!
//! The public key lives in `updater.pub` and a test makes sure it is the key the desktop app trusts, so the two cannot drift.

use base64::Engine;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const DEFAULT_FEED: &str = "https://github.com/longsengchhun-crypto/Master_Tool/releases/latest/download/botd-latest.json";
pub const PUBLIC_KEY: &str = include_str!("../updater.pub");
pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
/// The service program is a few MB; anything near this is not it.
const MAX_BYTES: u64 = 96 * 1024 * 1024;

#[derive(Deserialize)]
struct Manifest {
    version: String,
    url: String,
    sha256: String,
    signature: String,
    #[serde(default)]
    notes: String,
}

pub struct Update {
    pub version: String,
    pub notes: String,
    pub bytes: Vec<u8>,
}

fn parts(v: &str) -> Option<Vec<u64>> {
    let core = v.trim().trim_start_matches('v').split(['-', '+']).next()?;
    let p: Option<Vec<u64>> = core.split('.').map(|s| s.parse().ok()).collect();
    p.filter(|p| !p.is_empty() && p.len() <= 4)
}

/// `candidate` is a well-formed version that is strictly higher than `current`. Anything unparseable is "not newer".
pub fn is_newer(candidate: &str, current: &str) -> bool {
    let (Some(mut a), Some(mut b)) = (parts(candidate), parts(current)) else { return false };
    let n = a.len().max(b.len());
    a.resize(n, 0);
    b.resize(n, 0);
    a > b
}

/// https everywhere, plus this computer for tests and development.
fn address_ok(u: &str) -> bool {
    if u.starts_with("https://") {
        return true;
    }
    let Some(rest) = u.strip_prefix("http://") else { return false };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    // "127.0.0.1.evil.com" and "127.0.0.1@evil.com" must not pass: the whole host has to be this computer.
    !authority.contains('@') && matches!(authority.rsplit_once(':').map_or(authority, |(h, _)| h), "127.0.0.1" | "localhost")
}

fn b64d(s: &str) -> Result<String, String> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(s.trim()).map_err(|_| "not valid base64".to_string())?;
    String::from_utf8(bytes).map_err(|_| "not valid text".to_string())
}

/// `pubkey_b64` and `signature_b64` are in the form the Tauri tooling writes (base64 of the minisign text).
pub fn verify(pubkey_b64: &str, signature_b64: &str, data: &[u8]) -> Result<(), String> {
    let pk = minisign_verify::PublicKey::decode(&b64d(pubkey_b64).map_err(|e| format!("public key: {e}"))?).map_err(|_| "the public key is not valid".to_string())?;
    let sig = minisign_verify::Signature::decode(&b64d(signature_b64).map_err(|e| format!("signature: {e}"))?).map_err(|_| "the signature is not valid".to_string())?;
    pk.verify(data, &sig, false).map_err(|_| "the signature does not match this file".to_string())
}

fn agent(secs: u64) -> ureq::Agent {
    ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(secs))).build().into()
}

/// Is there a newer, correctly signed version? `Ok(None)`: no. `Err`: could not tell, or something failed a check; the
/// caller logs it and carries on with the current version.
pub fn check(feed: &str, pubkey_b64: &str, current: &str) -> Result<Option<Update>, String> {
    if !address_ok(feed) {
        return Err("the update feed address must be https".into());
    }
    let m: Manifest = agent(30).get(feed).call().map_err(|e| format!("update feed: {e}"))?.body_mut().read_json().map_err(|e| format!("update feed is not valid: {e}"))?;
    if !is_newer(&m.version, current) {
        return Ok(None);
    }
    if !address_ok(&m.url) {
        return Err("the update download address must be https".into());
    }
    let mut resp = agent(300).get(&m.url).call().map_err(|e| format!("update download: {e}"))?;
    let bytes = resp.body_mut().with_config().limit(MAX_BYTES).read_to_vec().map_err(|e| format!("update download: {e}"))?;
    let digest = hex::encode(Sha256::digest(&bytes));
    if !digest.eq_ignore_ascii_case(m.sha256.trim()) {
        return Err("the downloaded update does not match its checksum; it was not installed".into());
    }
    verify(pubkey_b64, &m.signature, &bytes).map_err(|e| format!("the downloaded update failed its signature check ({e}); it was not installed"))?;
    if cfg!(windows) && !bytes.starts_with(b"MZ") {
        return Err("the downloaded update is not a Windows program; it was not installed".into());
    }
    Ok(Some(Update { version: m.version, notes: m.notes, bytes }))
}

fn sibling(exe: &Path, suffix: &str) -> PathBuf {
    let name = exe.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "sentrix-botd".into());
    exe.with_file_name(format!("{name}.{suffix}"))
}

/// Put `bytes` where `exe` is. A running program cannot be overwritten on Windows but it can be renamed, so the old file is
/// moved aside (`.old`), the new one moved in, and the old one removed on the next start. If anything fails the old program
/// is put back and the error returned.
pub fn install_over(exe: &Path, bytes: &[u8]) -> Result<(), String> {
    let (new, old) = (sibling(exe, "new"), sibling(exe, "old"));
    std::fs::write(&new, bytes).map_err(|e| format!("cannot write the update: {e}"))?;
    let _ = std::fs::remove_file(&old);
    if let Err(e) = std::fs::rename(exe, &old) {
        let _ = std::fs::remove_file(&new);
        return Err(format!("cannot move the current program aside: {e}"));
    }
    if let Err(e) = std::fs::rename(&new, exe) {
        let _ = std::fs::rename(&old, exe);
        let _ = std::fs::remove_file(&new);
        return Err(format!("cannot put the update in place: {e}"));
    }
    Ok(())
}

/// Remove what a previous update left behind. Call at start-up.
pub fn cleanup(exe: &Path) {
    let _ = std::fs::remove_file(sibling(exe, "old"));
    let _ = std::fs::remove_file(sibling(exe, "new"));
}

/// Start `exe` again with the same arguments (the environment is inherited). The caller exits right after.
pub fn restart(exe: &Path) -> std::io::Result<()> {
    std::process::Command::new(exe).args(std::env::args().skip(1)).spawn().map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::{Arc, Mutex};

    fn keypair() -> (minisign::KeyPair, String) {
        let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let pk_b64 = base64::engine::general_purpose::STANDARD.encode(kp.pk.to_box().unwrap().to_string());
        (kp, pk_b64)
    }

    fn sign(kp: &minisign::KeyPair, data: &[u8]) -> String {
        let sig = minisign::sign(Some(&kp.pk), &kp.sk, Cursor::new(data), Some("t"), Some("t")).unwrap();
        base64::engine::general_purpose::STANDARD.encode(sig.to_string())
    }

    #[test]
    fn versions_compare_by_number_not_by_text() {
        assert!(is_newer("0.2.0", "0.1.0") && is_newer("0.10.0", "0.9.9") && is_newer("1.0.0", "0.99.99") && is_newer("v0.2.1", "0.2.0"));
        assert!(!is_newer("0.2.0", "0.2.0") && !is_newer("0.1.9", "0.2.0") && !is_newer("0.2", "0.2.0"));
        assert!(is_newer("0.2.0.1", "0.2.0"));
        for junk in ["", "abc", "1..2", "1.x", "-1", "9999999999999999999999.0"] {
            assert!(!is_newer(junk, "0.1.0"), "{junk:?}");
        }
    }

    #[test]
    fn only_https_or_this_computer_is_accepted() {
        assert!(address_ok("https://github.com/x") && address_ok("http://127.0.0.1:9/x") && address_ok("http://localhost/x"));
        for bad in ["http://example.com/x", "ftp://example.com", "file:///c:/x", "http://127.0.0.1.evil.com/x", "http://127.0.0.1@evil.com/x", "http://localhost.evil.com/x", "", "127.0.0.1"] {
            assert!(!address_ok(bad), "{bad}");
        }
    }

    #[test]
    fn the_signature_must_match_the_file_and_the_key() {
        let (kp, pk) = keypair();
        let data = vec![9u8; 5000];
        let sig = sign(&kp, &data);
        assert!(verify(&pk, &sig, &data).is_ok());
        let mut bad = data.clone();
        bad[100] ^= 1;
        assert!(verify(&pk, &sig, &bad).is_err(), "one flipped byte");
        let (other, other_pk) = keypair();
        assert!(verify(&other_pk, &sig, &data).is_err(), "signed by a different key");
        assert!(verify(&pk, &sign(&other, &data), &data).is_err(), "an attacker's own signature");
        assert!(verify(&pk, "", &data).is_err() && verify(&pk, "garbage", &data).is_err() && verify("garbage", &sig, &data).is_err());
    }

    #[test]
    fn the_key_in_the_bot_is_the_key_the_desktop_app_trusts() {
        let conf: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../apps/desktop/src-tauri/tauri.conf.json")).unwrap()).unwrap();
        assert_eq!(conf["plugins"]["updater"]["pubkey"].as_str().unwrap().trim(), PUBLIC_KEY.trim(), "updater.pub and tauri.conf.json must hold the same key");
        assert!(minisign_verify::PublicKey::decode(&b64d(PUBLIC_KEY).unwrap()).is_ok());
    }

    /// A one-file web server for the feed and the download. `body` is what /bot.exe returns.
    struct Server {
        base: String,
        hits: Arc<Mutex<Vec<String>>>,
    }

    fn serve(manifest: impl Fn(&str) -> String + Send + 'static, body: Vec<u8>) -> Server {
        let http = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let base = format!("http://{}", http.server_addr().to_ip().unwrap());
        let hits = Arc::new(Mutex::new(vec![]));
        let (b, h) = (base.clone(), hits.clone());
        std::thread::spawn(move || {
            for req in http.incoming_requests() {
                let url = req.url().to_string();
                h.lock().unwrap().push(url.clone());
                let data = if url == "/feed.json" { manifest(&b).into_bytes() } else { body.clone() };
                let _ = req.respond(tiny_http::Response::from_data(data));
            }
        });
        Server { base, hits }
    }

    fn manifest_for(version: &str, bytes: &[u8], sig: &str, sha: Option<String>) -> impl Fn(&str) -> String {
        let (version, sig, sha) = (version.to_string(), sig.to_string(), sha.unwrap_or_else(|| hex::encode(Sha256::digest(bytes))));
        move |base: &str| serde_json::json!({"version": version, "url": format!("{base}/bot.exe"), "sha256": sha, "signature": sig, "notes": "faster"}).to_string()
    }

    fn program(tag: u8) -> Vec<u8> {
        let mut v = b"MZ".to_vec();
        v.extend(std::iter::repeat(tag).take(4000));
        v
    }

    #[test]
    fn a_newer_signed_version_is_downloaded_and_verified() {
        let (kp, pk) = keypair();
        let bytes = program(1);
        let s = serve(manifest_for("0.3.0", &bytes, &sign(&kp, &bytes), None), bytes.clone());
        let u = check(&format!("{}/feed.json", s.base), &pk, "0.2.0").unwrap().expect("an update");
        assert_eq!((u.version.as_str(), u.notes.as_str(), u.bytes == bytes), ("0.3.0", "faster", true));
    }

    #[test]
    fn the_same_or_an_older_version_downloads_nothing() {
        let (kp, pk) = keypair();
        let bytes = program(2);
        let s = serve(manifest_for("0.2.0", &bytes, &sign(&kp, &bytes), None), bytes);
        assert!(check(&format!("{}/feed.json", s.base), &pk, "0.2.0").unwrap().is_none());
        assert!(check(&format!("{}/feed.json", s.base), &pk, "0.3.0").unwrap().is_none(), "no downgrade");
        assert!(!s.hits.lock().unwrap().iter().any(|h| h == "/bot.exe"), "the program was never fetched");
    }

    #[test]
    fn a_tampered_download_is_refused_even_with_a_matching_checksum() {
        let (kp, pk) = keypair();
        let good = program(3);
        let sig = sign(&kp, &good);
        // The server swaps the file AND publishes the swapped file's checksum: only the signature can catch it.
        let evil = program(4);
        let s = serve(manifest_for("0.3.0", &evil, &sig, None), evil);
        let e = check(&format!("{}/feed.json", s.base), &pk, "0.2.0").err().expect("must be refused");
        assert!(e.contains("signature"), "{e}");
    }

    #[test]
    fn a_wrong_checksum_or_a_foreign_key_is_refused() {
        let (kp, pk) = keypair();
        let bytes = program(5);
        let s = serve(manifest_for("0.3.0", &bytes, &sign(&kp, &bytes), Some("00".repeat(32))), bytes.clone());
        assert!(check(&format!("{}/feed.json", s.base), &pk, "0.2.0").err().unwrap().contains("checksum"));
        let (attacker, _) = keypair();
        let s = serve(manifest_for("0.3.0", &bytes, &sign(&attacker, &bytes), None), bytes);
        assert!(check(&format!("{}/feed.json", s.base), &pk, "0.2.0").err().unwrap().contains("signature"), "signed by someone else");
    }

    #[test]
    fn a_feed_that_points_at_plain_http_somewhere_else_is_refused() {
        let (kp, pk) = keypair();
        let bytes = program(6);
        let sig = sign(&kp, &bytes);
        let s = serve(move |_b: &str| serde_json::json!({"version": "0.3.0", "url": "http://example.com/bot.exe", "sha256": "00", "signature": sig.clone()}).to_string(), bytes);
        assert!(check(&format!("{}/feed.json", s.base), &pk, "0.2.0").err().unwrap().contains("https"));
        assert!(check("http://example.com/feed.json", &pk, "0.2.0").err().unwrap().contains("https"));
    }

    #[test]
    fn installing_swaps_the_program_keeps_the_old_one_aside_and_cleanup_removes_it() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("sentrix-botd.exe");
        std::fs::write(&exe, program(7)).unwrap();
        install_over(&exe, &program(8)).unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), program(8));
        assert_eq!(std::fs::read(sibling(&exe, "old")).unwrap(), program(7));
        assert!(!sibling(&exe, "new").exists());
        cleanup(&exe);
        assert!(!sibling(&exe, "old").exists());
    }

    #[test]
    fn a_failed_install_leaves_the_current_program_alone() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.exe");
        assert!(install_over(&missing, &program(9)).is_err());
        assert!(!sibling(&missing, "new").exists(), "no half-written file is left behind");
    }
}
