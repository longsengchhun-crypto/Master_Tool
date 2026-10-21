//! Locating Telegram Desktop's download folder.
//!
//! Telegram Desktop keeps its configuration (including the chosen download path) inside the encrypted `tdata` store,
//! which SENTRIX does not and must not read. What can be done honestly is: detect whether Telegram Desktop appears to be
//! installed, offer the well-known default folder(s) that actually exist, and let the user confirm or pick another.
//! The user's choice is authoritative; Telegram can change it at any time, and the Real-Time Protection page shows
//! whether the chosen folder is still being watched.

use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Candidate {
    pub path: String,
    pub exists: bool,
    /// Files in the folder (non-recursive, capped): a hint that Telegram really saves here.
    pub file_count: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Detection {
    pub installed: bool,
    /// What indicated an installation (shown to the user so the guess is transparent).
    pub evidence: Vec<String>,
    pub candidates: Vec<Candidate>,
}

/// `downloads` and `documents` are the user's shell folders (they can be relocated, so they are inputs, not guesses).
pub fn detect(appdata: &Path, local_appdata: &Path, program_files: &[PathBuf], downloads: Option<&Path>, documents: Option<&Path>) -> Detection {
    let mut evidence = Vec::new();
    if appdata.join("Telegram Desktop").join("tdata").is_dir() {
        evidence.push("Telegram Desktop settings folder found in your profile".to_string());
    }
    if appdata.join("Telegram Desktop").join("Telegram.exe").is_file() {
        evidence.push("Telegram.exe found in your profile".to_string());
    }
    for pf in program_files {
        if pf.join("Telegram Desktop").join("Telegram.exe").is_file() {
            evidence.push(format!("Telegram.exe found in {}", pf.display()));
        }
    }
    if local_appdata.join("Packages").read_dir().map(|d| d.flatten().any(|e| e.file_name().to_string_lossy().starts_with("TelegramMessengerLLP."))).unwrap_or(false) {
        evidence.push("Microsoft Store version of Telegram Desktop found".to_string());
    }

    let mut paths: Vec<PathBuf> = Vec::new();
    if let Some(d) = downloads {
        paths.push(d.join("Telegram Desktop"));
    }
    if let Some(d) = documents {
        paths.push(d.join("Telegram Desktop"));
    }
    paths.dedup();
    let candidates = paths
        .into_iter()
        .map(|p| {
            let exists = p.is_dir();
            let file_count = if exists { p.read_dir().map(|d| d.flatten().filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false)).take(10_000).count()).unwrap_or(0) } else { 0 };
            Candidate { path: p.display().to_string(), exists, file_count }
        })
        .collect();
    Detection { installed: !evidence.is_empty(), evidence, candidates }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_found_on_a_machine_without_telegram() {
        let d = tempfile::tempdir().unwrap();
        let r = detect(&d.path().join("a"), &d.path().join("l"), &[], Some(&d.path().join("dl")), None);
        assert!(!r.installed && r.evidence.is_empty());
        assert_eq!(r.candidates.len(), 1);
        assert!(!r.candidates[0].exists, "a default folder that does not exist must say so, not pretend");
    }

    #[test]
    fn detects_an_install_and_the_default_download_folder() {
        let d = tempfile::tempdir().unwrap();
        let appdata = d.path().join("Roaming");
        std::fs::create_dir_all(appdata.join("Telegram Desktop").join("tdata")).unwrap();
        let dl = d.path().join("Downloads");
        std::fs::create_dir_all(dl.join("Telegram Desktop")).unwrap();
        std::fs::write(dl.join("Telegram Desktop").join("file1.pdf"), b"x").unwrap();
        std::fs::write(dl.join("Telegram Desktop").join("file2.zip"), b"x").unwrap();
        std::fs::create_dir(dl.join("Telegram Desktop").join("subdir")).unwrap();
        let r = detect(&appdata, &d.path().join("Local"), &[], Some(&dl), None);
        assert!(r.installed);
        assert!(r.evidence.iter().any(|e| e.contains("settings folder")));
        assert_eq!((r.candidates[0].exists, r.candidates[0].file_count), (true, 2), "folders are not counted as files");
    }

    #[test]
    fn detects_program_files_and_store_installs() {
        let d = tempfile::tempdir().unwrap();
        let pf = d.path().join("Program Files");
        std::fs::create_dir_all(pf.join("Telegram Desktop")).unwrap();
        std::fs::write(pf.join("Telegram Desktop").join("Telegram.exe"), b"MZ").unwrap();
        let local = d.path().join("Local");
        std::fs::create_dir_all(local.join("Packages").join("TelegramMessengerLLP.TelegramDesktop_abc")).unwrap();
        let r = detect(&d.path().join("none"), &local, &[pf], None, None);
        assert!(r.installed);
        assert_eq!(r.evidence.len(), 2);
    }

    #[test]
    fn relocated_shell_folders_are_respected() {
        let d = tempfile::tempdir().unwrap();
        let moved = d.path().join("D-drive").join("MyDownloads");
        std::fs::create_dir_all(moved.join("Telegram Desktop")).unwrap();
        let r = detect(&d.path().join("a"), &d.path().join("l"), &[], Some(&moved), Some(&d.path().join("Docs")));
        assert!(r.candidates[0].path.contains("MyDownloads") && r.candidates[0].exists);
        assert_eq!(r.candidates.len(), 2);
    }
}
