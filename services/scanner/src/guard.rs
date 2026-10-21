//! Execution guard: the strongest *user-mode, OS-supported, reversible* protection available without a kernel driver.
//!
//! For a file confirmed MALICIOUS by a signature engine that could not be quarantined, a deny-execute ACE for Everyone
//! (`icacls <file> /deny *S-1-1-0:(X)`) makes Windows refuse to launch it. The ACE is read back to confirm it exists
//! before SENTRIX claims the file is blocked.
//!
//! What this is NOT (documented in the product): it does not stop interpreters from reading a script, does not stop a
//! document from being opened, does not intercept downloads, and code running as the same user can remove it. It
//! complements quarantine; it is not a pre-download filter or a replacement for a signed minifilter driver.
//!
//! `icacls` is invoked by absolute path with an argument vector (no shell), so file names cannot inject commands.

use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GuardError {
    #[error("the execution guard is only available on Windows")]
    Unsupported,
    #[error("only an existing regular file can be guarded (links and folders are refused)")]
    NotAFile,
    #[error("icacls failed: {0}")]
    Failed(String),
    #[error("the deny-execute entry could not be confirmed after applying it")]
    NotApplied,
}

fn icacls() -> PathBuf {
    let root = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("C:\\Windows"));
    root.join("System32").join("icacls.exe")
}

fn check_target(path: &Path) -> Result<(), GuardError> {
    let m = std::fs::symlink_metadata(path).map_err(|_| GuardError::NotAFile)?;
    #[cfg(windows)]
    let link = {
        use std::os::windows::fs::MetadataExt;
        m.file_type().is_symlink() || m.file_attributes() & 0x400 != 0
    };
    #[cfg(not(windows))]
    let link = m.file_type().is_symlink();
    if !m.is_file() || link || !path.is_absolute() {
        return Err(GuardError::NotAFile);
    }
    Ok(())
}

#[cfg(windows)]
fn run(args: &[&std::ffi::OsStr]) -> Result<String, GuardError> {
    let out = Command::new(icacls()).args(args).output().map_err(|e| GuardError::Failed(e.to_string()))?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    if out.status.success() {
        Ok(text)
    } else {
        Err(GuardError::Failed(format!("{} {}", text.trim(), String::from_utf8_lossy(&out.stderr).trim()).trim().chars().take(200).collect()))
    }
}

/// Is a deny-execute entry present on the file?
#[cfg(windows)]
pub fn is_blocked(path: &Path) -> bool {
    use std::ffi::OsStr;
    // `(DENY)(X)` is not localised, unlike the account names around it.
    run(&[path.as_os_str(), OsStr::new("/q")]).map(|o| o.contains("(DENY)(X)") || o.contains("(DENY)(RX)")).unwrap_or(false)
}
#[cfg(not(windows))]
pub fn is_blocked(_path: &Path) -> bool {
    false
}

/// Apply the guard and verify it. Idempotent.
#[cfg(windows)]
pub fn block_execution(path: &Path) -> Result<(), GuardError> {
    use std::ffi::OsStr;
    check_target(path)?;
    run(&[path.as_os_str(), OsStr::new("/deny"), OsStr::new("*S-1-1-0:(X)"), OsStr::new("/q")])?;
    if is_blocked(path) {
        Ok(())
    } else {
        Err(GuardError::NotApplied)
    }
}
#[cfg(not(windows))]
pub fn block_execution(_path: &Path) -> Result<(), GuardError> {
    Err(GuardError::Unsupported)
}

/// Remove the guard (used when the user explicitly decides to allow the file).
#[cfg(windows)]
pub fn allow_execution(path: &Path) -> Result<(), GuardError> {
    use std::ffi::OsStr;
    check_target(path)?;
    run(&[path.as_os_str(), OsStr::new("/remove:d"), OsStr::new("*S-1-1-0"), OsStr::new("/q")])?;
    Ok(())
}
#[cfg(not(windows))]
pub fn allow_execution(_path: &Path) -> Result<(), GuardError> {
    Err(GuardError::Unsupported)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    fn sample_exe(dir: &Path) -> PathBuf {
        // A harmless, always-present console program copied into a temp folder.
        let src = PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32").join("whoami.exe");
        let dst = dir.join("guarded-sample.exe");
        std::fs::copy(src, &dst).unwrap();
        dst
    }

    #[test]
    fn the_guard_really_stops_the_program_from_launching_and_is_reversible() {
        let d = tempfile::tempdir().unwrap();
        let exe = sample_exe(d.path());
        assert!(Command::new(&exe).output().is_ok(), "precondition: the copy runs");
        assert!(!is_blocked(&exe));

        block_execution(&exe).unwrap();
        assert!(is_blocked(&exe), "the ACE must be read back");
        let err = Command::new(&exe).output().expect_err("Windows must refuse to launch a guarded executable");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
        assert!(std::fs::read(&exe).is_ok(), "reading must still work so the file can be rescanned and quarantined");

        block_execution(&exe).unwrap(); // idempotent

        allow_execution(&exe).unwrap();
        assert!(!is_blocked(&exe));
        assert!(Command::new(&exe).output().is_ok(), "running works again after the user allows it");
    }

    #[test]
    fn a_guarded_file_can_still_be_quarantined() {
        let d = tempfile::tempdir().unwrap();
        let exe = sample_exe(d.path());
        block_execution(&exe).unwrap();
        let q = crate::quarantine::Quarantine::open(d.path().join("vault")).unwrap();
        let rec = q.quarantine(&exe, None, crate::Verdict::Malicious, "t", "PE").unwrap();
        assert!(!exe.exists(), "deny-execute must not prevent removal by the owner");
        assert_eq!(rec.original_name, "guarded-sample.exe");
    }

    #[test]
    fn folders_missing_files_and_links_are_refused() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(block_execution(d.path()), Err(GuardError::NotAFile));
        assert_eq!(block_execution(&d.path().join("nope.exe")), Err(GuardError::NotAFile));
        let exe = sample_exe(d.path());
        let rel = Path::new("guarded-sample.exe");
        assert_eq!(block_execution(rel), Err(GuardError::NotAFile), "relative paths are refused");
        let junction_target = d.path().join("real");
        std::fs::create_dir(&junction_target).unwrap();
        let junction = d.path().join("jct");
        let st = Command::new("cmd").args(["/C", "mklink", "/J"]).arg(&junction).arg(&junction_target).output().unwrap();
        assert!(st.status.success());
        assert_eq!(block_execution(&junction), Err(GuardError::NotAFile));
        let _ = exe;
    }

    #[test]
    fn hostile_file_names_cannot_inject_arguments() {
        let d = tempfile::tempdir().unwrap();
        // Characters that would be dangerous in a shell line; valid in a Windows file name.
        let name = "a & calc.exe & echo (X) .exe";
        let p = d.path().join(name);
        std::fs::copy(PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32").join("whoami.exe"), &p).unwrap();
        block_execution(&p).unwrap();
        assert!(is_blocked(&p));
        allow_execution(&p).unwrap();
    }
}
