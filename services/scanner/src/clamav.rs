//! Layer B: known-threat detection via ClamAV.
//!
//! ClamAV is run as a supervised `clamd` daemon bound to 127.0.0.1 only, so the signature database is loaded once
//! (instead of ~10s per `clamscan` invocation). Files are streamed to it with INSTREAM; it never receives a path,
//! which sidesteps path/permission/TOCTOU issues. ClamAV is GPLv2 and is used strictly as a separate process.
//!
//! ClamAV does not detect every threat. A "clean" answer from it is evidence, not a guarantee.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClamOutcome {
    Clean,
    /// Raw signature name as reported by ClamAV.
    Found(String),
    /// The engine answered but reported an error (e.g. size limit); the file was NOT fully scanned.
    Error(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ClamError {
    #[error("ClamAV is not installed at the configured location")]
    NotInstalled,
    #[error("ClamAV signature database is missing; run a signature update first")]
    NoDatabase,
    #[error("clamd failed to start: {0}")]
    StartFailed(String),
    #[error("clamd connection failed: {0}")]
    Connect(String),
    #[error("i/o error talking to clamd: {0}")]
    Io(#[from] std::io::Error),
}

/// Map a ClamAV signature name to how we treat it. ClamAV's own "Heuristics.*" detections are not
/// definitive malware identifications, and its limit/encryption notices are coverage gaps, not threats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClamClass {
    Malicious,
    Suspicious,
    CoverageGap,
}

pub fn classify_signature(name: &str) -> ClamClass {
    let n = name.to_ascii_lowercase();
    if n.starts_with("heuristics.encrypted") || n.starts_with("heuristics.limits") || n.contains("exceeds.max") {
        ClamClass::CoverageGap
    } else if n.starts_with("heuristics.") || n.starts_with("pua.") {
        ClamClass::Suspicious
    } else {
        ClamClass::Malicious
    }
}

pub struct ClamEngine {
    install_dir: PathBuf,
    data_dir: PathBuf,
    child: Mutex<Option<Child>>,
    addr: Mutex<Option<SocketAddr>>,
}

impl ClamEngine {
    pub fn new(install_dir: impl Into<PathBuf>, data_dir: impl Into<PathBuf>) -> Self {
        ClamEngine {
            install_dir: install_dir.into(),
            data_dir: data_dir.into(),
            child: Mutex::new(None),
            addr: Mutex::new(None),
        }
    }

    fn exe(&self, name: &str) -> PathBuf {
        let n = if cfg!(windows) { format!("{name}.exe") } else { name.to_string() };
        self.install_dir.join(n)
    }

    pub fn db_dir(&self) -> PathBuf {
        self.data_dir.join("clamav-db")
    }

    pub fn is_installed(&self) -> bool {
        self.exe("clamd").is_file() && self.exe("freshclam").is_file()
    }

    pub fn has_database(&self) -> bool {
        let d = self.db_dir();
        ["main.cvd", "main.cld"].iter().any(|f| d.join(f).is_file()) && ["daily.cvd", "daily.cld"].iter().any(|f| d.join(f).is_file())
    }

    /// Age of the newest signature file, used to surface stale protection honestly.
    pub fn database_age(&self) -> Option<Duration> {
        let mut newest = None;
        for e in std::fs::read_dir(self.db_dir()).ok()?.flatten() {
            let n = e.file_name().to_string_lossy().to_ascii_lowercase();
            if n.ends_with(".cvd") || n.ends_with(".cld") {
                if let Ok(m) = e.metadata().and_then(|m| m.modified()) {
                    if newest.map_or(true, |x| m > x) {
                        newest = Some(m);
                    }
                }
            }
        }
        newest.and_then(|t| t.elapsed().ok())
    }

    /// Download/refresh signatures via freshclam. Updates are cryptographically verified by ClamAV itself
    /// (signed .cvd files). Returns freshclam's combined output.
    pub fn update_signatures(&self) -> Result<String, ClamError> {
        if !self.is_installed() {
            return Err(ClamError::NotInstalled);
        }
        std::fs::create_dir_all(self.db_dir())?;
        let conf = self.data_dir.join("freshclam.conf");
        std::fs::write(
            &conf,
            format!(
                "DatabaseDirectory {}\nDatabaseMirror database.clamav.net\nDNSDatabaseInfo current.cvd.clamav.net\nConnectTimeout 30\nReceiveTimeout 120\n",
                conf_path(&self.db_dir())
            ),
        )?;
        let out = crate::proc::no_window(Command::new(self.exe("freshclam")).arg(format!("--config-file={}", conf.display())).arg("--stdout").arg("--no-warnings").stdin(Stdio::null())).output()?;
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        if !out.status.success() {
            return Err(ClamError::StartFailed(format!("freshclam exited with {}: {}", out.status, text.lines().last().unwrap_or(""))));
        }
        Ok(text)
    }

    /// Start clamd if it is not already running. Idempotent.
    pub fn start(&self) -> Result<(), ClamError> {
        if !self.is_installed() {
            return Err(ClamError::NotInstalled);
        }
        if !self.has_database() {
            return Err(ClamError::NoDatabase);
        }
        if self.ping().is_ok() {
            return Ok(());
        }
        // Pick a free loopback port; clamd listens on 127.0.0.1 only.
        let port = TcpListener::bind("127.0.0.1:0").map_err(|e| ClamError::StartFailed(e.to_string()))?.local_addr()?.port();
        let conf = self.data_dir.join("clamd.conf");
        std::fs::write(
            &conf,
            format!(
                "DatabaseDirectory {}\nTCPSocket {port}\nTCPAddr 127.0.0.1\nForeground yes\nMaxThreads 4\nStreamMaxLength 512M\nMaxFileSize 512M\nMaxScanSize 1024M\nMaxRecursion 16\nMaxFiles 20000\nAlertEncrypted yes\nAlertExceedsMax yes\nLogTime yes\n{}",
                conf_path(&self.db_dir()),
                // Operator tuning without a rebuild: extra clamd.conf lines separated by ';' (read from the environment only).
                std::env::var("SENTRIX_CLAMD_EXTRA").map(|e| e.split(';').map(|l| format!("{}\n", l.trim())).collect::<String>()).unwrap_or_default()
            ),
        )?;
        let child = crate::proc::no_window(Command::new(self.exe("clamd")).arg(format!("--config-file={}", conf.display())).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()))
            .spawn()
            .map_err(|e| ClamError::StartFailed(e.to_string()))?;
        job::kill_with_parent(&child);
        *self.child.lock().unwrap() = Some(child);
        *self.addr.lock().unwrap() = Some(SocketAddr::from(([127, 0, 0, 1], port)));

        // Loading the database takes a while; wait for PONG with a ceiling.
        let deadline = Instant::now() + Duration::from_secs(180);
        while Instant::now() < deadline {
            if let Some(c) = self.child.lock().unwrap().as_mut() {
                if let Ok(Some(status)) = c.try_wait() {
                    return Err(ClamError::StartFailed(format!("clamd exited early with {status}")));
                }
            }
            if self.ping().is_ok() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        self.stop();
        Err(ClamError::StartFailed("timed out waiting for clamd to load signatures".into()))
    }

    pub fn stop(&self) {
        if let Some(mut c) = self.child.lock().unwrap().take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        *self.addr.lock().unwrap() = None;
    }

    fn connect(&self) -> Result<TcpStream, ClamError> {
        let addr = (*self.addr.lock().unwrap()).ok_or_else(|| ClamError::Connect("clamd is not running".into()))?;
        let s = TcpStream::connect_timeout(&addr, Duration::from_secs(3)).map_err(|e| ClamError::Connect(e.to_string()))?;
        s.set_read_timeout(Some(Duration::from_secs(300)))?;
        s.set_write_timeout(Some(Duration::from_secs(60)))?;
        Ok(s)
    }

    fn command(&self, cmd: &[u8]) -> Result<String, ClamError> {
        let mut s = self.connect()?;
        s.write_all(cmd)?;
        let mut buf = Vec::new();
        s.read_to_end(&mut buf)?;
        Ok(String::from_utf8_lossy(&buf).trim_end_matches('\0').trim().to_string())
    }

    pub fn ping(&self) -> Result<(), ClamError> {
        if self.command(b"zPING\0")? == "PONG" {
            Ok(())
        } else {
            Err(ClamError::Connect("unexpected PING reply".into()))
        }
    }

    /// e.g. "ClamAV 1.4.3/27800/Tue Oct 20 08:25:00 2026" — engine version / signature DB version / DB build time.
    pub fn version(&self) -> Result<String, ClamError> {
        self.command(b"zVERSION\0")
    }

    pub fn reload(&self) -> Result<(), ClamError> {
        self.command(b"zRELOAD\0").map(|_| ())
    }

    /// Stream `reader` to clamd. `cancel` is polled between chunks.
    pub fn scan_stream(&self, reader: &mut dyn Read, cancel: &dyn Fn() -> bool) -> Result<ClamOutcome, ClamError> {
        let mut s = self.connect()?;
        s.write_all(b"zINSTREAM\0")?;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            if cancel() {
                return Ok(ClamOutcome::Error("cancelled".into()));
            }
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            s.write_all(&(n as u32).to_be_bytes())?;
            s.write_all(&buf[..n])?;
        }
        s.write_all(&0u32.to_be_bytes())?;
        let mut reply = Vec::new();
        s.read_to_end(&mut reply)?;
        Ok(parse_reply(&String::from_utf8_lossy(&reply)))
    }
}

impl Drop for ClamEngine {
    fn drop(&mut self) {
        self.stop();
    }
}

/// clamd replies "stream: OK", "stream: <Name> FOUND" or "<msg> ERROR", NUL-terminated.
pub fn parse_reply(raw: &str) -> ClamOutcome {
    let r = raw.trim_matches(|c: char| c == '\0' || c.is_whitespace());
    if let Some(body) = r.strip_suffix("FOUND") {
        let name = body.trim().trim_start_matches("stream:").trim();
        return ClamOutcome::Found(name.to_string());
    }
    if r.ends_with("ERROR") {
        return ClamOutcome::Error(r.to_string());
    }
    if r.ends_with("OK") {
        return ClamOutcome::Clean;
    }
    ClamOutcome::Error(format!("unrecognised clamd reply: {r:?}"))
}

/// Ensure clamd cannot outlive SENTRIX: a crash of the parent must not leave a ~1 GB daemon running.
#[cfg(windows)]
mod job {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;
    use std::sync::OnceLock;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::JobObjects::*;

    static JOB: OnceLock<usize> = OnceLock::new();

    pub fn kill_with_parent(child: &std::process::Child) {
        let job = *JOB.get_or_init(|| unsafe {
            let h = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if h.is_null() {
                return 0;
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let ok = SetInformationJobObject(h, JobObjectExtendedLimitInformation, &info as *const _ as *const c_void, std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32);
            if ok == 0 {
                return 0;
            }
            h as usize
        });
        if job != 0 {
            unsafe {
                AssignProcessToJobObject(job as HANDLE, child.as_raw_handle() as HANDLE);
            }
        }
    }
}
#[cfg(not(windows))]
mod job {
    pub fn kill_with_parent(_child: &std::process::Child) {}
}

/// clamd.conf wants forward slashes on Windows too.
fn conf_path(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_replies() {
        assert_eq!(parse_reply("stream: OK\0"), ClamOutcome::Clean);
        assert_eq!(parse_reply("stream: Win.Test.EICAR_HDB-1 FOUND\0"), ClamOutcome::Found("Win.Test.EICAR_HDB-1".into()));
        assert!(matches!(parse_reply("INSTREAM size limit exceeded. ERROR\0"), ClamOutcome::Error(_)));
        assert!(matches!(parse_reply("???"), ClamOutcome::Error(_)));
    }

    #[test]
    fn classification_is_conservative() {
        assert_eq!(classify_signature("Win.Test.EICAR_HDB-1"), ClamClass::Malicious);
        assert_eq!(classify_signature("Heuristics.Phishing.Email.SpoofedDomain"), ClamClass::Suspicious);
        assert_eq!(classify_signature("Heuristics.Encrypted.Zip"), ClamClass::CoverageGap);
        assert_eq!(classify_signature("Heuristics.Limits.Exceeded"), ClamClass::CoverageGap);
    }

    #[test]
    fn missing_install_is_reported_not_faked() {
        let e = ClamEngine::new("Z:/does/not/exist", "Z:/nope");
        assert!(!e.is_installed());
        assert!(matches!(e.start(), Err(ClamError::NotInstalled)));
    }
}
