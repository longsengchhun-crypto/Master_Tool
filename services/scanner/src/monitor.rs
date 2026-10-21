//! Folder monitoring using OS file-change notifications (ReadDirectoryChangesW on Windows via `notify`), never
//! by polling the whole disk. A file is handed to the callback only after it has stopped changing, so partial
//! downloads are not scanned (and not reported clean) while a browser is still writing them.
//!
//! Scope: this watches the folders it is given. It does not hook browsers or mail clients and does not block
//! execution; it scans after the file lands. See docs/PLATFORM_SUPPORT.md.

use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const SETTLE: Duration = Duration::from_millis(1500);
const TEMP_SUFFIXES: &[&str] = &[".crdownload", ".part", ".partial", ".download", ".tmp", ".temp", ".opdownload", ".!ut"];

#[derive(Debug, Clone, serde::Serialize)]
pub struct MonitorStatus {
    pub watching: Vec<PathBuf>,
    /// Folders that could not be watched (missing, permission denied). Reported, never silently dropped.
    pub failed: Vec<(PathBuf, String)>,
}

pub struct Monitor {
    _watcher: RecommendedWatcher,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    pub status: MonitorStatus,
}

pub fn is_temp_name(p: &Path) -> bool {
    let n = p.file_name().map(|s| s.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    n.starts_with("~$") || TEMP_SUFFIXES.iter().any(|s| n.ends_with(s))
}

impl Monitor {
    /// `on_file` runs on the monitor's worker thread; keep it quick or hand work to a queue.
    pub fn start(dirs: &[PathBuf], on_file: Arc<dyn Fn(PathBuf) + Send + Sync>) -> Result<Monitor, notify::Error> {
        let (tx, rx) = channel::<PathBuf>();
        let mut watcher = notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
            if let Ok(ev) = res {
                if matches!(ev.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                    for p in ev.paths {
                        let _ = tx.send(p);
                    }
                }
            }
        })?;

        let mut status = MonitorStatus { watching: Vec::new(), failed: Vec::new() };
        for d in dirs {
            match watcher.watch(d, RecursiveMode::Recursive) {
                Ok(()) => status.watching.push(d.clone()),
                Err(e) => status.failed.push((d.clone(), e.to_string())),
            }
        }

        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let worker = std::thread::spawn(move || {
            // path -> (last seen size, time of last change)
            let mut pending: HashMap<PathBuf, (u64, Instant)> = HashMap::new();
            while !stop2.load(Ordering::Relaxed) {
                match rx.recv_timeout(Duration::from_millis(400)) {
                    Ok(p) => {
                        if !is_temp_name(&p) {
                            pending.entry(p).and_modify(|e| e.1 = Instant::now()).or_insert((u64::MAX, Instant::now()));
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => break,
                }
                let now = Instant::now();
                let due: Vec<PathBuf> = pending.iter().filter(|(_, (_, t))| now.duration_since(*t) >= SETTLE).map(|(p, _)| p.clone()).collect();
                for p in due {
                    let Ok(m) = std::fs::symlink_metadata(&p) else {
                        pending.remove(&p);
                        continue;
                    };
                    if !m.is_file() {
                        pending.remove(&p);
                        continue;
                    }
                    let (last_size, _) = pending[&p];
                    if m.len() != last_size {
                        // Still growing (or first observation): wait another settle period.
                        pending.insert(p, (m.len(), Instant::now()));
                    } else {
                        pending.remove(&p);
                        on_file(p);
                    }
                }
            }
        });

        Ok(Monitor { _watcher: watcher, stop, worker: Some(worker), status })
    }

    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn temp_names_are_ignored() {
        assert!(is_temp_name(Path::new("C:/d/file.zip.crdownload")));
        assert!(is_temp_name(Path::new("C:/d/~$doc.docx")));
        assert!(!is_temp_name(Path::new("C:/d/setup.exe")));
    }

    #[test]
    fn new_file_is_reported_once_after_it_settles() {
        let d = tempfile::tempdir().unwrap();
        let seen: Arc<Mutex<Vec<PathBuf>>> = Arc::new(Mutex::new(Vec::new()));
        let s2 = seen.clone();
        let m = Monitor::start(&[d.path().to_path_buf()], Arc::new(move |p| s2.lock().unwrap().push(p))).unwrap();
        assert!(m.status.failed.is_empty());
        let f = d.path().join("download.bin");
        // Simulate a download still being written, then finishing.
        std::fs::write(&f, b"part1").unwrap();
        std::thread::sleep(Duration::from_millis(600));
        std::fs::write(&f, b"part1part2part3").unwrap();
        let deadline = Instant::now() + Duration::from_secs(12);
        while Instant::now() < deadline && seen.lock().unwrap().is_empty() {
            std::thread::sleep(Duration::from_millis(200));
        }
        std::thread::sleep(Duration::from_secs(3)); // make sure no duplicate fires
        m.stop();
        let v = seen.lock().unwrap();
        assert_eq!(v.len(), 1, "expected exactly one callback, got {v:?}");
        assert_eq!(v[0].file_name().unwrap(), "download.bin");
    }

    #[test]
    fn missing_folder_is_reported_not_hidden() {
        let m = Monitor::start(&[PathBuf::from("Z:/definitely/not/here")], Arc::new(|_| {})).unwrap();
        assert_eq!(m.status.failed.len(), 1);
        assert!(m.status.watching.is_empty());
    }
}
