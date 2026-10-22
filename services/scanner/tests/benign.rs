//! False-positive check for the behaviour rules: run them over ordinary files that ship with Windows and common
//! programs, and list anything they would flag. Slow and machine-dependent, so it is ignored by default:
//!
//!     cargo test -p sentrix-core --test benign -- --ignored --nocapture
//!
//! The assertion is deliberately loose (almost nothing from a clean system should reach High); the printed list is the
//! useful part, because every entry is either a rule to tighten or a legitimate tool that really behaves that way.

use sentrix_core::heuristics;
use sentrix_core::identify;
use sentrix_core::types::Severity;
use std::path::{Path, PathBuf};

fn walk(dir: &Path, depth: usize, out: &mut Vec<PathBuf>, cap: usize) {
    if depth == 0 || out.len() >= cap {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        if out.len() >= cap {
            return;
        }
        let p = e.path();
        match e.file_type() {
            Ok(t) if t.is_dir() => walk(&p, depth - 1, out, cap),
            Ok(t) if t.is_file() => {
                if e.metadata().map(|m| m.len() <= 40 * 1024 * 1024).unwrap_or(false) {
                    out.push(p)
                }
            }
            _ => {}
        }
    }
}

#[test]
#[ignore = "scans files on this machine; run on purpose"]
fn ordinary_windows_and_program_files_are_not_flagged_high() {
    let roots = ["C:\\Windows\\System32", "C:\\Windows\\SysWOW64", "C:\\Windows\\Fonts", "C:\\Program Files", "C:\\Program Files (x86)"];
    let mut files = Vec::new();
    for r in roots {
        let cap = files.len() + 1000;
        walk(Path::new(r), 5, &mut files, cap);
    }
    let (mut scanned, mut medium, mut high) = (0usize, 0usize, 0usize);
    let mut shown = Vec::new();
    let mut tally: std::collections::BTreeMap<String, (usize, String)> = Default::default();
    for p in &files {
        let Ok(data) = std::fs::read(p) else { continue };
        let ext = p.extension().and_then(|e| e.to_str()).map(|e| e.to_ascii_lowercase());
        let kind = identify::identify(&data[..data.len().min(4096)], ext.as_deref());
        let found = heuristics::analyze(kind, &data);
        scanned += 1;
        for f in found.iter().filter(|f| f.source == sentrix_core::rules::SRC) {
            let e = tally.entry(f.name.clone()).or_insert((0usize, String::new()));
            e.0 += 1;
            if e.0 <= 3 {
                let m = f.evidence.split("Matched:").nth(1).unwrap_or("").chars().take(120).collect::<String>();
                e.1.push_str(&format!("\n      {} -> {m}", p.file_name().and_then(|n| n.to_str()).unwrap_or("")));
            }
        }
        let worst = found.iter().map(|f| f.severity).max();
        match worst {
            Some(Severity::High) => high += 1,
            Some(Severity::Medium) => medium += 1,
            _ => {}
        }
        if matches!(worst, Some(Severity::Medium) | Some(Severity::High)) && shown.len() < 80 {
            let what: Vec<String> = found.iter().filter(|f| f.severity >= Severity::Medium).map(|f| f.name.clone()).collect();
            shown.push(format!("{:?}: {}", worst.unwrap(), p.display()) + &format!("  <- {}", what.join("; ")));
        }
    }
    println!("scanned {scanned} files: {high} High, {medium} Medium");
    println!("technique rules that fired on ordinary files:");
    for (name, (n, ex)) in &tally {
        println!("  {n:>5} x {name}{ex}");
    }
    if std::env::var("SHOW_FILES").is_ok() {
        for s in &shown {
            println!("  {s}");
        }
    }
    assert!(scanned > 100, "found too few files to mean anything ({scanned})");
    assert!(high * 200 <= scanned, "{high} of {scanned} ordinary files reached High; tighten the rules");
}
