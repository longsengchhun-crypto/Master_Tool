//! Safe archive inspection (ZIP family). Entries are decompressed into bounded in-memory buffers, analysed, and
//! discarded. Nothing is ever extracted to disk or executed, so entry names cannot cause path traversal here.
//! 7z/RAR/ISO/DMG are not opened by in-house code; they rely on the signature engine's unpacker and are reported
//! as such rather than being implied safe.

use crate::eicar;
use crate::heuristics;
use crate::identify::{self, FileKind};
use crate::types::{CheckStatus, Finding, FindingKind, Limits, Severity};
use std::io::{Cursor, Read};

const SRC: &str = "heuristic.archive";

pub struct ArchiveResult {
    pub findings: Vec<Finding>,
    pub status: CheckStatus,
    pub note: Option<String>,
    pub refined_kind: FileKind,
}

struct Budget {
    total: u64,
    entries: usize,
    limited: Option<String>,
}

pub fn inspect_zip(data: &[u8], limits: &Limits, cancel: &dyn Fn() -> bool) -> ArchiveResult {
    let mut findings = Vec::new();
    let mut budget = Budget { total: 0, entries: 0, limited: None };
    let (refined, failed) = walk(data, limits, 0, "", &mut findings, &mut budget, cancel);
    let (status, note) = if failed {
        (CheckStatus::Failed, Some("The archive structure could not be read; contents were not inspected.".to_string()))
    } else if let Some(why) = budget.limited.take() {
        (CheckStatus::Incomplete, Some(why))
    } else if cancel() {
        (CheckStatus::Incomplete, Some("Scan cancelled before the archive was fully inspected.".to_string()))
    } else {
        (CheckStatus::Completed, None)
    };
    ArchiveResult { findings, status, note, refined_kind: refined }
}

/// Returns (refined kind, structure_unreadable).
fn walk(data: &[u8], limits: &Limits, depth: u32, prefix: &str, out: &mut Vec<Finding>, b: &mut Budget, cancel: &dyn Fn() -> bool) -> (FileKind, bool) {
    let mut zip = match zip::ZipArchive::new(Cursor::new(data)) {
        Ok(z) => z,
        Err(e) => {
            out.push(Finding::new(SRC, "Malformed archive", FindingKind::Heuristic, Severity::Low, format!("The ZIP structure is damaged or deliberately malformed: {e}")).at(label(prefix)));
            return (FileKind::Zip, true);
        }
    };
    let names: Vec<String> = zip.file_names().map(|s| s.to_string()).collect();
    let refined = identify::refine_zip(&names);

    if zip.len() > limits.archive_max_entries {
        b.limited.get_or_insert_with(|| format!("Archive has {} entries (limit {}); only part was inspected.", zip.len(), limits.archive_max_entries));
    }

    for i in 0..zip.len().min(limits.archive_max_entries) {
        if cancel() {
            return (refined, false);
        }
        b.entries += 1;
        let (name, size, csize, encrypted, is_dir) = match zip.by_index_raw(i) {
            Ok(f) => (f.name().to_string(), f.size(), f.compressed_size(), f.encrypted(), f.is_dir()),
            Err(_) => continue,
        };
        if is_dir {
            continue;
        }
        let loc = format!("{}{}", prefix, name);

        // Names that would escape the extraction directory in a naive extractor (Zip Slip).
        if name.contains("..") || name.starts_with('/') || name.starts_with('\\') || name.as_bytes().get(1) == Some(&b':') {
            out.push(Finding::new(SRC, "Entry path escapes the extraction folder", FindingKind::Heuristic, Severity::Medium, "The entry name uses '..' or an absolute path, which some extraction tools would follow outside the target folder.").at(&loc));
        }
        if identify::double_extension(&name) {
            out.push(Finding::new(SRC, "Double file extension", FindingKind::Heuristic, Severity::Medium, "A document-style extension is followed by an executable extension, a common disguise.").at(&loc));
        }
        if encrypted {
            out.push(Finding::new(SRC, "Password-protected entry", FindingKind::Coverage, Severity::Low, "This entry is encrypted, so its contents cannot be inspected.").at(&loc));
            b.limited.get_or_insert_with(|| "One or more archive entries are password-protected and could not be inspected.".to_string());
            continue;
        }
        if size > 1024 * 1024 && csize > 0 && size / csize > limits.archive_max_ratio {
            out.push(Finding::new(SRC, "Possible decompression bomb", FindingKind::Heuristic, Severity::Medium, format!("Entry expands from {csize} to {size} bytes (ratio over {}:1); it was not decompressed.", limits.archive_max_ratio)).at(&loc));
            b.limited.get_or_insert_with(|| "An entry with an extreme compression ratio was skipped.".to_string());
            continue;
        }
        if size > limits.archive_max_entry_bytes || b.total.saturating_add(size) > limits.archive_max_total_bytes {
            b.limited.get_or_insert_with(|| "Archive contents exceed the safe inspection size; some entries were skipped.".to_string());
            continue;
        }

        // Bounded read: never trust the declared size (a lying header is itself a bomb signal).
        let mut buf = Vec::with_capacity(size.min(16 * 1024 * 1024) as usize);
        let read_ok = match zip.by_index(i) {
            Ok(f) => f.take(size + 1).read_to_end(&mut buf).is_ok(),
            Err(_) => false,
        };
        if !read_ok {
            b.limited.get_or_insert_with(|| "An archive entry could not be decompressed.".to_string());
            continue;
        }
        if buf.len() as u64 > size {
            out.push(Finding::new(SRC, "Entry larger than declared", FindingKind::Heuristic, Severity::Medium, "The decompressed data exceeds the size recorded in the archive header, which indicates a malformed or hostile archive.").at(&loc));
            continue;
        }
        b.total += buf.len() as u64;

        if eicar::contains_eicar(&buf) {
            let mut fnd = Finding::new("builtin-eicar", "EICAR-Test-File", FindingKind::Signature, Severity::High, "The EICAR anti-malware test string was found inside the archive.").at(&loc);
            fnd.engine_version = Some(crate::ENGINE_VERSION.to_string());
            out.push(fnd);
        }

        let ext = identify::extension_of(&name);
        let head = &buf[..buf.len().min(0x9000)];
        let mut kind = identify::identify(head, ext.as_deref());
        if identify::extension_mismatch(kind, ext.as_deref()) {
            out.push(Finding::new(SRC, "File content does not match its name", FindingKind::Heuristic, Severity::Medium, format!("Content looks like {} but the name suggests otherwise.", kind.label())).at(&loc));
        }
        if matches!(kind, FileKind::Zip | FileKind::Jar | FileKind::Apk | FileKind::Ooxml) && kind != FileKind::Ooxml {
            if depth + 1 >= limits.archive_max_depth {
                out.push(Finding::new(SRC, "Archive nesting limit reached", FindingKind::Coverage, Severity::Low, format!("Nested archives deeper than {} levels were not opened.", limits.archive_max_depth)).at(&loc));
                b.limited.get_or_insert_with(|| "Nested archives beyond the depth limit were not inspected.".to_string());
            } else {
                let nested_prefix = format!("{loc}!");
                let (k, _bad) = walk(&buf, limits, depth + 1, &nested_prefix, out, b, cancel);
                kind = k;
            }
        }
        if kind.has_static_analyzer() && !kind.zip_family() {
            let found = std::panic::catch_unwind(|| heuristics::analyze(kind, &buf)).unwrap_or_else(|_| {
                vec![Finding::new(SRC, "Analyzer failure", FindingKind::Coverage, Severity::Low, "An internal parser failed on this entry; it was not analysed.")]
            });
            out.extend(found.into_iter().map(|f| f.at(&loc)));
        }
    }
    (refined, false)
}

fn label(prefix: &str) -> String {
    if prefix.is_empty() { "(archive)".to_string() } else { prefix.trim_end_matches('!').to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (n, d) in entries {
            w.start_file(*n, SimpleFileOptions::default()).unwrap();
            w.write_all(d).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn eicar_inside_zip_is_found() {
        let z = make_zip(&[("a.txt", b"hi"), ("sub/eicar.com", &eicar::eicar_bytes())]);
        let r = inspect_zip(&z, &Limits::default(), &|| false);
        assert!(r.findings.iter().any(|f| f.kind == FindingKind::Signature && f.location.as_deref() == Some("sub/eicar.com")));
        assert_eq!(r.status, CheckStatus::Completed);
    }

    #[test]
    fn nested_zip_eicar_is_found_within_depth() {
        let inner = make_zip(&[("e.com", &eicar::eicar_bytes())]);
        let outer = make_zip(&[("inner.zip", &inner)]);
        let r = inspect_zip(&outer, &Limits::default(), &|| false);
        assert!(r.findings.iter().any(|f| f.kind == FindingKind::Signature));
    }

    #[test]
    fn depth_limit_makes_scan_incomplete() {
        let mut z = make_zip(&[("e.com", &eicar::eicar_bytes())]);
        for _ in 0..5 {
            z = make_zip(&[("n.zip", &z)]);
        }
        let r = inspect_zip(&z, &Limits::default(), &|| false);
        assert_eq!(r.status, CheckStatus::Incomplete);
    }

    #[test]
    fn zip_slip_name_flagged() {
        let z = make_zip(&[("../../evil.txt", b"x")]);
        let r = inspect_zip(&z, &Limits::default(), &|| false);
        assert!(r.findings.iter().any(|f| f.name.contains("escapes")));
    }

    #[test]
    fn double_extension_flagged() {
        let z = make_zip(&[("invoice.pdf.exe", b"MZ")]);
        let r = inspect_zip(&z, &Limits::default(), &|| false);
        assert!(r.findings.iter().any(|f| f.name.contains("Double")));
    }

    #[test]
    fn decompression_bomb_is_skipped_not_inflated() {
        // 64 MiB of zeros deflates to ~64 KiB (ratio ~1000:1).
        let big = vec![0u8; 64 * 1024 * 1024];
        let z = make_zip(&[("bomb.bin", &big)]);
        let r = inspect_zip(&z, &Limits::default(), &|| false);
        assert!(r.findings.iter().any(|f| f.name.contains("bomb")));
        assert_eq!(r.status, CheckStatus::Incomplete);
    }

    #[test]
    fn corrupt_zip_fails_closed() {
        let r = inspect_zip(b"PK\x03\x04garbage-not-a-zip", &Limits::default(), &|| false);
        assert_eq!(r.status, CheckStatus::Failed);
    }

    #[test]
    fn entry_budget_limit_is_enforced() {
        let l = Limits { archive_max_total_bytes: 1000, ..Limits::default() };
        let z = make_zip(&[("a.bin", &vec![1u8; 2000])]);
        let r = inspect_zip(&z, &l, &|| false);
        assert_eq!(r.status, CheckStatus::Incomplete);
    }
}
