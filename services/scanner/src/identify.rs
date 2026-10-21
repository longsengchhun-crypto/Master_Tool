//! Layer A: file identification by content. The extension is only ever used to detect a *mismatch*.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    Pe,
    Elf,
    MachO,
    Lnk,
    Zip,
    Ooxml,
    Jar,
    Apk,
    Ole2,
    Pdf,
    SevenZip,
    Rar,
    Gzip,
    Iso,
    Dmg,
    ScriptPowerShell,
    ScriptBatch,
    ScriptVbs,
    ScriptJs,
    ScriptPython,
    ScriptShell,
    Html,
    Image,
    Media,
    Text,
    Unknown,
}

impl FileKind {
    pub fn label(self) -> &'static str {
        match self {
            FileKind::Pe => "Windows executable (PE)",
            FileKind::Elf => "Linux executable (ELF)",
            FileKind::MachO => "macOS executable (Mach-O)",
            FileKind::Lnk => "Windows shortcut (LNK)",
            FileKind::Zip => "ZIP archive",
            FileKind::Ooxml => "Office document (Open XML)",
            FileKind::Jar => "Java archive (JAR)",
            FileKind::Apk => "Android package (APK)",
            FileKind::Ole2 => "Legacy Office / installer container (OLE2)",
            FileKind::Pdf => "PDF document",
            FileKind::SevenZip => "7-Zip archive",
            FileKind::Rar => "RAR archive",
            FileKind::Gzip => "GZIP archive",
            FileKind::Iso => "ISO disk image",
            FileKind::Dmg => "Apple disk image (DMG)",
            FileKind::ScriptPowerShell => "PowerShell script",
            FileKind::ScriptBatch => "Batch script",
            FileKind::ScriptVbs => "VBScript",
            FileKind::ScriptJs => "JavaScript",
            FileKind::ScriptPython => "Python script",
            FileKind::ScriptShell => "Shell script",
            FileKind::Html => "HTML document",
            FileKind::Image => "Image",
            FileKind::Media => "Audio/video",
            FileKind::Text => "Plain text",
            FileKind::Unknown => "Unknown binary format",
        }
    }

    pub fn is_executable(self) -> bool {
        matches!(self, FileKind::Pe | FileKind::Elf | FileKind::MachO | FileKind::Lnk) || self.is_script()
    }

    pub fn is_script(self) -> bool {
        matches!(
            self,
            FileKind::ScriptPowerShell
                | FileKind::ScriptBatch
                | FileKind::ScriptVbs
                | FileKind::ScriptJs
                | FileKind::ScriptPython
                | FileKind::ScriptShell
        )
    }

    pub fn is_archive(self) -> bool {
        matches!(
            self,
            FileKind::Zip | FileKind::Jar | FileKind::Apk | FileKind::Ooxml | FileKind::SevenZip | FileKind::Rar | FileKind::Gzip | FileKind::Iso | FileKind::Dmg
        )
    }

    /// Whether our own parsers can open the container (ZIP family). Others rely on the signature engine's unpacker.
    pub fn zip_family(self) -> bool {
        matches!(self, FileKind::Zip | FileKind::Ooxml | FileKind::Jar | FileKind::Apk)
    }

    /// Formats the in-house static analyzers cover. Everything else is signature-engine-only and says so in the report.
    pub fn has_static_analyzer(self) -> bool {
        matches!(
            self,
            FileKind::Pe | FileKind::Elf | FileKind::MachO | FileKind::Pdf | FileKind::Ole2 | FileKind::Lnk | FileKind::Html
        ) || self.is_script()
            || self.zip_family()
    }
}

/// Extensions that users reasonably expect to be inert data. Executable content under one of these is a red flag.
const INERT_EXTS: &[&str] = &[
    "txt", "pdf", "jpg", "jpeg", "png", "gif", "bmp", "webp", "mp3", "mp4", "mov", "avi", "mkv", "wav", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "csv", "zip",
    "psd", "ai", "svg",
];

pub fn extension_of(name: &str) -> Option<String> {
    let n = name.rsplit(['\\', '/']).next().unwrap_or(name);
    let (stem, ext) = n.rsplit_once('.')?;
    if stem.is_empty() || ext.is_empty() || ext.len() > 12 {
        return None;
    }
    Some(ext.to_ascii_lowercase())
}

/// True if the name has a "document-like" extension followed by an executable one (invoice.pdf.exe).
pub fn double_extension(name: &str) -> bool {
    let n = name.rsplit(['\\', '/']).next().unwrap_or(name).to_ascii_lowercase();
    let parts: Vec<&str> = n.split('.').collect();
    if parts.len() < 3 {
        return false;
    }
    let last = parts[parts.len() - 1];
    let prev = parts[parts.len() - 2];
    matches!(last, "exe" | "scr" | "com" | "bat" | "cmd" | "ps1" | "vbs" | "js" | "jar" | "msi" | "lnk" | "pif") && INERT_EXTS.contains(&prev)
}

/// Identify from the first bytes plus (for text) a bounded prefix. `ext` disambiguates only where content is ambiguous.
pub fn identify(head: &[u8], ext: Option<&str>) -> FileKind {
    let h = head;
    let ext = ext.unwrap_or("");

    if h.starts_with(b"MZ") && looks_like_pe(h) {
        return FileKind::Pe;
    }
    if h.starts_with(b"\x7fELF") {
        return FileKind::Elf;
    }
    if h.len() >= 4 {
        let m = [h[0], h[1], h[2], h[3]];
        if matches!(m, [0xfe, 0xed, 0xfa, 0xce] | [0xfe, 0xed, 0xfa, 0xcf] | [0xce, 0xfa, 0xed, 0xfe] | [0xcf, 0xfa, 0xed, 0xfe] | [0xca, 0xfe, 0xba, 0xbe])
            && !(m == [0xca, 0xfe, 0xba, 0xbe] && ext == "class")
        {
            return FileKind::MachO;
        }
    }
    if h.starts_with(&[0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00]) {
        return FileKind::Lnk;
    }
    if h.starts_with(b"%PDF-") {
        return FileKind::Pdf;
    }
    if h.starts_with(b"PK\x03\x04") || h.starts_with(b"PK\x05\x06") {
        return match ext {
            "docx" | "xlsx" | "pptx" | "docm" | "xlsm" | "pptm" | "dotm" | "xltm" => FileKind::Ooxml,
            "jar" => FileKind::Jar,
            "apk" => FileKind::Apk,
            _ => FileKind::Zip,
        };
    }
    if h.starts_with(b"7z\xbc\xaf\x27\x1c") {
        return FileKind::SevenZip;
    }
    if h.starts_with(b"Rar!\x1a\x07") {
        return FileKind::Rar;
    }
    if h.starts_with(&[0x1f, 0x8b]) {
        return FileKind::Gzip;
    }
    if h.starts_with(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]) {
        return FileKind::Ole2;
    }
    if h.len() > 0x8006 && &h[0x8001..0x8006] == b"CD001" {
        return FileKind::Iso;
    }
    if h.starts_with(b"\x89PNG") || h.starts_with(&[0xff, 0xd8, 0xff]) || h.starts_with(b"GIF8") || h.starts_with(b"BM") && matches!(ext, "bmp") || h.starts_with(b"RIFF") && h.get(8..12) == Some(b"WEBP") {
        return FileKind::Image;
    }
    if h.starts_with(b"ID3") || h.starts_with(b"RIFF") || h.get(4..8) == Some(b"ftyp") || h.starts_with(b"\x1a\x45\xdf\xa3") || h.starts_with(b"OggS") || h.starts_with(b"fLaC") {
        return FileKind::Media;
    }
    if ext == "dmg" {
        return FileKind::Dmg; // DMG trailer ("koly") lives at EOF; extension is the only cheap hint here, and the report says so.
    }

    // Text-based formats: require the prefix to be valid-ish text before trusting keywords.
    if is_mostly_text(h) {
        let s = String::from_utf8_lossy(&h[..h.len().min(4096)]).to_ascii_lowercase();
        let first = s.trim_start_matches('\u{feff}').trim_start();
        if first.starts_with("#!") {
            if first.contains("python") {
                return FileKind::ScriptPython;
            }
            if first.contains("sh") || first.contains("bash") || first.contains("zsh") {
                return FileKind::ScriptShell;
            }
        }
        match ext {
            "ps1" | "psm1" | "psd1" => return FileKind::ScriptPowerShell,
            "bat" | "cmd" => return FileKind::ScriptBatch,
            "vbs" | "vbe" | "wsf" | "wsh" => return FileKind::ScriptVbs,
            "js" | "jse" | "mjs" => return FileKind::ScriptJs,
            "py" | "pyw" => return FileKind::ScriptPython,
            "sh" | "bash" => return FileKind::ScriptShell,
            "html" | "htm" | "hta" => return FileKind::Html,
            _ => {}
        }
        // Extension-independent content sniffing (catches scripts renamed to .txt/.jpg).
        if first.starts_with("@echo off") || first.starts_with("@echo on") || s.contains("\r\nset ") && s.contains("%~") {
            return FileKind::ScriptBatch;
        }
        if s.contains("invoke-expression") || s.contains("-encodedcommand") || s.contains("new-object net.webclient") || s.contains("$ErrorActionPreference".to_ascii_lowercase().as_str()) {
            return FileKind::ScriptPowerShell;
        }
        if s.contains("wscript.shell") || s.contains("createobject(") {
            return FileKind::ScriptVbs;
        }
        if first.starts_with("<!doctype html") || first.starts_with("<html") {
            return FileKind::Html;
        }
        return FileKind::Text;
    }
    FileKind::Unknown
}

/// Refine a ZIP once its central directory is readable. JAR/APK/OOXML can be disguised under any extension.
pub fn refine_zip(names: &[String]) -> FileKind {
    let has = |p: &str| names.iter().any(|n| n == p || n.starts_with(p));
    if has("[Content_Types].xml") && (has("word/") || has("xl/") || has("ppt/")) {
        FileKind::Ooxml
    } else if has("AndroidManifest.xml") && names.iter().any(|n| n.ends_with(".dex")) {
        FileKind::Apk
    } else if has("META-INF/MANIFEST.MF") {
        FileKind::Jar
    } else {
        FileKind::Zip
    }
}

/// Does executable content sit under an extension implying inert data (or under a different executable family)?
pub fn extension_mismatch(kind: FileKind, ext: Option<&str>) -> bool {
    let Some(ext) = ext else { return false };
    let inert = INERT_EXTS.contains(&ext);
    match kind {
        FileKind::Pe | FileKind::Elf | FileKind::MachO | FileKind::Lnk => inert,
        k if k.is_script() => inert && ext != "zip",
        // A document extension that is not actually that document type.
        FileKind::Pdf => ext != "pdf" && matches!(ext, "doc" | "docx" | "xls" | "xlsx" | "jpg" | "png" | "txt" | "mp3" | "mp4"),
        FileKind::Image => matches!(ext, "exe" | "dll" | "scr" | "bat" | "ps1" | "js" | "pdf" | "docx"),
        FileKind::Zip | FileKind::Ooxml => matches!(ext, "jpg" | "jpeg" | "png" | "gif" | "mp3" | "mp4" | "txt" | "pdf"),
        _ => false,
    }
}

fn looks_like_pe(h: &[u8]) -> bool {
    if h.len() < 0x40 {
        return false;
    }
    let off = u32::from_le_bytes([h[0x3c], h[0x3d], h[0x3e], h[0x3f]]) as usize;
    // If e_lfanew lies beyond our header window we cannot confirm; MZ + plausible offset is accepted and the PE parser decides.
    match h.get(off..off + 4) {
        Some(sig) => sig == b"PE\0\0",
        None => off < 0x1000_0000,
    }
}

fn is_mostly_text(h: &[u8]) -> bool {
    if h.is_empty() {
        return true;
    }
    let sample = &h[..h.len().min(4096)];
    if sample.contains(&0) && !(sample.starts_with(&[0xff, 0xfe]) || sample.starts_with(&[0xfe, 0xff])) {
        return false;
    }
    let bad = sample.iter().filter(|&&b| b < 0x09 || (b > 0x0d && b < 0x20)).count();
    bad * 20 < sample.len().max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exe_renamed_to_jpg_is_pe_and_mismatch() {
        let mut b = vec![0u8; 0x200];
        b[0] = b'M';
        b[1] = b'Z';
        b[0x3c] = 0x80;
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        let k = identify(&b, Some("jpg"));
        assert_eq!(k, FileKind::Pe);
        assert!(extension_mismatch(k, Some("jpg")));
    }

    #[test]
    fn script_renamed_to_txt_is_still_a_script() {
        let k = identify(b"@echo off\r\nset x=1\r\n", Some("txt"));
        assert_eq!(k, FileKind::ScriptBatch);
        assert!(extension_mismatch(k, Some("txt")));
    }

    #[test]
    fn double_extension_detected() {
        assert!(double_extension("invoice.pdf.exe"));
        assert!(!double_extension("setup.exe"));
        assert!(!double_extension("archive.tar.gz"));
    }

    #[test]
    fn plain_text_is_text() {
        assert_eq!(identify(b"hello world\n", Some("txt")), FileKind::Text);
        assert!(!extension_mismatch(FileKind::Text, Some("txt")));
    }

    #[test]
    fn binary_noise_is_unknown() {
        assert_eq!(identify(&[0, 1, 2, 3, 0, 0, 7, 8], None), FileKind::Unknown);
    }

    #[test]
    fn zip_refines_to_ooxml_and_jar() {
        let ooxml = vec!["[Content_Types].xml".to_string(), "word/document.xml".to_string()];
        assert_eq!(refine_zip(&ooxml), FileKind::Ooxml);
        let jar = vec!["META-INF/MANIFEST.MF".to_string()];
        assert_eq!(refine_zip(&jar), FileKind::Jar);
    }
}
