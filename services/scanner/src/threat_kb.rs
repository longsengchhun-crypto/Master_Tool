//! What kinds of threat exist, what attackers want from each, how they usually get in, and what to do.
//!
//! This is explanation, not detection. Detection comes from the signature engine (which NAMES a threat) and from the technique
//! rules (which describe BEHAVIOUR). This module turns either into plain language, so a person learns what they are looking at:
//! "Information stealer: it takes saved passwords and Telegram sessions", not just a code like `Win.Trojan.Agent-1234`.
//!
//! Two confidence levels are kept apart on purpose:
//!  * identified: the malware engine named the file, and the name maps to a family. Strong, but the mapping is by naming
//!    convention, so the family is the engine's own classification and not a separate finding.
//!  * suggested: no engine named it; its behaviour resembles a family. This is evidence and never proof.
//!
//! MITRE ATT&CK ids are reference labels for the behaviour (https://attack.mitre.org/techniques/<id>/). They say what the
//! technique is called, not that the file did it.

use crate::types::{Finding, FindingKind, Severity, ThreatInfo};

pub struct Family {
    pub id: &'static str,
    pub title: &'static str,
    /// What the attacker gets out of it, in plain words.
    pub goal: &'static str,
    /// The usual ways it reaches a victim.
    pub arrives_via: &'static [&'static str],
    pub attack: &'static [&'static str],
    pub advice: &'static str,
}

pub static FAMILIES: &[Family] = &[
    Family {
        id: "ransomware",
        title: "Ransomware",
        goal: "Locks your files with encryption and demands payment for the key. It usually deletes backups first, and often steals copies of your files to threaten to publish them.",
        arrives_via: &["Email attachments and fake invoices", "Cracked software and key generators", "Hacked remote-desktop or VPN logins", "Fake updates and malicious downloads"],
        attack: &["T1486", "T1490"],
        advice: "Do not open or run it. If it already ran: disconnect from the network at once, do not restart, do not pay, keep the file quarantined, and restore from an offline backup. Change passwords from a clean device.",
    },
    Family {
        id: "stealer",
        title: "Information stealer",
        goal: "Takes saved passwords, browser cookies and sessions, crypto wallets and messenger data (Telegram, Discord) and sends them to the attacker. A stolen session lets them sign in as you without a password.",
        arrives_via: &["Cracked software, game cheats and mods", "Fake installers and fake updates", "Malicious email attachments", "Files sent in Telegram or Discord chats"],
        attack: &["T1555.003", "T1539", "T1005", "T1567"],
        advice: "Do not run it. If it already ran: from a clean device change your passwords, sign out everywhere (in Telegram: Settings, Devices, end all other sessions), turn on two-step verification, and move any crypto to a new wallet.",
    },
    Family {
        id: "spyware",
        title: "Spyware or keylogger",
        goal: "Records what you type, takes screenshots or watches your activity, and sends it out.",
        arrives_via: &["Cracked software", "Fake installers", "Email attachments"],
        attack: &["T1056.001", "T1113", "T1567"],
        advice: "Do not run it. If it already ran, change your passwords from a clean device and scan the computer fully.",
    },
    Family {
        id: "backdoor",
        title: "Backdoor or remote-access trojan (RAT)",
        goal: "Gives the attacker remote control: files, keyboard, camera and commands, and a way back in later.",
        arrives_via: &["Email attachments", "Cracked or trojanized software", "Exposed servers and weak passwords"],
        attack: &["T1059", "T1071", "T1095", "T1219"],
        advice: "Do not run it. If it already ran, treat the computer as controlled by someone else: disconnect it, scan it fully, and change passwords from another device.",
    },
    Family {
        id: "loader",
        title: "Downloader, dropper or loader",
        goal: "Its job is to bring other malware onto the computer, often ransomware or a stealer, usually after checking that it is not being analysed.",
        arrives_via: &["Email attachments: scripts, shortcuts, ZIP, ISO and OneNote files", "Malicious web pages", "Fake updates"],
        attack: &["T1105", "T1204.002", "T1059", "T1027.006"],
        advice: "Do not open it. It is the first step of a larger attack, so check where it came from and quarantine it.",
    },
    Family {
        id: "defense-evasion",
        title: "Security-tool evasion",
        goal: "Hides the attack from antivirus and analysts by switching protections off, patching scanners or detecting sandboxes.",
        arrives_via: &["Part of a larger piece of malware"],
        attack: &["T1562.001", "T1497.001", "T1027"],
        advice: "Treat as suspicious. Legitimate management tools do some of this, so confirm the source before deciding.",
    },
    Family {
        id: "credential-theft",
        title: "Credential-theft tooling",
        goal: "Pulls passwords and login tickets out of memory so an attacker can move on to other accounts and computers.",
        arrives_via: &["Used by an attacker who already has access", "Bundled into ransomware and intrusion kits"],
        attack: &["T1003.001"],
        advice: "Do not run it. Security testers use these tools, but on a normal computer their presence is a warning sign: check who put it there.",
    },
    Family {
        id: "phishing",
        title: "Phishing page",
        goal: "Imitates a sign-in page to capture your username, password and sometimes one-time codes.",
        arrives_via: &["HTML attachments in email or chat", "Links in messages"],
        attack: &["T1566.002", "T1056.003"],
        advice: "Do not open it or type anything into it. If you did, change that password at the real site and turn on two-step verification.",
    },
    Family {
        id: "webshell",
        title: "Web shell",
        goal: "A hidden control panel on a web server that lets the attacker run commands there and keep access.",
        arrives_via: &["Uploaded through a vulnerable website or plugin", "Compromised hosting accounts"],
        attack: &["T1505.003", "T1190"],
        advice: "Remove it from the server, then find out how it got there and patch that, or it will come back. Change the server's passwords and keys.",
    },
    Family {
        id: "miner",
        title: "Cryptocurrency miner",
        goal: "Uses your processor or graphics card to earn coins for someone else. It slows the computer and raises power use.",
        arrives_via: &["Cracked software", "Compromised servers", "Malicious scripts on websites"],
        attack: &["T1496"],
        advice: "Do not run it. Remove it and check why it was there; miners often arrive with other unwanted software.",
    },
    Family {
        id: "worm",
        title: "Worm",
        goal: "Copies itself to other computers through USB drives, network shares or by exploiting network services.",
        arrives_via: &["USB drives", "Network shares", "Unpatched network services"],
        attack: &["T1091", "T1210", "T1021.002"],
        advice: "Do not run it, and check other computers and drives that were connected to this one.",
    },
    Family {
        id: "botnet",
        title: "Botnet or flood-attack tool",
        goal: "Makes the device part of a network the attacker controls, used to flood websites, send spam or relay traffic. Routers and smart devices are common targets.",
        arrives_via: &["Weak or default passwords on routers and cameras", "Exposed services", "Malicious downloads"],
        attack: &["T1498", "T1071"],
        advice: "Do not run it. If a router or smart device is involved, update its software and change its password.",
    },
    Family {
        id: "wiper",
        title: "Wiper",
        goal: "Destroys data or boot records to cause damage, not to make money.",
        arrives_via: &["Targeted attacks", "Disguised as ransomware or updates"],
        attack: &["T1561.002", "T1485"],
        advice: "Do not run it. Keep backups offline, and treat any attempt to run it as a serious incident.",
    },
    Family {
        id: "exploit",
        title: "Document or program exploit",
        goal: "Abuses a bug in a program, such as an Office or PDF reader, to run code simply because you opened the file.",
        arrives_via: &["Email attachments", "Files shared in chats and on websites"],
        attack: &["T1203"],
        advice: "Do not open it. Keep your Office and PDF programs updated; most exploits only work on old versions.",
    },
    Family {
        id: "macro",
        title: "Malicious Office document",
        goal: "Uses macros, remote templates or embedded fields to run code once the document is opened and content is enabled. Usually the first step that brings in a loader.",
        arrives_via: &["Email attachments: invoices, resumes, shipping notices", "Files shared in chats"],
        attack: &["T1204.002", "T1221", "T1559.002", "T1059.005"],
        advice: "Do not open it, and never press \"Enable content\" or \"Enable macros\" on a document you did not expect.",
    },
    Family {
        id: "mobile-trojan",
        title: "Android banking or spy trojan",
        goal: "Reads text messages to steal one-time codes, overlays fake screens on banking apps and may control the phone.",
        arrives_via: &["Apps installed from outside the Play Store", "Links in messages", "Fake updates"],
        attack: &["T1636.004", "T1626.001", "T1417"],
        advice: "Do not install it. If it is already installed, remove its device-administrator rights, uninstall it and change your banking passwords from another device.",
    },
    Family {
        id: "banker",
        title: "Banking trojan",
        goal: "Steals online-banking logins and money by watching browser sessions and injecting fake forms.",
        arrives_via: &["Email attachments", "Malicious downloads", "Loaders"],
        attack: &["T1185", "T1056"],
        advice: "Do not run it. If it ran, contact your bank and change banking passwords from a clean device.",
    },
    Family {
        id: "rootkit",
        title: "Rootkit or bootkit",
        goal: "Hides itself and other malware deep in the system or in startup code, and survives ordinary cleaning.",
        arrives_via: &["Other malware that already has administrator rights"],
        attack: &["T1014", "T1542"],
        advice: "Do not run it. A computer with a rootkit usually needs a full reinstall to be trusted again.",
    },
    Family {
        id: "virus",
        title: "File infector (virus)",
        goal: "Attaches itself to other programs so it spreads whenever they are run or shared.",
        arrives_via: &["Infected programs shared on drives and networks"],
        attack: &[],
        advice: "Do not run it. Scan every program on the affected computer and drives.",
    },
    Family {
        id: "adware",
        title: "Adware or unwanted program",
        goal: "Shows ads, changes browser settings or bundles extra software. Not always malicious, but unwanted and sometimes a doorway for worse.",
        arrives_via: &["Free-software bundles", "Fake download buttons"],
        attack: &[],
        advice: "Remove it if you did not choose it. Download software only from the maker's own site.",
    },
    Family {
        id: "trojan",
        title: "Trojan",
        goal: "A program pretending to be something useful while doing something else. The exact aim depends on the family; many are loaders or stealers.",
        arrives_via: &["Fake installers", "Cracked software", "Email attachments"],
        attack: &["T1204.002"],
        advice: "Do not run it. Quarantine it and check where it came from.",
    },
    Family {
        id: "test-file",
        title: "Antivirus test file",
        goal: "The EICAR file is harmless. It exists only so people can check that antivirus software is working.",
        arrives_via: &["Downloaded deliberately for testing"],
        attack: &[],
        advice: "Nothing to fear. Delete it when you are done testing.",
    },
    Family {
        id: "malware",
        title: "Malware",
        goal: "The malware engine identified this file as malicious, but its name does not say what the program does.",
        arrives_via: &[],
        attack: &[],
        advice: "Do not open it. Quarantine it, and delete it if you do not need it.",
    },
];

pub fn family(id: &str) -> Option<&'static Family> {
    FAMILIES.iter().find(|f| f.id == id)
}

/// Words in a ClamAV-style detection name that point to a family, most specific first. ClamAV names look like
/// `Win.Ransomware.Lockbit-9876543-0`, `Doc.Dropper.Agent-1234`, `Andr.Trojan.Agent-5`, `Pdf.Exploit.CVE_2010_0188-1`.
const BY_NAME: &[(&str, &[&str])] = &[
    ("test-file", &["eicar"]),
    ("ransomware", &["ransom", "wannacry", "wcry", "locky", "cryptolocker", "lockbit", "ryuk", "conti", "gandcrab", "sodinokibi", "revil", "teslacrypt", "cerber", "stop.djvu", "blackcat", "babuk", "akira", "hive"]),
    ("wiper", &["wiper", "shamoon", "notpetya", "hermeticwiper", "whispergate"]),
    ("stealer", &["stealer", "infostealer", "pws", "redline", "vidar", "raccoon", "lumma", "azorult", "arkei", "stealc", "formbook", "lokibot", "agenttesla", "pony", "mars", "rhadamanthys"]),
    ("spyware", &["spy", "keylog", "keystroke", "spyware"]),
    ("banker", &["banker", "zeus", "zbot", "dridex", "ursnif", "gozi", "trickbot", "qakbot", "qbot", "emotet", "icedid"]),
    ("backdoor", &["backdoor", "bdoor", "njrat", "bladabindi", "asyncrat", "remcos", "quasar", "nanocore", "darkcomet", "netwire", "poisonivy", "meterpreter", "metasploit", "cobaltstrike", "beacon", "rat.", ".rat", "-rat"]),
    ("webshell", &["webshell", "web-shell", "c99", "r57", "b374k", "wso.", "php.shell", "asp.shell", "jsp.shell", "chopper"]),
    ("miner", &["miner", "coinminer", "xmrig", "cryptojack", "cryptominer", "bitcoinminer"]),
    ("botnet", &["mirai", "gafgyt", "bashlite", "botnet", "tsunami", "kaiten", ".bot."]),
    ("worm", &["worm", "conficker", "mydoom", "sasser"]),
    ("rootkit", &["rootkit", "bootkit", "mbr."]),
    ("virus", &["virus", "sality", "virut", "ramnit", "parite", "expiro", "nimda"]),
    ("exploit", &["exploit", "cve-", "cve_", "cve20", "shellcode"]),
    ("phishing", &["phish", "phishing"]),
    ("macro", &["macro", "doc.dropper", "xls.dropper", "vba", "xlm", "ppt.dropper", "doc.malware", "xls.malware", "office"]),
    ("mobile-trojan", &["andr.", "android", "apk"]),
    ("loader", &["downloader", "dropper", "loader", "smokeloader", "guloader", "bumblebee", "dldr", "script.", "js.", "vbs.", "psh.", "ps1.", "hta.", "html.", "heuristics.phishing"]),
    ("adware", &["adware", "pua.", "pup.", "unwanted", "bundler", "toolbar", "riskware"]),
    ("trojan", &["trojan", "agent", "generic", "malware"]),
];

/// The family a malware-engine detection name points to, if any.
pub fn family_from_signature(name: &str) -> Option<&'static Family> {
    let n = name.to_ascii_lowercase();
    BY_NAME.iter().find(|(_, tokens)| tokens.iter().any(|t| n.contains(t))).and_then(|(id, _)| family(id))
}

fn to_info(f: &Family, basis: &str, also: Vec<String>) -> ThreatInfo {
    ThreatInfo {
        family: f.id.to_string(),
        title: f.title.to_string(),
        goal: f.goal.to_string(),
        arrives_via: f.arrives_via.iter().map(|s| s.to_string()).collect(),
        attack: f.attack.iter().map(|s| s.to_string()).collect(),
        advice: f.advice.to_string(),
        basis: basis.to_string(),
        also,
    }
}

/// Explain a finished scan: what kind of threat is this, if it is one. `None` for clean files and for findings that carry no
/// family (for example "type does not match extension").
pub fn summarize(findings: &[Finding]) -> Option<ThreatInfo> {
    // 1. A name from the malware engine is the strongest statement.
    let sigs: Vec<&Finding> = findings.iter().filter(|f| f.kind == FindingKind::Signature).collect();
    if !sigs.is_empty() {
        let fam = sigs.iter().find_map(|f| family_from_signature(&f.name)).or_else(|| family("malware"))?;
        return Some(to_info(fam, "identified", behaviour_families(findings, Some(fam.id))));
    }
    // 2. Otherwise the family the behavioural evidence points to, strongest first.
    let mut scored: Vec<(&str, u32)> = Vec::new();
    for f in findings.iter().filter(|f| f.kind == FindingKind::Heuristic && f.severity >= Severity::Medium) {
        if let Some(fam) = f.family.as_deref() {
            match scored.iter_mut().find(|(id, _)| *id == fam) {
                Some(e) => e.1 += f.severity.weight(),
                None => scored.push((fam, f.severity.weight())),
            }
        }
    }
    scored.sort_by_key(|e| std::cmp::Reverse(e.1));
    let top = scored.first()?;
    let fam = family(top.0)?;
    let also = scored.iter().skip(1).take(2).map(|(id, _)| id.to_string()).collect();
    Some(to_info(fam, "suggested", also))
}

fn behaviour_families(findings: &[Finding], not: Option<&str>) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    for f in findings.iter().filter(|f| f.kind == FindingKind::Heuristic && f.severity >= Severity::Medium) {
        if let Some(id) = f.family.as_deref() {
            if Some(id) != not && !v.iter().any(|x| x == id) {
                v.push(id.to_string());
            }
        }
    }
    v.truncate(2);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(name: &str) -> Finding {
        Finding::new("clamav", name, FindingKind::Signature, Severity::High, "x")
    }
    fn heur(name: &str, fam: &str, sev: Severity) -> Finding {
        Finding::new("heuristic.technique", name, FindingKind::Heuristic, sev, "x").with_family(fam, &["T1000"])
    }

    #[test]
    fn engine_names_map_to_families() {
        let cases = [
            ("Win.Ransomware.Lockbit-9876543-0", "ransomware"),
            ("Win.Trojan.Redline-1234", "stealer"),
            ("Win.Dropper.Emotet-8", "banker"),
            ("Doc.Dropper.Agent-1234", "macro"),
            ("Andr.Trojan.Agent-5", "mobile-trojan"),
            ("Pdf.Exploit.CVE_2010_0188-1", "exploit"),
            ("Win.Coinminer.Xmrig-9", "miner"),
            ("Php.Webshell.C99-1", "webshell"),
            ("Win.Test.EICAR_HDB-1", "test-file"),
            ("Win.Trojan.Agent-1234", "trojan"),
            ("Js.Downloader.Nemucod-1", "loader"),
            ("Unix.Trojan.Mirai-7", "botnet"),
        ];
        for (name, want) in cases {
            assert_eq!(family_from_signature(name).map(|f| f.id), Some(want), "{name}");
        }
        assert!(family_from_signature("Totally.Unknown.Name-1").is_none());
    }

    #[test]
    fn an_engine_name_is_identified_and_behaviour_is_only_suggested() {
        let t = summarize(&[sig("Win.Ransomware.Lockbit-1")]).unwrap();
        assert_eq!((t.family.as_str(), t.basis.as_str()), ("ransomware", "identified"));
        let t = summarize(&[heur("Deletes backups", "ransomware", Severity::Medium)]).unwrap();
        assert_eq!((t.family.as_str(), t.basis.as_str()), ("ransomware", "suggested"));
    }

    #[test]
    fn an_unrecognised_engine_name_is_still_malware_not_nothing() {
        let t = summarize(&[sig("Zzz.Weird.Name-1")]).unwrap();
        assert_eq!(t.family, "malware");
        assert_eq!(t.basis, "identified");
    }

    #[test]
    fn nothing_dangerous_means_no_threat_card() {
        assert!(summarize(&[]).is_none());
        assert!(summarize(&[heur("Looks odd", "defense-evasion", Severity::Low)]).is_none(), "low evidence is not explained as a threat");
        assert!(summarize(&[Finding::new("heuristic.identify", "Double file extension", FindingKind::Heuristic, Severity::Medium, "x")]).is_none(), "no family, no card");
    }

    #[test]
    fn the_strongest_behaviour_wins_and_others_are_listed() {
        let t = summarize(&[heur("a", "stealer", Severity::High), heur("b", "loader", Severity::Medium), heur("c", "defense-evasion", Severity::Medium)]).unwrap();
        assert_eq!(t.family, "stealer");
        assert_eq!(t.also, vec!["loader".to_string(), "defense-evasion".to_string()]);
    }

    #[test]
    fn every_family_is_complete_and_attack_ids_look_right() {
        let mut seen = std::collections::HashSet::new();
        for f in FAMILIES {
            assert!(seen.insert(f.id), "duplicate {}", f.id);
            assert!(!f.title.is_empty() && f.goal.len() > 20 && f.advice.len() > 10, "{}", f.id);
            assert!(f.attack.iter().all(|a| a.starts_with('T') && a[1..].chars().next().is_some_and(|c| c.is_ascii_digit())), "{}", f.id);
        }
        for (id, _) in BY_NAME {
            assert!(family(id).is_some(), "BY_NAME refers to missing family {id}");
        }
        // Every family a technique rule points to must exist.
        for r in crate::rules::RULES {
            assert!(family(r.family).is_some(), "rule {} refers to missing family {}", r.id, r.family);
        }
    }

    #[test]
    fn advice_never_promises_what_it_cannot_know() {
        for f in FAMILIES {
            let a = f.advice.to_ascii_lowercase();
            assert!(!a.contains("100%") && !a.contains("guarantee") && !a.contains("completely safe"), "{}", f.id);
        }
    }
}
