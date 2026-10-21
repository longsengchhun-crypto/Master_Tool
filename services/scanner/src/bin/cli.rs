//! sentrix-cli: scan files from a terminal using the same engine as the desktop app.
//!   sentrix-cli scan <path>... [--json] [--clamav-dir DIR] [--data-dir DIR]
//!   sentrix-cli update-signatures [--clamav-dir DIR] [--data-dir DIR]
//!   sentrix-cli status [--clamav-dir DIR] [--data-dir DIR]
//! Exit codes: 0 clean, 1 suspicious, 2 malicious, 3 unable to verify / error.

use sentrix_core::clamav::ClamEngine;
use sentrix_core::{report, Limits, ScanOptions, Scanner, Verdict};
use std::path::PathBuf;
use std::sync::Arc;

fn arg_val(args: &mut Vec<String>, name: &str) -> Option<String> {
    let i = args.iter().position(|a| a == name)?;
    if i + 1 >= args.len() {
        return None;
    }
    let v = args.remove(i + 1);
    args.remove(i);
    Some(v)
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let json = if let Some(i) = args.iter().position(|a| a == "--json") { args.remove(i); true } else { false };
    let clam_dir = arg_val(&mut args, "--clamav-dir").map(PathBuf::from).or_else(|| std::env::var_os("SENTRIX_CLAMAV_DIR").map(PathBuf::from));
    let data_dir = arg_val(&mut args, "--data-dir")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("SENTRIX_DATA_DIR").map(PathBuf::from))
        .unwrap_or_else(|| std::env::temp_dir().join("sentrix-cli"));
    let _ = std::fs::create_dir_all(&data_dir);
    let clam = clam_dir.map(|d| Arc::new(ClamEngine::new(d, data_dir.clone())));
    let scanner = Scanner::new(Limits::default(), clam.clone());

    let cmd = if args.is_empty() { String::new() } else { args.remove(0) };
    match cmd.as_str() {
        "status" => {
            println!("{}", serde_json::to_string_pretty(&scanner.engine_status()).unwrap());
        }
        "update-signatures" => match clam {
            Some(c) => match c.update_signatures() {
                Ok(out) => println!("{out}"),
                Err(e) => {
                    eprintln!("update failed: {e}");
                    std::process::exit(3);
                }
            },
            None => {
                eprintln!("no ClamAV directory configured (use --clamav-dir)");
                std::process::exit(3);
            }
        },
        "scan" if !args.is_empty() => {
            let paths: Vec<PathBuf> = args.iter().map(PathBuf::from).collect();
            let batch = scanner.scan_paths(&paths, &ScanOptions::default(), 2, &|_| {}, &|_| {});
            let mut worst = 0;
            for r in &batch.reports {
                if json {
                    println!("{}", report::to_json(r));
                } else {
                    println!("{}", report::to_text(r));
                }
                worst = worst.max(match r.verdict {
                    Verdict::Clean => 0,
                    Verdict::Suspicious => 1,
                    Verdict::Malicious => 2,
                    _ => 3,
                });
            }
            for (p, why) in &batch.skipped {
                eprintln!("NOT SCANNED: {} ({why})", p.display());
                worst = worst.max(3);
            }
            std::process::exit(worst);
        }
        _ => {
            eprintln!("usage: sentrix-cli scan <path>... | status | update-signatures  [--json] [--clamav-dir DIR] [--data-dir DIR]");
            std::process::exit(3);
        }
    }
}
