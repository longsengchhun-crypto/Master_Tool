//! sentrix-botd: the hosted SENTRIX bot. One bot for every customer.
//!
//!   sentrix-botd [--env-file FILE] [--check]
//!
//! Configuration is read from the environment (or from a KEY=VALUE file given with --env-file, or `.sentrix-dev/bot.env` when
//! it exists). The bot token is a secret: it is never printed, logged or returned by any endpoint.
//!
//!   SENTRIX_BOT_TOKEN       required. From @BotFather.
//!   SENTRIX_DATA_DIR        where botd.db, the quarantine vault and (if you keep them here) ClamAV signatures live
//!   SENTRIX_CLAMAV_DIR      folder with clamd/freshclam (without it every file is reported "not checked", never clean)
//!   SENTRIX_RELAY_BIND      address for the app relay, default 127.0.0.1:8787 (put HTTPS in front of it)
//!   SENTRIX_TRUST_PROXY     1 when a reverse proxy you control sets X-Forwarded-For
//!   SENTRIX_DOWNLOAD_URL    where the bot tells people to get the desktop app
//!
//! `--check` validates the configuration, asks Telegram who the bot is, prints the bot's username and exits.

use sentrix_core::clamav::ClamEngine;
use sentrix_core::hosted::HostedConfig;
use sentrix_core::quarantine::Quarantine;
use sentrix_core::queue::JobStore;
use sentrix_core::relay::RelayServer;
use sentrix_core::service::{Hooks, ProtectionService, ServiceConfig};
use sentrix_core::telegram::BotClient;
use sentrix_core::{Limits, ScanReport, Scanner};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// Logs that a scan finished and how, never which file or whose.
struct LogHooks;

impl Hooks for LogHooks {
    fn on_report(&self, r: &ScanReport) {
        println!("[scan] verdict={} complete={}", r.verdict.label(), r.complete);
    }
}

fn load_env_file(path: &std::path::Path) {
    let Ok(text) = std::fs::read_to_string(path) else { return };
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        if let Some((k, v)) = line.split_once('=') {
            // The real environment wins over the file.
            if std::env::var_os(k.trim()).is_none() && !v.trim().is_empty() {
                std::env::set_var(k.trim(), v.trim());
            }
        }
    }
}

fn die(msg: &str) -> ! {
    eprintln!("sentrix-botd: {msg}");
    std::process::exit(2);
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let check = args.iter().position(|a| a == "--check").map(|i| args.remove(i)).is_some();
    if let Some(i) = args.iter().position(|a| a == "--env-file") {
        if i + 1 < args.len() {
            load_env_file(&PathBuf::from(&args[i + 1]));
        }
    }
    load_env_file(&PathBuf::from(".sentrix-dev/bot.env"));

    let Ok(token) = std::env::var("SENTRIX_BOT_TOKEN") else { die("SENTRIX_BOT_TOKEN is not set.") };
    let bot = match BotClient::new(token.trim()) {
        Ok(b) => b,
        Err(e) => die(&e.user_message()),
    };
    let me = match bot.get_me() {
        Ok(m) => m,
        Err(e) => die(&format!("Telegram did not accept the bot token: {}", e.user_message())),
    };
    let username = me.username.clone().unwrap_or_default();
    println!("[botd] bot @{username}");
    if me.can_read_all_group_messages == Some(false) {
        println!("[botd] WARNING: BotFather privacy mode is ON. The bot cannot see files in groups unless it is made an administrator there. Fix it once for everyone: @BotFather > /setprivacy > choose this bot > Disable, then remove and re-add the bot in existing groups.");
    }
    if me.can_join_groups == Some(false) {
        println!("[botd] WARNING: group joining is OFF for this bot. @BotFather > /setjoingroups > Enable.");
    }
    if check {
        println!("[botd] configuration is valid");
        return;
    }

    let data_dir = PathBuf::from(std::env::var("SENTRIX_DATA_DIR").unwrap_or_else(|_| "botd-data".into()));
    let _ = std::fs::create_dir_all(&data_dir);
    let store = Arc::new(JobStore::open(&data_dir.join("botd.db")).unwrap_or_else(|e| die(&format!("database: {e}"))));
    let quarantine = Arc::new(Quarantine::open(data_dir.join("vault")).unwrap_or_else(|e| die(&format!("quarantine: {e}"))));

    // The scan engine. Without it nothing can be checked, and every file is reported "not checked", never clean.
    let clam = std::env::var_os("SENTRIX_CLAMAV_DIR").map(|d| Arc::new(ClamEngine::new(PathBuf::from(d), data_dir.clone())));
    if let Some(c) = &clam {
        if c.is_installed() && c.has_database() {
            match c.start() {
                Ok(()) => println!("[botd] scan engine running"),
                Err(e) => println!("[botd] WARNING: scan engine did not start ({e}). Files will be reported as not checked."),
            }
        } else {
            println!("[botd] WARNING: ClamAV or its signatures are missing. Files will be reported as not checked.");
        }
        let c2 = c.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(4 * 3600));
            match c2.update_signatures() {
                Ok(_) => {
                    let _ = c2.reload();
                    println!("[botd] signatures updated");
                }
                Err(e) => println!("[botd] signature update failed: {e}"),
            }
        });
    } else {
        println!("[botd] WARNING: SENTRIX_CLAMAV_DIR is not set. Files will be reported as not checked.");
    }
    let scanner = Arc::new(Scanner::new(Limits::default(), clam));

    let mut cfg = ServiceConfig::new(data_dir.join("tmp"));
    cfg.realtime = false;
    cfg.group_shield = true;
    cfg.hosted = Some(HostedConfig { download_url: std::env::var("SENTRIX_DOWNLOAD_URL").unwrap_or_default() });
    let svc = ProtectionService::new(scanner, quarantine, store.clone(), Arc::new(LogHooks), cfg);
    svc.set_bot(Some(Arc::new(bot)));
    svc.start();

    let bind = std::env::var("SENTRIX_RELAY_BIND").unwrap_or_else(|_| "127.0.0.1:8787".into());
    let trust = std::env::var("SENTRIX_TRUST_PROXY").map(|v| v == "1").unwrap_or(false);
    let relay = RelayServer::start(&bind, store.clone(), trust).unwrap_or_else(|e| die(&format!("relay could not listen on {bind}: {e}")));
    println!("[botd] relay listening on {} (put HTTPS in front of it)", relay.addr);
    println!("[botd] running");

    // Every 30 seconds: is the bot actually receiving Telegram's messages? A bot that is silent says why, right here.
    let mut ticks = 0u32;
    loop {
        std::thread::sleep(Duration::from_secs(30));
        ticks += 1;
        let now = sentrix_core::queue::now_ms();
        let ok_at: i64 = store.kv_get("tg_poll_ok_at").and_then(|v| v.parse().ok()).unwrap_or(0);
        if now - ok_at > 90_000 {
            let why = store.kv_get("tg_poll_error").unwrap_or_else(|| "no answer from Telegram yet".into());
            println!("[botd] WARNING: the bot has not received anything from Telegram for {} s: {why}", (now - ok_at.max(now - 3_600_000)) / 1000);
        }
        for e in store.recent_events(5).unwrap_or_default().iter().filter(|e| e.ts > now - 31_000 && e.severity != "info") {
            println!("[botd] {}: {}", e.severity, e.message);
        }
        if ticks % 10 == 0 {
            store.codes_prune(now);
            let t = store.hosted_totals();
            println!("[botd] people={} linked_apps={}", t.users, t.devices);
        }
    }
}
