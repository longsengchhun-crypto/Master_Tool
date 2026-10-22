//! SENTRIX security core. UI-independent: the desktop app, CLI and tests all call this crate.

pub mod account;
pub mod account_td;
pub mod archive;
pub mod clamav;
pub mod eicar;
pub mod group;
pub mod guard;
pub mod hosted;
pub mod hosted_store;
pub mod hash;
pub mod heuristics;
pub mod identify;
pub mod monitor;
pub mod notify;
pub mod quarantine;
pub mod proc;
pub mod relay;
pub mod queue;
pub mod report;
pub mod scanner;
pub mod secret;
pub mod service;
pub mod signature;
pub mod telegram;
pub mod telegram_desktop;
pub mod tdjson;
pub mod types;
pub mod verdict;

pub const ENGINE_VERSION: &str = concat!("sentrix-core/", env!("CARGO_PKG_VERSION"));

pub use scanner::{ScanOptions, Scanner};
pub use types::*;
