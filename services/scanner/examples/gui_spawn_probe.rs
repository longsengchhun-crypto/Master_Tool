//! Manual probe (not a test): a GUI-subsystem program, like the real app, that starts a console program either the old way
//! (`plain`) or through `proc::no_window` (`hide`). Used to confirm that the helper really suppresses the console window.
#![cfg_attr(windows, windows_subsystem = "windows")]

use std::process::Command;

fn main() {
    let hide = std::env::args().nth(1).as_deref() == Some("hide");
    let mut cmd = Command::new("ping.exe");
    cmd.args(["-n", "14", "127.0.0.1"]);
    if hide {
        sentrix_core::proc::no_window(&mut cmd);
    }
    let _ = cmd.output();
}
