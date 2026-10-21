//! Helpers for starting helper programs from a GUI process.

use std::process::Command;

/// Windows gives every console program started from a GUI app its own console window. For long-running `clamd` that is a
/// permanent black window; for `freshclam` and `icacls` it is a flash. This asks Windows not to create one.
/// No effect on other platforms.
pub fn no_window(cmd: &mut Command) -> &mut Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}
