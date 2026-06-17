//! `usg-tray` — a system-tray status indicator for the usg-supplicant.
//!
//! Polls the auth status the EAPHost peer method publishes (via `usg-status`) and
//! shows it as a tray icon whose tooltip + right-click menu report the outer
//! (TEAP tunnel) and inner (EAP-TLS) authentication state and the client
//! certificate in use. Windows-only; a no-op stub elsewhere so the workspace
//! still builds on other CI targets.
#![cfg_attr(not(windows), allow(dead_code))]

#[cfg(windows)]
mod tray;

fn main() {
    #[cfg(windows)]
    tray::run();
    #[cfg(not(windows))]
    eprintln!("usg-tray is a Windows-only system-tray app.");
}
