//! `usg-status-window` — a modern (Slint) status window for the usg-supplicant.
//!
//! The tray (a Win32 message-loop app) can't host Slint's own event loop, so the
//! "Status window…" menu item launches *this* separate process. It reads the same
//! published [`usg_status::AuthStatus`] the tray does and refreshes on a poll timer,
//! rendering the DoD seal, the outer/inner authentication state, and the client
//! certificate in a Fluent-style window.
//!
//! Windows-only: the Slint GUI stack is a `cfg(windows)` dependency.
#![cfg_attr(not(windows), allow(unused))]
// Release builds are a GUI app (no console window); debug builds keep the console
// so panics/`eprintln!` are visible while developing.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

#[cfg(windows)]
mod app {
    use std::path::PathBuf;
    use std::time::Duration;

    use usg_status::{AuthState, AuthStatus, dash, read_status};

    slint::include_modules!();

    /// Poll the published status this often.
    const POLL: Duration = Duration::from_millis(750);

    pub fn run() -> Result<(), slint::PlatformError> {
        let ui = MainWindow::new()?;
        if let Some(path) = seal_path()
            && let Ok(img) = slint::Image::load_from_path(&path)
        {
            ui.set_seal(img);
        }
        apply(&ui, read_status().as_ref());

        // Refresh on a timer; the closure holds only a weak handle so it can't keep
        // the window alive after close.
        let weak = ui.as_weak();
        let timer = slint::Timer::default();
        timer.start(slint::TimerMode::Repeated, POLL, move || {
            if let Some(ui) = weak.upgrade() {
                apply(&ui, read_status().as_ref());
            }
        });

        ui.run()
    }

    /// Push a status snapshot into the window's properties.
    fn apply(ui: &MainWindow, status: Option<&AuthStatus>) {
        let Some(s) = status else {
            ui.set_headline("No active session".into());
            for setter in [
                MainWindow::set_session,
                MainWindow::set_outer,
                MainWindow::set_inner,
                MainWindow::set_certificate,
                MainWindow::set_server,
                MainWindow::set_updated,
            ] {
                setter(ui, "—".into());
            }
            ui.set_detail("".into());
            ui.set_indicator(0);
            return;
        };
        let (outer, inner) = s.state.outer_inner();
        ui.set_headline(s.state.headline().into());
        ui.set_session(s.identity.display_name().into());
        ui.set_outer(outer.into());
        ui.set_inner(inner.into());
        ui.set_certificate(dash(&s.cert_subject).into());
        ui.set_server(dash(&s.server_name).into());
        ui.set_detail(s.detail.clone().into());
        ui.set_updated(updated_label(s.updated_unix).into());
        ui.set_indicator(indicator(s.state));
    }

    /// 0 idle/unknown · 1 in-progress · 2 authenticated · 3 failed — matches the
    /// `indicator` cases in `ui/main.slint`.
    fn indicator(state: AuthState) -> i32 {
        match state {
            AuthState::Authenticated => 2,
            AuthState::Failed => 3,
            AuthState::Connecting | AuthState::OuterEstablished | AuthState::InnerInProgress => 1,
            AuthState::Idle => 0,
        }
    }

    /// "N s/min/h ago" from a Unix timestamp, or "—" if unset/in the future.
    fn updated_label(updated_unix: u64) -> String {
        let now = usg_status::unix_now();
        if updated_unix == 0 || updated_unix > now {
            return "—".to_string();
        }
        let secs = now - updated_unix;
        if secs < 60 {
            format!("{secs} s ago")
        } else if secs < 3600 {
            format!("{} min ago", secs / 60)
        } else {
            format!("{} h ago", secs / 3600)
        }
    }

    /// First existing seal candidate (same search order as the tray's `gfx`).
    fn seal_path() -> Option<PathBuf> {
        seal_candidates().into_iter().find(|p| p.is_file())
    }

    fn seal_candidates() -> Vec<PathBuf> {
        let mut out = Vec::new();
        if let Some(pd) = std::env::var_os("ProgramData") {
            let base = PathBuf::from(pd).join("usg-supplicant");
            out.push(base.join("seal.png"));
            out.push(base.join("DOW-Seal.png"));
        }
        if let Ok(exe) = std::env::current_exe()
            && let Some(dir) = exe.parent()
        {
            out.push(dir.join("icons").join("DOW-Seal.png"));
        }
        out.push(PathBuf::from("icons").join("DOW-Seal.png"));
        out
    }
}

fn main() {
    #[cfg(windows)]
    {
        if let Err(e) = app::run() {
            eprintln!("usg-status-window: {e}");
            std::process::exit(1);
        }
    }
    #[cfg(not(windows))]
    eprintln!("usg-status-window is Windows-only.");
}
