//! The Win32 system-tray implementation: a message-only window owns a
//! `Shell_NotifyIcon`; a timer polls the published status to refresh the icon +
//! tooltip, and a right-click shows a menu with the outer/inner state, the
//! certificate, and Exit.
#![allow(unsafe_op_in_unsafe_fn)] // pervasive Win32 FFI inside the window proc

use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Shell::{
    NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW,
    Shell_NotifyIconW,
};
use windows::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, DestroyWindow,
    DispatchMessageW, GetCursorPos, GetMessageW, HICON, HWND_MESSAGE, IDI_APPLICATION, IDI_ERROR,
    IDI_INFORMATION, IDI_WARNING, LoadIconW, MF_GRAYED, MF_SEPARATOR, MF_STRING, MSG,
    PostQuitMessage, RegisterClassW, SetForegroundWindow, SetTimer, TPM_BOTTOMALIGN,
    TPM_RIGHTBUTTON, TrackPopupMenu, TranslateMessage, WINDOW_EX_STYLE, WINDOW_STYLE, WM_APP,
    WM_COMMAND, WM_DESTROY, WM_LBUTTONUP, WM_RBUTTONUP, WM_TIMER, WNDCLASSW,
};
use windows::core::{PCWSTR, w};

use std::cell::RefCell;
use std::path::PathBuf;
use std::process::{Child, Command};

use usg_status::{AuthState, AuthStatus, dash, read_status};

thread_local! {
    /// The last published state we showed, to fire a toast only on changes.
    static LAST_STATE: RefCell<Option<AuthState>> = const { RefCell::new(None) };
    /// The spawned status-window process, so repeated clicks don't open duplicates.
    static STATUS_WIN: RefCell<Option<Child>> = const { RefCell::new(None) };
}

/// Tray-icon callback message (`uCallbackMessage`).
const WM_TRAY: u32 = WM_APP + 1;
/// The one tray icon's id.
const TRAY_UID: u32 = 1;
/// Status-poll timer id and interval (ms).
const TIMER_ID: usize = 1;
const POLL_MS: u32 = 1500;
/// "Status window" menu-item command id.
const ID_STATUS: usize = 0xE71C;
/// "Exit" menu-item command id.
const ID_EXIT: usize = 0xE71D;

/// Run the tray: register a message-only window, add the icon, poll, pump messages.
pub fn run() {
    // SAFETY: standard Win32 tray-app setup; every pointer is a live local.
    unsafe {
        let hinstance = HINSTANCE(GetModuleHandleW(None).unwrap_or_default().0);
        let class = w!("UsgSupplicantTray");
        let wc = WNDCLASSW {
            lpfnWndProc: Some(wndproc),
            hInstance: hinstance,
            lpszClassName: class,
            ..Default::default()
        };
        RegisterClassW(&wc);
        let Ok(hwnd) = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            class,
            w!("usg-tray"),
            WINDOW_STYLE(0),
            0,
            0,
            0,
            0,
            Some(HWND_MESSAGE),
            None,
            Some(hinstance),
            None,
        ) else {
            return;
        };

        let mut nid = base_nid(hwnd);
        let status = read_status();
        refresh(&mut nid, status.as_ref());
        let _ = Shell_NotifyIconW(NIM_ADD, &nid);
        crate::gfx::startup();
        // Seed the last-seen state so a stale persisted status (e.g. yesterday's
        // result) doesn't pop a toast on startup — only genuine in-session changes do.
        LAST_STATE.with(|l| *l.borrow_mut() = status.as_ref().map(|s| s.state));
        SetTimer(Some(hwnd), TIMER_ID, POLL_MS, None);

        let mut msg = MSG::default();
        // GetMessageW returns -1 on error (not 0): handle it explicitly so an error
        // doesn't spin the loop forever re-dispatching a stale message.
        loop {
            match GetMessageW(&mut msg, None, 0, 0).0 {
                0 | -1 => break, // WM_QUIT or error
                _ => {
                    let _ = TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }
        }
        crate::gfx::shutdown();
    }
}

/// The icon descriptor for our single tray icon (id + callback + flags).
fn base_nid(hwnd: HWND) -> NOTIFYICONDATAW {
    NOTIFYICONDATAW {
        cbSize: size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: hwnd,
        uID: TRAY_UID,
        uFlags: NIF_ICON | NIF_MESSAGE | NIF_TIP,
        uCallbackMessage: WM_TRAY,
        ..Default::default()
    }
}

/// Refresh `nid`'s icon + tooltip from `status` (a single read by the caller).
fn refresh(nid: &mut NOTIFYICONDATAW, status: Option<&AuthStatus>) {
    nid.hIcon = icon_for(status.map(|s| s.state));
    set_tip(nid, &tooltip(status));
}

/// Copy `tip` (truncated, NUL-terminated) into the fixed `szTip` buffer.
fn set_tip(nid: &mut NOTIFYICONDATAW, tip: &str) {
    nid.szTip = [0u16; 128];
    let wide: Vec<u16> = tip.encode_utf16().take(nid.szTip.len() - 1).collect();
    for (dst, src) in nid.szTip.iter_mut().zip(wide) {
        *dst = src;
    }
}

fn icon_for(state: Option<AuthState>) -> HICON {
    let id = match state {
        Some(AuthState::Authenticated) => IDI_INFORMATION,
        Some(AuthState::Failed) => IDI_ERROR,
        Some(AuthState::Connecting | AuthState::OuterEstablished | AuthState::InnerInProgress) => {
            IDI_WARNING
        }
        _ => IDI_APPLICATION,
    };
    // SAFETY: loading a shared stock icon (no module handle).
    unsafe { LoadIconW(None, id) }.unwrap_or_default()
}

fn tooltip(status: Option<&AuthStatus>) -> String {
    match status {
        None => "usg-TEAP: no status yet".to_string(),
        Some(s) => format!(
            "usg-TEAP — {} ({})",
            s.state.label(),
            s.identity.display_name()
        ),
    }
}

/// The detail lines shown (disabled) in the right-click menu.
fn menu_lines(status: Option<&AuthStatus>) -> Vec<String> {
    let Some(s) = status else {
        return vec!["No authentication status yet".to_string()];
    };
    let (outer, inner) = s.state.outer_inner();
    let mut lines = vec![
        format!("Session: {}", s.identity.display_name()),
        format!("Outer (TEAP tunnel): {outer}"),
        format!("Inner (EAP-TLS): {inner}"),
        format!("Certificate: {}", dash(&s.cert_subject)),
        format!("Server: {}", dash(&s.server_name)),
    ];
    if !s.detail.is_empty() {
        lines.push(format!("Detail: {}", s.detail));
    }
    lines
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Open the modern (Slint) status window — a separate process, since Slint runs its
/// own event loop and can't share this tray's Win32 message loop. If a window we
/// launched is still open, leave it alone instead of spawning a duplicate.
fn open_status_window() {
    STATUS_WIN.with(|c| {
        let mut slot = c.borrow_mut();
        if let Some(child) = slot.as_mut() {
            match child.try_wait() {
                Ok(None) => return, // still running — don't open a second one
                _ => *slot = None,  // exited or errored — fall through and respawn
            }
        }
        if let Some(path) = status_window_path()
            && let Ok(child) = Command::new(path).spawn()
        {
            *slot = Some(child);
        }
    });
}

/// Path to `usg-status-window.exe`, expected alongside the tray executable.
fn status_window_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let cand = exe.parent()?.join("usg-status-window.exe");
    cand.is_file().then_some(cand)
}

/// Build and show the right-click status menu at the cursor.
fn show_menu(hwnd: HWND) {
    // SAFETY: standard popup-menu sequence; the menu is destroyed before return.
    unsafe {
        let Ok(menu) = CreatePopupMenu() else {
            return;
        };
        for line in menu_lines(read_status().as_ref()) {
            // AppendMenuW copies the string, so the buffer can drop after the call.
            let text = wide(&line);
            let _ = AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, PCWSTR(text.as_ptr()));
        }
        let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
        let _ = AppendMenuW(menu, MF_STRING, ID_STATUS, w!("Status window…"));
        let _ = AppendMenuW(menu, MF_STRING, ID_EXIT, w!("Exit"));

        let mut pt = POINT::default();
        let _ = GetCursorPos(&mut pt);
        // Required so the menu dismisses correctly when focus is lost.
        let _ = SetForegroundWindow(hwnd);
        let _ = TrackPopupMenu(
            menu,
            TPM_RIGHTBUTTON | TPM_BOTTOMALIGN,
            pt.x,
            pt.y,
            Some(0),
            hwnd,
            None,
        );
        let _ = DestroyMenu(menu);
    }
}

/// Window procedure for the message-only window.
unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_TRAY => {
            let event = (lparam.0 as u32) & 0xFFFF;
            match event {
                // Left-click: pop the status toast with the current state.
                WM_LBUTTONUP => {
                    let state = read_status().map_or(AuthState::Idle, |s| s.state);
                    crate::toast::notify(state);
                }
                // Right-click: the text status menu.
                WM_RBUTTONUP => show_menu(hwnd),
                _ => {}
            }
            LRESULT(0)
        }
        WM_TIMER => {
            let status = read_status();
            let mut nid = base_nid(hwnd);
            refresh(&mut nid, status.as_ref());
            let _ = Shell_NotifyIconW(NIM_MODIFY, &nid);
            // Pop a toast only on a genuine change to a present state (don't let a
            // transient missing-file read overwrite the last state and re-fire).
            let cur = status.as_ref().map(|s| s.state);
            LAST_STATE.with(|l| {
                let mut last = l.borrow_mut();
                if cur.is_some() && cur != *last {
                    if let Some(state) = cur {
                        crate::toast::notify(state);
                    }
                    *last = cur;
                }
            });
            LRESULT(0)
        }
        WM_COMMAND => {
            match wparam.0 & 0xFFFF {
                ID_STATUS => open_status_window(),
                ID_EXIT => {
                    let _ = Shell_NotifyIconW(NIM_DELETE, &base_nid(hwnd));
                    let _ = DestroyWindow(hwnd);
                }
                _ => {}
            }
            LRESULT(0)
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}
