//! The full status window (right-click tray menu → "Status window"): the DoD seal,
//! the live authentication state with a bubble/spinner indicator, and every status
//! field (session, outer/inner phase, certificate, server, last update). A normal
//! titled, closable window; it refreshes ~1×/s while open and hides on close.
#![allow(unsafe_op_in_unsafe_fn)] // pervasive Win32/GDI+ FFI in the window proc

use std::cell::Cell;

use windows::Win32::Foundation::{COLORREF, HINSTANCE, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    BeginPaint, BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, CreateSolidBrush,
    DT_END_ELLIPSIS, DT_LEFT, DT_SINGLELINE, DeleteDC, DeleteObject, DrawTextW, EndPaint, FillRect,
    HDC, InvalidateRect, PAINTSTRUCT, SRCCOPY, SelectObject, SetBkMode, SetTextColor, TRANSPARENT,
};
use windows::Win32::Graphics::GdiPlus::{
    GdipCreateFromHDC, GdipDeleteGraphics, GdipDrawImageRectI, GdipSetSmoothingMode, GpGraphics,
    SmoothingModeAntiAlias,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, GetClientRect, GetSystemMetrics, KillTimer, RegisterClassW,
    SM_CXSCREEN, SM_CYSCREEN, SW_HIDE, SW_SHOW, SWP_NOZORDER, SetForegroundWindow, SetTimer,
    SetWindowPos, ShowWindow, WINDOW_EX_STYLE, WM_CLOSE, WM_ERASEBKGND, WM_PAINT, WM_TIMER,
    WNDCLASSW, WS_CAPTION, WS_MINIMIZEBOX, WS_OVERLAPPED, WS_SYSMENU,
};
use windows::core::w;

use usg_status::{AuthState, AuthStatus, Identity, read_status, unix_now};

const W: i32 = 470;
const H: i32 = 330;
const REFRESH_TIMER: usize = 9;
/// Refresh/animation interval while the window is open (ms).
const REFRESH_MS: u32 = 150;

thread_local! {
    static WIN: Cell<Option<HWND>> = const { Cell::new(None) };
    static FRAME: Cell<u32> = const { Cell::new(0) };
}

/// Open (or re-show) the status window, centered, and start its refresh timer.
pub fn open() {
    let hwnd = ensure_window();
    if hwnd.0.is_null() {
        return;
    }
    // SAFETY: center on the primary screen, show, focus, refresh.
    unsafe {
        let x = (GetSystemMetrics(SM_CXSCREEN) - W) / 2;
        let y = (GetSystemMetrics(SM_CYSCREEN) - H) / 2;
        let _ = SetWindowPos(hwnd, None, x, y, W, H, SWP_NOZORDER);
        let _ = ShowWindow(hwnd, SW_SHOW);
        let _ = SetForegroundWindow(hwnd);
        SetTimer(Some(hwnd), REFRESH_TIMER, REFRESH_MS, None);
        let _ = InvalidateRect(Some(hwnd), None, true);
    }
}

fn ensure_window() -> HWND {
    if let Some(h) = WIN.with(Cell::get) {
        return h;
    }
    // SAFETY: register the class + create a hidden titled window once.
    unsafe {
        let hinst = HINSTANCE(GetModuleHandleW(None).unwrap_or_default().0);
        let class = w!("UsgSupplicantStatusWindow");
        let wc = WNDCLASSW {
            lpfnWndProc: Some(win_proc),
            hInstance: hinst,
            lpszClassName: class,
            ..Default::default()
        };
        RegisterClassW(&wc);
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            class,
            w!("USG Supplicant — Authentication Status"),
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
            0,
            0,
            W,
            H,
            None,
            None,
            Some(hinst),
            None,
        )
        .unwrap_or_default();
        if !hwnd.0.is_null() {
            WIN.with(|c| c.set(Some(hwnd)));
        }
        hwnd
    }
}

unsafe extern "system" fn win_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_ERASEBKGND => LRESULT(1),
        WM_PAINT => {
            paint(hwnd);
            LRESULT(0)
        }
        WM_TIMER => {
            // Advance the spinner and live-refresh while open.
            FRAME.with(|f| f.set(f.get().wrapping_add(1)));
            let _ = InvalidateRect(Some(hwnd), None, false);
            LRESULT(0)
        }
        WM_CLOSE => {
            // Reuse the window: hide and stop refreshing instead of destroying.
            let _ = KillTimer(Some(hwnd), REFRESH_TIMER);
            let _ = ShowWindow(hwnd, SW_HIDE);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

fn paint(hwnd: HWND) {
    let status = read_status();
    let state = status.as_ref().map_or(AuthState::Idle, |s| s.state);
    // SAFETY: BeginPaint + off-screen double-buffer + GDI/GDI+ drawing.
    unsafe {
        let mut ps = PAINTSTRUCT::default();
        let hdc = BeginPaint(hwnd, &mut ps);
        let mut rc = RECT::default();
        let _ = GetClientRect(hwnd, &mut rc);
        let (cw, ch) = (rc.right, rc.bottom);

        let mem = CreateCompatibleDC(Some(hdc));
        let bmp = CreateCompatibleBitmap(hdc, cw, ch);
        let old = SelectObject(mem, bmp.into());

        let bg = CreateSolidBrush(COLORREF(0x0093_5E35)); // #355e93
        FillRect(mem, &rc, bg);
        let _ = DeleteObject(bg.into());

        SetBkMode(mem, TRANSPARENT);
        let _ = SetTextColor(mem, COLORREF(0x00FF_FFFF));
        draw(mem, headline(state), 140, 34, W - 80);
        // Field rows.
        let mut y = 150;
        for (label, value) in fields(status.as_ref()) {
            let _ = SetTextColor(mem, COLORREF(0x00C2_D4EA));
            draw(mem, &format!("{label}:"), 28, y, 150);
            let _ = SetTextColor(mem, COLORREF(0x00FF_FFFF));
            draw(mem, &value, 180, y, W - 200);
            y += 26;
        }

        let mut g: *mut GpGraphics = std::ptr::null_mut();
        if GdipCreateFromHDC(mem, &mut g).0 == 0 {
            let _ = GdipSetSmoothingMode(g, SmoothingModeAntiAlias);
            let seal = crate::gfx::seal();
            if !seal.is_null() {
                let _ = GdipDrawImageRectI(g, seal, 24, 24, 100, 100);
            }
            crate::gfx::draw_indicator(g, state, FRAME.with(Cell::get), W - 70, 32, 38);
            let _ = GdipDeleteGraphics(g);
        }

        let _ = BitBlt(hdc, 0, 0, cw, ch, Some(mem), 0, 0, SRCCOPY);
        SelectObject(mem, old);
        let _ = DeleteObject(bmp.into());
        let _ = DeleteDC(mem);
        let _ = EndPaint(hwnd, &ps);
    }
}

fn headline(state: AuthState) -> &'static str {
    match state {
        AuthState::Authenticated => "Authenticated",
        AuthState::Failed => "Authentication failed",
        AuthState::Idle => "No active session",
        _ => "Authenticating…",
    }
}

fn outer_inner(state: AuthState) -> (&'static str, &'static str) {
    match state {
        AuthState::Idle => ("—", "—"),
        AuthState::Connecting => ("in progress", "waiting"),
        AuthState::OuterEstablished => ("established", "waiting"),
        AuthState::InnerInProgress => ("established", "in progress"),
        AuthState::Authenticated => ("established", "authenticated"),
        AuthState::Failed => ("see detail", "see detail"),
    }
}

fn fields(status: Option<&AuthStatus>) -> Vec<(&'static str, String)> {
    let Some(s) = status else {
        return vec![("Status", "No published authentication status".to_string())];
    };
    let id = match s.identity {
        Identity::Machine => "Machine",
        Identity::User => "User",
    };
    let (outer, inner) = outer_inner(s.state);
    let dash = |v: &str| {
        if v.is_empty() {
            "—".to_string()
        } else {
            v.to_string()
        }
    };
    let mut out = vec![
        ("Session", id.to_string()),
        ("Outer (TEAP tunnel)", outer.to_string()),
        ("Inner (EAP-TLS)", inner.to_string()),
        ("Certificate", dash(&s.cert_subject)),
        ("Server", dash(&s.server_name)),
        (
            "Updated",
            format!("{}s ago", unix_now().saturating_sub(s.updated_unix)),
        ),
    ];
    if !s.detail.is_empty() {
        out.push(("Detail", s.detail.clone()));
    }
    out
}

fn draw(hdc: HDC, text: &str, x: i32, y: i32, width: i32) {
    let mut buf: Vec<u16> = text.encode_utf16().collect();
    if buf.is_empty() {
        return;
    }
    let mut rc = RECT {
        left: x,
        top: y,
        right: x + width,
        bottom: y + 24,
    };
    // SAFETY: DrawTextW with a mutable wide buffer + rect.
    unsafe {
        DrawTextW(
            hdc,
            &mut buf,
            &mut rc,
            DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS,
        );
    }
}
