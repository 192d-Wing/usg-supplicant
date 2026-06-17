//! A custom animated "toast" popup shown on authentication state changes: the DoD
//! seal on the left, then a bold status line, the session/cert/server details, and
//! a status indicator on the right — a green bubble (authenticated), a red bubble
//! (failed), or a **spinning ring** (in progress). Bottom-right of the work area;
//! terminal toasts auto-dismiss, an in-progress toast persists and animates.
//!
//! GDI+ and the seal image come from [`crate::gfx`]; this module owns the popup
//! window, its animation, and the card layout.
#![allow(unsafe_op_in_unsafe_fn)] // pervasive Win32/GDI+ FFI in the window proc

use std::cell::RefCell;
use std::ffi::c_void;

use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, RECT, WPARAM};
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
    CreateWindowExW, DefWindowProcW, GetClientRect, HWND_TOPMOST, KillTimer, RegisterClassW,
    SPI_GETWORKAREA, SW_HIDE, SW_SHOWNOACTIVATE, SWP_NOACTIVATE,
    SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS, SetTimer, SetWindowPos, ShowWindow, SystemParametersInfoW,
    WM_ERASEBKGND, WM_PAINT, WM_TIMER, WNDCLASSW, WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW,
    WS_EX_TOPMOST, WS_POPUP,
};
use windows::core::w;

use usg_status::{AuthState, AuthStatus, read_status};

const W: i32 = 360;
const H: i32 = 104;
const ANIM_TIMER: usize = 7;
const ANIM_MS: u32 = 60;
/// Hide a terminal toast after this many animation ticks (~5s at 60 ms).
const AUTO_HIDE_TICKS: u32 = 83;

/// Per-thread toast state (the message loop and toast live on one thread).
struct Ctx {
    hwnd: HWND,
    state: AuthState,
    frame: u32,
    ticks: u32,
}

thread_local! {
    static CTX: RefCell<Option<Ctx>> = const { RefCell::new(None) };
}

/// Show (or refresh) the toast for `state`.
pub fn notify(state: AuthState) {
    let hwnd = ensure_window();
    if hwnd.0.is_null() {
        return; // window creation failed; nothing to show (and don't arm a timer)
    }
    CTX.with(|c| {
        if let Some(ctx) = c.borrow_mut().as_mut() {
            ctx.state = state;
            ctx.frame = 0;
            ctx.ticks = 0;
        }
    });
    // SAFETY: position bottom-right of the work area and show without activating.
    unsafe {
        let mut work = RECT::default();
        let _ = SystemParametersInfoW(
            SPI_GETWORKAREA,
            0,
            Some((&mut work as *mut RECT).cast::<c_void>()),
            SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
        );
        let x = work.right - W - 16;
        let y = work.bottom - H - 16;
        let _ = SetWindowPos(hwnd, Some(HWND_TOPMOST), x, y, W, H, SWP_NOACTIVATE);
        let _ = ShowWindow(hwnd, SW_SHOWNOACTIVATE);
        let _ = InvalidateRect(Some(hwnd), None, false);
        SetTimer(Some(hwnd), ANIM_TIMER, ANIM_MS, None);
    }
}

fn ensure_window() -> HWND {
    if let Some(h) = CTX.with(|c| c.borrow().as_ref().map(|x| x.hwnd)) {
        return h;
    }
    // SAFETY: register the toast class + create a hidden popup once.
    unsafe {
        let hinst =
            windows::Win32::Foundation::HINSTANCE(GetModuleHandleW(None).unwrap_or_default().0);
        let class = w!("UsgSupplicantToast");
        let wc = WNDCLASSW {
            lpfnWndProc: Some(toast_proc),
            hInstance: hinst,
            lpszClassName: class,
            ..Default::default()
        };
        RegisterClassW(&wc);
        let hwnd = CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
            class,
            w!("usg-toast"),
            WS_POPUP,
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
        if hwnd.0.is_null() {
            return hwnd; // don't cache a null handle — leave CTX empty so we retry
        }
        CTX.with(|c| {
            *c.borrow_mut() = Some(Ctx {
                hwnd,
                state: AuthState::Idle,
                frame: 0,
                ticks: 0,
            });
        });
        hwnd
    }
}

unsafe extern "system" fn toast_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_ERASEBKGND => LRESULT(1), // we paint the whole client area ourselves
        WM_PAINT => {
            paint(hwnd);
            LRESULT(0)
        }
        WM_TIMER => {
            let mut hide = false;
            let mut animate = false;
            CTX.with(|c| {
                if let Some(ctx) = c.borrow_mut().as_mut() {
                    ctx.frame = ctx.frame.wrapping_add(1);
                    ctx.ticks = ctx.ticks.saturating_add(1);
                    let terminal = matches!(
                        ctx.state,
                        AuthState::Authenticated | AuthState::Failed | AuthState::Idle
                    );
                    animate = !terminal; // only the spinner needs per-tick repaints
                    if terminal && ctx.ticks > AUTO_HIDE_TICKS {
                        hide = true;
                    }
                }
            });
            if hide {
                let _ = KillTimer(Some(hwnd), ANIM_TIMER);
                let _ = ShowWindow(hwnd, SW_HIDE);
            } else if animate {
                let _ = InvalidateRect(Some(hwnd), None, false);
            }
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

fn paint(hwnd: HWND) {
    let (state, frame) = CTX.with(|c| {
        c.borrow()
            .as_ref()
            .map_or((AuthState::Idle, 0), |x| (x.state, x.frame))
    });
    let status = read_status();
    // SAFETY: BeginPaint, then draw to an off-screen buffer and blit it once, so
    // the per-tick spinner repaint doesn't flicker.
    unsafe {
        let mut ps = PAINTSTRUCT::default();
        let hdc = BeginPaint(hwnd, &mut ps);
        let mut rc = RECT::default();
        let _ = GetClientRect(hwnd, &mut rc);
        let (cw, ch) = (rc.right, rc.bottom);

        let mem = CreateCompatibleDC(Some(hdc));
        let bmp = CreateCompatibleBitmap(hdc, cw, ch);
        let old = SelectObject(mem, bmp.into());

        // Card background #355e93 (COLORREF is 0x00BBGGRR).
        let bg = CreateSolidBrush(COLORREF(0x0093_5E35));
        FillRect(mem, &rc, bg);
        let _ = DeleteObject(bg.into());

        // Text block.
        SetBkMode(mem, TRANSPARENT);
        let _ = SetTextColor(mem, COLORREF(0x00FF_FFFF));
        draw_line(mem, headline(state), 104, 16);
        let _ = SetTextColor(mem, COLORREF(0x00C8_C8C8));
        for (i, line) in detail_lines(status.as_ref()).iter().enumerate() {
            draw_line(mem, line, 104, 44 + 20 * i32::try_from(i).unwrap_or(0));
        }

        // Seal + indicator via GDI+ (shared with the status window).
        let mut g: *mut GpGraphics = std::ptr::null_mut();
        if GdipCreateFromHDC(mem, &mut g).0 == 0 {
            let _ = GdipSetSmoothingMode(g, SmoothingModeAntiAlias);
            let seal = crate::gfx::seal();
            if seal.is_null() {
                crate::gfx::draw_indicator(g, AuthState::Idle, 0, 14, 14, 76); // placeholder disc
            } else {
                let _ = GdipDrawImageRectI(g, seal, 14, 14, 76, 76);
            }
            crate::gfx::draw_indicator(g, state, frame, W - 52, 18, 30);
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
        AuthState::Idle => "usg-TEAP",
        _ => "Authenticating…",
    }
}

fn detail_lines(status: Option<&AuthStatus>) -> Vec<String> {
    let Some(s) = status else {
        return vec!["No active session".to_string()];
    };
    let id = match s.identity {
        usg_status::Identity::Machine => "Machine",
        usg_status::Identity::User => "User",
    };
    let cert = if s.cert_subject.is_empty() {
        "—"
    } else {
        &s.cert_subject
    };
    vec![
        format!("{id} · {cert}"),
        format!("Server: {}", s.server_name),
    ]
}

fn draw_line(hdc: HDC, text: &str, x: i32, y: i32) {
    let mut buf: Vec<u16> = text.encode_utf16().collect();
    if buf.is_empty() {
        return;
    }
    let mut rc = RECT {
        left: x,
        top: y,
        right: W - 60,
        bottom: y + 20,
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
