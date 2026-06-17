//! A custom animated "toast" popup shown on authentication state changes: the DoD
//! seal on the left, then a bold status line, the session/cert/server details, and
//! a status indicator on the right — a green bubble (authenticated), a red bubble
//! (failed), or a **spinning ring** (in progress). Bottom-right of the work area;
//! terminal toasts auto-dismiss, an in-progress toast persists and animates.
//!
//! The seal is loaded (GDI+) from `%ProgramData%\usg-supplicant\seal.png`; if it's
//! absent a placeholder disc is drawn. Replace that file with the official seal.
#![allow(unsafe_op_in_unsafe_fn)] // pervasive Win32/GDI+ FFI in the window proc

use std::cell::RefCell;
use std::ffi::c_void;
use std::path::PathBuf;

use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    BeginPaint, CreateSolidBrush, DT_END_ELLIPSIS, DT_LEFT, DT_SINGLELINE, DeleteObject, DrawTextW,
    EndPaint, FillRect, HDC, InvalidateRect, PAINTSTRUCT, SetBkMode, SetTextColor, TRANSPARENT,
};
use windows::Win32::Graphics::GdiPlus::{
    GdipCreateBitmapFromFile, GdipCreateFromHDC, GdipCreatePen1, GdipCreateSolidFill,
    GdipDeleteBrush, GdipDeleteGraphics, GdipDeletePen, GdipDisposeImage, GdipDrawArcI,
    GdipDrawImageRectI, GdipFillEllipseI, GdipSetSmoothingMode, GdiplusShutdown, GdiplusStartup,
    GdiplusStartupInput, GpBitmap, GpGraphics, GpImage, SmoothingModeAntiAlias, Unit,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, GetClientRect, HWND_TOPMOST, KillTimer, RegisterClassW,
    SPI_GETWORKAREA, SW_HIDE, SW_SHOWNOACTIVATE, SWP_NOACTIVATE,
    SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS, SetTimer, SetWindowPos, ShowWindow, SystemParametersInfoW,
    WM_ERASEBKGND, WM_PAINT, WM_TIMER, WNDCLASSW, WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW,
    WS_EX_TOPMOST, WS_POPUP,
};
use windows::core::{PCWSTR, w};

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
    seal: *mut GpImage,
    state: AuthState,
    frame: u32,
    ticks: u32,
}

thread_local! {
    static CTX: RefCell<Option<Ctx>> = const { RefCell::new(None) };
    static TOKEN: RefCell<usize> = const { RefCell::new(0) };
}

/// Initialize GDI+. Call once before [`notify`].
pub fn startup() {
    // SAFETY: standard GDI+ init; token stored for shutdown.
    unsafe {
        let mut token = 0usize;
        let input = GdiplusStartupInput {
            GdiplusVersion: 1,
            ..Default::default()
        };
        let _ = GdiplusStartup(&mut token, &input, std::ptr::null_mut());
        TOKEN.with(|t| *t.borrow_mut() = token);
    }
}

/// Dispose the seal image and shut GDI+ down.
pub fn shutdown() {
    // SAFETY: dispose what startup/ensure_window created.
    unsafe {
        CTX.with(|c| {
            if let Some(ctx) = c.borrow_mut().take()
                && !ctx.seal.is_null()
            {
                let _ = GdipDisposeImage(ctx.seal);
            }
        });
        let token = TOKEN.with(|t| *t.borrow());
        if token != 0 {
            GdiplusShutdown(token);
        }
    }
}

/// Show (or refresh) the toast for `state`.
pub fn notify(state: AuthState) {
    let hwnd = ensure_window();
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
        let seal = load_seal();
        CTX.with(|c| {
            *c.borrow_mut() = Some(Ctx {
                hwnd,
                seal,
                state: AuthState::Idle,
                frame: 0,
                ticks: 0,
            });
        });
        hwnd
    }
}

/// Load the DoD seal PNG (GDI+) from the first candidate that opens, or null.
fn load_seal() -> *mut GpImage {
    for path in seal_candidates() {
        let wide: Vec<u16> = path
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut bitmap: *mut GpBitmap = std::ptr::null_mut();
        // SAFETY: GDI+ file load; on failure leaves `bitmap` null.
        let img = unsafe {
            if GdipCreateBitmapFromFile(PCWSTR(wide.as_ptr()), &mut bitmap).0 == 0 {
                bitmap.cast::<GpImage>()
            } else {
                std::ptr::null_mut()
            }
        };
        if !img.is_null() {
            return img;
        }
    }
    std::ptr::null_mut()
}

/// Where to look for the seal, in order: the deployed `%ProgramData%` copy, an
/// `icons\DOW-Seal.png` next to the executable, then the same relative to the cwd
/// (running from the repo).
fn seal_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut programdata = usg_status::status_file_path();
    programdata.set_file_name("seal.png");
    out.push(programdata);
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        out.push(dir.join("icons").join("DOW-Seal.png"));
    }
    out.push(PathBuf::from("icons").join("DOW-Seal.png"));
    out
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
            CTX.with(|c| {
                if let Some(ctx) = c.borrow_mut().as_mut() {
                    ctx.frame = ctx.frame.wrapping_add(1);
                    ctx.ticks = ctx.ticks.saturating_add(1);
                    let terminal = matches!(
                        ctx.state,
                        AuthState::Authenticated | AuthState::Failed | AuthState::Idle
                    );
                    if terminal && ctx.ticks > AUTO_HIDE_TICKS {
                        hide = true;
                    }
                }
            });
            if hide {
                let _ = KillTimer(Some(hwnd), ANIM_TIMER);
                let _ = ShowWindow(hwnd, SW_HIDE);
            } else {
                let _ = InvalidateRect(Some(hwnd), None, false);
            }
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

fn paint(hwnd: HWND) {
    let (state, seal, frame) = CTX.with(|c| {
        c.borrow()
            .as_ref()
            .map_or((AuthState::Idle, std::ptr::null_mut(), 0), |x| {
                (x.state, x.seal, x.frame)
            })
    });
    let status = read_status();
    // SAFETY: standard BeginPaint/EndPaint with GDI + GDI+ drawing on the DC.
    unsafe {
        let mut ps = PAINTSTRUCT::default();
        let hdc = BeginPaint(hwnd, &mut ps);
        let mut rc = RECT::default();
        let _ = GetClientRect(hwnd, &mut rc);

        // Card background #355e93 (COLORREF is 0x00BBGGRR).
        let bg = CreateSolidBrush(COLORREF(0x0093_5E35));
        FillRect(hdc, &rc, bg);
        let _ = DeleteObject(bg.into());

        // Text block.
        SetBkMode(hdc, TRANSPARENT);
        let _ = SetTextColor(hdc, COLORREF(0x00FF_FFFF));
        draw_line(hdc, headline(state), 104, 16);
        let _ = SetTextColor(hdc, COLORREF(0x00C8_C8C8));
        for (i, line) in detail_lines(status.as_ref()).iter().enumerate() {
            draw_line(hdc, line, 104, 44 + 20 * i32::try_from(i).unwrap_or(0));
        }

        // Seal + indicator via GDI+.
        let mut g: *mut GpGraphics = std::ptr::null_mut();
        if GdipCreateFromHDC(hdc, &mut g).0 == 0 {
            let _ = GdipSetSmoothingMode(g, SmoothingModeAntiAlias);
            if seal.is_null() {
                fill_circle(g, 0xFF37_4A8B, 14, 14, 76); // placeholder disc
            } else {
                let _ = GdipDrawImageRectI(g, seal, 14, 14, 76, 76);
            }
            draw_indicator(g, state, frame, W - 52, 18, 30);
            let _ = GdipDeleteGraphics(g);
        }
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

/// The right-hand status indicator: a filled bubble, or a spinning ring.
unsafe fn draw_indicator(g: *mut GpGraphics, state: AuthState, frame: u32, x: i32, y: i32, d: i32) {
    match state {
        AuthState::Authenticated => fill_circle(g, 0xFF43_A047, x, y, d), // green
        AuthState::Failed => fill_circle(g, 0xFFE5_3935, x, y, d),        // red
        AuthState::Idle => fill_circle(g, 0xFF9E_9E9E, x, y, d),          // gray
        _ => spinner(g, frame, x, y, d),                                  // in progress
    }
}

unsafe fn fill_circle(g: *mut GpGraphics, argb: u32, x: i32, y: i32, d: i32) {
    let mut brush = std::ptr::null_mut();
    if GdipCreateSolidFill(argb, &mut brush).0 == 0 {
        let _ = GdipFillEllipseI(g, brush.cast(), x, y, d, d);
        let _ = GdipDeleteBrush(brush.cast());
    }
}

unsafe fn spinner(g: *mut GpGraphics, frame: u32, x: i32, y: i32, d: i32) {
    // Faint full track, then a bright rotating 90° arc.
    let mut track = std::ptr::null_mut();
    if GdipCreatePen1(0x3FFF_FFFF, 4.0, Unit(2), &mut track).0 == 0 {
        let _ = GdipDrawArcI(g, track, x, y, d, d, 0.0, 360.0);
        let _ = GdipDeletePen(track);
    }
    let start = (frame.wrapping_mul(20) % 360) as f32;
    let mut arc = std::ptr::null_mut();
    if GdipCreatePen1(0xFF42_A5F5, 4.0, Unit(2), &mut arc).0 == 0 {
        let _ = GdipDrawArcI(g, arc, x, y, d, d, start, 90.0);
        let _ = GdipDeletePen(arc);
    }
}
