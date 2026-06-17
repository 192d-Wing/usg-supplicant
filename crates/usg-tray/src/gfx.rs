//! Shared GDI+ helpers for the tray popups: the GDI+ lifecycle, the cached DoD
//! seal image, and the status indicator (a filled bubble or a spinning ring).
#![allow(unsafe_op_in_unsafe_fn)] // GDI+ FFI

use std::cell::Cell;
use std::path::PathBuf;

use windows::Win32::Graphics::GdiPlus::{
    GdipCreateBitmapFromFile, GdipCreatePen1, GdipCreateSolidFill, GdipDeleteBrush, GdipDeletePen,
    GdipDisposeImage, GdipDrawArcI, GdipFillEllipseI, GdiplusShutdown, GdiplusStartup,
    GdiplusStartupInput, GpBitmap, GpGraphics, GpImage, Unit,
};
use windows::core::PCWSTR;

use usg_status::AuthState;

thread_local! {
    static TOKEN: Cell<usize> = const { Cell::new(0) };
    static SEAL: Cell<*mut GpImage> = const { Cell::new(std::ptr::null_mut()) };
}

/// Start GDI+ and load the seal once. Call before any drawing.
pub fn startup() {
    // SAFETY: standard GDI+ init.
    unsafe {
        let mut token = 0usize;
        let input = GdiplusStartupInput {
            GdiplusVersion: 1,
            ..Default::default()
        };
        let _ = GdiplusStartup(&mut token, &input, std::ptr::null_mut());
        TOKEN.with(|t| t.set(token));
        SEAL.with(|s| s.set(load_seal()));
    }
}

/// Dispose the seal and shut GDI+ down.
pub fn shutdown() {
    // SAFETY: dispose what startup created.
    unsafe {
        let seal = SEAL.with(|s| s.replace(std::ptr::null_mut()));
        if !seal.is_null() {
            let _ = GdipDisposeImage(seal);
        }
        let token = TOKEN.with(Cell::take);
        if token != 0 {
            GdiplusShutdown(token);
        }
    }
}

/// The cached seal image (null if none loaded).
pub fn seal() -> *mut GpImage {
    SEAL.with(Cell::get)
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

/// Where to look for the seal, in order: the deployed `%ProgramData%` copy (either
/// name), an `icons\DOW-Seal.png` next to the executable, then relative to the cwd.
fn seal_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let dir = {
        let mut p = usg_status::status_file_path();
        p.pop();
        p
    };
    out.push(dir.join("seal.png"));
    out.push(dir.join("DOW-Seal.png"));
    if let Ok(exe) = std::env::current_exe()
        && let Some(d) = exe.parent()
    {
        out.push(d.join("icons").join("DOW-Seal.png"));
    }
    out.push(PathBuf::from("icons").join("DOW-Seal.png"));
    out
}

/// Draw the status indicator into `g`: a filled bubble (green/red/gray), or a
/// spinning blue ring for the in-progress states (advanced by `frame`).
///
/// # Safety
/// `g` must be a valid `GpGraphics`.
pub unsafe fn draw_indicator(
    g: *mut GpGraphics,
    state: AuthState,
    frame: u32,
    x: i32,
    y: i32,
    d: i32,
) {
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
    // Faint full track, then a bright rotating 90° arc (Unit(2) = pixels).
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
