//! Shared GDI+ helpers for the tray popups: the GDI+ lifecycle, the cached DoD
//! seal image, and the status indicator (a filled bubble or a spinning ring).
#![allow(unsafe_op_in_unsafe_fn)] // GDI+ FFI

use std::cell::Cell;
use std::path::PathBuf;

use windows::Win32::Graphics::GdiPlus::{
    GdipCreateBitmapFromFile, GdipCreateBitmapFromScan0, GdipCreateHICONFromBitmap, GdipCreatePen1,
    GdipCreateSolidFill, GdipDeleteBrush, GdipDeleteGraphics, GdipDeletePen, GdipDisposeImage,
    GdipDrawArcI, GdipDrawImageRectI, GdipDrawLineI, GdipFillEllipseI, GdipFillRectangleI,
    GdipGetImageGraphicsContext, GdipSetInterpolationMode, GdipSetPixelOffsetMode,
    GdipSetSmoothingMode, GdiplusShutdown, GdiplusStartup, GdiplusStartupInput, GpBitmap,
    GpGraphics, GpImage, InterpolationModeHighQualityBicubic, PixelOffsetModeHighQuality,
    SmoothingModeAntiAlias, Unit,
};
use windows::Win32::UI::WindowsAndMessaging::HICON;
use windows::core::PCWSTR;

use usg_status::AuthState;

/// `PixelFormat32bppARGB` (not exposed as a named const by the crate): premultiplied
/// 32-bit BGRA, the format `GdipCreateHICONFromBitmap` expects for an alpha icon.
const PIXEL_FORMAT_32BPP_ARGB: i32 = 0x0026_200A;

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

/// Draw the cached seal into `g` at `(x, y)` sized `d×d`, using high-quality
/// downscaling so the detailed seal stays crisp when shrunk. Returns `false` if no
/// seal is loaded, so the caller can draw a placeholder instead.
///
/// # Safety
/// `g` must be a valid `GpGraphics`.
pub unsafe fn draw_seal(g: *mut GpGraphics, x: i32, y: i32, d: i32) -> bool {
    let img = seal();
    if img.is_null() {
        return false;
    }
    let _ = GdipSetInterpolationMode(g, InterpolationModeHighQualityBicubic);
    let _ = GdipSetPixelOffsetMode(g, PixelOffsetModeHighQuality);
    let _ = GdipDrawImageRectI(g, img, x, y, d, d);
    true
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

/// Build a 32×32 tray icon: a padlock + key, with the padlock body colored by
/// `state` (green authenticated, red failed, amber in-progress, steel idle). The
/// caller owns the returned `HICON` and must `DestroyIcon` it. Null on failure.
///
/// GDI+ must be started (see [`startup`]).
pub fn make_tray_icon(state: AuthState) -> HICON {
    let body = match state {
        AuthState::Authenticated => 0xFF43_A047, // green
        AuthState::Failed => 0xFFE5_3935,        // red
        AuthState::Idle => 0xFF90_A4AE,          // steel
        _ => 0xFFFB_C02D,                        // amber (in progress)
    };
    const METAL: u32 = 0xFFCF_D8DC; // shackle + key
    const HOLE: u32 = 0xFF26_3238; // keyhole

    // SAFETY: allocate an ARGB GDI+ bitmap, draw into it, convert to an HICON.
    unsafe {
        let mut bmp: *mut GpBitmap = std::ptr::null_mut();
        if GdipCreateBitmapFromScan0(32, 32, 0, PIXEL_FORMAT_32BPP_ARGB, None, &mut bmp).0 != 0
            || bmp.is_null()
        {
            return HICON::default();
        }
        let mut g: *mut GpGraphics = std::ptr::null_mut();
        if GdipGetImageGraphicsContext(bmp.cast(), &mut g).0 == 0 {
            draw_lock_and_key(g, body, METAL, HOLE);
            let _ = GdipDeleteGraphics(g);
        }
        let mut icon = HICON::default();
        let _ = GdipCreateHICONFromBitmap(bmp, &mut icon);
        let _ = GdipDisposeImage(bmp.cast());
        icon
    }
}

/// Paint a bold padlock (left) and a separate key (right) onto `g` (a 32×32 canvas),
/// kept simple and chunky so both read at 16 px tray size. `body` colors the lock.
///
/// # Safety
/// `g` must be a valid `GpGraphics`.
unsafe fn draw_lock_and_key(g: *mut GpGraphics, body: u32, metal: u32, hole: u32) {
    let _ = GdipSetSmoothingMode(g, SmoothingModeAntiAlias);

    // Padlock (left). Shackle: a top arch with two legs into the body.
    stroke_arc(g, metal, 4, 4, 11, 13, 180.0, 180.0, 3.0);
    stroke_line(g, metal, 4, 10, 4, 15, 3.0);
    stroke_line(g, metal, 15, 10, 15, 15, 3.0);
    // Body + keyhole.
    fill_rect(g, body, 2, 14, 15, 15);
    fill_circle(g, hole, 7, 18, 5);
    fill_rect(g, hole, 9, 21, 2, 5);

    // Key (right): round bow at top, a stem down, and two teeth.
    stroke_ellipse(g, metal, 21, 3, 9, 9, 3.0);
    stroke_line(g, metal, 25, 12, 25, 29, 3.0);
    stroke_line(g, metal, 25, 23, 30, 23, 3.0);
    stroke_line(g, metal, 25, 28, 29, 28, 3.0);
}

unsafe fn fill_rect(g: *mut GpGraphics, argb: u32, x: i32, y: i32, w: i32, h: i32) {
    let mut brush = std::ptr::null_mut();
    if GdipCreateSolidFill(argb, &mut brush).0 == 0 {
        let _ = GdipFillRectangleI(g, brush.cast(), x, y, w, h);
        let _ = GdipDeleteBrush(brush.cast());
    }
}

unsafe fn stroke_line(g: *mut GpGraphics, argb: u32, x1: i32, y1: i32, x2: i32, y2: i32, w: f32) {
    let mut pen = std::ptr::null_mut();
    if GdipCreatePen1(argb, w, Unit(2), &mut pen).0 == 0 {
        let _ = GdipDrawLineI(g, pen, x1, y1, x2, y2);
        let _ = GdipDeletePen(pen);
    }
}

#[allow(clippy::too_many_arguments)] // mirrors the GDI+ arc signature (rect + angles)
unsafe fn stroke_arc(
    g: *mut GpGraphics,
    argb: u32,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    start: f32,
    sweep: f32,
    pen_w: f32,
) {
    let mut pen = std::ptr::null_mut();
    if GdipCreatePen1(argb, pen_w, Unit(2), &mut pen).0 == 0 {
        let _ = GdipDrawArcI(g, pen, x, y, w, h, start, sweep);
        let _ = GdipDeletePen(pen);
    }
}

unsafe fn stroke_ellipse(
    g: *mut GpGraphics,
    argb: u32,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    pen_w: f32,
) {
    let mut pen = std::ptr::null_mut();
    if GdipCreatePen1(argb, pen_w, Unit(2), &mut pen).0 == 0 {
        let _ = GdipDrawArcI(g, pen, x, y, w, h, 0.0, 360.0);
        let _ = GdipDeletePen(pen);
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

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::UI::WindowsAndMessaging::DestroyIcon;

    #[test]
    fn tray_icon_builds_non_null() {
        startup();
        let icon = make_tray_icon(AuthState::Authenticated);
        let built = !icon.0.is_null();
        if built {
            // SAFETY: an icon we own from GdipCreateHICONFromBitmap.
            unsafe {
                let _ = DestroyIcon(icon);
            }
        }
        shutdown();
        assert!(built, "GdipCreateHICONFromBitmap returned a null HICON");
    }
}
