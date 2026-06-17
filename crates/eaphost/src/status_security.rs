//! Harden the directory that holds the published status file (status assessment
//! H1/M1).
//!
//! `usg-status` writes `%ProgramData%\usg-supplicant\status` as **Local System**;
//! the user-session tray/window read it and trust it as Local-System-authored. The
//! default `ProgramData` ACL lets any authenticated user create files there, so a
//! non-privileged user could pre-create or replace the directory/file — poisoning
//! the trusted status, or planting a reparse point the SYSTEM writer follows when
//! it stages the atomic-rename temp file.
//!
//! Before publishing, we create (or re-secure) the directory with a **protected**
//! DACL — SYSTEM and Administrators full control, all other authenticated users
//! read-only, no inheritance from the permissive `ProgramData` ACE — and the caller
//! refuses to publish if we can't secure it (fail closed). With the directory
//! writable only by SYSTEM/Admins, a low-priv user can neither poison the file nor
//! plant a temp-file reparse point.

use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::sync::OnceLock;

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, OBJECT_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
    SetFileSecurityW,
};
use windows::Win32::Storage::FileSystem::CreateDirectoryW;
use windows::core::PCWSTR;

/// Owner = SYSTEM; protected DACL (`P`, no inheritance): SYSTEM (`SY`) and
/// Administrators (`BA`) full control, all other authenticated users (`AU`) generic
/// read + execute (traverse) only. `OICI` makes the ACEs inherit to the status file
/// and any subdirs, so the file itself is SYSTEM/Admin-write, user-read.
const STATUS_DIR_SDDL: &str = "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;AU)";

/// Ensure `%ProgramData%\usg-supplicant` exists with the hardened DACL. The FFI runs
/// once per process on success and retries while it keeps failing. Returns whether
/// the directory is secured — callers must **not** publish status if this is `false`.
pub(crate) fn secure_status_dir() -> bool {
    static SECURED: OnceLock<()> = OnceLock::new();
    if SECURED.get().is_some() {
        return true;
    }
    let mut dir = usg_status::status_file_path();
    dir.pop(); // drop the "status" filename, leaving the directory.
    if apply(&dir) {
        let _ = SECURED.set(());
        true
    } else {
        false
    }
}

/// Create `dir` (if absent) with the protected DACL, then enforce owner + protected
/// DACL so a pre-created (attacker-owned) directory is corrected. Returns success.
fn apply(dir: &Path) -> bool {
    let path: Vec<u16> = dir
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let sddl: Vec<u16> = STATUS_DIR_SDDL
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut psd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: parse the static SDDL into a self-relative descriptor; `psd` is owned
    // by us and freed with `LocalFree` below on every path.
    let built = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &raw mut psd,
            None,
        )
    };
    if built.is_err() || psd.0.is_null() {
        return false;
    }

    let sa = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
        lpSecurityDescriptor: psd.0,
        bInheritHandle: false.into(),
    };
    let info = OBJECT_SECURITY_INFORMATION(
        OWNER_SECURITY_INFORMATION.0
            | DACL_SECURITY_INFORMATION.0
            | PROTECTED_DACL_SECURITY_INFORMATION.0,
    );
    // SAFETY: create the directory with our DACL (a no-op error if it already
    // exists), then enforce owner + protected DACL on the existing directory so a
    // directory an attacker pre-created with a weak ACL is reset. SYSTEM holds the
    // privileges to set the owner; if it can't, `SetFileSecurityW` returns false and
    // we report failure (the caller then skips publishing).
    let ok = unsafe {
        let _ = CreateDirectoryW(PCWSTR(path.as_ptr()), Some(&raw const sa));
        SetFileSecurityW(PCWSTR(path.as_ptr()), info, psd).as_bool()
    };

    // SAFETY: free the descriptor `ConvertString...` allocated with `LocalAlloc`.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(psd.0)));
    }
    ok
}
