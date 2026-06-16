//! Register / unregister the `EAPHost` peer method in the Windows registry
//! (WINDOWS_DEV.md §4.1 step 3).
//!
//! `dot3svc` discovers peer methods under
//! `HKLM\SYSTEM\CurrentControlSet\Services\EapHost\Methods\{AuthorId}\{TypeId}`.
//! We register under a **distinct Author ID** (not Microsoft's) with TypeId 55
//! (TEAP) so the wired profile selects our method rather than the in-box one.
//!
//! Writing under HKLM requires elevation; [`register`] / [`unregister`] target
//! HKLM. The write/read/delete FFI is validated headlessly under HKCU (no admin)
//! via [`register_under`] / [`unregister_under`].
#![allow(clippy::cast_possible_truncation)]

use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_WRITE, REG_DWORD, REG_OPTION_NON_VOLATILE, REG_SAM_FLAGS, REG_SZ,
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegSetValueExW,
};
use windows::core::PCWSTR;

use crate::EAPHOST_METHODS_KEY;
use crate::error::EapHostError;

/// Our `EAPHost` Author ID — distinct from Microsoft's so we never collide with
/// the in-box TEAP method. Set to the organization's IANA Private Enterprise
/// Number before production.
pub const USG_AUTHOR_ID: u32 = 192_000;
/// EAP type 55 (TEAP).
pub const USG_TYPE_ID: u32 = 55;
/// Friendly name shown for the method.
const FRIENDLY_NAME: &str = "usg-TEAP/1.3";

/// The method's registry subkey path, relative to a root hive: the methods base,
/// then our Author ID and the TEAP type id (decimal, as `EAPHost` expects).
fn method_subkey(base: &str) -> String {
    format!("{base}\\{USG_AUTHOR_ID}\\{USG_TYPE_ID}")
}

/// Wide (UTF-16, NUL-terminated) form of `s`.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(core::iter::once(0)).collect()
}

/// View a `u16` slice as bytes (for `RegSetValueExW`, which takes `REG_SZ` data
/// as the raw wide-string bytes).
fn u16_bytes(w: &[u16]) -> &[u8] {
    // SAFETY: `w` is valid for `w.len()*2` bytes; `u8` has no alignment needs.
    unsafe { core::slice::from_raw_parts(w.as_ptr().cast::<u8>(), w.len().saturating_mul(2)) }
}

/// Register the peer method under `root` at `base` (`base` is the methods key).
/// Writes `PeerDllPath` (the auth/method DLL), `PeerIdentityPath` (the DLL whose
/// by-name `EapPeerGetIdentity` `EAPHost` calls to build the EAP-Response/Identity
/// — the same DLL), `PeerFriendlyName`, the username/password-dialog opt-outs, and
/// `Properties`. Without `PeerIdentityPath`, `EAPHost` aborts a session with
/// `EAP_E_EAPHOST_IDENTITY_UNKNOWN` before any method packet.
///
/// # Errors
/// [`EapHostError::Win32`] if any registry call fails (e.g. access denied when
/// `root` is HKLM and the caller is not elevated).
pub fn register_under(root: HKEY, base: &str, dll_path: &str) -> Result<(), EapHostError> {
    let subkey = wide(&method_subkey(base));
    let mut hkey = HKEY::default();
    // SAFETY: standard RegCreateKeyExW; out-param `hkey` is an owned local.
    let status = unsafe {
        RegCreateKeyExW(
            root,
            PCWSTR(subkey.as_ptr()),
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            REG_SAM_FLAGS(KEY_WRITE.0),
            None,
            &raw mut hkey,
            None,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(EapHostError::Win32 { code: status.0 });
    }

    let result = (|| {
        set_sz(hkey, "PeerDllPath", dll_path)?;
        // EAPHost loads PeerIdentityPath and calls its by-name EapPeerGetIdentity
        // to produce the EAP-Response/Identity. Our DLL serves both roles.
        set_sz(hkey, "PeerIdentityPath", dll_path)?;
        set_sz(hkey, "PeerFriendlyName", FRIENDLY_NAME)?;
        // Certificate method: never prompt for a username/password (mirrors the
        // in-box TEAP). EAPHost then sources the identity from EapPeerGetIdentity.
        set_dword(hkey, "PeerInvokeUsernameDialog", 0)?;
        set_dword(hkey, "PeerInvokePasswordDialog", 0)?;
        set_dword(hkey, "Properties", 0)?;
        Ok(())
    })();
    // SAFETY: close the key we opened, regardless of the value writes' outcome.
    let _ = unsafe { RegCloseKey(hkey) };
    result
}

/// Remove the method's registry subtree under `root` at `base`.
///
/// # Errors
/// [`EapHostError::Win32`] if the delete fails (access denied / not found).
pub fn unregister_under(root: HKEY, base: &str) -> Result<(), EapHostError> {
    let subkey = wide(&method_subkey(base));
    // SAFETY: deletes the named subtree under `root`.
    let status = unsafe { RegDeleteTreeW(root, PCWSTR(subkey.as_ptr())) };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(EapHostError::Win32 { code: status.0 })
    }
}

/// Register the method under HKLM (requires elevation).
///
/// # Errors
/// See [`register_under`].
pub fn register(dll_path: &str) -> Result<(), EapHostError> {
    register_under(HKEY_LOCAL_MACHINE, EAPHOST_METHODS_KEY, dll_path)
}

/// Unregister the method from HKLM (requires elevation).
///
/// # Errors
/// See [`unregister_under`].
pub fn unregister() -> Result<(), EapHostError> {
    unregister_under(HKEY_LOCAL_MACHINE, EAPHOST_METHODS_KEY)
}

fn set_sz(hkey: HKEY, name: &str, value: &str) -> Result<(), EapHostError> {
    let name_w = wide(name);
    let value_w = wide(value);
    // SAFETY: `name_w`/`value_w` outlive the call; REG_SZ data is the wide bytes.
    let status = unsafe {
        RegSetValueExW(
            hkey,
            PCWSTR(name_w.as_ptr()),
            None,
            REG_SZ,
            Some(u16_bytes(&value_w)),
        )
    };
    win32(status.0)
}

fn set_dword(hkey: HKEY, name: &str, value: u32) -> Result<(), EapHostError> {
    let name_w = wide(name);
    let bytes = value.to_le_bytes();
    // SAFETY: `name_w` outlives the call; REG_DWORD data is 4 little-endian bytes.
    let status =
        unsafe { RegSetValueExW(hkey, PCWSTR(name_w.as_ptr()), None, REG_DWORD, Some(&bytes)) };
    win32(status.0)
}

fn win32(code: u32) -> Result<(), EapHostError> {
    if code == ERROR_SUCCESS.0 {
        Ok(())
    } else {
        Err(EapHostError::Win32 { code })
    }
}
