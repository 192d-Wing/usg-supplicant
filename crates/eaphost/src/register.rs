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

pub use crate::{USG_AUTHOR_ID, USG_TYPE_ID};
/// Friendly name shown for the method.
const FRIENDLY_NAME: &str = "usg-TEAP/1.3";

/// `Properties` bitmask (eaptypes.h `eapProp*`) advertising what the method does,
/// so `EAPHost` enables the matching behavior (identity delegation, machine/user
/// auth, config). A zero mask makes `EAPHost` treat the method as capability-less
/// and never source an outer identity from it. We emit MPPE keys, are a tunnel
/// method with identity privacy (anonymous outer identity), do machine and user
/// auth, and support configuration.
const METHOD_PROPERTIES: u32 = 0x0008_0000  // eapPropMppeEncryption
    | 0x0010_0000  // eapPropTunnelMethod
    | 0x0020_0000  // eapPropSupportsConfig
    | 0x0100_0000  // eapPropMachineAuth
    | 0x0200_0000  // eapPropUserAuth
    | 0x0400_0000; // eapPropIdentityPrivacy

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

/// Register the peer method under `root` at `base` (`base` is the methods key),
/// mirroring the in-box TEAP method's registration shape (`311\55`). Writes:
/// - `PeerDllPath` — the auth/method DLL.
/// - `PeerConfigUIPath` — the DLL `EAPHost` loads for the config-conversion entry
///   points (`EapPeerConfigXml2Blob`/`Blob2Xml`) on the host-API
///   `EapHostPeerConfigXml2Blob` path. Without it that path can't reach our method.
/// - `PeerIdentityPath` — the DLL whose by-name `EapPeerGetIdentity` `EAPHost` is
///   documented to call for the identity. (All three point at the same DLL.)
/// - `PeerFriendlyName`, the username/password-dialog opt-outs, and `Properties`.
///
/// NOTE: on the host-API supplicant path, on-hardware testing showed `EAPHost`
/// does **not** call `EapPeerGetIdentity` — the outer EAP-Response/Identity is
/// formed from the user data passed to `EapHostPeerBeginSession`, and a session
/// without it still aborts with `EAP_E_EAPHOST_IDENTITY_UNKNOWN`. These values are
/// the correct registration shape; sourcing that identity blob is separate
/// (see `tests/real_eaphost_config.rs`).
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
        // The DLL EAPHost loads to build the identity (documented role of
        // EapPeerGetIdentity); see the NOTE above for the host-API caveat.
        set_sz(hkey, "PeerIdentityPath", dll_path)?;
        // EAPHost loads PeerConfigUIPath for the config-conversion entry points
        // (EapPeerConfigXml2Blob / EapPeerConfigBlob2Xml) used by the host-API
        // EapHostPeerConfigXml2Blob path. Our DLL serves this role too.
        set_sz(hkey, "PeerConfigUIPath", dll_path)?;
        set_sz(hkey, "PeerFriendlyName", FRIENDLY_NAME)?;
        // Certificate method: never prompt for a username/password (mirrors the
        // in-box TEAP), so EAPHost doesn't raise a credential dialog.
        set_dword(hkey, "PeerInvokeUsernameDialog", 0)?;
        set_dword(hkey, "PeerInvokePasswordDialog", 0)?;
        set_dword(hkey, "Properties", METHOD_PROPERTIES)?;
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
