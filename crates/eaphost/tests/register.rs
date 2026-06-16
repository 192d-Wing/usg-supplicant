//! Validate the registry-write FFI under HKCU (no admin). Production
//! `register()` targets HKLM and needs elevation; the mechanics — create nested
//! key, set values, read back, delete subtree — are identical and exercised here.
#![cfg(windows)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::arithmetic_side_effects
)]

use eaphost::register::{USG_AUTHOR_ID, USG_TYPE_ID, register_under, unregister_under};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, RRF_RT_REG_SZ, RegDeleteTreeW, RegGetValueW,
};
use windows::core::PCWSTR;

const TEST_BASE: &str = "Software\\usg-eaphost-test\\EapHost\\Methods";

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Read a `REG_SZ` value, or `None` if absent.
fn read_sz(root: HKEY, subkey: &str, name: &str) -> Option<String> {
    let subkey_w = wide(subkey);
    let name_w = wide(name);
    let mut buf = vec![0u16; 1024];
    let mut cb: u32 = (buf.len() * 2) as u32;
    // SAFETY: out buffer/size are owned locals; RRF_RT_REG_SZ restricts the type.
    let status = unsafe {
        RegGetValueW(
            root,
            PCWSTR(subkey_w.as_ptr()),
            PCWSTR(name_w.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr().cast()),
            Some(&raw mut cb),
        )
    };
    if status != ERROR_SUCCESS {
        return None;
    }
    let chars: Vec<u16> = buf
        .iter()
        .copied()
        .take(cb as usize / 2)
        .take_while(|&c| c != 0)
        .collect();
    Some(String::from_utf16_lossy(&chars))
}

#[test]
fn register_writes_and_unregister_removes_the_method() {
    let dll = "C:\\Windows\\System32\\drivers\\usg\\eaphost.dll";
    // Start clean (ignore "not found").
    let _ = unregister_under(HKEY_CURRENT_USER, TEST_BASE);

    register_under(HKEY_CURRENT_USER, TEST_BASE, dll).expect("register under HKCU");

    // The method key carries PeerDllPath / PeerFriendlyName under {AuthorId}\{TypeId}.
    let subkey = format!("{TEST_BASE}\\{USG_AUTHOR_ID}\\{USG_TYPE_ID}");
    assert_eq!(
        read_sz(HKEY_CURRENT_USER, &subkey, "PeerDllPath").as_deref(),
        Some(dll),
        "PeerDllPath round-trips"
    );
    assert!(
        read_sz(HKEY_CURRENT_USER, &subkey, "PeerFriendlyName").is_some(),
        "PeerFriendlyName is set"
    );

    unregister_under(HKEY_CURRENT_USER, TEST_BASE).expect("unregister");
    assert!(
        read_sz(HKEY_CURRENT_USER, &subkey, "PeerDllPath").is_none(),
        "the method key is gone after unregister"
    );

    // Clean up the whole test tree (leaves no empty keys behind).
    let root = wide("Software\\usg-eaphost-test");
    // SAFETY: delete the test subtree we created under HKCU.
    let _ = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, PCWSTR(root.as_ptr())) };
}
