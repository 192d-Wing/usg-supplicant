//! Self-hosted validation of the peer-method DLL ABI: load the built
//! `eaphost.dll`, obtain `EapPeerGetInfo`, and drive it exactly as `dot3svc`
//! would — no `dot3svc`, no admin, no network. Validates symbol export, the
//! entry-point ABI, the routine table, and that `EapPeerInitialize` (called
//! through the table) fails closed on a non-FIPS host.
//!
//! `#[ignore]`d (needs the cdylib built first): `cargo build -p eaphost` then
//! `cargo test -p eaphost --test peer_dll -- --ignored --nocapture`. Override the
//! DLL path with `USG_EAPHOST_DLL` if your target dir differs.
#![cfg(windows)]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use windows::Win32::Security::ExtensibleAuthenticationProtocol::{
    EAP_ERROR, EAP_PEER_METHOD_ROUTINES, EAP_TYPE,
};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::core::{PCWSTR, s};

type EapPeerGetInfoFn = unsafe extern "system" fn(
    *mut EAP_TYPE,
    *mut EAP_PEER_METHOD_ROUTINES,
    *mut *mut EAP_ERROR,
) -> u32;
type EapPeerInitializeFn = unsafe extern "system" fn(*mut *mut EAP_ERROR) -> u32;

fn dll_path() -> String {
    std::env::var("USG_EAPHOST_DLL").unwrap_or_else(|_| {
        format!(
            "{}/../../target/debug/eaphost.dll",
            env!("CARGO_MANIFEST_DIR")
        )
    })
}

#[test]
#[ignore = "needs the cdylib built: cargo build -p eaphost"]
fn dll_loads_and_entrypoint_yields_routines() {
    let path: Vec<u16> = dll_path()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: standard LoadLibrary/GetProcAddress/FreeLibrary FFI on a path we
    // built; the function pointers are called with their ABI-correct signatures.
    unsafe {
        let lib = LoadLibraryW(PCWSTR(path.as_ptr())).expect("LoadLibrary eaphost.dll");

        let proc =
            GetProcAddress(lib, s!("EapPeerGetInfo")).expect("eaphost.dll exports EapPeerGetInfo");
        let get_info: EapPeerGetInfoFn = core::mem::transmute(proc);

        // Drive the entry point as EAPHost does: ask for TEAP (type 55).
        let mut eap_type = EAP_TYPE {
            r#type: 55,
            dwVendorId: 0,
            dwVendorType: 0,
        };
        let mut routines = EAP_PEER_METHOD_ROUTINES::default();
        let mut err: *mut EAP_ERROR = core::ptr::null_mut();
        let rc = get_info(&raw mut eap_type, &raw mut routines, &raw mut err);
        assert_eq!(rc, 0, "EapPeerGetInfo should succeed");
        assert_eq!(routines.dwVersion, 1, "routine table version");
        assert!(!routines.pEapType.is_null(), "pEapType set");
        assert_eq!((*routines.pEapType).r#type, 55, "advertises TEAP");
        // Every routine slot is populated (no null function pointers).
        for slot in [
            routines.EapPeerInitialize,
            routines.EapPeerBeginSession,
            routines.EapPeerProcessRequestPacket,
            routines.EapPeerGetResponsePacket,
            routines.EapPeerGetResult,
            routines.EapPeerEndSession,
            routines.EapPeerShutdown,
        ] {
            assert_ne!(slot, 0, "routine pointer must be set");
        }

        // Call EapPeerInitialize through the table. On this non-FIPS host the OS
        // FIPS gate must fail closed (nonzero), proving the routine is callable
        // and wired to the gate.
        let initialize: EapPeerInitializeFn = core::mem::transmute(routines.EapPeerInitialize);
        let init_rc = initialize(&raw mut err);
        assert_ne!(
            init_rc, 0,
            "EapPeerInitialize must fail closed on a non-FIPS host"
        );
        // The module handle is intentionally leaked: this is a one-shot test
        // process, and FreeLibrary mid-test risks unloading code still on the
        // stack. Process exit reclaims it.
        let _ = lib;
    }

    eprintln!(
        "eaphost.dll loaded; EapPeerGetInfo returned a wired routine table; EapPeerInitialize failed closed (non-FIPS) — ABI OK"
    );
}
