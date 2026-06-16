//! Validation against the **real** Windows `EAPHost` service (`eappprxy.dll`),
//! requiring an **elevated** shell (HKLM registration) and OS FIPS mode.
//!
//! - `real_eaphost_enumerates_registered_method`: register our peer method, then
//!   confirm the live `EAPHost` lists it via `EapHostPeerGetMethods`.
//! - `real_eaphost_loads_and_begins_session`: drive `EapHostPeerBeginSession` so
//!   the **real** `EAPHost` service loads our DLL, runs `EapPeerInitialize` (the
//!   OS FIPS gate) and `EapPeerBeginSession` (config blob -> CNG credential ->
//!   driver), returning a live session — proving the DLL runs inside real
//!   `EAPHost` through the C ABI.
//!
//! `#[ignore]`d (needs admin + FIPS + a service-loadable DLL + a machine cert):
//! ```text
//! cargo build -p eaphost
//! copy target\debug\eaphost.dll C:\Windows\System32\usg-eaphost-test.dll
//! # provision an ECDSA client-auth cert in LocalMachine\My, then:
//! USG_EAPHOST_DLL=C:\Windows\System32\usg-eaphost-test.dll USG_CNG_TEST_SUBJECT=... \
//!   cargo test -p eaphost --test real_eaphost -- --ignored --nocapture
//! ```
//!
//! NOTE: the full packet relay (`EapHostPeerProcessReceivedPacket` onward)
//! returns `ERROR_PROC_NOT_FOUND` — our method DLL exports exactly the two
//! by-name symbols the SDK mandates (`EapPeerGetInfo`, `EapPeerFreeErrorMemory`),
//! so the missing proc is in the **config DLL** (`PeerConfigDllPath`, §4.1 step
//! 4: `EapPeerConfigXml2Blob` / `EapPeerGetConfigBlobAndUserBlob` …) which we
//! have not built yet. Completing the live packet flow is gated on that DLL.
#![cfg(windows)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use std::sync::Mutex;

use eaphost::config::SessionConfigBlob;
use eaphost::register::{USG_AUTHOR_ID, USG_TYPE_ID, register, unregister};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::ExtensibleAuthenticationProtocol::{
    EAP_ERROR, EAP_METHOD_INFO_ARRAY, EAP_METHOD_TYPE, EAP_TYPE, EapHostPeerBeginSession,
    EapHostPeerEndSession, EapHostPeerFreeMemory, EapHostPeerGetMethods, EapHostPeerInitialize,
};
use windows::core::GUID;

/// Both tests share the one process-global method registration, so serialize
/// them even under cargo's parallel test runner.
static REG_LOCK: Mutex<()> = Mutex::new(());

fn dll_path() -> String {
    std::env::var("USG_EAPHOST_DLL").unwrap_or_else(|_| {
        format!(
            "{}\\..\\..\\target\\debug\\eaphost.dll",
            env!("CARGO_MANIFEST_DIR")
        )
    })
}

#[test]
#[ignore = "elevated + real EAPHost: registers our method and checks enumeration"]
fn real_eaphost_enumerates_registered_method() {
    let _serialize = REG_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    register(&dll_path()).expect("register in HKLM (needs elevation)");

    // SAFETY: standard EapHostPeer host-API calls; the method array is owned by
    // EAPHost and freed with EapHostPeerFreeMemory.
    let found = unsafe {
        assert_eq!(EapHostPeerInitialize(), 0, "EapHostPeerInitialize");
        let mut arr = EAP_METHOD_INFO_ARRAY::default();
        let mut err: *mut EAP_ERROR = core::ptr::null_mut();
        assert_eq!(
            EapHostPeerGetMethods(&raw mut arr, &raw mut err),
            0,
            "EapHostPeerGetMethods"
        );
        let methods = core::slice::from_raw_parts(arr.pEapMethods, arr.dwNumberOfMethods as usize);
        let found = methods.iter().any(|m| {
            m.eaptype.eapType.r#type == USG_TYPE_ID as u8 && m.eaptype.dwAuthorId == USG_AUTHOR_ID
        });
        EapHostPeerFreeMemory(arr.pEapMethods.cast());
        found
    };

    let _ = unregister();
    assert!(
        found,
        "real EAPHost must enumerate our method (author {USG_AUTHOR_ID}, type {USG_TYPE_ID})"
    );
    eprintln!(
        "real EAPHost enumerated our registered TEAP method — registration validated against the live service"
    );
}

/// The real `EAPHost` service loads our DLL and drives `EapPeerInitialize` (FIPS
/// gate) + `EapPeerBeginSession` (config blob -> machine CNG cert -> driver),
/// returning a live session handle. Machine session so the service (Local System)
/// finds the cert in `Local Machine\My`. Empty trust anchors are fine: a session
/// builds before any server cert is verified.
#[test]
#[ignore = "elevated + real EAPHost + FIPS + machine cert (USG_CNG_TEST_SUBJECT) at a service-loadable DLL"]
fn real_eaphost_loads_and_begins_session() {
    let _serialize = REG_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let subject = std::env::var("USG_CNG_TEST_SUBJECT").expect("USG_CNG_TEST_SUBJECT");
    register(&dll_path()).expect("register in HKLM");

    let blob = SessionConfigBlob {
        machine: true,
        server_name: "teap.test.local".to_string(),
        mat_vendor_id: 0x0000_9999,
        max_fragment: 64 * 1024,
        selector_subject: subject,
        roots: vec![],
        mat: None,
    }
    .to_bytes();

    // SAFETY: EapHostPeer host-API calls per the EAPHost contract.
    let session_id = unsafe {
        assert_eq!(EapHostPeerInitialize(), 0, "EapHostPeerInitialize");
        let eap_type = EAP_METHOD_TYPE {
            eapType: EAP_TYPE {
                r#type: USG_TYPE_ID as u8,
                dwVendorId: 0,
                dwVendorType: 0,
            },
            dwAuthorId: USG_AUTHOR_ID,
        };
        let cid = GUID::zeroed();
        let mut session_id = 0u32;
        let mut err: *mut EAP_ERROR = core::ptr::null_mut();
        let rc = EapHostPeerBeginSession(
            0,
            eap_type,
            core::ptr::null(),
            HANDLE::default(),
            blob.len() as u32,
            blob.as_ptr(),
            0,
            core::ptr::null(),
            4096,
            &raw const cid,
            None,
            core::ptr::null_mut(),
            &raw mut session_id,
            &raw mut err,
        );
        assert_eq!(
            rc, 0,
            "EapHostPeerBeginSession: real EAPHost loads our DLL, runs the FIPS gate + BeginSession"
        );
        let _ = EapHostPeerEndSession(session_id, &raw mut err);
        session_id
    };

    let _ = unregister();
    assert_ne!(session_id, 0, "real EAPHost returned a live session handle");
    eprintln!(
        "real Windows EAPHost loaded our DLL and drove EapPeerInitialize(FIPS) + EapPeerBeginSession (CNG machine cert) — real-host load/begin validated"
    );
}
