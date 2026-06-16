//! Self-hosted DLL-driven session start: load `eaphost.dll`, hand
//! `EapPeerBeginSession` a real config blob, and drive
//! `ProcessRequestPacket(TEAP-Start)` -> `GetResponsePacket` through the C ABI —
//! getting a real `ClientHello` out, signed by a real CNG credential. We play
//! `dot3svc`; no `dot3svc`/admin/network.
//!
//! `#[ignore]`d (needs the cdylib built + a provisioned user client-auth cert):
//! provision a unique-subject non-exportable cert in `CurrentUser\My`, then
//! `USG_CNG_TEST_SUBJECT=... cargo build -p eaphost &&
//!  cargo test -p eaphost --test peer_session_dll -- --ignored --nocapture`.
#![cfg(windows)]
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used,
    clippy::cast_possible_truncation
)]

use core::ffi::c_void;

use eaphost::config::SessionConfigBlob;
use teap::eap::{EapCode, EapPacket};
use teap::outer::{TEAP_EAP_TYPE, TeapOuter};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::ExtensibleAuthenticationProtocol::{
    EAP_ERROR, EAP_PEER_METHOD_ROUTINES, EAP_TYPE, EapPeerMethodOutput,
    EapPeerMethodResponseActionSend,
};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::core::{PCWSTR, s};

type GetInfoFn = unsafe extern "system" fn(
    *mut EAP_TYPE,
    *mut EAP_PEER_METHOD_ROUTINES,
    *mut *mut EAP_ERROR,
) -> u32;
type BeginSessionFn = unsafe extern "system" fn(
    u32,
    *const c_void,
    HANDLE,
    u32,
    *const u8,
    u32,
    *const u8,
    u32,
    *mut *mut c_void,
    *mut *mut EAP_ERROR,
) -> u32;
type ProcessFn = unsafe extern "system" fn(
    *const c_void,
    u32,
    *const u8,
    *mut EapPeerMethodOutput,
    *mut *mut EAP_ERROR,
) -> u32;
type GetResponseFn =
    unsafe extern "system" fn(*const c_void, *mut u32, *mut u8, *mut *mut EAP_ERROR) -> u32;
type EndSessionFn = unsafe extern "system" fn(*const c_void, *mut *mut EAP_ERROR) -> u32;

fn dll_path() -> String {
    std::env::var("USG_EAPHOST_DLL").unwrap_or_else(|_| {
        format!(
            "{}/../../target/debug/eaphost.dll",
            env!("CARGO_MANIFEST_DIR")
        )
    })
}

/// The opening EAP-Request/TEAP-Start, encoded as raw EAP packet bytes.
fn teap_start() -> Vec<u8> {
    let start = TeapOuter {
        more_fragments: false,
        start: true,
        version: 1,
        tls_message_length: None,
        data: vec![],
    };
    EapPacket {
        code: EapCode::Request,
        id: 1,
        type_: Some(TEAP_EAP_TYPE),
        data: start.build(),
    }
    .encode()
    .unwrap()
}

#[test]
#[ignore = "needs the cdylib built + a provisioned cert; set USG_CNG_TEST_SUBJECT"]
fn dll_begins_session_and_emits_client_hello() {
    // On a non-FIPS host the FIPS gate trips before cert selection, so a
    // placeholder subject is fine; a FIPS host needs the real provisioned cert.
    let subject =
        std::env::var("USG_CNG_TEST_SUBJECT").unwrap_or_else(|_| "USG-DLL-TEST".to_string());
    let blob = SessionConfigBlob {
        machine: false, // user session -> Current User\My, no admin
        server_name: "teap.test.local".to_string(),
        mat_vendor_id: 0x0000_9999,
        max_fragment: 1024,
        selector_subject: subject,
        roots: vec![], // ClientHello does not verify the server cert
        mat: None,
    }
    .to_bytes();

    let path: Vec<u16> = dll_path()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: load our DLL and call the routine table with ABI-correct signatures
    // (Windows SDK eapmethodpeerapis.h), playing the role of EAPHost.
    unsafe {
        let lib = LoadLibraryW(PCWSTR(path.as_ptr())).expect("LoadLibrary eaphost.dll");
        let get_info: GetInfoFn = core::mem::transmute(
            GetProcAddress(lib, s!("EapPeerGetInfo")).expect("EapPeerGetInfo"),
        );

        let mut routines = EAP_PEER_METHOD_ROUTINES::default();
        let mut err: *mut EAP_ERROR = core::ptr::null_mut();
        assert_eq!(
            get_info(core::ptr::null_mut(), &raw mut routines, &raw mut err),
            0
        );

        let begin: BeginSessionFn = core::mem::transmute(routines.EapPeerBeginSession);
        let process: ProcessFn = core::mem::transmute(routines.EapPeerProcessRequestPacket);
        let get_response: GetResponseFn = core::mem::transmute(routines.EapPeerGetResponsePacket);
        let end_session: EndSessionFn = core::mem::transmute(routines.EapPeerEndSession);

        // BeginSession: parse the blob, select the CNG cert, build the driver.
        let mut handle: *mut c_void = core::ptr::null_mut();
        let rc = begin(
            0,
            core::ptr::null(),
            HANDLE::default(),
            blob.len() as u32,
            blob.as_ptr(),
            0,
            core::ptr::null(),
            1500,
            &raw mut handle,
            &raw mut err,
        );
        // BeginSession enforces the per-session OS FIPS gate. On a non-FIPS host
        // (this dev box) it MUST fail closed; the full ClientHello flow below only
        // runs on a FIPS-mode host.
        if !matches!(eaphost::os_fips::fips_policy_enabled(), Ok(true)) {
            assert_ne!(rc, 0, "BeginSession must fail closed when OS FIPS is off");
            eprintln!(
                "non-FIPS host: DLL BeginSession failed closed at the FIPS gate — OK (full flow needs FIPS mode)"
            );
            let _ = lib;
            return;
        }
        assert_eq!(rc, 0, "BeginSession should build the driver");
        assert!(!handle.is_null(), "a session handle was returned");

        // ProcessRequestPacket(TEAP-Start) -> the method wants to send a response.
        let req = teap_start();
        let mut output = EapPeerMethodOutput::default();
        let rc = process(
            handle,
            req.len() as u32,
            req.as_ptr(),
            &raw mut output,
            &raw mut err,
        );
        assert_eq!(rc, 0, "ProcessRequestPacket");
        assert_eq!(
            output.action, EapPeerMethodResponseActionSend,
            "method should send the ClientHello"
        );

        // GetResponsePacket -> the ClientHello EAP response bytes.
        let mut buf = vec![0u8; 4096];
        let mut cb = buf.len() as u32;
        let rc = get_response(handle, &raw mut cb, buf.as_mut_ptr(), &raw mut err);
        assert_eq!(rc, 0, "GetResponsePacket");
        assert!(cb > 4, "a non-empty EAP response was produced");
        buf.truncate(cb as usize);
        let resp = EapPacket::decode(&buf).expect("valid EAP response");
        assert_eq!(resp.code, EapCode::Response);
        assert_eq!(resp.type_, Some(TEAP_EAP_TYPE));

        assert_eq!(end_session(handle, &raw mut err), 0, "EndSession");
        let _ = lib;
    }

    eprintln!(
        "DLL drove BeginSession (real CNG cert) -> ProcessRequestPacket -> GetResponsePacket = ClientHello — keystone OK"
    );
}
