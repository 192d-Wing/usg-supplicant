//! The capstone: a **full** TEAP authentication driven end-to-end through the
//! peer DLL on this machine. We load `eaphost.dll`, `BeginSession` with a real
//! config blob (selecting a provisioned CNG cert), then shuttle every EAP packet
//! through `ProcessRequestPacket`/`GetResponsePacket` against the shared rustls
//! TEAP server until `GetResult` reports success.
//!
//! Requires OS FIPS mode (the per-session gate) + a provisioned user cert. Run:
//! ```text
//! # provision a CNG cert, export its DER, then:
//! USG_CNG_TEST_SUBJECT=... USG_CNG_TEST_CERT_DER=...\cert.der \
//!   cargo build -p eaphost && \
//!   cargo test -p eaphost --test peer_full_session_dll -- --ignored --nocapture
//! ```
#![cfg(windows)]
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used,
    clippy::cast_possible_truncation
)]

use core::ffi::c_void;

use eaphost::config::SessionConfigBlob;
use rustls::pki_types::CertificateDer;
use teap::session::Identity;
use teap_test_harness::{SERVER_NAME, TeapServer, gen_id};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::ExtensibleAuthenticationProtocol::{
    EAP_ERROR, EAP_PEER_METHOD_ROUTINES, EAP_TYPE, EapPeerMethodOutput,
    EapPeerMethodResponseActionResult, EapPeerMethodResponseActionSend, EapPeerMethodResult,
    EapPeerMethodResultReason, EapPeerMethodResultSuccess,
};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::core::{PCWSTR, s};

type GetInfoFn = unsafe extern "system" fn(
    *mut EAP_TYPE,
    *mut EAP_PEER_METHOD_ROUTINES,
    *mut *mut EAP_ERROR,
) -> u32;
type BeginFn = unsafe extern "system" fn(
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
type GetRespFn =
    unsafe extern "system" fn(*const c_void, *mut u32, *mut u8, *mut *mut EAP_ERROR) -> u32;
type GetResultFn = unsafe extern "system" fn(
    *const c_void,
    EapPeerMethodResultReason,
    *mut EapPeerMethodResult,
    *mut *mut EAP_ERROR,
) -> u32;
type EndFn = unsafe extern "system" fn(*const c_void, *mut *mut EAP_ERROR) -> u32;

fn dll_path() -> String {
    std::env::var("USG_EAPHOST_DLL").unwrap_or_else(|_| {
        format!(
            "{}/../../target/debug/eaphost.dll",
            env!("CARGO_MANIFEST_DIR")
        )
    })
}

#[test]
#[ignore = "needs OS FIPS mode + a provisioned cert (USG_CNG_TEST_SUBJECT, USG_CNG_TEST_CERT_DER)"]
fn dll_authenticates_full_teap_session() {
    let subject = std::env::var("USG_CNG_TEST_SUBJECT").expect("set USG_CNG_TEST_SUBJECT");
    let cert_path = std::env::var("USG_CNG_TEST_CERT_DER").expect("set USG_CNG_TEST_CERT_DER");
    let client_cert = CertificateDer::from(std::fs::read(cert_path).expect("read client cert DER"));

    // The TEAP server: presents its own cert, trusts the client (CNG) cert for the
    // inner EAP-TLS, expects a User identity.
    let server_id = gen_id(SERVER_NAME);
    let mut server = TeapServer::new(&server_id, &client_cert, Identity::User);

    // Config blob: user session, trust the server cert, select the CNG cert.
    let blob = SessionConfigBlob {
        machine: false,
        server_name: SERVER_NAME.to_string(),
        // 64 KiB: no TEAP fragmentation in this harness (fragmentation/ACK is
        // covered by teap::outer's own tests). Real dot3svc uses a ~1500 MTU.
        mat_vendor_id: 0x0000_9999,
        max_fragment: 64 * 1024,
        selector_subject: subject,
        roots: vec![server_id.cert.as_ref().to_vec()],
        mat: None,
    }
    .to_bytes();

    let path: Vec<u16> = dll_path()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: drive the DLL routine table per the EAPHost peer ABI.
    unsafe {
        let lib = LoadLibraryW(PCWSTR(path.as_ptr())).expect("LoadLibrary");
        let get_info: GetInfoFn = core::mem::transmute(
            GetProcAddress(lib, s!("EapPeerGetInfo")).expect("EapPeerGetInfo"),
        );
        let mut r = EAP_PEER_METHOD_ROUTINES::default();
        let mut err: *mut EAP_ERROR = core::ptr::null_mut();
        assert_eq!(get_info(core::ptr::null_mut(), &raw mut r, &raw mut err), 0);

        let begin: BeginFn = core::mem::transmute(r.EapPeerBeginSession);
        let process: ProcessFn = core::mem::transmute(r.EapPeerProcessRequestPacket);
        let get_resp: GetRespFn = core::mem::transmute(r.EapPeerGetResponsePacket);
        let get_result: GetResultFn = core::mem::transmute(r.EapPeerGetResult);
        let end: EndFn = core::mem::transmute(r.EapPeerEndSession);

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
        assert_eq!(rc, 0, "BeginSession (needs OS FIPS mode)");

        // Shuttle EAP packets: server -> ProcessRequestPacket -> GetResponsePacket
        // -> server, until the method reports a terminal result.
        let mut inbound = server.start();
        let mut authenticated = false;
        for _ in 0..64 {
            let mut output = EapPeerMethodOutput::default();
            assert_eq!(
                process(
                    handle,
                    inbound.len() as u32,
                    inbound.as_ptr(),
                    &raw mut output,
                    &raw mut err,
                ),
                0,
                "ProcessRequestPacket"
            );
            if output.action == EapPeerMethodResponseActionResult {
                let mut result = EapPeerMethodResult::default();
                assert_eq!(
                    get_result(
                        handle,
                        EapPeerMethodResultSuccess,
                        &raw mut result,
                        &raw mut err
                    ),
                    0,
                    "GetResult"
                );
                authenticated = result.fIsSuccess.as_bool();
                break;
            }
            assert_eq!(output.action, EapPeerMethodResponseActionSend);

            let mut buf = vec![0u8; 16384];
            let mut cb = buf.len() as u32;
            assert_eq!(
                get_resp(handle, &raw mut cb, buf.as_mut_ptr(), &raw mut err),
                0,
                "GetResponsePacket"
            );
            buf.truncate(cb as usize);
            inbound = server.handle(&buf);
        }

        assert!(authenticated, "DLL must reach GetResult=success");
        assert!(server.is_done(), "server reached EAP-Success");
        assert_eq!(end(handle, &raw mut err), 0, "EndSession");
        let _ = lib;
    }

    eprintln!(
        "DLL drove a FULL TEAP session to GetResult=success (real CNG cert, OS FIPS mode) — capstone OK"
    );
}
