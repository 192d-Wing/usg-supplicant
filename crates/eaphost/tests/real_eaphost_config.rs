//! Drive the **real** Windows `EAPHost` host-API config path end to end: author an
//! `EapHostConfig` profile naming our method and embedding our config, convert it
//! with `EapHostPeerConfigXml2Blob` (which loads our DLL and calls our
//! `EapPeerConfigXml2Blob`), then start a live session with the resulting
//! connection blob.
//!
//! This proves the connection-profile pipeline (§4.1 step 4): the host config API
//! recognizes our registered method, round-trips our config through our config
//! DLL, and `EapHostPeerBeginSession` accepts the EAPHost-format blob (running our
//! FIPS gate + `EapPeerBeginSession` -> CNG machine cert -> driver).
//!
//! NOTE: the subsequent packet relay is gated on the outer EAP **identity**. The
//! supplicant call sequence forms the EAP-Response/Identity from the user data
//! passed to `BeginSession`; a certificate method that pulls its cert from the
//! store passes none, and `EAPHost` does not source the outer identity from our
//! `EapPeerGetIdentity` (verified: it is never called on this path), so the
//! in-session Identity round returns `EAP_E_EAPHOST_IDENTITY_UNKNOWN`. Producing
//! that user blob is the remaining piece, so this test stops at a live session.
//!
//! `#[ignore]`d (needs admin + FIPS + a service-loadable DLL + a machine cert):
//! ```text
//! cargo build -p eaphost
//! copy target\debug\eaphost.dll C:\Windows\System32\usg-eaphost-testN.dll
//! USG_EAPHOST_DLL=...\usg-eaphost-testN.dll USG_CNG_TEST_SUBJECT=... \
//!   cargo test -p eaphost --test real_eaphost_config -- --ignored --nocapture
//! ```
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
use windows::Win32::Data::Xml::MsXml::{DOMDocument60, IXMLDOMDocument2, IXMLDOMNode};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::ExtensibleAuthenticationProtocol::{
    EAP_ERROR, EAP_METHOD_TYPE, EAP_TYPE, EapHostPeerBeginSession, EapHostPeerConfigXml2Blob,
    EapHostPeerEndSession, EapHostPeerFreeMemory, EapHostPeerInitialize,
};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
    CoUninitialize,
};
use windows::core::{BSTR, GUID, Interface};

/// Serialize this binary's tests, which share the one HKLM method registration.
/// This lock only covers *this* test binary; the `real_eaphost` binary registers
/// the same author/type key, so run these `#[ignore]`d suites one `--test` binary
/// at a time, not via a blanket `--ignored` across binaries.
static REG_LOCK: Mutex<()> = Mutex::new(());

fn dll_path() -> String {
    std::env::var("USG_EAPHOST_DLL").unwrap_or_else(|_| {
        format!(
            "{}\\..\\..\\target\\debug\\eaphost.dll",
            env!("CARGO_MANIFEST_DIR")
        )
    })
}

fn usg_eap_method_type() -> EAP_METHOD_TYPE {
    EAP_METHOD_TYPE {
        eapType: EAP_TYPE {
            r#type: USG_TYPE_ID as u8,
            dwVendorId: 0,
            dwVendorType: 0,
        },
        dwAuthorId: USG_AUTHOR_ID,
    }
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut s = String::new();
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Author the `EapHostConfig` profile XML naming our method and embedding our
/// connection blob (hex) in `<Config>`. `EAPHost` parses `<EapMethod>` to locate
/// us and hands the `<Config>` subtree to our `EapPeerConfigXml2Blob`.
fn eaphost_config_xml(blob: &[u8]) -> String {
    const COMMON: &str = "http://www.microsoft.com/provisioning/EapCommon";
    format!(
        "<EapHostConfig xmlns=\"http://www.microsoft.com/provisioning/EapHostConfig\">\
           <EapMethod>\
             <Type xmlns=\"{COMMON}\">{USG_TYPE_ID}</Type>\
             <VendorId xmlns=\"{COMMON}\">0</VendorId>\
             <VendorType xmlns=\"{COMMON}\">0</VendorType>\
             <AuthorId xmlns=\"{COMMON}\">{USG_AUTHOR_ID}</AuthorId>\
           </EapMethod>\
           <Config><UsgTeapConfigBlob>{}</UsgTeapConfigBlob></Config>\
         </EapHostConfig>",
        hex(blob)
    )
}

/// Parse `xml` into an MSXML document node.
///
/// # Safety
/// COM must be initialized on this thread.
unsafe fn xml_node(xml: &str) -> Result<IXMLDOMNode, String> {
    unsafe {
        let doc: IXMLDOMDocument2 = CoCreateInstance(&DOMDocument60, None, CLSCTX_INPROC_SERVER)
            .map_err(|e| format!("CoCreateInstance(DOMDocument60): {e}"))?;
        if !doc
            .loadXML(&BSTR::from(xml))
            .map_err(|e| format!("loadXML: {e}"))?
            .as_bool()
        {
            return Err("loadXML rejected the EapHostConfig XML".to_string());
        }
        doc.cast::<IXMLDOMNode>()
            .map_err(|e| format!("cast to IXMLDOMNode: {e}"))
    }
}

/// Convert the `EapHostConfig` XML into the `EAPHost` connection blob via
/// `EapHostPeerConfigXml2Blob` (which drives our `EapPeerConfigXml2Blob`).
/// Returns `(connection_blob, method_type)`.
///
/// # Safety
/// COM initialized; the returned blob is EAPHost-owned and freed here.
unsafe fn host_config_to_blob(xml: &str) -> Result<(Vec<u8>, EAP_METHOD_TYPE), String> {
    let node = unsafe { xml_node(xml) }?;
    let mut cb = 0u32;
    let mut p: *mut u8 = core::ptr::null_mut();
    let mut method = EAP_METHOD_TYPE::default();
    let mut err: *mut EAP_ERROR = core::ptr::null_mut();
    let rc = unsafe {
        EapHostPeerConfigXml2Blob(
            0,
            &node,
            &raw mut cb,
            &raw mut p,
            &raw mut method,
            &raw mut err,
        )
    };
    if rc != 0 {
        return Err(format!("EapHostPeerConfigXml2Blob: 0x{rc:08x}"));
    }
    if p.is_null() || cb == 0 {
        return Err("EapHostPeerConfigXml2Blob returned an empty blob".to_string());
    }
    let blob = unsafe { core::slice::from_raw_parts(p, cb as usize) }.to_vec();
    unsafe { EapHostPeerFreeMemory(p.cast()) };
    Ok((blob, method))
}

/// The host config pipeline + live session, returning the connection-blob length
/// and the begun session id. Always ends the session before returning.
fn run_profile_pipeline(inner_blob: &[u8]) -> Result<(usize, u32), String> {
    let xml = eaphost_config_xml(inner_blob);
    // SAFETY: COM is initialized for this thread by the caller.
    let (conn_blob, method) = unsafe { host_config_to_blob(&xml) }?;
    if method.dwAuthorId != USG_AUTHOR_ID || u32::from(method.eapType.r#type) != USG_TYPE_ID {
        return Err(format!(
            "EapHostPeerConfigXml2Blob returned method author {} type {} (expected {USG_AUTHOR_ID}/{USG_TYPE_ID})",
            method.dwAuthorId, method.eapType.r#type
        ));
    }

    // SAFETY: EapHostPeer host-API calls; the session is always ended below.
    unsafe {
        if EapHostPeerInitialize() != 0 {
            return Err("EapHostPeerInitialize".to_string());
        }
        let cid = GUID::zeroed();
        let mut session_id = 0u32;
        let mut err: *mut EAP_ERROR = core::ptr::null_mut();
        let rc = EapHostPeerBeginSession(
            0,
            usg_eap_method_type(),
            core::ptr::null(),
            HANDLE::default(),
            conn_blob.len() as u32,
            conn_blob.as_ptr(),
            0,
            core::ptr::null(),
            4096,
            &raw const cid,
            None,
            core::ptr::null_mut(),
            &raw mut session_id,
            &raw mut err,
        );
        if rc != 0 {
            return Err(format!("EapHostPeerBeginSession: 0x{rc:08x}"));
        }
        let _ = EapHostPeerEndSession(session_id, &raw mut err);
        Ok((conn_blob.len(), session_id))
    }
}

#[test]
#[ignore = "elevated + real EAPHost + FIPS + machine cert (USG_CNG_TEST_SUBJECT)"]
fn real_eaphost_config_profile_begins_session() {
    let _serialize = REG_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let subject = std::env::var("USG_CNG_TEST_SUBJECT").expect("USG_CNG_TEST_SUBJECT");

    let inner_blob = SessionConfigBlob {
        machine: true,
        server_name: "teap.test.local".to_string(),
        mat_vendor_id: 0x0000_9999,
        max_fragment: 64 * 1024,
        selector_subject: subject,
        roots: vec![],
        mat: None,
    }
    .to_bytes();

    // SAFETY: COM init for MSXML; only balanced when init succeeded.
    let co_init = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
    register(&dll_path()).expect("register in HKLM");
    let outcome = run_profile_pipeline(&inner_blob);
    let _ = unregister();
    if co_init.is_ok() {
        // SAFETY: balances the successful CoInitializeEx above.
        unsafe { CoUninitialize() };
    }

    let (blob_len, session_id) =
        outcome.unwrap_or_else(|e| panic!("real EAPHost config-profile pipeline failed: {e}"));
    assert_ne!(session_id, 0, "real EAPHost returned a live session handle");
    eprintln!(
        "real Windows EAPHost converted our EapHostConfig profile to a {blob_len}-byte connection blob (our config DLL was driven) and began session {session_id} — host-config pipeline validated"
    );
}
