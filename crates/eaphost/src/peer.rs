//! The `EAPHost` peer-method DLL exports (C ABI), matching the Windows SDK
//! `eapmethodpeerapis.h` / `EAP_PEER_METHOD_ROUTINES`.
//!
//! `dot3svc` / `EapHost` loads `eaphost.dll`, calls the one exported entry
//! [`EapPeerGetInfo`] to obtain the routine table, then drives the method through
//! those function pointers. Each routine marshals a C call into the safe
//! orchestration core ([`crate::session_registry`] + [`crate::session`] +
//! [`crate::builder`]) and fails closed.
//!
//! `EAP_SESSION_HANDLE` is `VOID*` (opaque); we carry the registry's `u64`
//! handle in it — `EAPHost` never dereferences it.
//!
//! Validation: a self-hosted `LoadLibrary` test drives `EapPeerGetInfo` +
//! `EapPeerInitialize` on this machine (no `dot3svc`, no admin). Full session
//! marshaling additionally needs the config-blob format (§4.1 step 4) and, for
//! the real host, registration + an on-device `dot3svc` run.
#![allow(non_snake_case)]
// FFI glue: pointer<->integer handle conversions and fn-pointer table fills are
// inherent to the C ABI; the lint baseline's cast denials don't fit here.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::not_unsafe_ptr_arg_deref
)]

use core::ffi::c_void;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock, PoisonError};

use windows::Win32::Data::Xml::MsXml::{DOMDocument60, IXMLDOMDocument2};
use windows::Win32::Foundation::{ERROR_NOT_SUPPORTED, ERROR_SUCCESS, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::ExtensibleAuthenticationProtocol::{
    EAP_ERROR, EAP_METHOD_PROPERTY_ARRAY, EAP_METHOD_TYPE, EAP_PEER_METHOD_ROUTINES, EAP_TYPE,
    EapCredential, EapPacket, EapPeerMethodOutput, EapPeerMethodResponseActionResult,
    EapPeerMethodResponseActionSend, EapPeerMethodResult, EapPeerMethodResultReason,
};
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance};
use windows::Win32::System::Memory::{LMEM_FIXED, LMEM_ZEROINIT, LocalAlloc};
use windows::core::{BSTR, Interface};

use creds::selection::CertSelector;
use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use supplicant::driver::DriverConfig;
use teap::session::Identity;

use crate::builder::build_driver;
use crate::config::SessionConfigBlob;
use crate::os_fips::assert_fips_policy;
use crate::session::{AuthResult, PeerSession, ProcessAction, SessionKind};
use crate::session_registry::{ResponseFetch, SessionRegistry};

/// EAP type 55 (TEAP). A distinct **Author ID** in the registry (registration)
/// keeps us from colliding with the in-box Windows TEAP method.
const EAP_TYPE_TEAP: u8 = 55;

/// The EAP type this method advertises (returned via `EapPeerGetInfo`).
static EAP_TYPE_VALUE: EAP_TYPE = EAP_TYPE {
    r#type: EAP_TYPE_TEAP,
    dwVendorId: 0,
    dwVendorType: 0,
};

/// `ERROR_NOT_SUPPORTED` as a bare `u32` return code.
const NOT_SUPPORTED: u32 = ERROR_NOT_SUPPORTED.0;
/// Generic failure for a routine that cannot complete (fail closed).
const E_FAIL: u32 = 0x8000_4005; // E_FAIL-ish; EAPHost only needs nonzero.

/// The EAP-Response/Identity we present in the outer exchange. TEAP protects the
/// real identity (the inner EAP-TLS client certificate) inside the TLS tunnel, so
/// the cleartext outer identity is deliberately anonymous.
const ANONYMOUS_IDENTITY: &str = "anonymous";

/// The process-global session table the routines marshal into.
fn registry() -> &'static SessionRegistry<supplicant::driver::TeapDriver> {
    static REG: OnceLock<SessionRegistry<supplicant::driver::TeapDriver>> = OnceLock::new();
    REG.get_or_init(SessionRegistry::new)
}

// --- Status publishing for the user-session tray (usg-status) ---------------
// The method runs as Local System; it publishes a coarse auth status (state,
// identity, cert subject, server) to a ProgramData file the tray polls. Failures
// to write are ignored — status is best-effort and never affects authentication.

/// Per-handle metadata the status snapshots need but `PeerSession` doesn't hold.
struct StatusMeta {
    identity: usg_status::Identity,
    cert_subject: String,
    cert_thumbprint: String,
    server_name: String,
}

/// A credential's published identity: subject + uppercase-hex SHA-256 thumbprint.
#[derive(Default, Clone)]
struct CertInfo {
    subject: String,
    thumbprint: String,
}

fn status_meta() -> &'static Mutex<HashMap<u64, StatusMeta>> {
    static M: OnceLock<Mutex<HashMap<u64, StatusMeta>>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Last-known `(machine, user)` credentials so both survive across the one-at-a-time
/// machine/user sessions. The published status file is the cross-process channel, but
/// a transient read miss (the file is briefly locked mid-rename) must not wipe the
/// other identity's cert, so we also remember it in-process.
fn last_certs() -> &'static Mutex<(CertInfo, CertInfo)> {
    static C: OnceLock<Mutex<(CertInfo, CertInfo)>> = OnceLock::new();
    C.get_or_init(|| Mutex::new((CertInfo::default(), CertInfo::default())))
}

/// Write a status snapshot for `handle` (no-op if the handle has no metadata).
fn publish_status(handle: u64, state: usg_status::AuthState, detail: &str) {
    let map = status_meta().lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(meta) = map.get(&handle) {
        // Preserve the *other* identity's credential so the window can show both.
        // Start from the in-process memory, then refresh from the published file's
        // non-empty values (covers a different process publishing) — a transient read
        // miss or a momentarily-empty field then can't wipe a cert we already know.
        let mut certs = last_certs().lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(prev) = usg_status::read_status() {
            if !prev.machine_cert.is_empty() {
                certs.0.subject = prev.machine_cert;
            }
            if !prev.machine_thumbprint.is_empty() {
                certs.0.thumbprint = prev.machine_thumbprint;
            }
            if !prev.user_cert.is_empty() {
                certs.1.subject = prev.user_cert;
            }
            if !prev.user_thumbprint.is_empty() {
                certs.1.thumbprint = prev.user_thumbprint;
            }
        }
        let active = CertInfo {
            subject: meta.cert_subject.clone(),
            thumbprint: meta.cert_thumbprint.clone(),
        };
        match meta.identity {
            usg_status::Identity::Machine => certs.0 = active,
            usg_status::Identity::User => certs.1 = active,
        }
        let _ = usg_status::write_status(&usg_status::AuthStatus {
            state,
            identity: meta.identity,
            cert_subject: meta.cert_subject.clone(),
            machine_cert: certs.0.subject.clone(),
            user_cert: certs.1.subject.clone(),
            machine_thumbprint: certs.0.thumbprint.clone(),
            user_thumbprint: certs.1.thumbprint.clone(),
            server_name: meta.server_name.clone(),
            detail: detail.to_string(),
            updated_unix: usg_status::unix_now(),
        });
    }
}

/// Map a terminal [`AuthResult`] to a tray status + detail string.
fn terminal_status(result: Option<&AuthResult>) -> (usg_status::AuthState, String) {
    match result {
        Some(AuthResult::Success { .. }) => (usg_status::AuthState::Authenticated, String::new()),
        Some(AuthResult::Failure(reason)) => (usg_status::AuthState::Failed, format!("{reason:?}")),
        None => (usg_status::AuthState::Failed, "no result".to_string()),
    }
}

/// Carry a registry handle in an `EAP_SESSION_HANDLE` (`VOID*`), and back.
fn handle_to_ptr(handle: u64) -> *mut c_void {
    handle as usize as *mut c_void
}
fn ptr_to_handle(ptr: *const c_void) -> u64 {
    ptr as usize as u64
}

/// Clear an `_Outptr_ EAP_ERROR**`: we report failures via the return code and
/// leave no `EAP_ERROR` to free (`EAPHost` tolerates a null error object).
unsafe fn clear_error(pp_eap_error: *mut *mut EAP_ERROR) {
    if !pp_eap_error.is_null() {
        unsafe { *pp_eap_error = core::ptr::null_mut() };
    }
}

/// The one exported symbol: `EAPHost` calls it to obtain the routine table.
///
/// # Safety
/// `p_eap_info` must be a valid, writable `EAP_PEER_METHOD_ROUTINES`. Called by
/// `EAPHost` per its peer-method contract.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn EapPeerGetInfo(
    p_eap_type: *mut EAP_TYPE,
    p_eap_info: *mut EAP_PEER_METHOD_ROUTINES,
    pp_eap_error: *mut *mut EAP_ERROR,
) -> u32 {
    unsafe { clear_error(pp_eap_error) };
    if p_eap_info.is_null() {
        return E_FAIL;
    }
    // SAFETY: p_eap_info is the caller's writable routine table; p_eap_type, if
    // provided, is the type EAPHost is querying (we accept TEAP only).
    unsafe {
        if !p_eap_type.is_null() && (*p_eap_type).r#type != EAP_TYPE_TEAP {
            return NOT_SUPPORTED;
        }
        let routines = EAP_PEER_METHOD_ROUTINES {
            dwVersion: 1,
            pEapType: core::ptr::addr_of!(EAP_TYPE_VALUE).cast_mut(),
            EapPeerInitialize: EapPeerInitialize as *const () as isize,
            EapPeerGetIdentity: EapPeerGetIdentity as *const () as isize,
            EapPeerBeginSession: EapPeerBeginSession as *const () as isize,
            EapPeerSetCredentials: EapPeerSetCredentials as *const () as isize,
            EapPeerProcessRequestPacket: EapPeerProcessRequestPacket as *const () as isize,
            EapPeerGetResponsePacket: EapPeerGetResponsePacket as *const () as isize,
            EapPeerGetResult: EapPeerGetResult as *const () as isize,
            EapPeerGetUIContext: EapPeerGetUIContext as *const () as isize,
            EapPeerSetUIContext: EapPeerSetUIContext as *const () as isize,
            EapPeerGetResponseAttributes: EapPeerGetResponseAttributes as *const () as isize,
            EapPeerSetResponseAttributes: EapPeerSetResponseAttributes as *const () as isize,
            EapPeerEndSession: EapPeerEndSession as *const () as isize,
            EapPeerShutdown: EapPeerShutdown as *const () as isize,
        };
        *p_eap_info = routines;
    }
    ERROR_SUCCESS.0
}

/// Free an `EAP_ERROR` previously returned by this method. The second
/// by-name export `EAPHost` requires (alongside `EapPeerGetInfo`). We never
/// allocate `EAP_ERROR` objects — errors are reported via the return code with
/// `*ppEapError` left null — so this is a no-op, but the symbol must exist or
/// `EAPHost` fails routine calls with `ERROR_PROC_NOT_FOUND`.
///
/// # Safety
/// FFI export called by `EAPHost`. The argument is ignored: this method never
/// allocates an `EAP_ERROR` (so `EAPHost` never has one of ours to free here).
#[unsafe(no_mangle)]
pub unsafe extern "system" fn EapPeerFreeErrorMemory(_p_eap_error: *mut EAP_ERROR) {}

// ---------------------------------------------------------------------------
// Config-method exports. EAPHost loads the configuration entry points from the
// same `PeerDllPath` DLL (there is no separate config-DLL registry value for the
// core APIs — only `PeerConfigUIPath` for the optional UI). Even a method whose
// connection data is supplied directly to `BeginSession` must export these or
// EAPHost aborts the session with `ERROR_PROC_NOT_FOUND`. We carry no extra
// properties and derive no blobs from credentials, so they report empty.
// ---------------------------------------------------------------------------

/// Report the method's connection/user properties. We declare none (our
/// connection data is the `BeginSession` config blob), so return an empty array.
///
/// # Safety
/// FFI export called by `EAPHost`. `p_method_property_array` must be a valid,
/// writable `EAP_METHOD_PROPERTY_ARRAY`; `pp_eap_error` (if non-null) a writable
/// `*mut EAP_ERROR`. All other pointers are unused.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn EapPeerGetMethodProperties(
    _dw_version: u32,
    _dw_flags: u32,
    _eap_method_type: EAP_METHOD_TYPE,
    _h_user_impersonation_token: HANDLE,
    _cb_connection_data: u32,
    _p_connection_data: *const u8,
    _cb_user_data: u32,
    _p_user_data: *const u8,
    p_method_property_array: *mut EAP_METHOD_PROPERTY_ARRAY,
    pp_eap_error: *mut *mut EAP_ERROR,
) -> u32 {
    unsafe { clear_error(pp_eap_error) };
    if p_method_property_array.is_null() {
        return E_FAIL;
    }
    // Empty, heap-free property set: zero count, null array. EAPHost reads the
    // count first and never dereferences the pointer when the count is zero.
    unsafe {
        (*p_method_property_array).dwNumberOfProperties = 0;
        (*p_method_property_array).pMethodProperty = core::ptr::null_mut();
    }
    ERROR_SUCCESS.0
}

/// Derive the connection/user blobs from a credential. We take our connection
/// data directly from the `BeginSession` config blob and read no credential
/// here, so return empty blobs (zero size, null pointers).
///
/// # Safety
/// FFI export called by `EAPHost`. The four out-params, when non-null, must be
/// writable; `pp_eap_error` (if non-null) a writable `*mut EAP_ERROR`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn EapPeerGetConfigBlobAndUserBlob(
    _dw_flags: u32,
    _eap_method_type: EAP_METHOD_TYPE,
    _eap_credential: EapCredential,
    pdw_config_blob_size: *mut u32,
    pp_config_blob: *mut *mut u8,
    pdw_user_blob_size: *mut u32,
    pp_user_blob: *mut *mut u8,
    pp_eap_error: *mut *mut EAP_ERROR,
) -> u32 {
    unsafe { clear_error(pp_eap_error) };
    unsafe {
        if !pdw_config_blob_size.is_null() {
            *pdw_config_blob_size = 0;
        }
        if !pp_config_blob.is_null() {
            *pp_config_blob = core::ptr::null_mut();
        }
        if !pdw_user_blob_size.is_null() {
            *pdw_user_blob_size = 0;
        }
        if !pp_user_blob.is_null() {
            *pp_user_blob = core::ptr::null_mut();
        }
    }
    ERROR_SUCCESS.0
}

/// Free memory previously returned by a configuration API — currently the blob
/// from `EapPeerConfigXml2Blob`. Those allocations use `LocalAlloc`, so free with
/// `LocalFree`; a null pointer is ignored.
///
/// # Safety
/// FFI export called by `EAPHost`. `p_ui_context_data` must be null or a pointer
/// this method returned from a configuration API (hence `LocalAlloc`-owned).
#[unsafe(no_mangle)]
pub unsafe extern "system" fn EapPeerFreeMemory(p_ui_context_data: *mut c_void) {
    if !p_ui_context_data.is_null() {
        // SAFETY: the only config-API memory we hand out is LocalAlloc-allocated.
        let _ = unsafe { LocalFree(Some(HLOCAL(p_ui_context_data))) };
    }
}

/// Convert our connection blob into the XML config `EAPHost` stores in a
/// connection profile (`<UsgTeapConfigBlob>HEX</…>`), returned as a fresh
/// `IXMLDOMDocument2`. This is the half the host-API `EapHostPeerConfigXml2Blob`
/// path needs so `EAPHost` can wrap our method config in a connection-data
/// structure it can parse.
///
/// # Safety
/// FFI export called by `EAPHost`. `p_config_in`/`dw_size_of_config_in` describe a
/// readable blob (or null/0); `pp_config_doc` receives an owned `IXMLDOMDocument2`
/// the caller releases; `pp_eap_error` (if non-null) is writable.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn EapPeerConfigBlob2Xml(
    _dw_flags: u32,
    _eap_method_type: EAP_METHOD_TYPE,
    p_config_in: *const u8,
    dw_size_of_config_in: u32,
    pp_config_doc: *mut *mut c_void,
    pp_eap_error: *mut *mut EAP_ERROR,
) -> u32 {
    unsafe { clear_error(pp_eap_error) };
    if pp_config_doc.is_null() {
        return E_FAIL;
    }
    unsafe { *pp_config_doc = core::ptr::null_mut() };
    let blob: &[u8] = if p_config_in.is_null() || dw_size_of_config_in == 0 {
        &[]
    } else {
        // SAFETY: caller-promised readable region of `dw_size_of_config_in` bytes.
        unsafe { core::slice::from_raw_parts(p_config_in, dw_size_of_config_in as usize) }
    };
    let xml = crate::config_xml::blob_to_xml(blob);
    match build_xml_doc(&xml) {
        Some(doc) => {
            // Transfer the COM reference to the caller.
            unsafe { *pp_config_doc = doc.into_raw() };
            ERROR_SUCCESS.0
        }
        None => E_FAIL,
    }
}

/// Build an `IXMLDOMDocument2` from an XML string via MSXML. Returns `None` on a
/// COM-creation or parse failure.
fn build_xml_doc(xml: &str) -> Option<IXMLDOMDocument2> {
    // SAFETY: standard MSXML COM creation; the BSTR outlives the `loadXML` call.
    unsafe {
        let doc: IXMLDOMDocument2 =
            CoCreateInstance(&DOMDocument60, None, CLSCTX_INPROC_SERVER).ok()?;
        if doc.loadXML(&BSTR::from(xml)).ok()?.as_bool() {
            Some(doc)
        } else {
            None
        }
    }
}

/// Convert the XML config `EAPHost` holds for our method back into our connection
/// blob (the inverse of `EapPeerConfigBlob2Xml`).
///
/// # Safety
/// FFI export called by `EAPHost`. `p_config_doc` is a borrowed `IXMLDOMDocument2`;
/// `pp_config_out`/`pdw_size_of_config_out` are writable out-params; the returned
/// blob is `LocalAlloc`-owned and freed by `EAPHost` via `EapPeerFreeMemory`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn EapPeerConfigXml2Blob(
    _dw_flags: u32,
    _eap_method_type: EAP_METHOD_TYPE,
    p_config_doc: *mut c_void,
    pp_config_out: *mut *mut u8,
    pdw_size_of_config_out: *mut u32,
    pp_eap_error: *mut *mut EAP_ERROR,
) -> u32 {
    unsafe { clear_error(pp_eap_error) };
    if pp_config_out.is_null() || pdw_size_of_config_out.is_null() {
        return E_FAIL;
    }
    unsafe {
        *pp_config_out = core::ptr::null_mut();
        *pdw_size_of_config_out = 0;
    }
    // Borrow the document without taking ownership (EAPHost owns it).
    let Some(doc) = (unsafe { IXMLDOMDocument2::from_raw_borrowed(&p_config_doc) }) else {
        return E_FAIL;
    };
    // Read our element's text. Prefer selecting `<UsgTeapConfigBlob>` by name so a
    // document that wraps our element in EAPHost's connection-data structure
    // (siblings, indentation) doesn't contaminate the hex; fall back to the whole
    // document's text content for the bare, self-emitted form.
    let query = BSTR::from(format!("//{}", crate::config_xml::BLOB_ELEMENT));
    // SAFETY: borrowed COM calls. A no-match `selectSingleNode` yields a null node
    // (guarded here), so we read `text()` from our element or, failing that, the
    // document.
    let text_result = match unsafe { doc.selectSingleNode(&query) } {
        Ok(node) if !node.as_raw().is_null() => unsafe { node.text() },
        _ => unsafe { doc.text() },
    };
    let Ok(text) = text_result else {
        return E_FAIL;
    };
    let Some(blob) = crate::config_xml::xml_text_to_blob(&text.to_string()) else {
        return E_FAIL;
    };
    let Ok(len) = u32::try_from(blob.len()) else {
        return E_FAIL;
    };
    let Some(p) = local_alloc_bytes(&blob) else {
        return E_FAIL;
    };
    unsafe {
        *pp_config_out = p;
        *pdw_size_of_config_out = len;
    }
    ERROR_SUCCESS.0
}

/// Copy `bytes` into a fresh `LocalAlloc` buffer — the allocator `EAPHost` frees
/// config-API memory with (via [`EapPeerFreeMemory`]). Returns the buffer, or
/// `None` on allocation failure.
fn local_alloc_bytes(bytes: &[u8]) -> Option<*mut u8> {
    // SAFETY: fixed allocation of exactly `bytes.len()`; we copy that many bytes.
    let h = unsafe { LocalAlloc(LMEM_FIXED, bytes.len()) }.ok()?;
    let p = h.0.cast::<u8>();
    if p.is_null() {
        return None;
    }
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len()) };
    Some(p)
}

/// Per-DLL initialization. Gates on the OS FIPS policy and fails closed when the
/// host is not in FIPS mode (DESIGN §3 — the CNG/smartcard signing half of the
/// FIPS boundary is only valid under OS FIPS mode).
extern "system" fn EapPeerInitialize(pp_eap_error: *mut *mut EAP_ERROR) -> u32 {
    unsafe { clear_error(pp_eap_error) };
    match assert_fips_policy() {
        Ok(()) => ERROR_SUCCESS.0,
        Err(_) => E_FAIL,
    }
}

extern "system" fn EapPeerShutdown(pp_eap_error: *mut *mut EAP_ERROR) -> u32 {
    unsafe { clear_error(pp_eap_error) };
    ERROR_SUCCESS.0
}

/// Begin a session: parse the connection-data config blob into the session
/// profile, select the machine/user credential, build the driver, and register
/// it — returning an opaque handle. Fails closed on a bad blob or credential.
extern "system" fn EapPeerBeginSession(
    _dw_flags: u32,
    _p_attribute_array: *const c_void,
    _h_token_impersonate_user: HANDLE,
    cb_connection_data: u32,
    p_connection_data: *const u8,
    _cb_user_data: u32,
    _p_user_data: *const u8,
    _dw_max_send_packet_size: u32,
    p_session_handle: *mut *mut c_void,
    pp_eap_error: *mut *mut EAP_ERROR,
) -> u32 {
    unsafe { clear_error(pp_eap_error) };
    if p_session_handle.is_null() || p_connection_data.is_null() {
        return E_FAIL;
    }
    // SAFETY: the caller guarantees `cb_connection_data` bytes at the pointer.
    let blob =
        unsafe { core::slice::from_raw_parts(p_connection_data, cb_connection_data as usize) };
    match begin_session(blob) {
        Some(handle) => {
            // SAFETY: `p_session_handle` is the caller's writable out-handle.
            unsafe { *p_session_handle = handle_to_ptr(handle) };
            ERROR_SUCCESS.0
        }
        None => E_FAIL,
    }
}

/// Safe core of `EapPeerBeginSession`: blob -> profile -> credential -> driver ->
/// registered session handle. `None` on any failure (fail closed).
fn begin_session(blob: &[u8]) -> Option<u64> {
    // Per-session OS FIPS gate (WINDOWS_DEV.md §4.1 step 5, DESIGN.md §3): the
    // CNG/smartcard signing half of the FIPS boundary is only valid under OS FIPS
    // mode, and the policy is read live — so re-assert it at each BeginSession,
    // not just at Initialize. Fail closed.
    assert_fips_policy().ok()?;
    let cfg = SessionConfigBlob::from_bytes(blob).ok()?;
    let (identity, kind) = if cfg.machine {
        (Identity::Machine, SessionKind::Machine)
    } else {
        (Identity::User, SessionKind::User)
    };
    // Capture status metadata before cfg fields are moved into the driver config.
    // The cert thumbprint is filled once the cert is selected in `build_driver`.
    let mut meta = StatusMeta {
        identity: if cfg.machine {
            usg_status::Identity::Machine
        } else {
            usg_status::Identity::User
        },
        cert_subject: cfg.selector_subject.clone(),
        cert_thumbprint: String::new(),
        server_name: cfg.server_name.clone(),
    };
    let mut roots = RootCertStore::empty();
    for der in cfg.roots {
        roots.add(CertificateDer::from(der)).ok()?;
    }
    let selector = CertSelector {
        require_client_auth_eku: true,
        subject_contains: Some(cfg.selector_subject),
        ..Default::default()
    };
    let driver_cfg = DriverConfig {
        identity,
        server_name: cfg.server_name,
        mat_vendor_id: cfg.mat_vendor_id,
        mat_to_present: cfg.mat,
        max_fragment: cfg.max_fragment as usize,
    };
    let (driver, thumbprint) = build_driver(driver_cfg, roots, &selector).ok()?;
    meta.cert_thumbprint = thumbprint;
    let handle = registry().begin(PeerSession::new(kind, driver));
    status_meta()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(handle, meta);
    publish_status(handle, usg_status::AuthState::Connecting, "");
    Some(handle)
}

extern "system" fn EapPeerProcessRequestPacket(
    session_handle: *const c_void,
    cb_receive_packet: u32,
    p_receive_packet: *const EapPacket,
    p_eap_output: *mut EapPeerMethodOutput,
    pp_eap_error: *mut *mut EAP_ERROR,
) -> u32 {
    unsafe { clear_error(pp_eap_error) };
    if p_receive_packet.is_null() || p_eap_output.is_null() {
        return E_FAIL;
    }
    // The EapPacket is the raw EAP packet (header + data); cbReceivePacket is its
    // total length. SAFETY: the caller guarantees the buffer for cbReceivePacket.
    let eap = unsafe {
        core::slice::from_raw_parts(p_receive_packet.cast::<u8>(), cb_receive_packet as usize)
    };
    let handle = ptr_to_handle(session_handle);
    let Some(action) = registry().process(handle, eap) else {
        return E_FAIL; // unknown handle -> fail closed
    };
    // Publish the in-progress phase for the tray: outer handshaking, or the inner
    // EAP-TLS once the tunnel is up. The terminal verdict is published by
    // `EapPeerGetResult` (always called after a Finished step), which reads the
    // result once — so we don't re-read it under a second lock here.
    if action == ProcessAction::Respond {
        let state = if registry().tunnel_established(handle) == Some(true) {
            usg_status::AuthState::InnerInProgress
        } else {
            usg_status::AuthState::Connecting
        };
        publish_status(handle, state, "");
    }
    let response_action = match action {
        ProcessAction::Respond => EapPeerMethodResponseActionSend,
        ProcessAction::Finished => EapPeerMethodResponseActionResult,
    };
    // SAFETY: p_eap_output is the caller's writable output struct.
    unsafe {
        (*p_eap_output).action = response_action;
        (*p_eap_output).fAllowNotifications = false.into();
    }
    ERROR_SUCCESS.0
}

extern "system" fn EapPeerGetResponsePacket(
    session_handle: *const c_void,
    pcb_send_packet: *mut u32,
    p_send_packet: *mut EapPacket,
    pp_eap_error: *mut *mut EAP_ERROR,
) -> u32 {
    unsafe { clear_error(pp_eap_error) };
    if pcb_send_packet.is_null() {
        return E_FAIL;
    }
    // A null output buffer is a pure size probe; model its capacity as 0 so the
    // response is reported-but-kept. Reading *pcb_send_packet is only valid once we
    // know the buffer pointer is non-null (the caller's in/out size word). Per the
    // EapPeerGetResponsePacket contract, *pcb_send_packet is the buffer's true
    // capacity — the bounds of the copy below rest on the host declaring it honestly.
    // SAFETY: pcb_send_packet is non-null (checked); it's the caller's size word.
    let avail = if p_send_packet.is_null() {
        0
    } else {
        (unsafe { *pcb_send_packet }) as usize
    };
    // Consume the buffered response ONLY if it fits; a size-probe / too-small call
    // leaves it queued for the follow-up fetch (the two-call EAPHost convention).
    match registry().fetch_response(ptr_to_handle(session_handle), avail) {
        ResponseFetch::None => E_FAIL,
        ResponseFetch::TooSmall(len) => {
            // SAFETY: pcb_send_packet is non-null (checked above).
            unsafe { *pcb_send_packet = u32::try_from(len).unwrap_or(u32::MAX) };
            E_FAIL
        }
        ResponseFetch::Taken(resp) => {
            // SAFETY: the buffer was confirmed large enough for the whole packet.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    resp.as_ptr(),
                    p_send_packet.cast::<u8>(),
                    resp.len(),
                );
                *pcb_send_packet = u32::try_from(resp.len()).unwrap_or(u32::MAX);
            }
            ERROR_SUCCESS.0
        }
    }
}

extern "system" fn EapPeerGetResult(
    session_handle: *const c_void,
    _reason: EapPeerMethodResultReason,
    p_result: *mut EapPeerMethodResult,
    pp_eap_error: *mut *mut EAP_ERROR,
) -> u32 {
    unsafe { clear_error(pp_eap_error) };
    if p_result.is_null() {
        return E_FAIL;
    }
    let handle = ptr_to_handle(session_handle);
    let result = registry().result(handle);
    let success = matches!(result, Some(AuthResult::Success { .. }));
    let (state, detail) = terminal_status(result.as_ref());
    publish_status(handle, state, &detail);
    // SAFETY: p_result is the caller's writable result struct.
    // TODO(§4.1): deliver the MSK to EAPHost via EapPeerGetResponseAttributes
    // (MS-MPPE keys) for the 802.1X port keys.
    unsafe {
        (*p_result).fIsSuccess = success.into();
        (*p_result).dwFailureReasonCode = if success { 0 } else { E_FAIL };
    }
    ERROR_SUCCESS.0
}

extern "system" fn EapPeerEndSession(
    session_handle: *const c_void,
    pp_eap_error: *mut *mut EAP_ERROR,
) -> u32 {
    unsafe { clear_error(pp_eap_error) };
    let handle = ptr_to_handle(session_handle);
    registry().end(handle);
    // Drop the status metadata; the last published snapshot (terminal verdict)
    // stays on disk for the tray to keep showing until a new session starts.
    status_meta()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&handle);
    ERROR_SUCCESS.0
}

/// Provide the outer EAP identity. `EAPHost` calls this (by name, on the
/// `PeerIdentityPath` DLL, *and* via the routine table) to build the
/// EAP-Response/Identity before the method exchange; without it the host aborts
/// with `EAP_E_EAPHOST_IDENTITY_UNKNOWN`. We present an anonymous identity, no UI,
/// and no persisted user data (our session config rides on the connection blob).
///
/// # Safety
/// FFI export called by `EAPHost`. The out-params, when non-null, must be
/// writable; `ppwsz_identity` receives a `LocalAlloc`-owned string `EAPHost` frees
/// with `LocalFree`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn EapPeerGetIdentity(
    _flags: u32,
    _cb_connection_data: u32,
    _p_connection_data: *const u8,
    _cb_user_data: u32,
    _p_user_data: *const u8,
    _h_token: HANDLE,
    pf_invoke_ui: *mut windows::core::BOOL,
    pdw_user_data_out: *mut u32,
    pp_user_data_out: *mut *mut u8,
    ppwsz_identity: *mut windows::core::PWSTR,
    pp_eap_error: *mut *mut EAP_ERROR,
) -> u32 {
    unsafe { clear_error(pp_eap_error) };
    if ppwsz_identity.is_null() {
        return E_FAIL;
    }
    // Initialize every out-param up front (no UI prompt, no user-data blob to
    // carry into BeginSession, and a defined identity pointer) so the fallible
    // allocation below never leaves one indeterminate on the error path.
    unsafe {
        *ppwsz_identity = windows::core::PWSTR::null();
        if !pf_invoke_ui.is_null() {
            *pf_invoke_ui = false.into();
        }
        if !pdw_user_data_out.is_null() {
            *pdw_user_data_out = 0;
        }
        if !pp_user_data_out.is_null() {
            *pp_user_data_out = core::ptr::null_mut();
        }
    }
    match local_alloc_wide(ANONYMOUS_IDENTITY) {
        Some(p) => {
            unsafe { *ppwsz_identity = windows::core::PWSTR(p) };
            ERROR_SUCCESS.0
        }
        None => E_FAIL,
    }
}

/// Allocate a NUL-terminated UTF-16 copy of `s` with `LocalAlloc` — the allocator
/// `EAPHost` frees method-returned strings with (`LocalFree`). Returns the buffer,
/// or `None` on overflow or allocation failure.
fn local_alloc_wide(s: &str) -> Option<*mut u16> {
    let utf16: Vec<u16> = s.encode_utf16().chain(core::iter::once(0)).collect();
    let bytes = utf16.len().checked_mul(size_of::<u16>())?;
    // SAFETY: LMEM_ZEROINIT zero-fills `bytes`; we then copy exactly `utf16.len()`
    // u16s (= `bytes`) into the allocation.
    let h = unsafe { LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, bytes) }.ok()?;
    let p = h.0.cast::<u16>();
    if p.is_null() {
        return None;
    }
    unsafe { core::ptr::copy_nonoverlapping(utf16.as_ptr(), p, utf16.len()) };
    Some(p)
}

// --- Routines this method does not implement: fail closed / not supported. ---

extern "system" fn EapPeerSetCredentials(
    _session_handle: *const c_void,
    _pwsz_identity: windows::core::PWSTR,
    _pwsz_password: windows::core::PWSTR,
    pp_eap_error: *mut *mut EAP_ERROR,
) -> u32 {
    unsafe { clear_error(pp_eap_error) };
    NOT_SUPPORTED
}

extern "system" fn EapPeerGetUIContext(
    _session_handle: *const c_void,
    _pdw_size: *mut u32,
    _pp_ui_context: *mut *mut u8,
    pp_eap_error: *mut *mut EAP_ERROR,
) -> u32 {
    unsafe { clear_error(pp_eap_error) };
    NOT_SUPPORTED
}

extern "system" fn EapPeerSetUIContext(
    _session_handle: *const c_void,
    _dw_size: u32,
    _p_ui_context: *const u8,
    _p_eap_output: *mut EapPeerMethodOutput,
    pp_eap_error: *mut *mut EAP_ERROR,
) -> u32 {
    unsafe { clear_error(pp_eap_error) };
    NOT_SUPPORTED
}

extern "system" fn EapPeerGetResponseAttributes(
    _session_handle: *const c_void,
    _p_attribs: *mut c_void,
    pp_eap_error: *mut *mut EAP_ERROR,
) -> u32 {
    unsafe { clear_error(pp_eap_error) };
    NOT_SUPPORTED
}

extern "system" fn EapPeerSetResponseAttributes(
    _session_handle: *const c_void,
    _p_attribs: *const c_void,
    _p_eap_output: *mut EapPeerMethodOutput,
    pp_eap_error: *mut *mut EAP_ERROR,
) -> u32 {
    unsafe { clear_error(pp_eap_error) };
    NOT_SUPPORTED
}
