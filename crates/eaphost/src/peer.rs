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
use std::sync::OnceLock;

use windows::Win32::Foundation::{ERROR_NOT_SUPPORTED, ERROR_SUCCESS, HANDLE};
use windows::Win32::Security::ExtensibleAuthenticationProtocol::{
    EAP_ERROR, EAP_PEER_METHOD_ROUTINES, EAP_TYPE, EapPacket, EapPeerMethodOutput,
    EapPeerMethodResponseActionResult, EapPeerMethodResponseActionSend, EapPeerMethodResult,
    EapPeerMethodResultReason,
};

use creds::selection::CertSelector;
use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use supplicant::driver::DriverConfig;
use teap::session::Identity;

use crate::builder::build_driver;
use crate::config::SessionConfigBlob;
use crate::os_fips::assert_fips_policy;
use crate::session::{AuthResult, PeerSession, ProcessAction, SessionKind};
use crate::session_registry::SessionRegistry;

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

/// The process-global session table the routines marshal into.
fn registry() -> &'static SessionRegistry<supplicant::driver::TeapDriver> {
    static REG: OnceLock<SessionRegistry<supplicant::driver::TeapDriver>> = OnceLock::new();
    REG.get_or_init(SessionRegistry::new)
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
    let driver = build_driver(driver_cfg, roots, &selector).ok()?;
    Some(registry().begin(PeerSession::new(kind, driver)))
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
    let Some(action) = registry().process(ptr_to_handle(session_handle), eap) else {
        return E_FAIL; // unknown handle -> fail closed
    };
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
    let Some(resp) = registry().take_response(ptr_to_handle(session_handle)) else {
        return E_FAIL;
    };
    // SAFETY: pcb_send_packet is the caller's in/out buffer-size word.
    let avail = unsafe { *pcb_send_packet } as usize;
    if p_send_packet.is_null() || avail < resp.len() {
        // Tell the caller how much room we need (the two-call size pattern).
        unsafe { *pcb_send_packet = resp.len() as u32 };
        return E_FAIL;
    }
    // SAFETY: the buffer has room (checked) for the whole EAP packet.
    unsafe {
        core::ptr::copy_nonoverlapping(resp.as_ptr(), p_send_packet.cast::<u8>(), resp.len());
        *pcb_send_packet = resp.len() as u32;
    }
    ERROR_SUCCESS.0
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
    let success = matches!(
        registry().result(ptr_to_handle(session_handle)),
        Some(AuthResult::Success { .. })
    );
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
    registry().end(ptr_to_handle(session_handle));
    ERROR_SUCCESS.0
}

// --- Routines this method does not implement: fail closed / not supported. ---

extern "system" fn EapPeerGetIdentity(
    _flags: u32,
    _cb_connection_data: u32,
    _p_connection_data: *const u8,
    _cb_user_data: u32,
    _p_user_data: *const u8,
    _h_token: HANDLE,
    _pf_invoke_ui: *mut windows::core::BOOL,
    _pdw_user_data_out: *mut u32,
    _pp_user_data_out: *mut *mut u8,
    _ppwsz_identity: *mut windows::core::PWSTR,
    pp_eap_error: *mut *mut EAP_ERROR,
) -> u32 {
    unsafe { clear_error(pp_eap_error) };
    NOT_SUPPORTED
}

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
