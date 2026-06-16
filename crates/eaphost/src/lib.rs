//! Windows `EAPHost` integration for the TEAP supplicant.
//!
//! The supplicant ships as an **`EAPHost` peer EAP-method DLL** driven by Wired
//! `AutoConfig` (`dot3svc`): Windows owns EAPOL/L2, the 802.1X port state, and the
//! machine-at-boot / user-at-logon timing, while this DLL implements the TEAP
//! method by driving [`teap`] + [`fips_tls`] + [`creds`] + [`pac`].
//!
//! This crate currently provides the parts that are verifiable off-device:
//! - [`os_fips`] — the OS-level `FipsAlgorithmPolicy` gate (DESIGN §3), which
//!   together with `fips_tls`'s provider self-check completes the FIPS boundary.
//! - [`session`] — [`session::PeerSession`], the platform-independent adapter
//!   that maps `EAPHost`'s split call sequence (process / get-response /
//!   get-result) onto the [`supplicant::driver::TeapDriver`], with response
//!   buffering, MSK capture, and fail-closed behavior. The FFI exports marshal
//!   into this.
//!
//! ## Remaining work (requires the Windows `EAPHost` SDK + an on-device test host)
//!
//! **Peer-method DLL exports** (C ABI, `extern "system"`, `#[no_mangle]`): the
//! shim marshals each `EAPHost` call into [`session::PeerSession`] —
//! `EapPeerGetInfo`, `EapPeerInitialize`, `EapPeerBeginSession`,
//! `EapPeerProcessRequestPacket`, `EapPeerGetResponsePacket`, `EapPeerGetResult`,
//! `EapPeerGetIdentity`, `EapPeerGet/SetUIContext`,
//! `EapPeerGet/SetResponseAttributes`, `EapPeerEndSession`, `EapPeerShutdown`.
//! `EapPeerBeginSession` receives the machine-vs-user context, selecting the
//! CNG machine credential (boot) or the smartcard user credential (logon) and,
//! for the user session, presenting the stored MAT ([`pac`]).
//!
//! **Registration** under
//! `HKLM\SYSTEM\CurrentControlSet\Services\EapHost\Methods\{AuthorId}\{TypeId}`
//! with `PeerDllPath` / `PeerConfigDllPath`, using a distinct Author ID so the
//! method does not collide with the in-box Windows TEAP (type 55).
//!
//! `unsafe` is confined to the Windows FFI; every other target forbids it.
#![cfg_attr(not(windows), forbid(unsafe_code))]

/// Build a session driver from the Windows credential store (CNG/smartcard).
#[cfg(windows)]
pub mod builder;
pub mod config;
pub mod error;
pub mod os_fips;
/// The `EAPHost` peer-method C-ABI exports (the DLL `dot3svc` loads).
#[cfg(windows)]
pub mod peer;
/// Register / unregister the peer method in the Windows registry.
#[cfg(windows)]
pub mod register;
pub mod session;
pub mod session_registry;

/// Registry location under which an `EAPHost` peer method is registered.
pub const EAPHOST_METHODS_KEY: &str = r"SYSTEM\CurrentControlSet\Services\EapHost\Methods";
