//! Machine Authorization Ticket (MAT) persistence (SERVER-CONTRACT §1).
//!
//! At boot, the machine TEAP session may receive a server-issued MAT — an
//! **opaque** ticket the client stores but never parses. At user logon the
//! stored MAT is presented in-tunnel so the server can correlate the machine
//! and user authentications (EAP chaining across sessions).
//!
//! Storage is machine-scope so the boot (machine) context can write it and the
//! logon (user) context can read it, and host-bound so it cannot be lifted to
//! another machine — on Windows that is **DPAPI in `LOCAL_MACHINE` scope**
//! ([`dpapi::DpapiSealer`]). `unsafe` is confined to that Windows FFI; every
//! other target forbids it.
#![cfg_attr(not(windows), forbid(unsafe_code))]

pub mod error;
pub mod record;
pub mod store;

#[cfg(windows)]
pub mod dpapi;
