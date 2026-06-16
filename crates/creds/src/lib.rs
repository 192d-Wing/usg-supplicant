//! Certificate/key providers for the supplicant.
//!
//! Exposes the machine certificate (Windows CNG, `Local Machine\My`) and the
//! user certificate (smartcard: CAC/PIV or SIPR token, via `ActivClient` / 90Meter
//! through CNG) as [`fips_tls::signer::RemoteSigner`]s — the private key never
//! leaves its store. [`adapter::RemoteCertResolver`] wires a signer into the
//! rustls client handshake.
//!
//! Cross-platform pieces (cert selection, ECDSA `r||s`→DER, the rustls adapter)
//! build and test everywhere. The CNG/smartcard FFI is `#[cfg(windows)]`.
//!
//! `unsafe` is permitted only in the Windows FFI modules; every other target
//! forbids it.
#![cfg_attr(not(windows), forbid(unsafe_code))]

pub mod adapter;
pub mod ecdsa;
pub mod error;
pub mod keyinfo;
pub mod selection;

/// Which identity a credential authenticates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredKind {
    /// Machine certificate (CNG, boot/pre-logon).
    Machine,
    /// User certificate (smartcard, at logon).
    User,
}

#[cfg(windows)]
pub mod cng;
