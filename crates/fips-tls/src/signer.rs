//! The signing seam for keys that never leave their store (Windows CNG machine
//! key, smartcard user key).
//!
//! This trait is the contract the `creds` crate (milestone 4) implements with a
//! rustls client-certificate resolver: rustls performs the TLS 1.3 transcript
//! construction and hands the to-be-signed bytes to a [`RemoteSigner`], which
//! computes the digest's signature *inside* the key store (e.g. `NCryptSignHash`
//! / a PKCS#11 token). The private key is never exported.
//!
//! The concrete rustls `SigningKey`/`Signer` adapter and the signature-encoding
//! details (raw `r||s` → DER for ECDSA on CNG) live with the CNG/smartcard
//! providers, because they depend on the platform key API.

use rustls::SignatureScheme;
use rustls::pki_types::CertificateDer;

/// Error from a remote signing operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerError {
    /// The key store refused or failed the signing operation.
    SigningFailed,
    /// The requested signature scheme is not supported by this key.
    UnsupportedScheme,
}

impl core::fmt::Display for SignerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SigningFailed => write!(f, "remote signing operation failed"),
            Self::UnsupportedScheme => write!(f, "signature scheme not supported by this key"),
        }
    }
}

impl std::error::Error for SignerError {}

/// A private key held in a non-exportable store, used for TLS client auth.
pub trait RemoteSigner: Send + Sync + core::fmt::Debug {
    /// The certificate chain (leaf first) presented to the server.
    fn cert_chain(&self) -> Vec<CertificateDer<'static>>;

    /// The single TLS 1.3 signature scheme this key supports (e.g.
    /// `ECDSA_NISTP384_SHA384` for a P-384 PIV key).
    fn scheme(&self) -> SignatureScheme;

    /// Sign `message` (the rustls to-be-signed bytes) inside the key store and
    /// return the signature in the encoding TLS expects (DER `SEQUENCE` for
    /// ECDSA; the RSA-PSS octet string for RSA — TLS 1.3 forbids PKCS#1 v1.5).
    /// Implementations hash `message` with the scheme's digest before invoking
    /// the store's hash-signing primitive.
    ///
    /// # Errors
    /// [`SignerError`] if the store rejects the operation.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError>;
}
