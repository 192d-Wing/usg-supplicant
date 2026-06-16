//! Determine the TLS 1.3 signature shape for a certificate's public key, from the
//! key algorithm + named-curve OID (robust, unlike inferring from key length).
//! Cross-platform so the Windows CNG provider and tests share one implementation.
//!
//! Two key families are supported, matching what `DoD` PKI issues:
//! - **ECDSA** P-256 / P-384 (PIV Authentication certs on newer cards) — signed
//!   raw and `r||s`→DER re-encoded by [`crate::ecdsa`].
//! - **RSA** 2048+ (the common CAC/PIV case today) — signed **RSA-PSS** (`rsae`),
//!   the only RSA signature TLS 1.3 permits. PKCS#1 v1.5 is not used.

use rustls::SignatureScheme;
use x509_parser::prelude::*;

use crate::ecdsa::{P256_COORD_LEN, P384_COORD_LEN};
use crate::error::CredError;

/// `id-ecPublicKey`.
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
/// `rsaEncryption` (a plain RSA key; TLS 1.3 signs it with RSA-PSS `rsae`).
const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
/// `secp256r1` / NIST P-256.
const OID_P256: &str = "1.2.840.10045.3.1.7";
/// `secp384r1` / NIST P-384.
const OID_P384: &str = "1.3.132.0.34";
/// Minimum approved RSA modulus size (DESIGN.md allow-list; FIPS 186-5).
const RSA_MIN_BITS: usize = 2048;

/// The signature shape derived from a certificate's public key: the TLS 1.3
/// scheme to advertise plus the data the CNG signer needs to encode the result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertKey {
    /// ECDSA on an approved curve. `coord_len` is the per-coordinate octet count
    /// used to turn CNG's raw `r||s` into ASN.1 DER ([`crate::ecdsa::raw_to_der`]).
    Ecdsa {
        /// TLS 1.3 signature scheme (`ECDSA_NISTP256_SHA256` / `..P384_SHA384`).
        scheme: SignatureScheme,
        /// ECDSA coordinate length in octets (32 for P-256, 48 for P-384).
        coord_len: usize,
    },
    /// RSA, signed RSA-PSS (`rsae`) in TLS 1.3. `digest_len` is the hash size and
    /// also the PSS salt length — RFC 8446 fixes the salt length to the digest
    /// length. The CNG signature is the final octet string (no DER re-encoding).
    RsaPss {
        /// TLS 1.3 signature scheme (rustls names the `rsae` codepoint
        /// `RSA_PSS_SHA256`).
        scheme: SignatureScheme,
        /// Hash output / PSS salt length in octets.
        digest_len: usize,
    },
}

impl CertKey {
    /// The TLS 1.3 signature scheme to advertise for this key.
    #[must_use]
    pub fn scheme(self) -> SignatureScheme {
        match self {
            Self::Ecdsa { scheme, .. } | Self::RsaPss { scheme, .. } => scheme,
        }
    }
}

/// Derive the [`CertKey`] from a certificate's `SubjectPublicKeyInfo`.
///
/// RSA keys advertise **`rsa_pss_rsae_sha256`** — the SHA-256 `rsae` scheme is
/// the most widely offered, and both ends of this protocol are ours
/// (SERVER-CONTRACT). RSA-2048 PSS with a 32-octet salt is FIPS-approved.
/// RSA keys below `RSA_MIN_BITS` are rejected (DESIGN.md allow-list).
///
/// # Errors
/// [`CredError::BadCertificate`] if the DER is invalid, or
/// [`CredError::UnsupportedKey`] if the key is not ECDSA P-256/P-384, not RSA,
/// or an RSA key smaller than `RSA_MIN_BITS`.
pub fn scheme_for_cert(cert_der: &[u8]) -> Result<CertKey, CredError> {
    let (_, cert) = X509Certificate::from_der(cert_der).map_err(|_| CredError::BadCertificate)?;
    let spki = cert.public_key();
    let key_alg = spki.algorithm.algorithm.to_id_string();

    if key_alg == OID_RSA_ENCRYPTION {
        // DESIGN.md allow-list: RSA >= 2048, anything else aborts. Fail closed —
        // a key whose size can't be determined is rejected too.
        let bits = match spki.parsed() {
            Ok(x509_parser::public_key::PublicKey::RSA(rsa)) => rsa.key_size(),
            _ => return Err(CredError::UnsupportedKey),
        };
        if bits < RSA_MIN_BITS {
            return Err(CredError::UnsupportedKey);
        }
        return Ok(CertKey::RsaPss {
            scheme: SignatureScheme::RSA_PSS_SHA256,
            digest_len: 32,
        });
    }
    if key_alg != OID_EC_PUBLIC_KEY {
        return Err(CredError::UnsupportedKey);
    }

    // ECDSA: the named curve is the algorithm parameter OID.
    let params = spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or(CredError::UnsupportedKey)?;
    let curve = params
        .as_oid()
        .map_err(|_| CredError::UnsupportedKey)?
        .to_id_string();
    if curve == OID_P256 {
        Ok(CertKey::Ecdsa {
            scheme: SignatureScheme::ECDSA_NISTP256_SHA256,
            coord_len: P256_COORD_LEN,
        })
    } else if curve == OID_P384 {
        Ok(CertKey::Ecdsa {
            scheme: SignatureScheme::ECDSA_NISTP384_SHA384,
            coord_len: P384_COORD_LEN,
        })
    } else {
        Err(CredError::UnsupportedKey)
    }
}
