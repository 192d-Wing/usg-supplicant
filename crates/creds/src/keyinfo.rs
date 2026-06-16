//! Determine the TLS signature scheme for a certificate's public key, by the
//! named-curve OID (robust, unlike inferring from key length). Cross-platform so
//! the Windows CNG provider and tests share one implementation.

use rustls::SignatureScheme;
use x509_parser::prelude::*;

use crate::ecdsa::{P256_COORD_LEN, P384_COORD_LEN};
use crate::error::CredError;

/// `id-ecPublicKey`.
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
/// `secp256r1` / NIST P-256.
const OID_P256: &str = "1.2.840.10045.3.1.7";
/// `secp384r1` / NIST P-384.
const OID_P384: &str = "1.3.132.0.34";

/// For an ECDSA P-256/P-384 certificate, return the TLS 1.3 signature scheme and
/// the ECDSA coordinate length. Rejects non-ECDSA keys and unapproved curves.
///
/// # Errors
/// [`CredError::BadCertificate`] if the DER is invalid, or
/// [`CredError::UnsupportedKey`] if the key is not ECDSA P-256/P-384.
pub fn ecdsa_scheme_for_cert(cert_der: &[u8]) -> Result<(SignatureScheme, usize), CredError> {
    let (_, cert) = X509Certificate::from_der(cert_der).map_err(|_| CredError::BadCertificate)?;
    let spki = cert.public_key();
    if spki.algorithm.algorithm.to_id_string() != OID_EC_PUBLIC_KEY {
        return Err(CredError::UnsupportedKey);
    }
    // The named curve is the algorithm parameter OID.
    let params = spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or(CredError::UnsupportedKey)?;
    let curve = params.as_oid().map_err(|_| CredError::UnsupportedKey)?;
    let curve = curve.to_id_string();
    if curve == OID_P256 {
        Ok((SignatureScheme::ECDSA_NISTP256_SHA256, P256_COORD_LEN))
    } else if curve == OID_P384 {
        Ok((SignatureScheme::ECDSA_NISTP384_SHA384, P384_COORD_LEN))
    } else {
        Err(CredError::UnsupportedKey)
    }
}
