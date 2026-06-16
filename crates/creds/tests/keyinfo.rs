//! Curve detection from the certificate's named-curve OID.
#![allow(clippy::unwrap_used, clippy::panic)]

use creds::error::CredError;
use creds::keyinfo::ecdsa_scheme_for_cert;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384};
use rustls::SignatureScheme;

fn self_signed(alg: &'static rcgen::SignatureAlgorithm) -> Vec<u8> {
    let key = KeyPair::generate_for(alg).unwrap();
    let params = CertificateParams::new(vec!["x".to_string()]).unwrap();
    params.self_signed(&key).unwrap().der().to_vec()
}

#[test]
fn detects_p256() {
    let der = self_signed(&PKCS_ECDSA_P256_SHA256);
    let (scheme, coord) = ecdsa_scheme_for_cert(&der).unwrap();
    assert_eq!(scheme, SignatureScheme::ECDSA_NISTP256_SHA256);
    assert_eq!(coord, 32);
}

#[test]
fn detects_p384() {
    let der = self_signed(&PKCS_ECDSA_P384_SHA384);
    let (scheme, coord) = ecdsa_scheme_for_cert(&der).unwrap();
    assert_eq!(scheme, SignatureScheme::ECDSA_NISTP384_SHA384);
    assert_eq!(coord, 48);
}

#[test]
fn rejects_non_ecdsa_key() {
    // Ed25519 key -> not an ECDSA P-256/P-384 cert.
    let der = self_signed(&rcgen::PKCS_ED25519);
    assert_eq!(ecdsa_scheme_for_cert(&der), Err(CredError::UnsupportedKey));
}
