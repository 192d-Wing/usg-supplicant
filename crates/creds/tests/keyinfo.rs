//! Signature-shape detection from the certificate's public key (ECDSA curve OID
//! or RSA), shared by the Windows CNG provider.
#![allow(clippy::unwrap_used, clippy::panic)]

use creds::error::CredError;
use creds::keyinfo::{CertKey, scheme_for_cert};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384};
use rustls::SignatureScheme;

/// A self-signed RSA-2048 cert (public DER only). rcgen cannot generate RSA keys,
/// so this fixture was produced once via Windows `New-SelfSignedCertificate`.
const RSA2048_SELF_SIGNED: &[u8] = include_bytes!("fixtures/rsa2048_selfsigned.der");

fn self_signed(alg: &'static rcgen::SignatureAlgorithm) -> Vec<u8> {
    let key = KeyPair::generate_for(alg).unwrap();
    let params = CertificateParams::new(vec!["x".to_string()]).unwrap();
    params.self_signed(&key).unwrap().der().to_vec()
}

#[test]
fn detects_p256() {
    let der = self_signed(&PKCS_ECDSA_P256_SHA256);
    assert_eq!(
        scheme_for_cert(&der).unwrap(),
        CertKey::Ecdsa {
            scheme: SignatureScheme::ECDSA_NISTP256_SHA256,
            coord_len: 32,
        }
    );
}

#[test]
fn detects_p384() {
    let der = self_signed(&PKCS_ECDSA_P384_SHA384);
    assert_eq!(
        scheme_for_cert(&der).unwrap(),
        CertKey::Ecdsa {
            scheme: SignatureScheme::ECDSA_NISTP384_SHA384,
            coord_len: 48,
        }
    );
}

#[test]
fn detects_rsa_as_pss() {
    // An RSA key (the common DoD CAC/PIV case) advertises RSA-PSS rsae-SHA256.
    assert_eq!(
        scheme_for_cert(RSA2048_SELF_SIGNED).unwrap(),
        CertKey::RsaPss {
            scheme: SignatureScheme::RSA_PSS_SHA256,
            digest_len: 32,
        }
    );
}

#[test]
fn rejects_unsupported_key() {
    // Ed25519 is neither ECDSA P-256/P-384 nor RSA.
    let der = self_signed(&rcgen::PKCS_ED25519);
    assert_eq!(scheme_for_cert(&der), Err(CredError::UnsupportedKey));
}
