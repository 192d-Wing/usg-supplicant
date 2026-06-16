//! On-hardware validation of the CNG providers (`WINDOWS_DEV.md` §4.2).
//!
//! These tests talk to the **real** Windows certificate store, so they are
//! `#[ignore]`d — CI has no certs and must not run them. Run explicitly on a
//! Windows box:
//!
//! ```text
//! cargo test -p creds --test cng_onhardware -- --ignored --nocapture
//! ```
//!
//! `user_store_*` / `machine_store_*` validate `CertOpenStore` +
//! `CertEnumCertificatesInStore` + selection + fail-closed against the certs
//! actually present — no private-key access, since the ambiguous/empty outcome
//! is reached before `acquire_key`. This part runs against the org PKI as-is.
//!
//! `sign_roundtrip` validates the full signing FFI path against a real
//! client-auth cert: `acquire_key` (NCRYPT), `NCryptSignHash` (RSA-PSS for an
//! RSA CAC/PIV cert, or ECDSA), signature encode, then verifies with aws-lc-rs
//! against the cert's public key. It also drives `CngSigner`'s `Drop`
//! (cert-context free + `caller_free`-gated `NCryptFreeObject`).
//!
//! Point `sign_roundtrip` at a cert by subject substring (must select exactly
//! one) via `USG_CNG_TEST_SUBJECT` (and `USG_CNG_TEST_STORE=machine` for the
//! machine store). A `DoD` CAC PIV Authentication cert (RSA) works directly now
//! that RSA-PSS is supported. To exercise the ECDSA path without an ECDSA card,
//! provision a throwaway non-exportable cert in `CurrentUser\My` (no admin):
//!
//! ```powershell
//! New-SelfSignedCertificate -Type Custom -Subject "CN=USG-CNG-ONHW-TEST" `
//!   -KeyAlgorithm ECDSA_nistP256 -CurveExport CurveName `
//!   -KeyExportPolicy NonExportable -KeyUsage DigitalSignature `
//!   -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2") `
//!   -CertStoreLocation Cert:\CurrentUser\My
//! ```
#![cfg(windows)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use creds::error::CredError;
use creds::selection::CertSelector;
use fips_tls::signer::RemoteSigner;

/// Open + enumerate the user store and select on the Client-Auth EKU. The store
/// holds several client-auth certs (CAC/PIV), so selection must fail closed with
/// `AmbiguousMatch` rather than silently pick one.
#[test]
#[ignore = "real cert store: needs CurrentUser\\My populated (e.g. a CAC)"]
fn user_store_enumerate_and_fail_closed() {
    let sel = CertSelector {
        require_client_auth_eku: true,
        ..Default::default()
    };
    match creds::cng::user_signer(&sel) {
        Err(CredError::AmbiguousMatch { count }) => {
            assert!(count > 1, "ambiguous match must report >1, got {count}");
            eprintln!("CurrentUser\\My: {count} client-auth certs — enumeration + fail-closed OK");
        }
        Ok(signer) => panic!(
            "expected AmbiguousMatch; uniquely matched a {:?} cert instead",
            signer.kind()
        ),
        Err(e) => panic!("expected AmbiguousMatch, got {e}"),
    }
}

/// Same, against the machine store. Reading/enumerating `Local Machine\My` does
/// not need elevation; the ambiguous outcome is reached before any key access.
#[test]
#[ignore = "real cert store: needs LocalMachine\\My populated"]
fn machine_store_enumerate_and_fail_closed() {
    let sel = CertSelector {
        require_client_auth_eku: true,
        ..Default::default()
    };
    match creds::cng::machine_signer(&sel) {
        Err(CredError::AmbiguousMatch { count }) => {
            assert!(count > 1, "ambiguous match must report >1, got {count}");
            eprintln!("LocalMachine\\My: {count} client-auth certs — enumeration + fail-closed OK");
        }
        Err(CredError::NoMatchingCert) => {
            eprintln!(
                "LocalMachine\\My: no client-auth cert present — enumeration OK, nothing to select"
            );
        }
        Ok(signer) => eprintln!(
            "LocalMachine\\My: uniquely matched one {:?} client-auth cert",
            signer.kind()
        ),
        Err(e) => panic!("unexpected error enumerating machine store: {e}"),
    }
}

/// Full signing path against a real client-auth cert (RSA CAC/PIV, or a
/// provisioned ECDSA cert): select -> acquire NCRYPT key -> `NCryptSignHash`
/// (RSA-PSS or ECDSA) -> encode -> verify with aws-lc-rs. See the module docs.
#[test]
#[ignore = "needs a client-auth signing cert; set USG_CNG_TEST_SUBJECT"]
fn sign_roundtrip() {
    let Ok(subject) = std::env::var("USG_CNG_TEST_SUBJECT") else {
        panic!("set USG_CNG_TEST_SUBJECT to the provisioned cert's subject substring");
    };
    let use_machine = std::env::var("USG_CNG_TEST_STORE").as_deref() == Ok("machine");

    let sel = CertSelector {
        require_client_auth_eku: true,
        subject_contains: Some(subject.clone()),
        ..Default::default()
    };
    let signer = if use_machine {
        creds::cng::machine_signer(&sel)
    } else {
        creds::cng::user_signer(&sel)
    }
    .unwrap_or_else(|e| panic!("select + acquire signing key for {subject:?}: {e}"));

    let msg = b"usg-supplicant CNG on-hardware validation";
    let der_sig = signer
        .sign(msg)
        .unwrap_or_else(|_| panic!("NCryptSignHash + DER encode failed"));

    let chain = signer.cert_chain();
    let cert_der = chain.first().expect("signer exposes its cert");
    verify_signature(cert_der.as_ref(), msg, &der_sig);
    eprintln!(
        "sign+verify OK: scheme={:?}, der_sig={} bytes — full CNG FFI path validated",
        signer.scheme(),
        der_sig.len()
    );

    // Dropping `signer` here exercises CngSigner::Drop (cert-context free +
    // caller_free-gated NCryptFreeObject); a double-free would fault the test.
    drop(signer);
}

/// Verify the signature over `msg` against the public key in `cert_der`, using
/// aws-lc-rs, dispatching on the cert's key type (ECDSA r||s→DER, or RSA-PSS).
/// Panics if it does not verify — that is the assertion.
fn verify_signature(cert_der: &[u8], msg: &[u8], sig: &[u8]) {
    use aws_lc_rs::signature;
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(cert_der).expect("cert parses as X.509");
    let spki = cert.public_key();
    let key_bytes = spki.subject_public_key.data.as_ref();
    let key_alg = spki.algorithm.algorithm.to_id_string();

    let alg: &dyn signature::VerificationAlgorithm = match key_alg.as_str() {
        // RSA (rsaEncryption): TLS 1.3 -> RSA-PSS rsae-SHA256. The SPKI BIT STRING
        // is the PKCS#1 RSAPublicKey DER aws-lc-rs expects.
        "1.2.840.113549.1.1.1" => &signature::RSA_PSS_2048_8192_SHA256,
        // ECDSA (id-ecPublicKey): pick by named curve; key is the 0x04||X||Y point.
        "1.2.840.10045.2.1" => {
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .expect("EC SPKI has a named-curve parameter")
                .as_oid()
                .expect("curve parameter is an OID")
                .to_id_string();
            match curve.as_str() {
                "1.2.840.10045.3.1.7" => &signature::ECDSA_P256_SHA256_ASN1,
                "1.3.132.0.34" => &signature::ECDSA_P384_SHA384_ASN1,
                other => panic!("unexpected/non-approved curve OID {other}"),
            }
        }
        other => panic!("unexpected key algorithm OID {other}"),
    };
    signature::UnparsedPublicKey::new(alg, key_bytes)
        .verify(msg, sig)
        .expect("signature verifies against the cert's public key");
}
