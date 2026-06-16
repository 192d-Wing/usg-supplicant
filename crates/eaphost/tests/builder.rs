//! `assemble_driver` wiring, exercised cross-platform with a software credential
//! (the `#[cfg(windows)]` `build_driver` just selects a CNG/smartcard signer and
//! delegates here; the CNG providers are validated on hardware in `creds`).
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use std::sync::Arc;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};
use creds::adapter::RemoteCertResolver;
use eaphost::builder::{PeerConfig, assemble_driver};
use eaphost::session::SessionKind;
use fips_tls::backend::ClientAuth;
use fips_tls::signer::{RemoteSigner, SignerError};
use rustls::pki_types::CertificateDer;
use rustls::{RootCertStore, SignatureScheme};
use supplicant::driver::DriverStep;
use teap::eap::{EapCode, EapPacket};
use teap::outer::{TEAP_EAP_TYPE, TeapOuter};

const SERVER_NAME: &str = "teap.test.local";

/// A software `RemoteSigner` standing in for the CNG machine / smartcard key.
struct SoftSigner {
    chain: Vec<CertificateDer<'static>>,
    key: EcdsaKeyPair,
}
impl core::fmt::Debug for SoftSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SoftSigner").finish_non_exhaustive()
    }
}
impl RemoteSigner for SoftSigner {
    fn cert_chain(&self) -> Vec<CertificateDer<'static>> {
        self.chain.clone()
    }
    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        self.key
            .sign(&SystemRandom::new(), message)
            .map(|s| s.as_ref().to_vec())
            .map_err(|_| SignerError::SigningFailed)
    }
}

fn software_client_auth() -> ClientAuth {
    let ck = rcgen::generate_simple_self_signed(["usg-client".to_string()]).unwrap();
    let signer = SoftSigner {
        chain: vec![ck.cert.der().clone()],
        key: EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_ASN1_SIGNING,
            &ck.key_pair.serialize_der(),
        )
        .unwrap(),
    };
    RemoteCertResolver::new(Arc::new(signer)).into_client_auth()
}

fn profile() -> PeerConfig {
    let server = rcgen::generate_simple_self_signed([SERVER_NAME.to_string()]).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(server.cert.der().clone()).unwrap();
    PeerConfig {
        server_name: SERVER_NAME.to_string(),
        roots,
        mat_vendor_id: 0x0000_9999,
        max_fragment: 1024,
        mat_to_present: None,
    }
}

/// The opening EAP-Request/TEAP-Start that kicks off a session.
fn teap_start() -> Vec<u8> {
    let start = TeapOuter {
        more_fragments: false,
        start: true,
        version: 1,
        tls_message_length: None,
        data: vec![],
    };
    EapPacket {
        code: EapCode::Request,
        id: 1,
        type_: Some(TEAP_EAP_TYPE),
        data: start.build(),
    }
    .encode()
    .unwrap()
}

#[test]
fn assembles_machine_driver_and_emits_client_hello() {
    let mut driver =
        assemble_driver(SessionKind::Machine, profile(), software_client_auth()).unwrap();
    // The driver carries the machine identity...
    assert!(format!("{driver:?}").contains("identity: Machine"));
    // ...and on TEAP-Start it drives the tunnel, emitting the ClientHello — proof
    // the inner config, trust anchors, and driver are wired and functional.
    match driver.step(&teap_start()).unwrap() {
        DriverStep::Respond(resp) => assert!(!resp.is_empty(), "ClientHello response"),
        DriverStep::Finished { outcome, .. } => {
            panic!("expected Respond(ClientHello), got Finished: {outcome:?}")
        }
    }
}

#[test]
fn assembles_user_driver_with_mat() {
    let mut cfg = profile();
    cfg.mat_to_present = Some(vec![0xAB; 16]);
    let driver = assemble_driver(SessionKind::User, cfg, software_client_auth()).unwrap();
    // User identity is mapped, and presenting a stored MAT does not break setup.
    assert!(format!("{driver:?}").contains("identity: User"));
}

/// On-hardware (`WINDOWS_DEV.md` §4.1): drive the real `build_driver` user path —
/// select a CNG cert from `Current User\My`, acquire its non-exportable key, and
/// build a functional driver. `#[ignore]`d (needs a provisioned client-auth cert;
/// no admin for the user store). Provision a unique-subject cert and run:
/// `USG_CNG_TEST_SUBJECT=... cargo test -p eaphost --test builder -- --ignored --nocapture`.
#[cfg(windows)]
#[test]
#[ignore = "on-hardware: needs a provisioned user client-auth cert; set USG_CNG_TEST_SUBJECT"]
fn build_user_driver_from_real_store() {
    let Ok(subject) = std::env::var("USG_CNG_TEST_SUBJECT") else {
        panic!("set USG_CNG_TEST_SUBJECT to the provisioned cert's subject substring");
    };
    let selector = creds::selection::CertSelector {
        require_client_auth_eku: true,
        subject_contains: Some(subject),
        ..Default::default()
    };
    let mut driver =
        eaphost::builder::build_driver(SessionKind::User, profile(), &selector).unwrap();
    // Selected the cert, acquired the CNG key, and the driver drives the tunnel.
    match driver.step(&teap_start()).unwrap() {
        DriverStep::Respond(resp) => assert!(!resp.is_empty(), "ClientHello response"),
        DriverStep::Finished { outcome, .. } => {
            panic!("expected Respond(ClientHello), got Finished: {outcome:?}")
        }
    }
    eprintln!("build_driver(User) selected a CNG cert and emitted a ClientHello — OK");
}
