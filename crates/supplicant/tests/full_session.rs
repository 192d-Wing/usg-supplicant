//! The capstone: a full TEAP machine session end-to-end, in-memory.
//!
//! The real [`TeapDriver`] (with the real inner EAP-TLS method `EapTlsInner`,
//! assembled via [`supplicant::builder::assemble_driver`]) authenticates against
//! the shared [`teap_test_harness::TeapServer`] (outer TLS 1.3 handshake, Phase-2
//! TLV exchange, nested inner EAP-TLS requiring the machine cert, Crypto-Binding,
//! Result, EAP-Success).
//!
//! Reaching `Outcome::Success` proves the whole stack composes: framing, FIPS
//! TLS 1.3 + ML-KEM-1024 (outer and inner), the key schedule, crypto-binding,
//! and the machine certificate authentication.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};
use creds::adapter::RemoteCertResolver;
use fips_tls::signer::{RemoteSigner, SignerError};
use rustls::pki_types::CertificateDer;
use rustls::{RootCertStore, SignatureScheme};
use supplicant::driver::{DriverConfig, DriverStep};
use teap::session::{Identity, Outcome};
use teap_test_harness::{SERVER_NAME, TeapServer, gen_id};

/// A software `RemoteSigner` standing in for the CNG machine key.
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

#[test]
fn full_machine_session_authenticates() {
    let server_id = gen_id(SERVER_NAME);
    let machine = gen_id("usg-machine");

    // The machine cert is presented via a RemoteSigner resolver; `assemble_driver`
    // wires the inner EAP-TLS + outer driver (the path the eaphost shim uses).
    let signer = SoftSigner {
        chain: vec![machine.cert.clone()],
        key: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &machine.pkcs8).unwrap(),
    };
    let client_auth = RemoteCertResolver::new(Arc::new(signer)).into_client_auth();
    let mut roots = RootCertStore::empty();
    roots.add(server_id.cert.clone()).unwrap();
    let cfg = DriverConfig {
        identity: Identity::Machine,
        server_name: SERVER_NAME.to_string(),
        mat_vendor_id: 0x0000_9999,
        mat_to_present: None,
        max_fragment: 64 * 1024,
    };
    let mut driver = supplicant::builder::assemble_driver(cfg, roots, client_auth).unwrap();

    let mut server = TeapServer::new(&server_id, &machine.cert, Identity::Machine);
    let mut inbound = server.start();

    for _ in 0..32 {
        match driver.step(&inbound).unwrap() {
            DriverStep::Respond(resp) => inbound = server.handle(&resp),
            DriverStep::Finished { outcome, .. } => match outcome {
                Outcome::Success { msk, emsk, .. } => {
                    assert_eq!(msk.len(), 64);
                    assert_eq!(emsk.len(), 64);
                    assert!(server.is_done(), "server reached EAP-Success");
                    return;
                }
                Outcome::Failure(reason) => panic!("expected Success, got {reason:?}"),
            },
        }
    }
    panic!("session did not converge");
}
