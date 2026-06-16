//! End-to-end proof that a `RemoteSigner` (CNG/smartcard stand-in) signs the
//! TLS 1.3 client handshake through the rustls adapter and the server accepts
//! it. The software signer here mimics what the CNG provider does: hold a cert
//! chain + a key and produce a DER ECDSA signature over the handshake transcript.
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::sync::Arc;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};
use creds::adapter::RemoteCertResolver;
use fips_tls::backend::{TeapTlsClient, client_config};
use fips_tls::provider::fips_provider_arc;
use fips_tls::signer::{RemoteSigner, SignerError};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::version::TLS13;
use rustls::{RootCertStore, ServerConfig, ServerConnection, SignatureScheme};

const SERVER_NAME: &str = "teap.test.local";

/// A software `RemoteSigner` standing in for a CNG/smartcard key.
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
        let rng = SystemRandom::new();
        self.key
            .sign(&rng, message)
            .map(|s| s.as_ref().to_vec())
            .map_err(|_| SignerError::SigningFailed)
    }
}

struct Identity {
    cert: CertificateDer<'static>,
    pkcs8: Vec<u8>,
}

fn gen_identity(name: &str) -> Identity {
    let ck = rcgen::generate_simple_self_signed([name.to_string()]).unwrap();
    Identity {
        cert: ck.cert.der().clone(),
        pkcs8: ck.key_pair.serialize_der(),
    }
}

#[test]
fn remote_signer_authenticates_the_client_to_the_server() {
    let server_id = gen_identity(SERVER_NAME);
    let client_id = gen_identity("usg-machine");

    // Server requires + verifies a client cert chaining to `client_id`.
    let mut client_roots = RootCertStore::empty();
    client_roots.add(client_id.cert.clone()).unwrap();
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(client_roots), fips_provider_arc())
            .build()
            .unwrap();
    let server_config = ServerConfig::builder_with_provider(fips_provider_arc())
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![server_id.cert.clone()],
            PrivateKeyDer::Pkcs8(server_id.pkcs8.clone().into()),
        )
        .unwrap();
    let mut srv = ServerConnection::new(Arc::new(server_config)).unwrap();

    // Client presents `client_id` via a RemoteSigner-backed resolver.
    let signer = SoftSigner {
        chain: vec![client_id.cert.clone()],
        key: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &client_id.pkcs8).unwrap(),
    };
    let resolver = RemoteCertResolver::new(Arc::new(signer));

    let mut server_roots = RootCertStore::empty();
    server_roots.add(server_id.cert.clone()).unwrap();
    let config = client_config(server_roots, resolver.into_client_auth()).unwrap();
    let mut cli = TeapTlsClient::connect(config, SERVER_NAME).unwrap();

    // Drive the handshake.
    for _ in 0..32 {
        let c2s = cli.take_outgoing().unwrap();
        if !c2s.is_empty() {
            let mut cur = std::io::Cursor::new(c2s);
            while srv.read_tls(&mut cur).unwrap() > 0 {
                srv.process_new_packets().unwrap();
            }
        }
        let mut s2c = Vec::new();
        while srv.wants_write() {
            srv.write_tls(&mut s2c).unwrap();
        }
        if !s2c.is_empty() {
            cli.feed_incoming(&s2c).unwrap();
        }
        if !cli.is_handshaking() && !srv.is_handshaking() {
            break;
        }
    }

    assert!(!cli.is_handshaking(), "client handshake incomplete");
    assert!(!srv.is_handshaking(), "server handshake incomplete");
    cli.finish_handshake().unwrap();

    // The server received and accepted the RemoteSigner-presented client cert.
    let peer = srv.peer_certificates().expect("server got a client cert");
    assert_eq!(peer.len(), 1);
    assert_eq!(peer[0], client_id.cert);
}
