//! In-memory TLS 1.3 handshake proving the FIPS provider negotiates ML-KEM-1024,
//! enforces the allow-list, and produces a 40-octet `session_key_seed` that both
//! ends agree on. Runs against the non-FIPS provider (dev build); the FIPS build
//! uses the same code path against the validated module.
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc
)]

use std::io::{Read as _, Write as _};
use std::sync::Arc;

use fips_tls::backend::{ClientAuth, TeapTlsClient, client_config};
use fips_tls::error::FipsTlsError;
use fips_tls::provider::{assert_fips, fips_provider, fips_provider_arc};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::version::TLS13;
use rustls::{CipherSuite, NamedGroup, RootCertStore, ServerConfig, ServerConnection};
use teap::keyschedule::TeapMac as _;

const SERVER_NAME: &str = "teap.test.local";

// RSA server-cert chain fixtures (see fixtures/gen_rsa_chain.go). DoD RADIUS
// server certs and their CA chain are RSA; rcgen cannot mint RSA, so these are
// a committed RSA-2048 CA + leaf (CN/SAN = SERVER_NAME) + the leaf's PKCS#8 key.
const RSA_CA: &[u8] = include_bytes!("fixtures/rsa_ca.der");
const RSA_LEAF: &[u8] = include_bytes!("fixtures/rsa_server_leaf.der");
const RSA_KEY: &[u8] = include_bytes!("fixtures/rsa_server_key_pkcs8.der");

struct TestServerCert {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

fn gen_server_cert() -> TestServerCert {
    let ck = rcgen::generate_simple_self_signed([SERVER_NAME.to_string()]).unwrap();
    let cert = ck.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(ck.key_pair.serialize_der().into());
    TestServerCert { cert, key }
}

fn server_conn(server: &TestServerCert) -> ServerConnection {
    let config = ServerConfig::builder_with_provider(fips_provider_arc())
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![server.cert.clone()], server.key.clone_key())
        .unwrap();
    ServerConnection::new(Arc::new(config)).unwrap()
}

fn client(server: &TestServerCert) -> TeapTlsClient {
    let mut roots = RootCertStore::empty();
    roots.add(server.cert.clone()).unwrap();
    let config = client_config(roots, ClientAuth::None).unwrap();
    TeapTlsClient::connect(config, SERVER_NAME).unwrap()
}

/// Drive the handshake to completion by shuttling records between the two ends.
fn drive(client: &mut TeapTlsClient, server: &mut ServerConnection) {
    for _ in 0..32 {
        let c2s = client.take_outgoing().unwrap();
        if !c2s.is_empty() {
            let mut cur = std::io::Cursor::new(c2s);
            while server.read_tls(&mut cur).unwrap() > 0 {
                server.process_new_packets().unwrap();
            }
        }
        let mut s2c = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut s2c).unwrap();
        }
        if !s2c.is_empty() {
            client.feed_incoming(&s2c).unwrap();
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            return;
        }
    }
    panic!("handshake did not converge");
}

#[test]
fn handshake_negotiates_mlkem1024_and_agrees_on_seed() {
    let server_cert = gen_server_cert();
    let mut srv = server_conn(&server_cert);
    let mut cli = client(&server_cert);

    drive(&mut cli, &mut srv);

    // ML-KEM-1024 key exchange and the SHA-384 AEAD suite must have been chosen.
    assert_eq!(cli.negotiated_group(), Some(NamedGroup::MLKEM1024));
    assert_eq!(
        cli.negotiated_suite(),
        Some(CipherSuite::TLS13_AES_256_GCM_SHA384)
    );
    // Secret-producing methods are gated until the handshake is finalized.
    assert!(matches!(
        cli.session_key_seed(),
        Err(FipsTlsError::NotEstablished)
    ));
    cli.finish_handshake()
        .expect("negotiated params are FIPS-allowed");

    // The exporter yields a 40-octet seed identical on both ends.
    let client_seed = cli.session_key_seed().unwrap();
    let server_seed = srv
        .export_keying_material([0u8; 40], b"EXPORTER: teap session key seed", None)
        .unwrap();
    assert_eq!(client_seed.len(), 40);
    assert_eq!(*client_seed, server_seed);

    // The MAC primitive tracks the negotiated suite hash (SHA-384 here).
    assert_eq!(cli.negotiated_mac().unwrap().hash_len(), 48);
}

#[test]
fn application_data_roundtrips_through_the_tunnel() {
    let server_cert = gen_server_cert();
    let mut srv = server_conn(&server_cert);
    let mut cli = client(&server_cert);
    drive(&mut cli, &mut srv);
    cli.finish_handshake().unwrap();

    // Client encrypts Phase-2 data; server decrypts it.
    let payload = b"teap-phase2-tlvs";
    let records = cli.protect(payload).unwrap();
    let mut cur = std::io::Cursor::new(records);
    while srv.read_tls(&mut cur).unwrap() > 0 {
        srv.process_new_packets().unwrap();
    }
    let mut got = Vec::new();
    srv.reader().read_to_end(&mut got).ok();
    assert_eq!(got, payload);
}

#[test]
fn server_name_mismatch_is_rejected() {
    let server_cert = gen_server_cert();
    let mut srv = server_conn(&server_cert);

    let mut roots = RootCertStore::empty();
    roots.add(server_cert.cert.clone()).unwrap();
    let config = client_config(roots, ClientAuth::None).unwrap();
    // Connect expecting a DIFFERENT name than the cert's SAN.
    let mut cli = TeapTlsClient::connect(config, "wrong.example.com").unwrap();

    // The handshake must fail (cert name mismatch) rather than complete.
    let mut converged = false;
    for _ in 0..32 {
        let Ok(c2s) = cli.take_outgoing() else {
            converged = true;
            break;
        };
        if !c2s.is_empty() {
            let mut cur = std::io::Cursor::new(c2s);
            while srv.read_tls(&mut cur).unwrap() > 0 {
                let _ = srv.process_new_packets();
            }
        }
        let mut s2c = Vec::new();
        while srv.wants_write() {
            srv.write_tls(&mut s2c).unwrap();
        }
        if !s2c.is_empty() && cli.feed_incoming(&s2c).is_err() {
            converged = true;
            break;
        }
        if !cli.is_handshaking() {
            break;
        }
    }
    assert!(
        converged,
        "expected the handshake to fail on server-name mismatch"
    );
}

#[test]
fn handshake_verifies_rsa_server_cert_chain() {
    // The outer tunnel must verify an RSA leaf (RSA-PSS CertificateVerify) issued
    // by an RSA CA (PKCS#1 chain signature) — the DoD server-cert case — while
    // still negotiating ML-KEM-1024 / AES-256-GCM. The server presents only the
    // leaf; the CA is the client's trust anchor.
    let leaf = CertificateDer::from(RSA_LEAF.to_vec());
    let key = PrivateKeyDer::Pkcs8(RSA_KEY.to_vec().into());
    let server_config = ServerConfig::builder_with_provider(fips_provider_arc())
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![leaf], key)
        .unwrap();
    let mut srv = ServerConnection::new(Arc::new(server_config)).unwrap();

    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(RSA_CA.to_vec())).unwrap();
    let config = client_config(roots, ClientAuth::None).unwrap();
    let mut cli = TeapTlsClient::connect(config, SERVER_NAME).unwrap();

    drive(&mut cli, &mut srv);

    assert_eq!(cli.negotiated_group(), Some(NamedGroup::MLKEM1024));
    assert_eq!(
        cli.negotiated_suite(),
        Some(CipherSuite::TLS13_AES_256_GCM_SHA384)
    );
    cli.finish_handshake()
        .expect("RSA server chain verifies and params are FIPS-allowed");

    // Both ends agreeing on the exporter seed proves the tunnel fully established
    // over the RSA-authenticated handshake.
    let client_seed = cli.session_key_seed().unwrap();
    let server_seed = srv
        .export_keying_material([0u8; 40], b"EXPORTER: teap session key seed", None)
        .unwrap();
    assert_eq!(*client_seed, server_seed);
}

#[test]
fn fips_self_check_matches_build() {
    // In a non-FIPS (dev) build the provider is not validated -> fail closed.
    // Under `--features fips` it is validated -> Ok. Assert the build-correct sense.
    let provider = fips_provider();
    let result = assert_fips(&provider);
    if cfg!(feature = "fips") {
        assert!(result.is_ok(), "fips build must pass the self-check");
    } else {
        assert!(result.is_err(), "non-fips build must fail closed");
    }
}

#[test]
fn server_to_client_app_data_unprotects() {
    let server_cert = gen_server_cert();
    let mut srv = server_conn(&server_cert);
    let mut cli = client(&server_cert);
    drive(&mut cli, &mut srv);
    cli.finish_handshake().unwrap();

    // Server sends application data post-handshake (incl. its NewSessionTickets);
    // the client must unprotect it.
    srv.writer().write_all(b"phase2-tlvs").unwrap();
    let mut records = Vec::new();
    while srv.wants_write() {
        srv.write_tls(&mut records).unwrap();
    }
    let got = cli.unprotect(&records).unwrap();
    assert_eq!(got, b"phase2-tlvs");
}
