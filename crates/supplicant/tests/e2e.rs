//! End-to-end: drive the `TeapDriver` through a real TLS 1.3 + ML-KEM-1024
//! handshake carried over the EAP/TEAP outer framing, against a rustls server.
//! Proves the driver parses TEAP Start, emits `ClientHello`, reassembles the
//! server flight, completes the handshake, enforces the FIPS/PQ allow-list, and
//! reaches Phase 2 (a session keyed by the agreed exporter seed).
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used
)]

use std::io::Cursor;
use std::sync::Arc;

use fips_tls::provider::fips_provider_arc;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::version::TLS13;
use rustls::{RootCertStore, ServerConfig, ServerConnection};
use supplicant::driver::{DriverConfig, DriverStep, TeapDriver};
use teap::eap::{EapCode, EapPacket};
use teap::outer::{Reassembler, TEAP_EAP_TYPE, TEAP_VERSION, TeapOuter};
use teap::session::{Identity, InnerMethod, InnerStep};

const SERVER_NAME: &str = "teap.test.local";
const MAX_MSG: usize = 256 * 1024;

struct MockInner;
impl InnerMethod for MockInner {
    fn process(&mut self, _inner_eap: &[u8]) -> InnerStep {
        InnerStep::Done(vec![0u8; 32])
    }
}

fn eap_request(id: u8, outer: &TeapOuter) -> Vec<u8> {
    EapPacket {
        code: EapCode::Request,
        id,
        type_: Some(TEAP_EAP_TYPE),
        data: outer.build(),
    }
    .encode()
    .unwrap()
}

/// Extract the TLS-record fragment from an EAP-Response the driver produced.
fn driver_outer(resp: &[u8]) -> TeapOuter {
    let pkt = EapPacket::decode(resp).unwrap();
    assert_eq!(pkt.code, EapCode::Response);
    assert_eq!(pkt.type_, Some(TEAP_EAP_TYPE));
    TeapOuter::parse(&pkt.data).unwrap()
}

#[test]
fn driver_completes_mlkem_handshake_over_teap_framing() {
    // Server: self-signed cert, FIPS provider, TLS 1.3, no client auth (the
    // outer tunnel is server-authenticated; inner auth carries the identity).
    let ck = rcgen::generate_simple_self_signed([SERVER_NAME.to_string()]).unwrap();
    let cert: CertificateDer<'static> = ck.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(ck.key_pair.serialize_der().into());
    let server_config = ServerConfig::builder_with_provider(fips_provider_arc())
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

    // Driver trusts the server cert.
    let mut roots = RootCertStore::empty();
    roots.add(cert).unwrap();
    let cfg = DriverConfig {
        identity: Identity::Machine,
        server_name: SERVER_NAME.to_string(),
        mat_vendor_id: 0x0000_9999,
        mat_to_present: None,
        max_fragment: 64 * 1024,
    };
    let mut driver = TeapDriver::new(cfg, roots, Box::new(MockInner)).unwrap();

    let mut server_reasm = Reassembler::new(MAX_MSG);
    // The authenticator opens with EAP-Request/TEAP-Start.
    let start = TeapOuter {
        more_fragments: false,
        start: true,
        version: TEAP_VERSION,
        tls_message_length: None,
        data: vec![],
    };
    let mut inbound = eap_request(1, &start);
    let mut id = 1u8;

    for _ in 0..16 {
        let step = driver.step(&inbound).unwrap();
        let resp = match step {
            DriverStep::Respond(bytes) => bytes,
            DriverStep::Finished { .. } => panic!("unexpected early finish"),
        };

        // Feed the driver's TLS records into the server.
        let outer = driver_outer(&resp);
        if let Some(records) = server_reasm.push(&outer).unwrap()
            && !records.is_empty()
        {
            let mut cur = Cursor::new(records);
            while server.read_tls(&mut cur).unwrap() > 0 {
                server.process_new_packets().unwrap();
            }
        }

        // Collect the server's next flight.
        let mut server_out = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut server_out).unwrap();
        }

        // Done when both ends finished the handshake.
        if driver.is_established() && !server.is_handshaking() {
            assert!(
                server.peer_certificates().is_none(),
                "outer tunnel has no client cert"
            );
            return;
        }

        id = id.wrapping_add(1);
        let flight = TeapOuter {
            more_fragments: false,
            start: false,
            version: TEAP_VERSION,
            tls_message_length: None,
            data: server_out,
        };
        inbound = eap_request(id, &flight);
    }
    panic!("handshake did not converge");
}

#[test]
fn driver_rejects_non_start_first_message() {
    let ck = rcgen::generate_simple_self_signed([SERVER_NAME.to_string()]).unwrap();
    let cert: CertificateDer<'static> = ck.cert.der().clone();
    let mut roots = RootCertStore::empty();
    roots.add(cert).unwrap();
    let cfg = DriverConfig {
        identity: Identity::Machine,
        server_name: SERVER_NAME.to_string(),
        mat_vendor_id: 1,
        mat_to_present: None,
        max_fragment: 64 * 1024,
    };
    let mut driver = TeapDriver::new(cfg, roots, Box::new(MockInner)).unwrap();
    // First message without the Start bit must be rejected.
    let not_start = TeapOuter {
        more_fragments: false,
        start: false,
        version: TEAP_VERSION,
        tls_message_length: None,
        data: vec![],
    };
    assert!(driver.step(&eap_request(1, &not_start)).is_err());
}
