//! The capstone: a full TEAP machine session end-to-end, in-memory.
//!
//! The real [`TeapDriver`] (with the real inner EAP-TLS method [`EapTlsInner`])
//! authenticates against a `TeapServer` harness that implements the server half:
//! the outer TLS 1.3 handshake, the Phase-2 TLV exchange, the nested inner
//! EAP-TLS handshake (requiring the machine client cert), the Crypto-Binding
//! (keyed by the outer seed + inner IMSK), the Result, and EAP-Success.
//!
//! Reaching `Outcome::Success` proves the whole stack composes: framing, FIPS
//! TLS 1.3 + ML-KEM-1024 (outer and inner), the key schedule, crypto-binding,
//! and the machine certificate authentication.
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used,
    clippy::match_wildcard_for_single_variants
)]

use std::io::{Cursor, Read as _, Write as _};
use std::sync::Arc;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};
use creds::adapter::RemoteCertResolver;
use fips_tls::backend::client_config;
use fips_tls::mac::AwsLcMac;
use fips_tls::provider::fips_provider_arc;
use fips_tls::signer::{RemoteSigner, SignerError};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::version::TLS13;
use rustls::{RootCertStore, ServerConfig, ServerConnection, SignatureScheme};
use supplicant::driver::{DriverConfig, DriverStep, TeapDriver};
use supplicant::inner_tls::EapTlsInner;
use teap::cryptobind::{self, CB_SUBTYPE_REQUEST};
use teap::eap::{EapCode, EapPacket};
use teap::keyschedule::{EXPORTER_LABEL_SESSION_KEY_SEED, IMSK_LEN, KeySchedule, S_IMCK_LEN};
use teap::outer::{TEAP_EAP_TYPE, TeapOuter};
use teap::session::Identity;
use teap::tlv::{
    CryptoBindingTlv, EapPayloadTlv, IdentityType, IntermediateResultTlv, RawTlv, ResultStatus,
    ResultTlv, TlvReader, encode_all, type_id,
};

const SERVER_NAME: &str = "teap.test.local";
const EAP_TLS_TYPE: u8 = 13;
const EAP_TLS_LABEL: &[u8] = b"EXPORTER_EAP_TLS_Key_Material";
const VENDOR_ID: u32 = 0x0000_9999;

// ---- a software RemoteSigner standing in for the CNG machine key ----
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

struct Id {
    cert: CertificateDer<'static>,
    pkcs8: Vec<u8>,
}
fn gen_id(name: &str) -> Id {
    let ck = rcgen::generate_simple_self_signed([name.to_string()]).unwrap();
    Id {
        cert: ck.cert.der().clone(),
        pkcs8: ck.key_pair.serialize_der(),
    }
}

// ---- low-level TLS byte helpers (slice-advance feed avoids spurious EOF) ----
fn srv_feed(conn: &mut ServerConnection, records: &[u8]) {
    let mut rest = records;
    while !rest.is_empty() {
        let mut cur = Cursor::new(rest);
        let n = conn.read_tls(&mut cur).unwrap();
        if n == 0 {
            break;
        }
        conn.process_new_packets().unwrap();
        rest = &rest[n..];
    }
}
fn srv_take(conn: &mut ServerConnection) -> Vec<u8> {
    let mut out = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut out).unwrap();
    }
    out
}
fn srv_read_plain(conn: &mut ServerConnection) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        match conn.reader().read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(ref e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::UnexpectedEof
                ) =>
            {
                break;
            }
            Err(e) => panic!("server read: {e}"),
        }
    }
    buf
}

fn eap(code: EapCode, id: u8, type_: Option<u8>, data: Vec<u8>) -> Vec<u8> {
    EapPacket {
        code,
        id,
        type_,
        data,
    }
    .encode()
    .unwrap()
}
/// Build an outer EAP-Request carrying TEAP type-data.
fn teap_req(id: u8, outer: &TeapOuter) -> Vec<u8> {
    eap(EapCode::Request, id, Some(TEAP_EAP_TYPE), outer.build())
}
/// Build a plain (version-1, unfragmented) TEAP outer message.
fn teap_msg(data: Vec<u8>) -> TeapOuter {
    TeapOuter {
        more_fragments: false,
        start: false,
        version: 1,
        tls_message_length: None,
        data,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum P {
    OuterHs,
    InnerHs,
    AfterCommit,
    AwaitClientCb,
    AwaitClientResult,
    Done,
}

struct TeapServer {
    outer: ServerConnection,
    inner: ServerConnection,
    phase: P,
    id: u8,
    inner_id: u8,
    mac: AwsLcMac,
}

impl TeapServer {
    fn new(server_id: &Id, machine_cert: &CertificateDer<'static>) -> Self {
        let outer = {
            let cfg = ServerConfig::builder_with_provider(fips_provider_arc())
                .with_protocol_versions(&[&TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![server_id.cert.clone()],
                    PrivateKeyDer::Pkcs8(server_id.pkcs8.clone().into()),
                )
                .unwrap();
            ServerConnection::new(Arc::new(cfg)).unwrap()
        };
        let inner = {
            let mut client_roots = RootCertStore::empty();
            client_roots.add(machine_cert.clone()).unwrap();
            let verifier = WebPkiClientVerifier::builder_with_provider(
                Arc::new(client_roots),
                fips_provider_arc(),
            )
            .build()
            .unwrap();
            let cfg = ServerConfig::builder_with_provider(fips_provider_arc())
                .with_protocol_versions(&[&TLS13])
                .unwrap()
                .with_client_cert_verifier(verifier)
                .with_single_cert(
                    vec![server_id.cert.clone()],
                    PrivateKeyDer::Pkcs8(server_id.pkcs8.clone().into()),
                )
                .unwrap();
            ServerConnection::new(Arc::new(cfg)).unwrap()
        };
        Self {
            outer,
            inner,
            phase: P::OuterHs,
            id: 1,
            inner_id: 1,
            mac: AwsLcMac::sha384(),
        }
    }

    /// The opening EAP-Request/TEAP-Start.
    fn start(&mut self) -> Vec<u8> {
        teap_req(
            self.id,
            &TeapOuter {
                more_fragments: false,
                start: true,
                version: 1,
                tls_message_length: None,
                data: vec![],
            },
        )
    }

    fn next_id(&mut self) -> u8 {
        self.id = self.id.wrapping_add(1);
        self.id
    }
    fn next_inner_id(&mut self) -> u8 {
        self.inner_id = self.inner_id.wrapping_add(1);
        self.inner_id
    }

    /// Extract the TLS records from a driver EAP-Response's TEAP outer.
    fn outer_records(resp: &[u8]) -> Vec<u8> {
        let pkt = EapPacket::decode(resp).unwrap();
        assert_eq!(pkt.type_, Some(TEAP_EAP_TYPE));
        TeapOuter::parse(&pkt.data).unwrap().data
    }

    /// Send Phase-2 TLVs (outer-encrypted) as an EAP-Request.
    fn send_tlvs(&mut self, tlvs: &[RawTlv]) -> Vec<u8> {
        self.outer
            .writer()
            .write_all(&encode_all(tlvs).unwrap())
            .unwrap();
        let records = srv_take(&mut self.outer);
        let id = self.next_id();
        teap_req(id, &teap_msg(records))
    }

    /// Receive Phase-2 TLVs from a driver EAP-Response.
    fn recv_tlvs(&mut self, resp: &[u8]) -> Vec<RawTlv> {
        let records = Self::outer_records(resp);
        srv_feed(&mut self.outer, &records);
        let plain = srv_read_plain(&mut self.outer);
        TlvReader::parse_all(&plain).unwrap()
    }

    /// Wrap an inner EAP-TLS message as an EAP-Payload TLV.
    fn inner_payload(&mut self, inner_data: TeapOuter, start: bool) -> RawTlv {
        let id = self.next_inner_id();
        let mut outer = inner_data;
        outer.version = 0;
        outer.start = start;
        let inner_eap = eap(EapCode::Request, id, Some(EAP_TLS_TYPE), outer.build());
        EapPayloadTlv { eap: inner_eap }.to_tlv(true)
    }

    /// Drive one step: consume the driver's response, return the next server msg.
    fn handle(&mut self, resp: &[u8]) -> Vec<u8> {
        match self.phase {
            P::OuterHs => {
                let records = Self::outer_records(resp);
                srv_feed(&mut self.outer, &records);
                if self.outer.is_handshaking() {
                    let flight = srv_take(&mut self.outer);
                    let id = self.next_id();
                    teap_req(id, &teap_msg(flight))
                } else {
                    // Outer tunnel up. Open Phase 2: ask for Machine identity and
                    // start the inner EAP-TLS method.
                    self.phase = P::InnerHs;
                    let id_type = IdentityType::Machine.to_tlv(true);
                    let inner_start = self.inner_payload(
                        TeapOuter {
                            more_fragments: false,
                            start: false,
                            version: 0,
                            tls_message_length: None,
                            data: vec![],
                        },
                        true,
                    );
                    self.send_tlvs(&[id_type, inner_start])
                }
            }
            P::InnerHs => {
                let tlvs = self.recv_tlvs(resp);
                let payload = find(&tlvs, type_id::EAP_PAYLOAD)
                    .map(|t| EapPayloadTlv::from_value(&t.value).eap)
                    .expect("inner EAP-Payload");
                let inner_pkt = EapPacket::decode(&payload).unwrap();
                let inner_records = TeapOuter::parse(&inner_pkt.data).unwrap().data;
                srv_feed(&mut self.inner, &inner_records);
                if self.inner.is_handshaking() {
                    let flight = srv_take(&mut self.inner);
                    let tlv = self.inner_payload(teap_msg(flight), false);
                    self.send_tlvs(&[tlv])
                } else {
                    // Inner handshake done (machine cert verified). Send the
                    // protected commitment, then expect the empty post-commit msg.
                    self.inner.writer().write_all(&[0x00]).unwrap();
                    let commit = srv_take(&mut self.inner);
                    let tlv = self.inner_payload(teap_msg(commit), false);
                    self.phase = P::AfterCommit;
                    self.send_tlvs(&[tlv])
                }
            }
            P::AfterCommit => {
                // Driver's empty Phase-2 after inner completion. Now bind the two
                // authentications with a Crypto-Binding and send Intermediate-Result.
                let _ = self.recv_tlvs(resp);
                let cb = self.build_crypto_binding();
                let ir = IntermediateResultTlv {
                    status: ResultStatus::Success,
                    tlvs: vec![cb.to_tlv(true).unwrap()],
                }
                .to_tlv(true)
                .unwrap();
                self.phase = P::AwaitClientCb;
                self.send_tlvs(&[ir])
            }
            P::AwaitClientCb => {
                // Driver's Intermediate-Result + Crypto-Binding response.
                let _ = self.recv_tlvs(resp);
                self.phase = P::AwaitClientResult;
                self.send_tlvs(&[ResultTlv(ResultStatus::Success).to_tlv(true)])
            }
            P::AwaitClientResult => {
                // Driver's Result(Success). Confirm with EAP-Success.
                let _ = self.recv_tlvs(resp);
                self.phase = P::Done;
                let id = self.next_id();
                eap(EapCode::Success, id, None, vec![])
            }
            P::Done => panic!("server stepped after done"),
        }
    }

    /// Compute the server's Crypto-Binding (Binding Request) over the shared
    /// keys: outer session seed folded with the inner IMSK.
    fn build_crypto_binding(&self) -> CryptoBindingTlv {
        let mut seed = [0u8; S_IMCK_LEN];
        self.outer
            .export_keying_material(&mut seed, EXPORTER_LABEL_SESSION_KEY_SEED, None)
            .unwrap();
        let mut imsk = [0u8; 64];
        self.inner
            .export_keying_material(&mut imsk, EAP_TLS_LABEL, None)
            .unwrap();

        let mut ks = KeySchedule::new(&seed).unwrap();
        let cmk = ks.absorb_inner(&self.mac, &imsk[..IMSK_LEN]).unwrap();
        let mut cb = CryptoBindingTlv {
            version: 1,
            received_version: 1,
            sub_type: CB_SUBTYPE_REQUEST,
            nonce: [0x55; 32],
            emsk_compound_mac: vec![],
            msk_compound_mac: vec![],
        };
        cryptobind::seal(&self.mac, &cmk, &mut cb).unwrap();
        cb
    }
}

fn find(tlvs: &[RawTlv], t: u16) -> Option<&RawTlv> {
    tlvs.iter().find(|x| x.tlv_type == t)
}

#[test]
fn full_machine_session_authenticates() {
    let server_id = gen_id(SERVER_NAME);
    let machine = gen_id("usg-machine");

    // Inner method presents the machine cert via a RemoteSigner resolver.
    let signer = SoftSigner {
        chain: vec![machine.cert.clone()],
        key: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &machine.pkcs8).unwrap(),
    };
    let mut inner_roots = RootCertStore::empty();
    inner_roots.add(server_id.cert.clone()).unwrap();
    let inner_config = client_config(
        inner_roots,
        RemoteCertResolver::new(Arc::new(signer)).into_client_auth(),
    )
    .unwrap();
    let inner = EapTlsInner::new(inner_config, SERVER_NAME, 64 * 1024).unwrap();

    // Outer driver trusts the server cert (outer tunnel is server-authenticated).
    let mut outer_roots = RootCertStore::empty();
    outer_roots.add(server_id.cert.clone()).unwrap();
    let cfg = DriverConfig {
        identity: Identity::Machine,
        server_name: SERVER_NAME.to_string(),
        mat_vendor_id: VENDOR_ID,
        mat_to_present: None,
        max_fragment: 64 * 1024,
    };
    let mut driver = TeapDriver::new(cfg, outer_roots, Box::new(inner)).unwrap();

    let mut server = TeapServer::new(&server_id, &machine.cert);
    let mut inbound = server.start();

    for _ in 0..32 {
        match driver.step(&inbound).unwrap() {
            DriverStep::Respond(resp) => {
                inbound = server.handle(&resp);
            }
            DriverStep::Finished { outcome, .. } => match outcome {
                teap::session::Outcome::Success { msk, emsk, .. } => {
                    assert_eq!(msk.len(), 64);
                    assert_eq!(emsk.len(), 64);
                    assert_eq!(server.phase, P::Done);
                    return;
                }
                other => panic!("expected Success, got {other:?}"),
            },
        }
    }
    panic!("session did not converge");
}
