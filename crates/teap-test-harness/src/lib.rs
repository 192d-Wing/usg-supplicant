//! Test-only TEAP **server** harness: the server half of a `usg-TEAP/1.3`
//! authentication (outer TLS 1.3 + ML-KEM, the Phase-2 TLV exchange, the nested
//! inner EAP-TLS requiring a client cert, crypto-binding, Result, EAP-Success).
//!
//! Shared by `usg-supplicant`'s `full_session` test (driving the real
//! `TeapDriver`) and `eaphost`'s DLL-driven capstone (driving the peer DLL).
//! Not for production — it uses `unwrap`/`panic` freely.
#![allow(clippy::missing_panics_doc)]

use std::io::{Cursor, Read as _, Write as _};
use std::sync::Arc;

use fips_tls::mac::AwsLcMac;
use fips_tls::provider::fips_provider_arc;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::version::TLS13;
use rustls::{RootCertStore, ServerConfig, ServerConnection};
use teap::cryptobind::{self, CB_SUBTYPE_REQUEST};
use teap::eap::{EapCode, EapPacket};
use teap::keyschedule::{EXPORTER_LABEL_SESSION_KEY_SEED, IMSK_LEN, KeySchedule, S_IMCK_LEN};
use teap::outer::{TEAP_EAP_TYPE, TeapOuter};
use teap::session::Identity;
use teap::tlv::{
    CryptoBindingTlv, EapPayloadTlv, IdentityType, IntermediateResultTlv, RawTlv, ResultStatus,
    ResultTlv, TlvReader, encode_all, type_id,
};

/// The server name the harness certificate is issued for.
pub const SERVER_NAME: &str = "teap.test.local";
const EAP_TLS_TYPE: u8 = 13;
const EAP_TLS_LABEL: &[u8] = b"EXPORTER_EAP_TLS_Key_Material";

/// A self-signed identity (cert + PKCS#8 key) for the harness.
pub struct Id {
    pub cert: CertificateDer<'static>,
    pub pkcs8: Vec<u8>,
}

/// Generate a self-signed ECDSA identity for `name`.
pub fn gen_id(name: &str) -> Id {
    let ck = rcgen::generate_simple_self_signed([name.to_string()]).unwrap();
    Id {
        cert: ck.cert.der().clone(),
        pkcs8: ck.key_pair.serialize_der(),
    }
}

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

fn teap_req(id: u8, outer: &TeapOuter) -> Vec<u8> {
    eap(EapCode::Request, id, Some(TEAP_EAP_TYPE), outer.build())
}

fn teap_msg(data: Vec<u8>) -> TeapOuter {
    TeapOuter {
        more_fragments: false,
        start: false,
        version: 1,
        tls_message_length: None,
        data,
    }
}

fn find(tlvs: &[RawTlv], t: u16) -> Option<&RawTlv> {
    tlvs.iter().find(|x| x.tlv_type == t)
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

/// The TEAP server. Drive it by feeding each client EAP-Response to
/// [`TeapServer::handle`], which returns the next server EAP-Request (or
/// EAP-Success once authentication completes).
pub struct TeapServer {
    outer: ServerConnection,
    inner: ServerConnection,
    phase: P,
    id: u8,
    inner_id: u8,
    mac: AwsLcMac,
    identity: IdentityType,
}

impl TeapServer {
    /// Build a server presenting `server_id`, requiring the client to present a
    /// cert chaining to `client_cert`, and expecting `identity` (machine/user).
    pub fn new(server_id: &Id, client_cert: &CertificateDer<'static>, identity: Identity) -> Self {
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
            client_roots.add(client_cert.clone()).unwrap();
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
            identity: match identity {
                Identity::Machine => IdentityType::Machine,
                Identity::User => IdentityType::User,
            },
        }
    }

    /// Whether authentication has completed (EAP-Success sent).
    pub fn is_done(&self) -> bool {
        self.phase == P::Done
    }

    /// The opening EAP-Request/TEAP-Start.
    pub fn start(&mut self) -> Vec<u8> {
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

    fn outer_records(resp: &[u8]) -> Vec<u8> {
        let pkt = EapPacket::decode(resp).unwrap();
        assert_eq!(pkt.type_, Some(TEAP_EAP_TYPE));
        TeapOuter::parse(&pkt.data).unwrap().data
    }

    fn send_tlvs(&mut self, tlvs: &[RawTlv]) -> Vec<u8> {
        self.outer
            .writer()
            .write_all(&encode_all(tlvs).unwrap())
            .unwrap();
        let records = srv_take(&mut self.outer);
        let id = self.next_id();
        teap_req(id, &teap_msg(records))
    }

    fn recv_tlvs(&mut self, resp: &[u8]) -> Vec<RawTlv> {
        let records = Self::outer_records(resp);
        srv_feed(&mut self.outer, &records);
        let plain = srv_read_plain(&mut self.outer);
        TlvReader::parse_all(&plain).unwrap()
    }

    fn inner_payload(&mut self, inner_data: TeapOuter, start: bool) -> RawTlv {
        let id = self.next_inner_id();
        let mut outer = inner_data;
        outer.version = 0;
        outer.start = start;
        let inner_eap = eap(EapCode::Request, id, Some(EAP_TLS_TYPE), outer.build());
        EapPayloadTlv { eap: inner_eap }.to_tlv(true)
    }

    /// Consume the client's EAP-Response and return the next server message.
    pub fn handle(&mut self, resp: &[u8]) -> Vec<u8> {
        match self.phase {
            P::OuterHs => {
                let records = Self::outer_records(resp);
                srv_feed(&mut self.outer, &records);
                if self.outer.is_handshaking() {
                    let flight = srv_take(&mut self.outer);
                    let id = self.next_id();
                    teap_req(id, &teap_msg(flight))
                } else {
                    self.phase = P::InnerHs;
                    let id_type = self.identity.to_tlv(true);
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
                    self.inner.writer().write_all(&[0x00]).unwrap();
                    let commit = srv_take(&mut self.inner);
                    let tlv = self.inner_payload(teap_msg(commit), false);
                    self.phase = P::AfterCommit;
                    self.send_tlvs(&[tlv])
                }
            }
            P::AfterCommit => {
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
                let _ = self.recv_tlvs(resp);
                self.phase = P::AwaitClientResult;
                self.send_tlvs(&[ResultTlv(ResultStatus::Success).to_tlv(true)])
            }
            P::AwaitClientResult => {
                let _ = self.recv_tlvs(resp);
                self.phase = P::Done;
                let id = self.next_id();
                eap(EapCode::Success, id, None, vec![])
            }
            P::Done => panic!("server stepped after done"),
        }
    }

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
