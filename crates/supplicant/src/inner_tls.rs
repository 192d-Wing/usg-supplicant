//! The inner EAP-TLS method (RFC 5216 / draft-ietf-emu-eap-tls13), the real
//! machine/user certificate authentication that runs *inside* the TEAP tunnel.
//!
//! It drives a second TLS 1.3 handshake in which the client presents its
//! certificate (machine via CNG, or smartcard user via the `creds` resolver
//! supplied in the injected client config) and, on completion, derives the
//! `IMSK` from the EAP-TLS keying exporter (SERVER-CONTRACT §3.2). The inner EAP
//! packets are carried in TEAP EAP-Payload TLVs; this type implements
//! [`teap::session::InnerMethod`] so the [`crate::driver::TeapDriver`] can use it.
//!
//! Completion follows EAP-TLS 1.3: after the client's Finished the server sends a
//! protected commitment message; receiving it triggers `IMSK` derivation.

use std::collections::VecDeque;
use std::sync::Arc;

use fips_tls::backend::TeapTlsClient;
use rustls::ClientConfig;
use teap::eap::{EapCode, EapPacket};
use teap::keyschedule::IMSK_LEN;
use teap::outer::{Reassembler, TeapOuter, fragment};
use teap::session::{InnerMethod, InnerStep};

/// EAP method type for EAP-TLS (IANA).
const EAP_TLS_TYPE: u8 = 13;
/// EAP-TLS uses the same L/M/S fragmentation as TEAP; the low "version" bits are
/// reserved (zero) for EAP-TLS.
const EAP_TLS_VERSION: u8 = 0;
/// RFC 8446 exporter label for the EAP-TLS 1.3 key material.
const EAP_TLS_EXPORTER_LABEL: &[u8] = b"EXPORTER_EAP_TLS_Key_Material";
/// Bytes to export; `IMSK` is the first [`IMSK_LEN`] of it.
const EAP_TLS_KEY_LEN: usize = 64;
/// Reassembly ceiling for inner TLS messages.
const MAX_TLS_MESSAGE: usize = 256 * 1024;

/// Inner EAP-TLS error. The public surface returns this; `process` collapses it
/// to [`InnerStep::Failed`] (fail closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InnerTlsError {
    /// The inner TLS connection could not be created.
    Connect,
    /// A framing, TLS, or sequencing failure during the inner handshake.
    Protocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Handshake,
    AwaitCommitment,
    Done,
    Failed,
}

/// Inner EAP-TLS method driving the machine/user certificate handshake.
pub struct EapTlsInner {
    tunnel: TeapTlsClient,
    reasm: Reassembler,
    out_queue: VecDeque<TeapOuter>,
    state: State,
    started: bool,
    max_fragment: usize,
    last_id: u8,
}

impl core::fmt::Debug for EapTlsInner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EapTlsInner")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl EapTlsInner {
    /// Build the inner method from a client config (which must carry the client
    /// certificate resolver for the machine/user key) and the EAP server name.
    ///
    /// # Errors
    /// [`InnerTlsError::Connect`] if the inner TLS connection cannot be created
    /// (invalid server name or config).
    pub fn new(
        config: Arc<ClientConfig>,
        server_name: &str,
        max_fragment: usize,
    ) -> Result<Self, InnerTlsError> {
        let tunnel =
            TeapTlsClient::connect(config, server_name).map_err(|_| InnerTlsError::Connect)?;
        Ok(Self {
            tunnel,
            reasm: Reassembler::new(MAX_TLS_MESSAGE),
            out_queue: VecDeque::new(),
            state: State::Handshake,
            started: false,
            max_fragment,
            last_id: 0,
        })
    }

    /// Internal step returning a precise result; the public [`InnerMethod::process`]
    /// maps any error to [`InnerStep::Failed`] (fail closed).
    fn try_process(&mut self, inner_eap: &[u8]) -> Result<InnerStep, InnerTlsError> {
        if matches!(self.state, State::Done | State::Failed) {
            return Err(InnerTlsError::Protocol);
        }
        let pkt = EapPacket::decode(inner_eap).map_err(|_| InnerTlsError::Protocol)?;
        if pkt.code != EapCode::Request || pkt.type_ != Some(EAP_TLS_TYPE) {
            return Err(InnerTlsError::Protocol);
        }
        self.last_id = pkt.id;
        let outer = TeapOuter::parse(&pkt.data).map_err(|_| InnerTlsError::Protocol)?;

        // Drive our outbound fragment queue on a bare ACK.
        if outer.is_ack() && !self.out_queue.is_empty() {
            return self.next_fragment();
        }

        match self.state {
            State::Handshake => self.on_handshake(&outer),
            State::AwaitCommitment => self.on_commitment(&outer),
            State::Done | State::Failed => Err(InnerTlsError::Protocol),
        }
    }

    fn on_handshake(&mut self, outer: &TeapOuter) -> Result<InnerStep, InnerTlsError> {
        if !self.started {
            // The inner server opens with EAP-TLS-Start.
            if !outer.start {
                return Err(InnerTlsError::Protocol);
            }
            self.started = true;
            let client_hello = self
                .tunnel
                .take_outgoing()
                .map_err(|_| InnerTlsError::Protocol)?;
            return self.send_tls(&client_hello);
        }
        let Some(records) = self
            .reasm
            .push(outer)
            .map_err(|_| InnerTlsError::Protocol)?
        else {
            return self.respond(&TeapOuter::ack(EAP_TLS_VERSION));
        };
        self.tunnel
            .feed_incoming(&records)
            .map_err(|_| InnerTlsError::Protocol)?;
        if self.tunnel.is_handshaking() {
            let flight = self
                .tunnel
                .take_outgoing()
                .map_err(|_| InnerTlsError::Protocol)?;
            return self.send_tls(&flight);
        }
        // Handshake complete: emit our Finished, enforce FIPS, await commitment.
        let flight = self
            .tunnel
            .take_outgoing()
            .map_err(|_| InnerTlsError::Protocol)?;
        self.tunnel
            .finish_handshake()
            .map_err(|_| InnerTlsError::Protocol)?;
        self.state = State::AwaitCommitment;
        self.send_tls(&flight)
    }

    fn on_commitment(&mut self, outer: &TeapOuter) -> Result<InnerStep, InnerTlsError> {
        // Wait for the whole post-handshake (commitment) message to arrive.
        let Some(records) = self
            .reasm
            .push(outer)
            .map_err(|_| InnerTlsError::Protocol)?
        else {
            return self.respond(&TeapOuter::ack(EAP_TLS_VERSION));
        };
        // Require an actual protected commitment record — reject an empty frame
        // so completion cannot be forced by a content-free M=0 message.
        if records.is_empty() {
            return Err(InnerTlsError::Protocol);
        }
        // The commitment signals inner-method completion. We do not need to
        // decrypt it: the IMSK is a pure function of the completed, mutually
        // authenticated handshake (the EAP-TLS keying exporter), so it is
        // derived directly. Reaching this state already required server-cert
        // verification and a successful, FIPS-enforced handshake.
        let key = self
            .tunnel
            .export_keying_material(EAP_TLS_EXPORTER_LABEL, EAP_TLS_KEY_LEN)
            .map_err(|_| InnerTlsError::Protocol)?;
        let imsk = key.get(..IMSK_LEN).ok_or(InnerTlsError::Protocol)?.to_vec();
        self.state = State::Done;
        Ok(InnerStep::Done(imsk))
    }

    fn send_tls(&mut self, message: &[u8]) -> Result<InnerStep, InnerTlsError> {
        let mut frags = fragment(message, self.max_fragment, EAP_TLS_VERSION).into_iter();
        let first = frags
            .next()
            .unwrap_or_else(|| TeapOuter::ack(EAP_TLS_VERSION));
        self.out_queue = frags.collect();
        self.respond(&first)
    }

    fn next_fragment(&mut self) -> Result<InnerStep, InnerTlsError> {
        match self.out_queue.pop_front() {
            Some(outer) => self.respond(&outer),
            None => self.respond(&TeapOuter::ack(EAP_TLS_VERSION)),
        }
    }

    fn respond(&self, outer: &TeapOuter) -> Result<InnerStep, InnerTlsError> {
        let pkt = EapPacket {
            code: EapCode::Response,
            id: self.last_id,
            type_: Some(EAP_TLS_TYPE),
            data: outer.build(),
        };
        Ok(InnerStep::Respond(
            pkt.encode().map_err(|_| InnerTlsError::Protocol)?,
        ))
    }
}

impl InnerMethod for EapTlsInner {
    fn process(&mut self, inner_eap: &[u8]) -> InnerStep {
        if let Ok(step) = self.try_process(inner_eap) {
            step
        } else {
            self.state = State::Failed;
            InnerStep::Failed
        }
    }
}
