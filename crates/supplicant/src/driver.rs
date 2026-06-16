//! The TEAP authentication driver: one object that consumes inbound EAP request
//! packets (handed up by `EAPHost` / `dot3svc`) and produces EAP responses,
//! sequencing the whole exchange:
//!
//! 1. **TEAP Start** → begin the TLS 1.3 handshake, emit `ClientHello`.
//! 2. **Handshake** → reassemble inbound TLS records, drive the tunnel, fragment
//!    and emit each flight; on completion enforce the FIPS/PQ allow-list and
//!    derive `session_key_seed`.
//! 3. **Phase 2** → decrypt inbound TLVs, run the [`TeapSession`] state machine,
//!    encrypt and emit reply TLVs, until a terminal [`Outcome`].
//!
//! The outer tunnel is server-authenticated only; the machine/user certificate
//! authentication happens in the inner EAP-TLS method (injected here).

use std::collections::VecDeque;
use std::sync::Arc;

use fips_tls::backend::{ClientAuth, TeapTlsClient, client_config};
use rustls::RootCertStore;
use teap::eap::{EapCode, EapPacket};
use teap::outer::{Reassembler, TEAP_EAP_TYPE, TEAP_VERSION, TeapOuter, fragment};
use teap::session::{Identity, InnerMethod, Outcome, SessionConfig, Step, TeapSession};
use teap::tlv::{TlvReader, encode_all};

use crate::error::DriverError;

/// Largest reassembled TLS message we will accept (bounds memory).
const MAX_TLS_MESSAGE: usize = 256 * 1024;
/// Cap on handshake flights, bounding a server that never completes the
/// handshake (defense-in-depth above rustls's own limits).
const MAX_HANDSHAKE_ROUNDS: usize = 64;

/// Static driver configuration.
#[derive(Debug, Clone)]
pub struct DriverConfig {
    /// Which identity this session authenticates.
    pub identity: Identity,
    /// Expected EAP-server name (validated against its certificate).
    pub server_name: String,
    /// SMI Private Enterprise Number for the MAT Vendor-Specific TLV.
    pub mat_vendor_id: u32,
    /// For a user session: the stored MAT to present in-tunnel.
    pub mat_to_present: Option<Vec<u8>>,
    /// Maximum TLS-fragment payload per TEAP message (EAP MTU budget).
    pub max_fragment: usize,
}

/// One step of the driver.
#[derive(Debug)]
pub enum DriverStep {
    /// Send these EAP response bytes; the exchange continues.
    Respond(Vec<u8>),
    /// Terminal: optionally send a final EAP response, then act on `outcome`.
    Finished {
        /// Final EAP bytes to send (if any).
        send: Option<Vec<u8>>,
        /// The authentication result.
        outcome: Outcome,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    ExpectStart,
    Handshake,
    Phase2,
    Terminated,
}

/// The driver.
pub struct TeapDriver {
    cfg: DriverConfig,
    tunnel: TeapTlsClient,
    inner: Option<Box<dyn InnerMethod>>,
    phase: Phase,
    reasm: Reassembler,
    out_queue: VecDeque<TeapOuter>,
    session: Option<TeapSession>,
    pending: Option<Outcome>,
    last_id: u8,
    rounds: usize,
}

impl core::fmt::Debug for TeapDriver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TeapDriver")
            .field("identity", &self.cfg.identity)
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

impl TeapDriver {
    /// Build a driver. `roots` are the trust anchors for the EAP server; `inner`
    /// is the inner EAP-TLS method (machine cert or smartcard).
    ///
    /// # Errors
    /// [`DriverError::Tls`] if the client config or connection cannot be built.
    pub fn new(
        cfg: DriverConfig,
        roots: RootCertStore,
        inner: Box<dyn InnerMethod>,
    ) -> Result<Self, DriverError> {
        let config: Arc<_> = client_config(roots, ClientAuth::None)?;
        let tunnel = TeapTlsClient::connect(config, &cfg.server_name)?;
        Ok(Self {
            cfg,
            tunnel,
            inner: Some(inner),
            phase: Phase::ExpectStart,
            reasm: Reassembler::new(MAX_TLS_MESSAGE),
            out_queue: VecDeque::new(),
            session: None,
            pending: None,
            last_id: 0,
            rounds: 0,
        })
    }

    /// Whether the TLS tunnel is established (Phase 2 reached or terminated).
    #[must_use]
    pub fn is_established(&self) -> bool {
        matches!(self.phase, Phase::Phase2 | Phase::Terminated)
    }

    /// Process one inbound EAP request packet, returning the next step.
    ///
    /// # Errors
    /// [`DriverError`] on framing/TLS/session errors or protocol violations.
    pub fn step(&mut self, eap_request: &[u8]) -> Result<DriverStep, DriverError> {
        let pkt = EapPacket::decode(eap_request)?;
        match pkt.code {
            EapCode::Failure => {
                // EAP-Failure is authoritative: the network denied us. Discard
                // any pending Success (e.g. a late Access-Reject after our TLVs
                // completed) and fail closed.
                self.phase = Phase::Terminated;
                self.pending = None;
                Ok(DriverStep::Finished {
                    send: None,
                    outcome: Outcome::Failure(teap::session::FailReason::ServerFailure),
                })
            }
            EapCode::Success => {
                self.phase = Phase::Terminated;
                let outcome = self
                    .pending
                    .take()
                    .ok_or(DriverError::Protocol("EAP-Success before a result"))?;
                Ok(DriverStep::Finished {
                    send: None,
                    outcome,
                })
            }
            EapCode::Request => self.on_request(&pkt),
            EapCode::Response | EapCode::Unknown(_) => {
                Err(DriverError::Protocol("unexpected EAP code from server"))
            }
        }
    }

    fn on_request(&mut self, pkt: &EapPacket) -> Result<DriverStep, DriverError> {
        if pkt.type_ != Some(TEAP_EAP_TYPE) {
            return Err(DriverError::Protocol("inner EAP type is not TEAP"));
        }
        self.last_id = pkt.id;
        let outer = TeapOuter::parse(&pkt.data)?;

        // A bare ACK drives our outbound fragment queue forward.
        if outer.is_ack() && !self.out_queue.is_empty() {
            return self.next_out_fragment();
        }

        match self.phase {
            Phase::ExpectStart => {
                if !outer.start {
                    return Err(DriverError::Protocol("expected TEAP Start"));
                }
                self.phase = Phase::Handshake;
                let client_hello = self.tunnel.take_outgoing()?;
                self.send_tls_message(&client_hello)
            }
            Phase::Handshake => self.on_handshake(&outer),
            Phase::Phase2 => self.on_phase2(&outer),
            Phase::Terminated => Err(DriverError::Protocol("packet after terminal state")),
        }
    }

    fn on_handshake(&mut self, outer: &TeapOuter) -> Result<DriverStep, DriverError> {
        self.rounds = self.rounds.saturating_add(1);
        if self.rounds > MAX_HANDSHAKE_ROUNDS {
            return Err(DriverError::Protocol("handshake exceeded round limit"));
        }
        let Some(message) = self.reasm.push(outer)? else {
            // Need more fragments — acknowledge.
            return self.respond(&TeapOuter::ack(TEAP_VERSION));
        };
        self.tunnel.feed_incoming(&message)?;

        if self.tunnel.is_handshaking() {
            let flight = self.tunnel.take_outgoing()?;
            return self.send_tls_message(&flight);
        }
        // Handshake complete: emit our final flight, enforce FIPS, start Phase 2.
        let flight = self.tunnel.take_outgoing()?;
        self.tunnel.finish_handshake()?;
        self.start_phase2()?;
        self.send_tls_message(&flight)
    }

    fn start_phase2(&mut self) -> Result<(), DriverError> {
        let seed = self.tunnel.session_key_seed()?;
        let mac = self.tunnel.negotiated_mac()?;
        let inner = self
            .inner
            .take()
            .ok_or(DriverError::Protocol("inner method already used"))?;
        let session = TeapSession::new(
            SessionConfig {
                identity: self.cfg.identity,
                mat_vendor_id: self.cfg.mat_vendor_id,
                mat_to_present: self.cfg.mat_to_present.clone(),
            },
            &seed[..],
            Box::new(mac),
            inner,
        )
        .map_err(|_| DriverError::Protocol("session key seed rejected"))?;
        self.session = Some(session);
        self.phase = Phase::Phase2;
        Ok(())
    }

    fn on_phase2(&mut self, outer: &TeapOuter) -> Result<DriverStep, DriverError> {
        let Some(records) = self.reasm.push(outer)? else {
            return self.respond(&TeapOuter::ack(TEAP_VERSION));
        };
        let plaintext = self.tunnel.unprotect(&records)?;
        let tlvs = TlvReader::parse_all(&plaintext)?;

        let session = self
            .session
            .as_mut()
            .ok_or(DriverError::Protocol("no session"))?;
        match session.step(&tlvs)? {
            Step::Continue(out) => {
                let ciphertext = self.protect_tlvs(&out)?;
                self.send_tls_message(&ciphertext)
            }
            Step::Done { send, outcome } => {
                let ciphertext = self.protect_tlvs(&send)?;
                self.phase = Phase::Terminated;
                self.pending = Some(outcome);
                // Emit the final TLVs; the server confirms with EAP-Success,
                // which yields the outcome on the next step().
                self.send_tls_message(&ciphertext)
            }
        }
    }

    /// Encrypt a list of TLVs into TLS application-data records.
    fn protect_tlvs(&mut self, tlvs: &[teap::tlv::RawTlv]) -> Result<Vec<u8>, DriverError> {
        let bytes = encode_all(tlvs)?;
        Ok(self.tunnel.protect(&bytes)?)
    }

    /// Fragment an outbound TLS message into TEAP messages, queue the tail, and
    /// return the first as an EAP response.
    fn send_tls_message(&mut self, message: &[u8]) -> Result<DriverStep, DriverError> {
        let mut frags = fragment(message, self.cfg.max_fragment, TEAP_VERSION).into_iter();
        let first = frags.next().unwrap_or_else(|| TeapOuter::ack(TEAP_VERSION));
        self.out_queue = frags.collect();
        self.respond(&first)
    }

    fn next_out_fragment(&mut self) -> Result<DriverStep, DriverError> {
        match self.out_queue.pop_front() {
            Some(outer) => self.respond(&outer),
            None => self.respond(&TeapOuter::ack(TEAP_VERSION)),
        }
    }

    /// Wrap a TEAP outer message in an EAP-Response with the current identifier.
    /// Propagates an encoding error rather than emitting a malformed frame.
    fn respond(&self, outer: &TeapOuter) -> Result<DriverStep, DriverError> {
        let pkt = EapPacket {
            code: EapCode::Response,
            id: self.last_id,
            type_: Some(TEAP_EAP_TYPE),
            data: outer.build(),
        };
        Ok(DriverStep::Respond(pkt.encode()?))
    }
}
