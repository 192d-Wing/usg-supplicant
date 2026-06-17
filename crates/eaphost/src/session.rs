//! `EAPHost` peer-method session adapter.
//!
//! `dot3svc` drives an EAP method through three *separate* `EAPHost` calls per
//! round — `EapPeerProcessRequestPacket` (hand us the inbound EAP request),
//! `EapPeerGetResponsePacket` (fetch our reply), and, at the end,
//! `EapPeerGetResult` (read the verdict + MSK). The platform-independent
//! [`supplicant::driver::TeapDriver`] instead returns the reply and the outcome
//! together from `step`. [`PeerSession`] bridges the two: it runs one driver
//! step per `process`, **buffers** the reply for a later [`PeerSession::take_response`],
//! and **captures** the terminal result for [`PeerSession::result`].
//!
//! It fails closed: any driver error becomes a [`AuthResult::Failure`] and a
//! terminal state, never a panic or a half-updated session. Once terminal, it
//! ignores further packets (`EAPHost` should not send any).
//!
//! This type is platform-independent and unit-tested with a fake driver; the
//! `#[cfg(windows)]` FFI exports (the `EAP_PEER_METHOD_ROUTINES` C-ABI shim) and
//! the machine/user credential wiring marshal into it.

use supplicant::driver::DriverStep;
use supplicant::error::DriverError;
use teap::session::{FailReason, Outcome};
use zeroize::Zeroizing;

/// Which identity an `EAPHost` session authenticates: the machine certificate at
/// boot (CNG) or the user smartcard certificate at logon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKind {
    /// Machine session (boot / pre-logon).
    Machine,
    /// User session (logon / smartcard).
    User,
}

/// The one operation [`PeerSession`] needs from a driver: process an inbound EAP
/// request and return the next step. Implemented by the real
/// [`supplicant::driver::TeapDriver`]; a fake implements it in unit tests so the
/// `EAPHost` call-sequence logic can be exercised without a live TLS server.
pub trait TeapStep {
    /// Process one inbound EAP request packet.
    ///
    /// # Errors
    /// Propagates the driver's [`DriverError`]; [`PeerSession`] treats any error
    /// as a fail-closed authentication failure.
    fn step(&mut self, eap_request: &[u8]) -> Result<DriverStep, DriverError>;

    /// Whether the outer TEAP tunnel (server-authenticated TLS 1.3) is established
    /// — i.e. the exchange has moved on to the inner EAP-TLS. Drives the status
    /// tray's outer-vs-inner display.
    fn tunnel_established(&self) -> bool;
}

impl TeapStep for supplicant::driver::TeapDriver {
    fn step(&mut self, eap_request: &[u8]) -> Result<DriverStep, DriverError> {
        supplicant::driver::TeapDriver::step(self, eap_request)
    }

    fn tunnel_established(&self) -> bool {
        supplicant::driver::TeapDriver::is_established(self)
    }
}

/// What `EAPHost` should do after a [`PeerSession::process`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessAction {
    /// A response packet is ready: fetch it with [`PeerSession::take_response`]
    /// and send it; the exchange continues.
    ///
    /// Invariant: a continue step always yields exactly one complete, non-empty
    /// EAP packet — the driver emits at least a TEAP ACK every round, so there is
    /// no "discard / no response this round" case for the FFI to model.
    Respond,
    /// The exchange is terminal: read the verdict with [`PeerSession::result`].
    /// A final response packet may still be queued (check `take_response`).
    Finished,
}

/// The terminal authentication result handed to `EAPHost` (`EapPeerGetResult`).
///
/// `PartialEq`/`Eq` are hand-written: the `msk` is wrapped in [`Zeroizing`]
/// (deliberately not `PartialEq`) so it is scrubbed on drop; the manual impl
/// compares the key bytes for test/bookkeeping use.
#[derive(Debug, Clone)]
pub enum AuthResult {
    /// Authentication succeeded. `msk` (64 octets) becomes the 802.1X port keys;
    /// `issued_mat` is the machine-session ticket to persist, if the server sent
    /// one.
    Success {
        /// The exported MSK for the port keys; scrubbed on drop.
        msk: Zeroizing<Vec<u8>>,
        /// The MAT issued in this session (machine session), if any.
        issued_mat: Option<Vec<u8>>,
    },
    /// Authentication failed; the supplicant must deny.
    Failure(FailReason),
}

impl PartialEq for AuthResult {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Success { msk, issued_mat },
                Self::Success {
                    msk: m2,
                    issued_mat: i2,
                },
            ) => msk.as_slice() == m2.as_slice() && issued_mat == i2,
            (Self::Failure(a), Self::Failure(b)) => a == b,
            _ => false,
        }
    }
}
impl Eq for AuthResult {}

/// An `EAPHost` peer-method session over a TEAP driver.
#[derive(Debug)]
pub struct PeerSession<D: TeapStep> {
    kind: SessionKind,
    driver: D,
    pending_response: Option<Vec<u8>>,
    result: Option<AuthResult>,
    terminated: bool,
}

impl<D: TeapStep> PeerSession<D> {
    /// Begin a session of `kind` over `driver` (already built with the right
    /// credential and trust anchors).
    pub fn new(kind: SessionKind, driver: D) -> Self {
        Self {
            kind,
            driver,
            pending_response: None,
            result: None,
            terminated: false,
        }
    }

    /// Which identity this session authenticates.
    #[must_use]
    pub fn kind(&self) -> SessionKind {
        self.kind
    }

    /// Whether the outer TEAP tunnel is established (the inner EAP-TLS runs after
    /// this). Used to publish outer-vs-inner status to the tray.
    #[must_use]
    pub fn tunnel_established(&self) -> bool {
        self.driver.tunnel_established()
    }

    /// Process one inbound EAP request (`EapPeerProcessRequestPacket`).
    ///
    /// Buffers any response (fetch via [`PeerSession::take_response`]) and, on a
    /// terminal step, captures the result (read via [`PeerSession::result`]).
    /// A driver error fails closed: the session becomes a terminal
    /// [`AuthResult::Failure`]. After a terminal step further packets are ignored.
    pub fn process(&mut self, eap_request: &[u8]) -> ProcessAction {
        if self.terminated {
            // `EAPHost` should not call after a result; report terminal, do nothing.
            return ProcessAction::Finished;
        }
        match self.driver.step(eap_request) {
            Ok(DriverStep::Respond(resp)) => {
                self.pending_response = Some(resp);
                ProcessAction::Respond
            }
            Ok(DriverStep::Finished { send, outcome }) => {
                // A final flight may accompany the terminal step; queue it so the
                // shim can still send it.
                if send.is_some() {
                    self.pending_response = send;
                }
                self.finish(outcome);
                ProcessAction::Finished
            }
            Err(_) => {
                // Fail closed: never surface a partial or ambiguous state.
                self.finish(Outcome::Failure(FailReason::ServerFailure));
                ProcessAction::Finished
            }
        }
    }

    /// Take the buffered response packet, if any (`EapPeerGetResponsePacket`).
    ///
    /// Holds exactly one response: the `EAPHost` contract is to consume it (one
    /// `EapPeerGetResponsePacket`) between successive `process` calls. Calling
    /// `process` again before taking would overwrite the prior, unsent response —
    /// the FFI shim must preserve that ordering.
    pub fn take_response(&mut self) -> Option<Vec<u8>> {
        self.pending_response.take()
    }

    /// The buffered response length without consuming it — lets the FFI answer a
    /// size probe (`EapPeerGetResponsePacket` with a small/null buffer) without
    /// dropping the response before the follow-up fetch.
    #[must_use]
    pub fn response_len(&self) -> Option<usize> {
        self.pending_response.as_ref().map(Vec::len)
    }

    /// The terminal result, once the session has finished (`EapPeerGetResult`).
    #[must_use]
    pub fn result(&self) -> Option<&AuthResult> {
        self.result.as_ref()
    }

    /// Whether the session has reached a terminal result.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.terminated
    }

    fn finish(&mut self, outcome: Outcome) {
        self.result = Some(match outcome {
            Outcome::Success {
                msk, issued_mat, ..
            } => AuthResult::Success { msk, issued_mat },
            Outcome::Failure(reason) => AuthResult::Failure(reason),
        });
        self.terminated = true;
    }
}
