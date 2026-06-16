//! Per-session TEAP Phase-2 (in-tunnel) state machine (DESIGN.md §8, adapted to
//! the two-session model: one identity, one inner EAP-TLS per session).
//!
//! Scope: this drives the **decrypted** TLV exchange once the TLS tunnel is up.
//! Phase-1 (TLS handshake), TEAP outer fragmentation, and record protection are
//! the TLS backend's job (later milestone); this module consumes a list of
//! inbound TLVs and returns the TLVs to send back, plus the terminal outcome.
//! It ties together the codec ([`crate::tlv`]), key schedule
//! ([`crate::keyschedule`]), and crypto-binding ([`crate::cryptobind`]).
//!
//! Fail-closed: any identity mismatch, missing/invalid Crypto-Binding, inner
//! failure, or out-of-order Result yields a failure outcome — never a silent
//! success. In particular an Intermediate-Result/Result of `Success` is only
//! honored when its Crypto-Binding verifies (the milestone-1 policy gate).

use crate::cryptobind::{self, CB_SUBTYPE_RESPONSE};
use crate::error::{CryptoBindError, KeyScheduleError};
use crate::keyschedule::{Cmk, KeySchedule, TeapMac};
use crate::tlv::{
    CryptoBindingTlv, EapPayloadTlv, IdentityType, IntermediateResultTlv, RawTlv, ResultStatus,
    ResultTlv, TlvError, VendorSpecificTlv, type_id,
};

/// Which identity this session authenticates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Identity {
    /// Boot/pre-logon machine session (machine cert).
    Machine,
    /// Logon user session (smartcard).
    User,
}

impl Identity {
    fn matches(self, it: IdentityType) -> bool {
        matches!(
            (self, it),
            (Self::Machine, IdentityType::Machine) | (Self::User, IdentityType::User)
        )
    }
}

/// Static configuration for one session.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// The identity being authenticated.
    pub identity: Identity,
    /// SMI Private Enterprise Number used for the Machine-Authorization-Ticket
    /// (MAT) Vendor-Specific TLV.
    pub mat_vendor_id: u32,
    /// For a user session: the opaque MAT captured at boot, to present in-tunnel.
    /// `None` for a machine session (or if no MAT is held yet).
    pub mat_to_present: Option<Vec<u8>>,
}

/// One inner EAP-TLS method, abstracted so the state machine is testable without
/// real TLS. The production impl drives an inner rustls/CNG/smartcard handshake.
pub trait InnerMethod {
    /// Process one inbound inner EAP packet, producing the next step.
    fn process(&mut self, inner_eap: &[u8]) -> InnerStep;
}

/// Result of feeding one inner EAP packet to an [`InnerMethod`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InnerStep {
    /// Send this inner EAP response (wrapped in an EAP-Payload TLV).
    Respond(Vec<u8>),
    /// The inner method succeeded; carries the 32-octet `IMSK`.
    Done(Vec<u8>),
    /// The inner method failed.
    Failed,
}

/// Terminal outcome of a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Both crypto-binding and inner auth succeeded.
    Success {
        /// Exported MSK (64 octets) handed to `dot3svc` for port keys.
        msk: Vec<u8>,
        /// Exported EMSK (64 octets).
        emsk: Vec<u8>,
        /// MAT issued by the server in this session (machine session), if any.
        issued_mat: Option<Vec<u8>>,
    },
    /// The session failed; the supplicant must deny / fail closed.
    Failure(FailReason),
}

/// Why a session failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailReason {
    /// Server requested an identity this session is not configured for.
    IdentityMismatch,
    /// The inner EAP-TLS method failed.
    InnerFailed,
    /// A `Success` Intermediate-Result/Result arrived without its Crypto-Binding.
    MissingCryptoBinding,
    /// The Crypto-Binding did not verify.
    CryptoBinding(CryptoBindError),
    /// The server reported a failure Result.
    ServerFailure,
    /// Key-schedule error (e.g. bad IMSK length from the inner method).
    KeySchedule(KeyScheduleError),
}

/// Hard protocol/parse errors (the input was malformed enough that we cannot
/// even continue). The caller still fails closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// A TLV body could not be decoded.
    Decode(TlvError),
    /// `step` was called after the session already reached a terminal state.
    AlreadyTerminated,
}

impl From<TlvError> for SessionError {
    fn from(e: TlvError) -> Self {
        Self::Decode(e)
    }
}

/// Output of one [`TeapSession::step`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Send these TLVs (to be encrypted into the tunnel); the exchange continues.
    Continue(Vec<RawTlv>),
    /// Terminal: send these final TLVs, then act on `outcome`.
    Done {
        /// Final TLVs to send.
        send: Vec<RawTlv>,
        /// The session result.
        outcome: Outcome,
    },
}

/// The Phase-2 TEAP state machine for one session.
pub struct TeapSession<'a> {
    cfg: SessionConfig,
    mac: &'a dyn TeapMac,
    inner: &'a mut dyn InnerMethod,
    ks: KeySchedule,
    cmk: Option<Cmk>,
    imsk: Option<Vec<u8>>,
    presented_mat: bool,
    terminated: bool,
}

impl core::fmt::Debug for TeapSession<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TeapSession")
            .field("identity", &self.cfg.identity)
            .field("absorbed", &self.cmk.is_some())
            .field("terminated", &self.terminated)
            .finish()
    }
}

impl<'a> TeapSession<'a> {
    /// Create a session. `session_key_seed` comes from the TLS exporter
    /// (SERVER-CONTRACT §3.1); the MAC and inner method are injected.
    ///
    /// # Errors
    /// [`KeyScheduleError::BadSeedLen`] if the seed is not 40 octets.
    pub fn new(
        cfg: SessionConfig,
        session_key_seed: &[u8],
        mac: &'a dyn TeapMac,
        inner: &'a mut dyn InnerMethod,
    ) -> Result<Self, KeyScheduleError> {
        Ok(Self {
            cfg,
            mac,
            inner,
            ks: KeySchedule::new(session_key_seed)?,
            cmk: None,
            imsk: None,
            presented_mat: false,
            terminated: false,
        })
    }

    /// Process one inbound message (a list of decrypted TLVs) and produce the
    /// reply TLVs, advancing the state machine.
    ///
    /// # Errors
    /// [`SessionError`] on malformed TLVs or use after termination.
    pub fn step(&mut self, inbound: &[RawTlv]) -> Result<Step, SessionError> {
        if self.terminated {
            return Err(SessionError::AlreadyTerminated);
        }
        let mut out: Vec<RawTlv> = Vec::new();

        // 1. Identity-Type — validate against our configured identity.
        if let Some(raw) = find(inbound, type_id::IDENTITY_TYPE) {
            let it = IdentityType::from_value(&raw.value)?;
            if !self.cfg.identity.matches(it) {
                return Ok(self.fail_step(out, FailReason::IdentityMismatch));
            }
            // User session presents its stored MAT once, as early as possible.
            if self.cfg.identity == Identity::User && !self.presented_mat {
                if let Some(mat) = self.cfg.mat_to_present.clone() {
                    let vs = VendorSpecificTlv {
                        vendor_id: self.cfg.mat_vendor_id,
                        data: mat,
                    };
                    out.push(vs.to_tlv(true));
                }
                self.presented_mat = true;
            }
        }

        // 2. Inner EAP-Payload — drive the inner EAP-TLS method.
        if let Some(raw) = find(inbound, type_id::EAP_PAYLOAD) {
            let payload = EapPayloadTlv::from_value(&raw.value);
            match self.inner.process(&payload.eap) {
                InnerStep::Respond(resp) => {
                    out.push(EapPayloadTlv { eap: resp }.to_tlv(true));
                }
                InnerStep::Done(imsk) => self.imsk = Some(imsk),
                InnerStep::Failed => return Ok(self.fail_step(out, FailReason::InnerFailed)),
            }
        }

        // 3. Intermediate-Result (+ Crypto-Binding) for the inner method.
        if let Some(raw) = find(inbound, type_id::INTERMEDIATE_RESULT) {
            let ir = IntermediateResultTlv::from_value(&raw.value)?;
            match ir.status {
                ResultStatus::Success => {
                    if let Some(step) = self.handle_inner_success(inbound, &ir, &mut out)? {
                        return Ok(step);
                    }
                }
                _ => return Ok(self.fail_step(out, FailReason::InnerFailed)),
            }
        }

        // 4. Result — overall session result.
        if let Some(raw) = find(inbound, type_id::RESULT) {
            let result = ResultTlv::from_value(&raw.value)?;
            return self.handle_result(inbound, result.0, out);
        }

        Ok(Step::Continue(out))
    }

    /// Handle a `Success` Intermediate-Result: absorb the IMSK, verify the
    /// server's Crypto-Binding, and emit our own. Returns `Some(Step)` only when
    /// it must terminate early (failure); `None` to continue accumulating `out`.
    fn handle_inner_success(
        &mut self,
        inbound: &[RawTlv],
        ir: &IntermediateResultTlv,
        out: &mut Vec<RawTlv>,
    ) -> Result<Option<Step>, SessionError> {
        // The inner method must have produced an IMSK first.
        let Some(imsk) = self.imsk.clone() else {
            return Ok(Some(
                self.fail_step(core::mem::take(out), FailReason::InnerFailed),
            ));
        };
        // Absorb exactly once to obtain CMK[1].
        if self.cmk.is_none() {
            match self.ks.absorb_inner(self.mac, &imsk) {
                Ok(cmk) => self.cmk = Some(cmk),
                Err(e) => {
                    return Ok(Some(
                        self.fail_step(core::mem::take(out), FailReason::KeySchedule(e)),
                    ));
                }
            }
        }

        // Crypto-Binding may be top-level or nested inside the IR. Required.
        let Some(cb) = find_crypto_binding(inbound, ir)? else {
            return Ok(Some(self.fail_step(
                core::mem::take(out),
                FailReason::MissingCryptoBinding,
            )));
        };

        // Clone the small CMK so the rest of this method can call `&mut self`
        // helpers without holding a borrow of `self.cmk`. Unreachable `None`
        // (set just above) still fails closed rather than panicking.
        let Some(cmk) = self.cmk.clone() else {
            return Ok(Some(self.fail_step(
                core::mem::take(out),
                FailReason::MissingCryptoBinding,
            )));
        };

        if let Err(e) = cryptobind::verify(self.mac, &cmk, &cb) {
            return Ok(Some(
                self.fail_step(core::mem::take(out), FailReason::CryptoBinding(e)),
            ));
        }

        // Emit our Binding Response: echo the nonce, flip the sub-type, seal.
        let mut resp = cb.clone();
        resp.sub_type = CB_SUBTYPE_RESPONSE;
        if let Err(e) = cryptobind::seal(self.mac, &cmk, &mut resp) {
            return Ok(Some(
                self.fail_step(core::mem::take(out), FailReason::CryptoBinding(e)),
            ));
        }
        let our_ir = IntermediateResultTlv {
            status: ResultStatus::Success,
            tlvs: vec![resp.to_tlv(true).map_err(SessionError::Decode)?],
        };
        out.push(our_ir.to_tlv(true).map_err(SessionError::Decode)?);
        Ok(None)
    }

    /// Handle the overall Result TLV.
    fn handle_result(
        &mut self,
        inbound: &[RawTlv],
        status: ResultStatus,
        mut out: Vec<RawTlv>,
    ) -> Result<Step, SessionError> {
        if status != ResultStatus::Success {
            return Ok(self.fail_step(out, FailReason::ServerFailure));
        }
        // A success Result is only valid once the crypto-binding has been
        // verified (which is what sets `cmk`).
        if self.cmk.is_none() {
            return Ok(self.fail_step(out, FailReason::MissingCryptoBinding));
        }
        let (msk, emsk) = match self.ks.derive_session_keys(self.mac) {
            Ok(keys) => keys,
            Err(e) => return Ok(self.fail_step(out, FailReason::KeySchedule(e))),
        };
        // A machine session may receive a freshly issued MAT to persist.
        let issued_mat = find_mat(inbound, self.cfg.mat_vendor_id)?;

        out.push(ResultTlv(ResultStatus::Success).to_tlv(true));
        self.terminated = true;
        Ok(Step::Done {
            send: out,
            outcome: Outcome::Success {
                msk,
                emsk,
                issued_mat,
            },
        })
    }

    /// Terminate with a failure Result and the given reason.
    fn fail_step(&mut self, mut out: Vec<RawTlv>, reason: FailReason) -> Step {
        self.terminated = true;
        out.push(ResultTlv(ResultStatus::Failure).to_tlv(true));
        Step::Done {
            send: out,
            outcome: Outcome::Failure(reason),
        }
    }
}

/// First TLV of `tlv_type` in `tlvs`.
fn find(tlvs: &[RawTlv], tlv_type: u16) -> Option<&RawTlv> {
    tlvs.iter().find(|t| t.tlv_type == tlv_type)
}

/// Locate the Crypto-Binding TLV: top-level first, else nested in the IR.
fn find_crypto_binding(
    inbound: &[RawTlv],
    ir: &IntermediateResultTlv,
) -> Result<Option<CryptoBindingTlv>, SessionError> {
    if let Some(raw) = find(inbound, type_id::CRYPTO_BINDING) {
        return Ok(Some(CryptoBindingTlv::from_value(&raw.value)?));
    }
    if let Some(raw) = find(&ir.tlvs, type_id::CRYPTO_BINDING) {
        return Ok(Some(CryptoBindingTlv::from_value(&raw.value)?));
    }
    Ok(None)
}

/// Locate a MAT (Vendor-Specific TLV matching our enterprise number).
fn find_mat(inbound: &[RawTlv], vendor_id: u32) -> Result<Option<Vec<u8>>, SessionError> {
    for raw in inbound
        .iter()
        .filter(|t| t.tlv_type == type_id::VENDOR_SPECIFIC)
    {
        let vs = VendorSpecificTlv::from_value(&raw.value)?;
        if vs.vendor_id == vendor_id {
            return Ok(Some(vs.data));
        }
    }
    Ok(None)
}
