//! Per-session TEAP Phase-2 state-machine tests. Drives full happy paths for a
//! machine and a user session, plus the fail-closed paths, using a scripted
//! inner method and an independent HMAC-SHA-384 reference (dev-only).
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::match_wildcard_for_single_variants,
    clippy::missing_panics_doc
)]

use std::collections::VecDeque;

use hmac::{Hmac, Mac};
use sha2::Sha384;
use teap::cryptobind::{CB_SUBTYPE_REQUEST, CB_SUBTYPE_RESPONSE, seal, verify};
use teap::keyschedule::{Cmk, KeySchedule, TeapMac};
use teap::session::{
    FailReason, Identity, InnerMethod, InnerStep, Outcome, SessionConfig, SessionError, Step,
    TeapSession,
};
use teap::tlv::{
    CryptoBindingTlv, EapPayloadTlv, IdentityType, IntermediateResultTlv, RawTlv, ResultStatus,
    ResultTlv, VendorSpecificTlv, type_id,
};
use usg_kat::{from_hex, keyschedule_vectors as kv};

const VENDOR_ID: u32 = 0x0000_9999;

struct RefSha384;
impl TeapMac for RefSha384 {
    fn hash_len(&self) -> usize {
        48
    }
    fn hmac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut m = Hmac::<Sha384>::new_from_slice(key).unwrap();
        m.update(data);
        m.finalize().into_bytes().to_vec()
    }
}

/// Inner method that returns a scripted sequence of steps.
struct ScriptedInner {
    steps: VecDeque<InnerStep>,
}
impl ScriptedInner {
    fn new(steps: Vec<InnerStep>) -> Self {
        Self {
            steps: steps.into(),
        }
    }
}
impl InnerMethod for ScriptedInner {
    fn process(&mut self, _inner_eap: &[u8]) -> InnerStep {
        self.steps.pop_front().unwrap_or(InnerStep::Failed)
    }
}

fn seed() -> Vec<u8> {
    from_hex(kv::SEED_HEX).unwrap()
}
fn imsk() -> Vec<u8> {
    from_hex(kv::IMSK_HEX).unwrap()
}

/// Compute the CMK the server would derive for the given IMSK.
fn server_cmk(imsk: &[u8]) -> Cmk {
    let mut ks = KeySchedule::new(&seed()).unwrap();
    ks.absorb_inner(&RefSha384, imsk).unwrap()
}

/// A server Binding-Request Crypto-Binding TLV sealed under `cmk`.
fn server_request_cb(cmk: &Cmk) -> CryptoBindingTlv {
    let mut cb = CryptoBindingTlv {
        version: 1,
        received_version: 1,
        sub_type: CB_SUBTYPE_REQUEST,
        nonce: [0x77; 32],
        emsk_compound_mac: vec![],
        msk_compound_mac: vec![],
    };
    seal(&RefSha384, cmk, &mut cb).unwrap();
    cb
}

fn eap_payload(bytes: &[u8]) -> RawTlv {
    EapPayloadTlv {
        eap: bytes.to_vec(),
    }
    .to_tlv(true)
}
fn ir_success_with_cb(cb: &CryptoBindingTlv) -> RawTlv {
    IntermediateResultTlv {
        status: ResultStatus::Success,
        tlvs: vec![cb.to_tlv(true).unwrap()],
    }
    .to_tlv(true)
    .unwrap()
}

fn find_type(tlvs: &[RawTlv], t: u16) -> Option<&RawTlv> {
    tlvs.iter().find(|x| x.tlv_type == t)
}

// ---- Happy paths ----

#[test]
fn machine_session_full_success_with_issued_mat() {
    let imsk = imsk();
    let inner = ScriptedInner::new(vec![
        InnerStep::Respond(b"client-hello".to_vec()),
        InnerStep::Done(imsk.clone()),
    ]);
    let cfg = SessionConfig {
        identity: Identity::Machine,
        mat_vendor_id: VENDOR_ID,
        mat_to_present: None,
    };
    let mut s = TeapSession::new(cfg, &seed(), Box::new(RefSha384), Box::new(inner)).unwrap();

    // Msg 1: Identity-Type(Machine) + inner start -> peer responds inner.
    let step = s
        .step(&[IdentityType::Machine.to_tlv(true), eap_payload(b"start")])
        .unwrap();
    let Step::Continue(out) = step else {
        panic!("expected Continue, got {step:?}")
    };
    let ep = find_type(&out, type_id::EAP_PAYLOAD).expect("inner response");
    assert_eq!(EapPayloadTlv::from_value(&ep.value).eap, b"client-hello");

    // Msg 2: inner finishes -> IMSK captured, nothing to send yet.
    let step = s.step(&[eap_payload(b"server-finished")]).unwrap();
    assert_eq!(step, Step::Continue(vec![]));

    // Msg 3: server Intermediate-Result(Success) + Crypto-Binding(request).
    let cmk = server_cmk(&imsk);
    let cb = server_request_cb(&cmk);
    let step = s.step(&[ir_success_with_cb(&cb)]).unwrap();
    let Step::Continue(out) = step else {
        panic!("expected Continue, got {step:?}")
    };
    // Peer must reply with an Intermediate-Result carrying a valid Binding Response.
    let ir_raw = find_type(&out, type_id::INTERMEDIATE_RESULT).expect("IR response");
    let ir = IntermediateResultTlv::from_value(&ir_raw.value).unwrap();
    let resp_cb_raw = find_type(&ir.tlvs, type_id::CRYPTO_BINDING).expect("response CB");
    let resp_cb = CryptoBindingTlv::from_value(&resp_cb_raw.value).unwrap();
    assert_eq!(resp_cb.sub_type, CB_SUBTYPE_RESPONSE);
    assert_eq!(verify(&RefSha384, &cmk, &resp_cb), Ok(()));

    // Msg 4: server Result(Success) + issued MAT -> terminal success.
    let mat = VendorSpecificTlv {
        vendor_id: VENDOR_ID,
        data: b"issued-mat-blob".to_vec(),
    };
    let step = s
        .step(&[
            ResultTlv(ResultStatus::Success).to_tlv(true),
            mat.to_tlv(true),
        ])
        .unwrap();
    match step {
        Step::Done { send, outcome } => {
            assert!(find_type(&send, type_id::RESULT).is_some());
            match outcome {
                Outcome::Success {
                    msk,
                    emsk,
                    issued_mat,
                } => {
                    assert_eq!(msk.len(), 64);
                    assert_eq!(emsk.len(), 64);
                    assert_eq!(issued_mat.as_deref(), Some(&b"issued-mat-blob"[..]));
                }
                other => panic!("expected Success, got {other:?}"),
            }
        }
        other => panic!("expected Done, got {other:?}"),
    }

    // Using the session after termination is rejected.
    assert_eq!(s.step(&[]), Err(SessionError::AlreadyTerminated));
}

#[test]
fn user_session_presents_mat_once() {
    let inner = ScriptedInner::new(vec![InnerStep::Respond(b"ch".to_vec())]);
    let cfg = SessionConfig {
        identity: Identity::User,
        mat_vendor_id: VENDOR_ID,
        mat_to_present: Some(b"stored-mat".to_vec()),
    };
    let mut s = TeapSession::new(cfg, &seed(), Box::new(RefSha384), Box::new(inner)).unwrap();

    let step = s
        .step(&[IdentityType::User.to_tlv(true), eap_payload(b"start")])
        .unwrap();
    let Step::Continue(out) = step else {
        panic!("expected Continue")
    };
    let mat = find_type(&out, type_id::VENDOR_SPECIFIC).expect("MAT presented");
    let vs = VendorSpecificTlv::from_value(&mat.value).unwrap();
    assert_eq!(vs.vendor_id, VENDOR_ID);
    assert_eq!(vs.data, b"stored-mat");

    // A second Identity-Type must not re-present the MAT.
    let step = s.step(&[IdentityType::User.to_tlv(true)]).unwrap();
    let Step::Continue(out) = step else {
        panic!("expected Continue")
    };
    assert!(find_type(&out, type_id::VENDOR_SPECIFIC).is_none());
}

// ---- Fail-closed paths ----

fn machine_session(inner: ScriptedInner) -> TeapSession {
    let cfg = SessionConfig {
        identity: Identity::Machine,
        mat_vendor_id: VENDOR_ID,
        mat_to_present: None,
    };
    TeapSession::new(cfg, &seed(), Box::new(RefSha384), Box::new(inner)).unwrap()
}

fn assert_fail(step: Step, want: FailReason) {
    match step {
        Step::Done { send, outcome } => {
            // Failure always emits a Result(Failure).
            let r = find_type(&send, type_id::RESULT).expect("failure Result");
            assert_eq!(
                ResultTlv::from_value(&r.value).unwrap().0,
                ResultStatus::Failure
            );
            assert_eq!(outcome, Outcome::Failure(want));
        }
        other => panic!("expected Done(Failure), got {other:?}"),
    }
}

#[test]
fn identity_mismatch_fails_closed() {
    let inner = ScriptedInner::new(vec![]);
    let mut s = machine_session(inner);
    // Machine session, but server asks for User identity.
    let step = s.step(&[IdentityType::User.to_tlv(true)]).unwrap();
    assert_fail(step, FailReason::IdentityMismatch);
}

#[test]
fn inner_failure_fails_closed() {
    let inner = ScriptedInner::new(vec![InnerStep::Failed]);
    let mut s = machine_session(inner);
    let step = s.step(&[eap_payload(b"start")]).unwrap();
    assert_fail(step, FailReason::InnerFailed);
}

#[test]
fn intermediate_result_success_without_crypto_binding_fails_closed() {
    let inner = ScriptedInner::new(vec![InnerStep::Done(imsk())]);
    let mut s = machine_session(inner);
    s.step(&[eap_payload(b"start")]).unwrap(); // capture IMSK

    // IR(Success) with NO crypto-binding.
    let ir = IntermediateResultTlv {
        status: ResultStatus::Success,
        tlvs: vec![],
    }
    .to_tlv(true)
    .unwrap();
    let step = s.step(&[ir]).unwrap();
    assert_fail(step, FailReason::MissingCryptoBinding);
}

#[test]
fn tampered_crypto_binding_fails_closed() {
    let inner = ScriptedInner::new(vec![InnerStep::Done(imsk())]);
    let mut s = machine_session(inner);
    s.step(&[eap_payload(b"start")]).unwrap();

    // CB sealed under the WRONG key (different IMSK) -> verify must fail.
    let wrong_cmk = server_cmk(&[0xAB; 32]);
    let cb = server_request_cb(&wrong_cmk);
    let step = s.step(&[ir_success_with_cb(&cb)]).unwrap();
    match step {
        Step::Done {
            outcome: Outcome::Failure(FailReason::CryptoBinding(_)),
            ..
        } => {}
        other => panic!("expected CryptoBinding failure, got {other:?}"),
    }
}

#[test]
fn result_success_before_crypto_binding_fails_closed() {
    let inner = ScriptedInner::new(vec![]);
    let mut s = machine_session(inner);
    // Result(Success) with no prior inner method / crypto-binding.
    let step = s
        .step(&[ResultTlv(ResultStatus::Success).to_tlv(true)])
        .unwrap();
    assert_fail(step, FailReason::MissingCryptoBinding);
}

#[test]
fn server_result_failure_fails_closed() {
    let inner = ScriptedInner::new(vec![]);
    let mut s = machine_session(inner);
    let step = s
        .step(&[ResultTlv(ResultStatus::Failure).to_tlv(true)])
        .unwrap();
    assert_fail(step, FailReason::ServerFailure);
}

#[test]
fn duplicate_critical_tlv_fails_closed() {
    let inner = ScriptedInner::new(vec![]);
    let mut s = machine_session(inner);
    let step = s
        .step(&[
            ResultTlv(ResultStatus::Success).to_tlv(true),
            ResultTlv(ResultStatus::Failure).to_tlv(true),
        ])
        .unwrap();
    assert_fail(step, FailReason::MalformedMessage);
}

#[test]
fn non_mandatory_critical_tlv_fails_closed() {
    let inner = ScriptedInner::new(vec![]);
    let mut s = machine_session(inner);
    let step = s
        .step(&[ResultTlv(ResultStatus::Success).to_tlv(false)])
        .unwrap();
    assert_fail(step, FailReason::MalformedMessage);
}

#[test]
fn bad_imsk_length_fails_closed() {
    let inner = ScriptedInner::new(vec![InnerStep::Done(vec![0u8; 16])]);
    let mut s = machine_session(inner);
    let step = s.step(&[eap_payload(b"start")]).unwrap();
    assert_fail(step, FailReason::BadImsk);
}

#[test]
fn crypto_binding_wrong_subtype_fails_closed() {
    let inner = ScriptedInner::new(vec![InnerStep::Done(imsk())]);
    let mut s = machine_session(inner);
    s.step(&[eap_payload(b"start")]).unwrap();

    // A correctly-MAC'd CB, but typed as a Binding RESPONSE (not Request).
    let cmk = server_cmk(&imsk());
    let mut cb = CryptoBindingTlv {
        version: 1,
        received_version: 1,
        sub_type: CB_SUBTYPE_RESPONSE,
        nonce: [0x77; 32],
        emsk_compound_mac: vec![],
        msk_compound_mac: vec![],
    };
    seal(&RefSha384, &cmk, &mut cb).unwrap();
    let step = s.step(&[ir_success_with_cb(&cb)]).unwrap();
    assert_fail(step, FailReason::BadCryptoBindingFields);
}

#[test]
fn user_session_does_not_capture_issued_mat() {
    let imsk = imsk();
    let inner = ScriptedInner::new(vec![InnerStep::Done(imsk.clone())]);
    let cfg = SessionConfig {
        identity: Identity::User,
        mat_vendor_id: VENDOR_ID,
        mat_to_present: None,
    };
    let mut s = TeapSession::new(cfg, &seed(), Box::new(RefSha384), Box::new(inner)).unwrap();

    s.step(&[IdentityType::User.to_tlv(true), eap_payload(b"start")])
        .unwrap();
    let cmk = server_cmk(&imsk);
    let cb = server_request_cb(&cmk);
    s.step(&[ir_success_with_cb(&cb)]).unwrap();

    // Server sends a MAT in the user session — it MUST be ignored.
    let mat = VendorSpecificTlv {
        vendor_id: VENDOR_ID,
        data: b"planted".to_vec(),
    };
    let step = s
        .step(&[
            ResultTlv(ResultStatus::Success).to_tlv(true),
            mat.to_tlv(true),
        ])
        .unwrap();
    match step {
        Step::Done {
            outcome: Outcome::Success { issued_mat, .. },
            ..
        } => {
            assert_eq!(issued_mat, None);
        }
        other => panic!("expected user success, got {other:?}"),
    }
}
