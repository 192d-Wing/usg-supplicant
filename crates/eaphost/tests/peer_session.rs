//! `EAPHost` call-sequence logic of `PeerSession`, exercised with a scripted fake
//! driver (no live TLS server needed — the real driver is covered end-to-end by
//! the supplicant crate's `full_session` test).
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use std::collections::VecDeque;

use eaphost::session::{AuthResult, PeerSession, ProcessAction, SessionKind, TeapStep};
use supplicant::driver::DriverStep;
use supplicant::error::DriverError;
use teap::session::{FailReason, Outcome};
use zeroize::Zeroizing;

/// A driver that replays a scripted list of steps; once exhausted it errors, so
/// an unexpected extra `step` call would surface as a failure rather than pass.
struct FakeDriver {
    steps: VecDeque<Result<DriverStep, DriverError>>,
}
impl FakeDriver {
    fn new(steps: Vec<Result<DriverStep, DriverError>>) -> Self {
        Self {
            steps: steps.into(),
        }
    }
}
impl TeapStep for FakeDriver {
    fn step(&mut self, _eap_request: &[u8]) -> Result<DriverStep, DriverError> {
        self.steps
            .pop_front()
            .unwrap_or(Err(DriverError::Protocol("fake exhausted")))
    }
}

fn success(msk: Vec<u8>, issued_mat: Option<Vec<u8>>) -> DriverStep {
    DriverStep::Finished {
        send: None,
        outcome: Outcome::Success {
            msk: Zeroizing::new(msk),
            emsk: Zeroizing::new(vec![0u8; 64]),
            issued_mat,
        },
    }
}

#[test]
fn buffers_each_response_then_captures_success_msk() {
    let mat = vec![0xAB; 8];
    let driver = FakeDriver::new(vec![
        Ok(DriverStep::Respond(b"client-hello".to_vec())),
        Ok(DriverStep::Respond(b"flight-2".to_vec())),
        Ok(success(vec![0x11; 64], Some(mat.clone()))),
    ]);
    let mut s = PeerSession::new(SessionKind::Machine, driver);
    assert_eq!(s.kind(), SessionKind::Machine);

    assert_eq!(s.process(b"req"), ProcessAction::Respond);
    assert_eq!(s.take_response().as_deref(), Some(&b"client-hello"[..]));
    // The response is consumed exactly once.
    assert_eq!(s.take_response(), None);
    assert!(!s.is_finished());

    assert_eq!(s.process(b"req"), ProcessAction::Respond);
    assert_eq!(s.take_response().as_deref(), Some(&b"flight-2"[..]));

    assert_eq!(s.process(b"req"), ProcessAction::Finished);
    assert!(s.is_finished());
    match s.result() {
        Some(AuthResult::Success { msk, issued_mat }) => {
            assert_eq!(msk.len(), 64);
            assert_eq!(issued_mat.as_deref(), Some(&mat[..]));
        }
        other => panic!("expected Success, got {other:?}"),
    }
}

#[test]
fn driver_error_fails_closed() {
    let driver = FakeDriver::new(vec![Err(DriverError::Protocol("boom"))]);
    let mut s = PeerSession::new(SessionKind::User, driver);

    assert_eq!(s.process(b"req"), ProcessAction::Finished);
    assert!(s.is_finished());
    assert!(matches!(s.result(), Some(AuthResult::Failure(_))));
    // No response packet is queued for a failed step.
    assert_eq!(s.take_response(), None);
}

#[test]
fn server_failure_outcome_maps_to_failure() {
    let driver = FakeDriver::new(vec![Ok(DriverStep::Finished {
        send: None,
        outcome: Outcome::Failure(FailReason::ServerFailure),
    })]);
    let mut s = PeerSession::new(SessionKind::Machine, driver);
    assert_eq!(s.process(b"req"), ProcessAction::Finished);
    assert_eq!(
        s.result(),
        Some(&AuthResult::Failure(FailReason::ServerFailure))
    );
}

#[test]
fn final_flight_on_finish_is_still_sendable() {
    // A terminal step that also carries a last packet to send.
    let driver = FakeDriver::new(vec![Ok(DriverStep::Finished {
        send: Some(b"final".to_vec()),
        outcome: Outcome::Success {
            msk: Zeroizing::new(vec![0x22; 64]),
            emsk: Zeroizing::new(vec![0u8; 64]),
            issued_mat: None,
        },
    })]);
    let mut s = PeerSession::new(SessionKind::Machine, driver);

    assert_eq!(s.process(b"req"), ProcessAction::Finished);
    assert_eq!(s.take_response().as_deref(), Some(&b"final"[..]));
    assert!(matches!(s.result(), Some(AuthResult::Success { .. })));
}

#[test]
fn ignores_packets_after_terminal_and_stops_driving() {
    let driver = FakeDriver::new(vec![Ok(success(vec![0x33; 64], None))]);
    let mut s = PeerSession::new(SessionKind::Machine, driver);

    assert_eq!(s.process(b"req"), ProcessAction::Finished);
    let first = s.result().cloned();

    // Further packets are inert: the terminal short-circuit returns before
    // touching the driver, so the result is unchanged (the fake has no steps
    // left and would error if it were called).
    assert_eq!(s.process(b"late"), ProcessAction::Finished);
    assert_eq!(s.result().cloned(), first);
}
