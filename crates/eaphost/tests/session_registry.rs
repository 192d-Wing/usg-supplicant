//! Lifecycle of `SessionRegistry`: handle allocation, per-handle isolation,
//! end/drop, and fail-closed behavior on unknown handles — exercised with a fake
//! driver (the real driver path is covered by supplicant's `full_session`).
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use std::collections::VecDeque;

use eaphost::session::{AuthResult, PeerSession, ProcessAction, SessionKind, TeapStep};
use eaphost::session_registry::SessionRegistry;
use supplicant::driver::DriverStep;
use supplicant::error::DriverError;
use teap::session::Outcome;
use zeroize::Zeroizing;

struct FakeDriver {
    steps: VecDeque<Result<DriverStep, DriverError>>,
}
impl TeapStep for FakeDriver {
    fn step(&mut self, _eap: &[u8]) -> Result<DriverStep, DriverError> {
        self.steps
            .pop_front()
            .unwrap_or(Err(DriverError::Protocol("fake exhausted")))
    }
    fn tunnel_established(&self) -> bool {
        false
    }
}

fn session(steps: Vec<Result<DriverStep, DriverError>>) -> PeerSession<FakeDriver> {
    PeerSession::new(
        SessionKind::Machine,
        FakeDriver {
            steps: steps.into(),
        },
    )
}

fn success(msk: u8) -> DriverStep {
    DriverStep::Finished {
        send: None,
        outcome: Outcome::Success {
            msk: Zeroizing::new(vec![msk; 64]),
            emsk: Zeroizing::new(vec![0u8; 64]),
            issued_mat: None,
        },
    }
}

#[test]
fn handles_are_unique_nonzero_and_isolated() {
    let reg = SessionRegistry::new();
    let a = reg.begin(session(vec![Ok(DriverStep::Respond(b"a1".to_vec()))]));
    let b = reg.begin(session(vec![Ok(DriverStep::Respond(b"b1".to_vec()))]));
    assert_ne!(a, 0);
    assert_ne!(b, 0);
    assert_ne!(a, b);
    assert_eq!(reg.len(), 2);

    // Each handle drives its own session.
    assert_eq!(reg.process(a, b"req"), Some(ProcessAction::Respond));
    assert_eq!(reg.take_response(a).as_deref(), Some(&b"a1"[..]));
    assert_eq!(reg.take_response(b), None); // b not processed yet
    assert_eq!(reg.process(b, b"req"), Some(ProcessAction::Respond));
    assert_eq!(reg.take_response(b).as_deref(), Some(&b"b1"[..]));
}

#[test]
fn unknown_handle_fails_closed() {
    let reg: SessionRegistry<FakeDriver> = SessionRegistry::new();
    let bogus = 999;
    assert_eq!(reg.process(bogus, b"req"), None);
    assert_eq!(reg.take_response(bogus), None);
    assert_eq!(reg.result(bogus), None);
    assert!(!reg.end(bogus));
}

#[test]
fn fetch_response_size_probe_does_not_drop_the_response() {
    use eaphost::session_registry::ResponseFetch;

    let reg = SessionRegistry::new();
    let h = reg.begin(session(vec![Ok(DriverStep::Respond(
        b"client-hello".to_vec(),
    ))]));
    assert_eq!(reg.process(h, b"req"), Some(ProcessAction::Respond));

    // First call: a too-small (size-probe) buffer must report the length and KEEP
    // the response buffered — the bug was that it consumed it here.
    match reg.fetch_response(h, 0) {
        ResponseFetch::TooSmall(len) => assert_eq!(len, b"client-hello".len()),
        other => panic!("expected TooSmall, got {other:?}"),
    }
    // Second call with a big-enough buffer: the response survived and is delivered.
    match reg.fetch_response(h, 64) {
        ResponseFetch::Taken(bytes) => assert_eq!(bytes, b"client-hello"),
        other => panic!("expected Taken, got {other:?}"),
    }
    // Now it's consumed.
    assert!(matches!(reg.fetch_response(h, 64), ResponseFetch::None));
    // Unknown handle fails closed.
    assert!(matches!(reg.fetch_response(12345, 64), ResponseFetch::None));
}

#[test]
fn end_drops_the_session_and_is_idempotent() {
    let reg = SessionRegistry::new();
    let h = reg.begin(session(vec![Ok(success(0x11))]));
    assert_eq!(reg.process(h, b"req"), Some(ProcessAction::Finished));
    assert!(matches!(reg.result(h), Some(AuthResult::Success { .. })));

    assert!(reg.end(h)); // existed
    assert!(!reg.end(h)); // already gone
    assert!(reg.is_empty());
    // After end, the handle is unknown -> fail closed.
    assert_eq!(reg.result(h), None);
}
