//! Thread-safe registry of live `EAPHost` peer sessions, keyed by an opaque
//! handle.
//!
//! `EAPHost` calls into a peer method are stateless C calls that reference a
//! session by an `EAP_METHOD_SESSION_HANDLE`; the DLL keeps one process-global
//! registry and marshals each call (begin / process / get-response / get-result
//! / end) into the matching [`PeerSession`]. This type is the safe, testable core
//! that the `#[cfg(windows)]` FFI exports drive — generic over the driver so the
//! lifecycle logic is unit-tested with a fake.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use crate::session::{AuthResult, PeerSession, ProcessAction, TeapStep};

/// An opaque session handle handed to `EAPHost` (its `EAP_METHOD_SESSION_HANDLE`).
/// Never zero, so the FFI can treat 0 as "no session".
pub type SessionHandle = u64;

struct Inner<D: TeapStep> {
    next: SessionHandle,
    sessions: HashMap<SessionHandle, PeerSession<D>>,
}

/// A registry of active peer sessions.
pub struct SessionRegistry<D: TeapStep> {
    inner: Mutex<Inner<D>>,
}

impl<D: TeapStep> core::fmt::Debug for SessionRegistry<D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let live = self.with(|i| i.sessions.len());
        f.debug_struct("SessionRegistry")
            .field("live", &live)
            .finish_non_exhaustive()
    }
}

impl<D: TeapStep> Default for SessionRegistry<D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: TeapStep> SessionRegistry<D> {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                next: 1,
                sessions: HashMap::new(),
            }),
        }
    }

    /// Lock the inner state, recovering from a poisoned mutex (a panic while
    /// holding the lock leaves the data consistent here; fail open on the lock,
    /// closed on the session — never panic).
    fn with<R>(&self, f: impl FnOnce(&mut Inner<D>) -> R) -> R {
        let mut guard = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        f(&mut guard)
    }

    /// Register `session`, returning its non-zero handle.
    pub fn begin(&self, session: PeerSession<D>) -> SessionHandle {
        self.with(|i| {
            let handle = i.next;
            // Saturate rather than wrap: the registry is bounded by EndSession, so
            // exhausting u64 is unreachable, but never reuse 0 or collide.
            i.next = i.next.saturating_add(1);
            i.sessions.insert(handle, session);
            handle
        })
    }

    /// Process one inbound EAP request for `handle`. `None` if the handle is
    /// unknown (e.g. after `end`, or a stale/forged handle — fail closed).
    pub fn process(&self, handle: SessionHandle, eap_request: &[u8]) -> Option<ProcessAction> {
        self.with(|i| i.sessions.get_mut(&handle).map(|s| s.process(eap_request)))
    }

    /// Take the buffered response for `handle` (`None` if no session / no response).
    pub fn take_response(&self, handle: SessionHandle) -> Option<Vec<u8>> {
        self.with(|i| {
            i.sessions
                .get_mut(&handle)
                .and_then(PeerSession::take_response)
        })
    }

    /// The terminal result for `handle`, if the session has finished.
    pub fn result(&self, handle: SessionHandle) -> Option<AuthResult> {
        self.with(|i| i.sessions.get(&handle).and_then(|s| s.result().cloned()))
    }

    /// Whether the outer TEAP tunnel is established for `handle` (for the status
    /// tray). `None` if the handle is unknown.
    pub fn tunnel_established(&self, handle: SessionHandle) -> Option<bool> {
        self.with(|i| i.sessions.get(&handle).map(PeerSession::tunnel_established))
    }

    /// End and drop the session for `handle`. Returns whether it existed.
    pub fn end(&self, handle: SessionHandle) -> bool {
        self.with(|i| i.sessions.remove(&handle).is_some())
    }

    /// Number of live sessions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.with(|i| i.sessions.len())
    }

    /// Whether there are no live sessions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
