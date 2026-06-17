//! Shared status-text helpers used by the tray menu, the toast, and the status
//! window, so the same status renders identically across all three surfaces.

use usg_status::{AuthState, Identity};

/// "Machine" / "User" label for the session identity.
pub fn identity_label(identity: Identity) -> &'static str {
    match identity {
        Identity::Machine => "Machine",
        Identity::User => "User",
    }
}

/// `(outer, inner)` phase words derived from the coarse state.
pub fn outer_inner(state: AuthState) -> (&'static str, &'static str) {
    match state {
        AuthState::Idle => ("—", "—"),
        AuthState::Connecting => ("in progress", "waiting"),
        AuthState::OuterEstablished => ("established", "waiting"),
        AuthState::InnerInProgress => ("established", "in progress"),
        AuthState::Authenticated => ("established", "authenticated"),
        AuthState::Failed => ("see detail", "see detail"),
    }
}

/// `v`, or an em dash when it's empty.
pub fn dash(v: &str) -> &str {
    if v.is_empty() { "—" } else { v }
}
