//! Shared authentication-status model + file codec.
//!
//! The `EAPHost` peer method runs as **Local System** inside the `EAPHost` service,
//! while the status tray runs in the **user session**. They can't share memory, so
//! the method *publishes* an [`AuthStatus`] to a small file under `ProgramData`
//! (Local System writes it; interactive users read it) and the tray *polls* it.
//!
//! The on-disk form is a tiny line-based `key=value` text codec — no `serde`, no
//! rigid schema coupling: unknown keys are ignored and a `version` line allows
//! forward evolution. Values are sanitized of newlines on write so each field
//! stays on one line.
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Where the authentication is in the TEAP exchange. Coarse on purpose — it drives
/// a tray icon + one-line summary, not a protocol trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthState {
    /// No session in progress.
    Idle,
    /// `BeginSession` ran; the outer TLS tunnel is handshaking.
    Connecting,
    /// The outer TEAP tunnel (server-authenticated TLS 1.3) is established.
    OuterEstablished,
    /// Inside the tunnel: the inner EAP-TLS (client-cert) exchange is running.
    InnerInProgress,
    /// Authentication completed successfully (MSK delivered).
    Authenticated,
    /// Authentication failed; see [`AuthStatus::detail`].
    Failed,
}

/// Which credential context the session authenticates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Identity {
    /// Machine session (boot): the machine certificate from `Local Machine\My`.
    Machine,
    /// User session (logon): the smartcard/user certificate from `Current User\My`.
    User,
}

/// A published snapshot of the current (or last) authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthStatus {
    /// Coarse phase of the exchange.
    pub state: AuthState,
    /// Machine vs user session.
    pub identity: Identity,
    /// Subject (or selector) of the client certificate in use.
    pub cert_subject: String,
    /// Expected EAP-server name for this session.
    pub server_name: String,
    /// Human-readable extra detail (e.g. a failure reason). May be empty.
    pub detail: String,
    /// Unix time (seconds) the snapshot was written. See [`unix_now`].
    pub updated_unix: u64,
}

impl AuthState {
    /// Stable token used in the file codec.
    #[must_use]
    pub fn as_token(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Connecting => "connecting",
            Self::OuterEstablished => "outer-established",
            Self::InnerInProgress => "inner-in-progress",
            Self::Authenticated => "authenticated",
            Self::Failed => "failed",
        }
    }

    fn from_token(s: &str) -> Option<Self> {
        Some(match s {
            "idle" => Self::Idle,
            "connecting" => Self::Connecting,
            "outer-established" => Self::OuterEstablished,
            "inner-in-progress" => Self::InnerInProgress,
            "authenticated" => Self::Authenticated,
            "failed" => Self::Failed,
            _ => return None,
        })
    }

    /// One-line human label for a tray tooltip / summary line.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Idle => "Idle",
            Self::Connecting => "Connecting (outer tunnel)…",
            Self::OuterEstablished => "Outer TEAP tunnel established",
            Self::InnerInProgress => "Inner EAP-TLS in progress…",
            Self::Authenticated => "Authenticated",
            Self::Failed => "Authentication failed",
        }
    }

    /// Short bold headline for a toast / window title line.
    #[must_use]
    pub fn headline(self) -> &'static str {
        match self {
            Self::Authenticated => "Authenticated",
            Self::Failed => "Authentication failed",
            Self::Idle => "usg-TEAP",
            Self::Connecting | Self::OuterEstablished | Self::InnerInProgress => "Authenticating…",
        }
    }

    /// `(outer, inner)` phase words derived from the coarse state, for the two-line
    /// outer-tunnel / inner-EAP summary shown in the menu, toast, and window.
    #[must_use]
    pub fn outer_inner(self) -> (&'static str, &'static str) {
        match self {
            Self::Idle => ("—", "—"),
            Self::Connecting => ("in progress", "waiting"),
            Self::OuterEstablished => ("established", "waiting"),
            Self::InnerInProgress => ("established", "in progress"),
            Self::Authenticated => ("established", "authenticated"),
            Self::Failed => ("see detail", "see detail"),
        }
    }
}

impl Identity {
    /// Stable token used in the file codec.
    #[must_use]
    pub fn as_token(self) -> &'static str {
        match self {
            Self::Machine => "machine",
            Self::User => "user",
        }
    }

    fn from_token(s: &str) -> Option<Self> {
        match s {
            "machine" => Some(Self::Machine),
            "user" => Some(Self::User),
            _ => None,
        }
    }

    /// "Machine" / "User" label for the session identity.
    #[must_use]
    pub fn display_name(self) -> &'static str {
        match self {
            Self::Machine => "Machine",
            Self::User => "User",
        }
    }
}

/// `v`, or an em dash when it's empty — for rendering possibly-empty status fields.
#[must_use]
pub fn dash(v: &str) -> &str {
    if v.is_empty() { "—" } else { v }
}

fn one_line(s: &str) -> String {
    s.chars()
        .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
        .collect()
}

impl AuthStatus {
    /// Serialize to the on-disk `key=value` text form.
    #[must_use]
    pub fn encode(&self) -> String {
        format!(
            "version=1\nstate={}\nidentity={}\ncert_subject={}\nserver_name={}\ndetail={}\nupdated_unix={}\n",
            self.state.as_token(),
            self.identity.as_token(),
            one_line(&self.cert_subject),
            one_line(&self.server_name),
            one_line(&self.detail),
            self.updated_unix,
        )
    }

    /// Parse the on-disk form. Tolerant: unknown keys are ignored; returns `None`
    /// only if the required `state`/`identity` are missing or unrecognized.
    #[must_use]
    pub fn decode(text: &str) -> Option<Self> {
        let mut state = None;
        let mut identity = None;
        let mut cert_subject = String::new();
        let mut server_name = String::new();
        let mut detail = String::new();
        let mut updated_unix = 0u64;
        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            match key {
                "state" => state = AuthState::from_token(value),
                "identity" => identity = Identity::from_token(value),
                "cert_subject" => cert_subject = value.to_string(),
                "server_name" => server_name = value.to_string(),
                "detail" => detail = value.to_string(),
                "updated_unix" => updated_unix = value.parse().unwrap_or(0),
                _ => {}
            }
        }
        Some(Self {
            state: state?,
            identity: identity?,
            cert_subject,
            server_name,
            detail,
            updated_unix,
        })
    }
}

/// Current Unix time in seconds (0 before the epoch / on a clock error).
#[must_use]
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The status file path: `%ProgramData%\usg-supplicant\status` on Windows.
///
/// `ProgramData` is a fixed system location Local System can write and interactive
/// users can read. On Windows we **don't** fall back to a temp dir if the variable
/// is somehow unset — the Local System writer and the user-session reader must
/// resolve the *same* path, and per-identity temp dirs diverge. Non-Windows
/// (dev/tests) uses the temp dir, where writer and reader share one environment.
#[must_use]
pub fn status_file_path() -> PathBuf {
    let dir = {
        #[cfg(windows)]
        {
            std::env::var_os("ProgramData")
                .map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from)
        }
        #[cfg(not(windows))]
        {
            std::env::temp_dir()
        }
    };
    dir.join("usg-supplicant").join("status")
}

/// A process- and call-unique staging name, so concurrent writers never clobber a
/// shared temp file before its atomic rename.
fn unique_tmp(path: &std::path::Path) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    path.with_extension(format!("{}.{seq}.tmp", std::process::id()))
}

/// Publish `status` to [`status_file_path`], creating the directory and writing
/// atomically (unique temp file + rename) so a poller never reads a half-written
/// file and concurrent sessions don't clobber each other's staging file.
///
/// # Errors
/// Any filesystem error creating the directory or writing/renaming the file.
pub fn write_status(status: &AuthStatus) -> std::io::Result<()> {
    let path = status_file_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = unique_tmp(&path);
    std::fs::write(&tmp, status.encode())?;
    std::fs::rename(&tmp, &path)
}

/// Read and parse the published status, or `None` if absent/unreadable/unparseable.
#[must_use]
pub fn read_status() -> Option<AuthStatus> {
    let text = std::fs::read_to_string(status_file_path()).ok()?;
    AuthStatus::decode(&text)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn sample() -> AuthStatus {
        AuthStatus {
            state: AuthState::InnerInProgress,
            identity: Identity::Machine,
            cert_subject: "CN=host.example, OU=DoD".to_string(),
            server_name: "teap.example".to_string(),
            detail: String::new(),
            updated_unix: 1_700_000_000,
        }
    }

    #[test]
    fn round_trips() {
        let s = sample();
        assert_eq!(AuthStatus::decode(&s.encode()).as_ref(), Some(&s));
    }

    #[test]
    fn decode_tolerates_unknown_keys_and_blank_lines() {
        let text = "version=1\nfuture_key=whatever\n\nstate=authenticated\nidentity=user\n";
        let s = AuthStatus::decode(text).expect("decodes");
        assert_eq!(s.state, AuthState::Authenticated);
        assert_eq!(s.identity, Identity::User);
        assert!(s.cert_subject.is_empty());
    }

    #[test]
    fn decode_requires_state_and_identity() {
        assert_eq!(AuthStatus::decode("identity=machine\n"), None);
        assert_eq!(AuthStatus::decode("state=idle\n"), None);
        assert_eq!(AuthStatus::decode("state=bogus\nidentity=machine\n"), None);
    }

    #[test]
    fn presentation_helpers() {
        assert_eq!(Identity::Machine.display_name(), "Machine");
        assert_eq!(AuthState::Authenticated.headline(), "Authenticated");
        assert_eq!(
            AuthState::InnerInProgress.outer_inner(),
            ("established", "in progress")
        );
        assert_eq!(dash(""), "—");
        assert_eq!(dash("CN=host"), "CN=host");
    }

    #[test]
    fn newlines_in_values_are_flattened() {
        let mut s = sample();
        s.detail = "line1\nline2\rline3".to_string();
        let encoded = s.encode();
        // version + 6 fields, each on one physical line.
        assert_eq!(encoded.lines().count(), 7);
        assert_eq!(
            AuthStatus::decode(&encoded).unwrap().detail,
            "line1 line2 line3"
        );
    }
}
