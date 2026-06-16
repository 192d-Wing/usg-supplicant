//! Errors for the Windows `EAPHost` integration.

/// Errors from the OS FIPS-policy gate and method registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EapHostError {
    /// The OS is not in FIPS mode (`FipsAlgorithmPolicy\Enabled` != 1).
    OsFipsDisabled,
    /// A Win32 call failed; carries the status code.
    Win32 {
        /// `WIN32_ERROR` / `HRESULT` status.
        code: u32,
    },
    /// This operation is only supported on Windows.
    NotWindows,
}

impl core::fmt::Display for EapHostError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OsFipsDisabled => {
                write!(f, "OS FIPS policy is not enabled (FipsAlgorithmPolicy)")
            }
            Self::Win32 { code } => write!(f, "Win32 error (status {code})"),
            Self::NotWindows => write!(f, "operation supported only on Windows"),
        }
    }
}

impl std::error::Error for EapHostError {}

/// Errors building a session's `TeapDriver` from its profile + credential.
///
/// The [`Credential`](BuildError::Credential) source is kept typed so the shim
/// can branch on the reason (no/ambiguous cert, no signing key, store failure) to
/// drive a UI prompt or retry. The TLS/driver sources are not `Clone`/`PartialEq`,
/// so their detail is rendered to a string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    /// Selecting the certificate or acquiring its key failed (CNG/smartcard).
    Credential(creds::error::CredError),
    /// Building the TLS client config or the inner EAP-TLS method failed.
    Tls(String),
    /// Building the TEAP driver failed.
    Driver(String),
}

impl core::fmt::Display for BuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Credential(e) => write!(f, "credential selection/acquisition failed: {e}"),
            Self::Tls(d) => write!(f, "inner TLS setup failed: {d}"),
            Self::Driver(d) => write!(f, "driver construction failed: {d}"),
        }
    }
}

impl std::error::Error for BuildError {}
