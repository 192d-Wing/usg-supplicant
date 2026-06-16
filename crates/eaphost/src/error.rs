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
    /// Assembling the driver failed (inner TLS config/method, or the driver).
    Driver(String),
}

impl core::fmt::Display for BuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Credential(e) => write!(f, "credential selection/acquisition failed: {e}"),
            Self::Driver(d) => write!(f, "driver assembly failed: {d}"),
        }
    }
}

impl std::error::Error for BuildError {}

/// Errors parsing the `EAPHost` connection-data config blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// The blob did not start with the expected magic.
    BadMagic,
    /// The blob format version is not understood.
    BadVersion,
    /// The blob ended mid-field.
    Truncated,
    /// A length-prefixed field claimed more bytes than remain.
    TrailingData,
    /// A string field was not valid UTF-8.
    BadUtf8,
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadMagic => write!(f, "config blob has a bad magic prefix"),
            Self::BadVersion => write!(f, "config blob version not understood"),
            Self::Truncated => write!(f, "config blob is truncated"),
            Self::TrailingData => write!(f, "config blob has trailing data"),
            Self::BadUtf8 => write!(f, "config blob string field is not valid UTF-8"),
        }
    }
}

impl std::error::Error for ConfigError {}
