//! Errors for the FIPS TLS backend.

/// Errors from configuring or running the FIPS TLS 1.3 backend.
#[derive(Debug)]
pub enum FipsTlsError {
    /// The active crypto provider is not the FIPS-validated module (the build
    /// was not compiled with `--features fips`, or the OS is not in FIPS mode).
    NotFips,
    /// A negotiated parameter fell outside the FIPS/PQ allow-list.
    DisallowedParameter {
        /// What was rejected (suite, version, or kx group).
        what: &'static str,
    },
    /// The configured expected server name is not a valid DNS name.
    BadServerName,
    /// The handshake completed but no negotiated parameters were available.
    NoNegotiatedParameters,
    /// `finish_handshake` was called while the handshake was still in progress.
    HandshakeIncomplete,
    /// A secret-producing method was called before `finish_handshake` verified
    /// the negotiated parameters (fail-closed gate).
    NotEstablished,
    /// An underlying rustls error.
    Rustls(rustls::Error),
}

impl core::fmt::Display for FipsTlsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotFips => write!(
                f,
                "crypto provider is not the FIPS-validated AWS-LC module (build without the `fips` feature)"
            ),
            Self::DisallowedParameter { what } => {
                write!(f, "negotiated {what} is outside the FIPS allow-list")
            }
            Self::BadServerName => write!(f, "expected server name is not a valid DNS name"),
            Self::NoNegotiatedParameters => {
                write!(f, "handshake produced no negotiated parameters")
            }
            Self::HandshakeIncomplete => write!(f, "handshake is not yet complete"),
            Self::NotEstablished => {
                write!(f, "tunnel not finalized: call finish_handshake first")
            }
            Self::Rustls(e) => write!(f, "rustls error: {e}"),
        }
    }
}

impl std::error::Error for FipsTlsError {}

impl From<rustls::Error> for FipsTlsError {
    fn from(e: rustls::Error) -> Self {
        Self::Rustls(e)
    }
}
