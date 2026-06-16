//! Driver errors.

use fips_tls::error::FipsTlsError;
use teap::session::SessionError;
use teap::tlv::TlvError;

/// Errors from the TEAP authentication driver.
#[derive(Debug)]
pub enum DriverError {
    /// An EAP/TEAP framing or TLV decode error.
    Decode(TlvError),
    /// A TLS-backend error (handshake, FIPS gate, exporter).
    Tls(FipsTlsError),
    /// A Phase-2 session error.
    Session(SessionError),
    /// A protocol-sequencing violation (unexpected packet for the current phase).
    Protocol(&'static str),
}

impl core::fmt::Display for DriverError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "framing/decode error: {e}"),
            Self::Tls(e) => write!(f, "TLS error: {e}"),
            Self::Session(e) => write!(f, "session error: {e:?}"),
            Self::Protocol(m) => write!(f, "protocol violation: {m}"),
        }
    }
}

impl std::error::Error for DriverError {}

impl From<TlvError> for DriverError {
    fn from(e: TlvError) -> Self {
        Self::Decode(e)
    }
}
impl From<FipsTlsError> for DriverError {
    fn from(e: FipsTlsError) -> Self {
        Self::Tls(e)
    }
}
impl From<SessionError> for DriverError {
    fn from(e: SessionError) -> Self {
        Self::Session(e)
    }
}
