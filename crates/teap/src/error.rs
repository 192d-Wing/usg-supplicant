//! Error types for the TEAP crypto layer (key schedule and crypto-binding).

/// Errors from the `usg-TEAP/1.3` key schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyScheduleError {
    /// `session_key_seed` was not [`crate::keyschedule::S_IMCK_LEN`] octets.
    BadSeedLen {
        /// The wrong length supplied.
        actual: usize,
    },
    /// An inner `IMSK` was not [`crate::keyschedule::IMSK_LEN`] octets.
    BadImskLen {
        /// The wrong length supplied.
        actual: usize,
    },
    /// The injected MAC reported a zero hash length.
    BadHashLen,
    /// Requested HKDF output exceeds `255 * HashLen`.
    OutputTooLong {
        /// Requested octets.
        requested: usize,
        /// Maximum permitted.
        max: usize,
    },
    /// `derive_session_keys` was called before any inner method was absorbed.
    NoMethods,
    /// An invariant that should be impossible was violated (defensive).
    Internal,
}

impl core::fmt::Display for KeyScheduleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadSeedLen { actual } => {
                write!(f, "session_key_seed must be 40 octets, got {actual}")
            }
            Self::BadImskLen { actual } => write!(f, "IMSK must be 32 octets, got {actual}"),
            Self::BadHashLen => write!(f, "MAC reported a zero hash length"),
            Self::OutputTooLong { requested, max } => {
                write!(f, "HKDF output {requested} exceeds maximum {max}")
            }
            Self::NoMethods => write!(f, "no inner method absorbed before key export"),
            Self::Internal => write!(f, "internal key-schedule invariant violated"),
        }
    }
}

impl std::error::Error for KeyScheduleError {}

/// Errors from Crypto-Binding compute/verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoBindError {
    /// The two MAC fields are not the negotiated hash length.
    BadMacLen {
        /// Expected length (= `HashLen` of `H`).
        expected: usize,
        /// Actual length of the offending field.
        actual: usize,
    },
    /// The EMSK Compound MAC field was non-zero (unused in `usg-TEAP/1.3`).
    EmskMacNotZero,
    /// The peer's MSK Compound MAC did not match (authentication failure).
    MacMismatch,
    /// Re-encoding the Crypto-Binding TLV for MAC input failed.
    Encode(crate::tlv::TlvError),
}

impl core::fmt::Display for CryptoBindError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadMacLen { expected, actual } => {
                write!(f, "compound MAC must be {expected} octets, got {actual}")
            }
            Self::EmskMacNotZero => write!(f, "EMSK Compound MAC field must be zero"),
            Self::MacMismatch => write!(f, "compound MAC mismatch"),
            Self::Encode(e) => write!(f, "crypto-binding re-encode failed: {e}"),
        }
    }
}

impl std::error::Error for CryptoBindError {}

impl From<crate::tlv::TlvError> for CryptoBindError {
    fn from(e: crate::tlv::TlvError) -> Self {
        Self::Encode(e)
    }
}
