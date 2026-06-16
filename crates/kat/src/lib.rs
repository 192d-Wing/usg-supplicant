//! Shared known-answer-test (KAT) helpers and vectors.
//!
//! This crate is intended to be vendored/shared with `usg-radius` so both
//! ends validate the wire format and (later) the `usg-TEAP/1.3` key schedule
//! against byte-identical vectors.
#![forbid(unsafe_code)]

/// Error returned when a hex string cannot be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexError {
    /// The string had an odd number of hex digits.
    OddLength,
    /// A non-hex, non-whitespace character was encountered.
    BadDigit(char),
}

impl core::fmt::Display for HexError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OddLength => write!(f, "hex string has an odd number of digits"),
            Self::BadDigit(c) => write!(f, "invalid hex digit {c:?}"),
        }
    }
}

impl std::error::Error for HexError {}

/// Decode a hex string into bytes, ignoring ASCII whitespace.
///
/// # Errors
/// Returns [`HexError`] on an odd digit count or an invalid character.
pub fn from_hex(s: &str) -> Result<Vec<u8>, HexError> {
    let mut nibbles: Vec<u8> = Vec::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_whitespace() {
            continue;
        }
        let v = c.to_digit(16).ok_or(HexError::BadDigit(c))?;
        // `to_digit(16)` yields 0..=15, so the cast cannot truncate.
        nibbles.push(u8::try_from(v).unwrap_or(0));
    }
    if !nibbles.len().is_multiple_of(2) {
        return Err(HexError::OddLength);
    }
    Ok(nibbles
        .chunks_exact(2)
        .map(|pair| {
            let hi = pair.first().copied().unwrap_or(0);
            let lo = pair.get(1).copied().unwrap_or(0);
            (hi << 4) | lo
        })
        .collect())
}

/// Encode bytes as a lowercase hex string.
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        use core::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Canonical TLV wire vectors (header + value) used by `teap` codec tests
/// and by the matching `usg-radius` decoder tests.
pub mod tlv_vectors {
    /// Result TLV, Mandatory bit set, status = Success (1).
    /// `0x8003` = M-bit | type 3, length `0x0002`, value `0x0001`.
    pub const RESULT_SUCCESS: &[u8] = &[0x80, 0x03, 0x00, 0x02, 0x00, 0x01];

    /// Result TLV, Mandatory, status = Failure (2).
    pub const RESULT_FAILURE: &[u8] = &[0x80, 0x03, 0x00, 0x02, 0x00, 0x02];

    /// Identity-Type TLV, Mandatory, type = Machine (2).
    pub const IDENTITY_TYPE_MACHINE: &[u8] = &[0x80, 0x02, 0x00, 0x02, 0x00, 0x02];

    /// Identity-Type TLV, Mandatory, type = User (1).
    pub const IDENTITY_TYPE_USER: &[u8] = &[0x80, 0x02, 0x00, 0x02, 0x00, 0x01];

    /// Error TLV, Mandatory, code = 2001 (`0x000007D1`).
    pub const ERROR_2001: &[u8] = &[0x80, 0x05, 0x00, 0x04, 0x00, 0x00, 0x07, 0xD1];

    /// EAP-Payload TLV, Mandatory, carrying a minimal EAP Response/Identity.
    /// Inner EAP: code=2 (Response), id=1, len=0x0008, type=1 (Identity), "ab".
    pub const EAP_PAYLOAD_IDENTITY: &[u8] = &[
        0x80, 0x0B, 0x00, 0x08, // M | type 11 (EAP-Payload), length 8
        0x02, 0x01, 0x00, 0x08, 0x01, b'a', b'b', 0x00,
    ];
}
