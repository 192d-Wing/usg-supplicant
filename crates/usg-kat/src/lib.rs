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

/// Frozen `usg-TEAP/1.3` key-schedule known-answer vectors (SERVER-CONTRACT.md
/// §3). Both usg-supplicant and usg-radius MUST reproduce these exactly from an
/// independent HMAC/SHA implementation.
///
/// Inputs (shared):
/// - `session_key_seed` = octets `00 01 .. 27` (40 bytes)
/// - `IMSK`             = octets `40 41 .. 5f` (32 bytes)
/// - Crypto-Binding: version=1, `received_version`=1, `sub_type`=1, nonce = `10`×32
pub mod keyschedule_vectors {
    /// `session_key_seed` input (40 octets, `00..27`).
    pub const SEED_HEX: &str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627";
    /// `IMSK` input (32 octets, `40..5f`).
    pub const IMSK_HEX: &str = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";

    /// CMK[1] under HMAC-SHA-384 (20 octets).
    pub const SHA384_CMK_HEX: &str = "ec65075ade52c48f9001de7170e56e8a61470bf3";
    /// Exported MSK under HMAC-SHA-384 (64 octets).
    pub const SHA384_MSK_HEX: &str = "d7a3eda0be0678a6ddec2a9e997f929eacce447cb764924beaf11ce57496c698caddce5a42b2653aa01c9e03c63febf1dd4de6ad3e996a772bb9a240492717b9";
    /// Exported EMSK under HMAC-SHA-384 (64 octets).
    pub const SHA384_EMSK_HEX: &str = "c5caaeb66a6ef1e909d4cb5b8f2fcf81d0477c09d6129ee3ebd789e6e9d33fa7ee7b0a0ebea55123067f5ae858f5a81c106a4323439343036a5217add9f3ce95";
    /// MSK Compound MAC under HMAC-SHA-384 for the fixed Crypto-Binding (48 octets).
    pub const SHA384_CB_MSK_MAC_HEX: &str = "37c3886d7bf8161722f120a61dfeca831b39d2fe03f12d0aff52892126892d77db39bb1f004ed455274cee831ca8018c";

    /// CMK[1] under HMAC-SHA-256 (20 octets).
    pub const SHA256_CMK_HEX: &str = "b80e91d0c7f5c87b375db2df2a57f89143168646";
    /// Exported MSK under HMAC-SHA-256 (64 octets).
    pub const SHA256_MSK_HEX: &str = "f289867655337dc4f4d6a6098285fe2984f7c94e750ef7386ef297b85983629e8235bfc3a519878c649dc4224d008558f842b0fef9a359c00becd11ed4378f23";
    /// Exported EMSK under HMAC-SHA-256 (64 octets).
    pub const SHA256_EMSK_HEX: &str = "ec12e38d0e2648730ffd1d476a6df4325830102e556d1a478e79b49ff332d5a6a90e7c2645e2e37bcccd0f88708ccd1221724966d9332a6180cdabc26866b188";
}
