//! Errors produced by the TLV codec. Every decode failure is one of these;
//! the codec never panics on malformed input.

/// Length requirement that a typed body failed to meet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LenReq {
    /// Body must be exactly this many octets.
    Exact(usize),
    /// Body must be at least this many octets.
    AtLeast(usize),
    /// Body must be at least `min` octets and `(len - base)` must be even
    /// (used by Crypto-Binding, whose two MAC fields are equal-length).
    EvenAtLeast {
        /// Minimum total length.
        min: usize,
        /// Fixed prefix excluded from the even-split check.
        base: usize,
    },
}

/// Codec error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlvError {
    /// Fewer than [`crate::tlv::HEADER_LEN`] octets remain for a TLV header.
    TruncatedHeader {
        /// Offset at which the truncated header begins.
        offset: usize,
        /// Octets actually available from `offset`.
        available: usize,
    },
    /// The header's declared value length exceeds the remaining buffer.
    TruncatedValue {
        /// TLV type whose value is truncated.
        tlv_type: u16,
        /// Declared value length.
        declared: usize,
        /// Octets actually available for the value.
        available: usize,
    },
    /// TLV type 0 is reserved and must not appear on the wire.
    ReservedType,
    /// A typed body did not satisfy its length requirement.
    BadBodyLength {
        /// TLV type being parsed.
        tlv_type: u16,
        /// Actual body length.
        actual: usize,
        /// The requirement that was violated.
        want: LenReq,
    },
    /// A value could not be serialized because it exceeds the 16-bit length field.
    ValueTooLong {
        /// TLV type being encoded.
        tlv_type: u16,
        /// The oversized length.
        len: usize,
    },
    /// A type number does not fit in the 14-bit TLV type field.
    TypeOutOfRange {
        /// The offending type number.
        tlv_type: u16,
    },
    /// Two fields that must be equal length were not (e.g. the Crypto-Binding MACs).
    FieldLengthMismatch {
        /// TLV type being encoded.
        tlv_type: u16,
        /// First field length.
        a: usize,
        /// Second field length.
        b: usize,
    },
    /// A buffer declared more TLVs than [`crate::tlv::MAX_TLVS`]; rejected to
    /// bound memory/CPU on untrusted input.
    TooManyTlvs {
        /// The enforced ceiling.
        limit: usize,
    },
}

impl core::fmt::Display for TlvError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TruncatedHeader { offset, available } => write!(
                f,
                "truncated TLV header at offset {offset}: {available} octet(s) available, need {}",
                crate::tlv::HEADER_LEN
            ),
            Self::TruncatedValue {
                tlv_type,
                declared,
                available,
            } => write!(
                f,
                "truncated value for TLV type {tlv_type}: declared {declared}, available {available}"
            ),
            Self::ReservedType => write!(f, "TLV type 0 is reserved"),
            Self::BadBodyLength {
                tlv_type,
                actual,
                want,
            } => {
                write!(
                    f,
                    "bad body length {actual} for TLV type {tlv_type}: requires {want:?}"
                )
            }
            Self::ValueTooLong { tlv_type, len } => {
                write!(
                    f,
                    "value length {len} exceeds 65535 for TLV type {tlv_type}"
                )
            }
            Self::TypeOutOfRange { tlv_type } => {
                write!(f, "TLV type {tlv_type} does not fit in 14 bits")
            }
            Self::FieldLengthMismatch { tlv_type, a, b } => {
                write!(f, "TLV type {tlv_type} field lengths differ: {a} vs {b}")
            }
            Self::TooManyTlvs { limit } => {
                write!(f, "buffer exceeds the {limit}-TLV ceiling")
            }
        }
    }
}

impl std::error::Error for TlvError {}
