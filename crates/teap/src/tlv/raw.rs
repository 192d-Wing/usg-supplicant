//! The generic TEAP TLV frame: `M|R|Type(14) | Length(16) | Value`.
//!
//! This is the only module that manipulates raw byte offsets, so all
//! bounds-checking lives here. Reads use `.get()` (never indexing) and
//! length arithmetic is checked, so no input can panic or over-read.

use super::error::TlvError;

/// Octets in a TLV header (flags+type = 2, length = 2).
pub const HEADER_LEN: usize = 4;
/// Mandatory (M) bit within the 16-bit flags+type word.
pub const MANDATORY_BIT: u16 = 0x8000;
/// Reserved (R) bit. Sent as 0, ignored on receipt.
pub const RESERVED_BIT: u16 = 0x4000;
/// Mask selecting the 14-bit TLV type.
pub const TYPE_MASK: u16 = 0x3FFF;
/// Maximum number of TLVs [`TlvReader::parse_all`] will decode from one buffer.
/// Bounds memory/CPU on untrusted input (a buffer of empty 4-octet TLVs would
/// otherwise allocate one `RawTlv` per 4 bytes). Far above any legitimate frame.
pub const MAX_TLVS: usize = 4096;
/// Maximum nesting depth the dispatch layer MUST enforce when recursively
/// interpreting enclosed TLVs (e.g. an Intermediate-Result whose value contains
/// further structured TLVs). The codec itself parses exactly one level into
/// opaque [`RawTlv`]s and never self-recurses, so it cannot overflow the stack;
/// this constant exists so the milestone-2 state machine stays bounded.
pub const MAX_NESTING_DEPTH: usize = 16;

/// A decoded TLV with its value still opaque.
///
/// The Reserved bit is not retained: per RFC 7170 it is ignored on receipt
/// and sent as 0, so encoding a decoded TLV is canonical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawTlv {
    /// Whether the Mandatory (M) bit is set.
    pub mandatory: bool,
    /// The 14-bit TLV type.
    pub tlv_type: u16,
    /// The raw value octets (length is implied by `value.len()`).
    pub value: Vec<u8>,
}

impl RawTlv {
    /// Construct a TLV. Does not validate the type range until encoding.
    #[must_use]
    pub fn new(mandatory: bool, tlv_type: u16, value: Vec<u8>) -> Self {
        Self {
            mandatory,
            tlv_type,
            value,
        }
    }

    /// Serialize this TLV onto `out`.
    ///
    /// # Errors
    /// - [`TlvError::ReservedType`] if the type is 0.
    /// - [`TlvError::TypeOutOfRange`] if the type needs more than 14 bits.
    /// - [`TlvError::ValueTooLong`] if the value exceeds 65535 octets.
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), TlvError> {
        if self.tlv_type == 0 {
            return Err(TlvError::ReservedType);
        }
        if self.tlv_type & !TYPE_MASK != 0 {
            return Err(TlvError::TypeOutOfRange {
                tlv_type: self.tlv_type,
            });
        }
        let len = u16::try_from(self.value.len()).map_err(|_| TlvError::ValueTooLong {
            tlv_type: self.tlv_type,
            len: self.value.len(),
        })?;

        let mut word = self.tlv_type & TYPE_MASK;
        if self.mandatory {
            word |= MANDATORY_BIT;
        }
        out.extend_from_slice(&word.to_be_bytes());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.value);
        Ok(())
    }

    /// Serialize this TLV to a fresh buffer.
    ///
    /// # Errors
    /// See [`RawTlv::encode_into`].
    pub fn encode(&self) -> Result<Vec<u8>, TlvError> {
        let mut out = Vec::with_capacity(HEADER_LEN.saturating_add(self.value.len()));
        self.encode_into(&mut out)?;
        Ok(out)
    }
}

/// A forward-only cursor that decodes a sequence of TLVs from a buffer.
#[derive(Debug)]
pub struct TlvReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> TlvReader<'a> {
    /// Wrap a buffer for decoding.
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Octets not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Whether the whole buffer has been consumed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// Decode the next TLV, advancing the cursor.
    ///
    /// # Errors
    /// - [`TlvError::TruncatedHeader`] / [`TlvError::TruncatedValue`] on short input.
    /// - [`TlvError::ReservedType`] if a type-0 TLV is encountered.
    pub fn next_tlv(&mut self) -> Result<RawTlv, TlvError> {
        // Parse the fixed 4-octet header directly. Destructuring the array
        // avoids any fallback coercion that could mask a short read.
        let [b0, b1, b2, b3] = self
            .buf
            .get(self.pos..self.pos.saturating_add(HEADER_LEN))
            .and_then(|s| <[u8; HEADER_LEN]>::try_from(s).ok())
            .ok_or(TlvError::TruncatedHeader {
                offset: self.pos,
                available: self.remaining(),
            })?;

        let word = u16::from_be_bytes([b0, b1]);
        let declared = usize::from(u16::from_be_bytes([b2, b3]));

        let mandatory = word & MANDATORY_BIT != 0;
        let tlv_type = word & TYPE_MASK;
        if tlv_type == 0 {
            return Err(TlvError::ReservedType);
        }

        let value_start = self.pos.saturating_add(HEADER_LEN);
        let value_end = value_start.saturating_add(declared);
        let value = self
            .buf
            .get(value_start..value_end)
            .ok_or(TlvError::TruncatedValue {
                tlv_type,
                declared,
                available: self.buf.len().saturating_sub(value_start),
            })?;

        self.pos = value_end;
        Ok(RawTlv {
            mandatory,
            tlv_type,
            value: value.to_vec(),
        })
    }

    /// Decode every TLV until the buffer is exhausted.
    ///
    /// Strict: a trailing partial TLV is an error, not a silent truncation.
    ///
    /// # Errors
    /// Propagates the first [`TlvError`] from [`TlvReader::next_tlv`].
    pub fn parse_all(buf: &'a [u8]) -> Result<Vec<RawTlv>, TlvError> {
        let mut reader = Self::new(buf);
        let mut tlvs = Vec::new();
        while !reader.is_empty() {
            if tlvs.len() >= MAX_TLVS {
                return Err(TlvError::TooManyTlvs { limit: MAX_TLVS });
            }
            tlvs.push(reader.next_tlv()?);
        }
        Ok(tlvs)
    }
}

/// Encode a slice of TLVs back-to-back.
///
/// # Errors
/// Propagates the first encoding error.
pub fn encode_all(tlvs: &[RawTlv]) -> Result<Vec<u8>, TlvError> {
    let mut out = Vec::new();
    for tlv in tlvs {
        tlv.encode_into(&mut out)?;
    }
    Ok(out)
}
