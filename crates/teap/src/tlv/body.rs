//! Typed bodies for the TLVs this supplicant produces and consumes.
//!
//! Each type knows its [`type_id`] and converts to/from a [`RawTlv`]. Parsing
//! validates *structure* (fixed-field sizes) only; semantic checks (version
//! numbers, sub-types, MAC verification) belong to the crypto layer.

use super::error::{LenReq, TlvError};
use super::raw::{RawTlv, TlvReader};
use super::types::type_id;

/// Read a big-endian `u16` at `off` within `body`.
fn u16_at(body: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    let arr: [u8; 2] = body.get(off..end)?.try_into().ok()?;
    Some(u16::from_be_bytes(arr))
}

/// Read a big-endian `u32` at `off` within `body`.
fn u32_at(body: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let arr: [u8; 4] = body.get(off..end)?.try_into().ok()?;
    Some(u32::from_be_bytes(arr))
}

/// Result / Intermediate-Result status code (2 octets on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultStatus {
    /// Status 1.
    Success,
    /// Status 2.
    Failure,
    /// Any other value, preserved for round-tripping and explicit rejection.
    Unknown(u16),
}

impl ResultStatus {
    #[must_use]
    fn from_u16(v: u16) -> Self {
        match v {
            1 => Self::Success,
            2 => Self::Failure,
            other => Self::Unknown(other),
        }
    }

    #[must_use]
    fn to_u16(self) -> u16 {
        match self {
            Self::Success => 1,
            Self::Failure => 2,
            Self::Unknown(v) => v,
        }
    }
}

/// Identity-Type TLV body (2 octets): which identity the server is requesting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityType {
    /// Identity-Type 1.
    User,
    /// Identity-Type 2.
    Machine,
    /// Any other value, preserved for round-tripping.
    Unknown(u16),
}

impl IdentityType {
    /// The TLV type number for Identity-Type.
    pub const TYPE: u16 = type_id::IDENTITY_TYPE;

    /// Parse from a raw value.
    ///
    /// # Errors
    /// [`TlvError::BadBodyLength`] unless the body is exactly 2 octets.
    pub fn from_value(body: &[u8]) -> Result<Self, TlvError> {
        let v = u16_at(body, 0)
            .filter(|_| body.len() == 2)
            .ok_or(TlvError::BadBodyLength {
                tlv_type: Self::TYPE,
                actual: body.len(),
                want: LenReq::Exact(2),
            })?;
        Ok(match v {
            1 => Self::User,
            2 => Self::Machine,
            other => Self::Unknown(other),
        })
    }

    /// Serialize to a [`RawTlv`].
    #[must_use]
    pub fn to_tlv(self, mandatory: bool) -> RawTlv {
        let v = match self {
            Self::User => 1,
            Self::Machine => 2,
            Self::Unknown(v) => v,
        };
        RawTlv::new(mandatory, Self::TYPE, v.to_be_bytes().to_vec())
    }
}

/// Result TLV body (2 octets).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResultTlv(pub ResultStatus);

impl ResultTlv {
    /// The TLV type number for Result.
    pub const TYPE: u16 = type_id::RESULT;

    /// Parse from a raw value.
    ///
    /// # Errors
    /// [`TlvError::BadBodyLength`] unless the body is exactly 2 octets.
    pub fn from_value(body: &[u8]) -> Result<Self, TlvError> {
        let v = u16_at(body, 0)
            .filter(|_| body.len() == 2)
            .ok_or(TlvError::BadBodyLength {
                tlv_type: Self::TYPE,
                actual: body.len(),
                want: LenReq::Exact(2),
            })?;
        Ok(Self(ResultStatus::from_u16(v)))
    }

    /// Serialize to a [`RawTlv`].
    #[must_use]
    pub fn to_tlv(self, mandatory: bool) -> RawTlv {
        RawTlv::new(
            mandatory,
            Self::TYPE,
            self.0.to_u16().to_be_bytes().to_vec(),
        )
    }
}

/// Error TLV body: a 4-octet error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorTlv(pub u32);

impl ErrorTlv {
    /// The TLV type number for Error.
    pub const TYPE: u16 = type_id::ERROR;

    /// Parse from a raw value.
    ///
    /// # Errors
    /// [`TlvError::BadBodyLength`] unless the body is exactly 4 octets.
    pub fn from_value(body: &[u8]) -> Result<Self, TlvError> {
        let code = u32_at(body, 0)
            .filter(|_| body.len() == 4)
            .ok_or(TlvError::BadBodyLength {
                tlv_type: Self::TYPE,
                actual: body.len(),
                want: LenReq::Exact(4),
            })?;
        Ok(Self(code))
    }

    /// Serialize to a [`RawTlv`].
    #[must_use]
    pub fn to_tlv(self, mandatory: bool) -> RawTlv {
        RawTlv::new(mandatory, Self::TYPE, self.0.to_be_bytes().to_vec())
    }
}

/// EAP-Payload TLV: an opaque inner-EAP packet. The codec does not validate
/// the inner EAP framing — that is the inner-EAP layer's responsibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapPayloadTlv {
    /// The encapsulated inner EAP packet bytes.
    pub eap: Vec<u8>,
}

impl EapPayloadTlv {
    /// The TLV type number for EAP-Payload.
    pub const TYPE: u16 = type_id::EAP_PAYLOAD;

    /// Parse from a raw value (any length, including empty).
    #[must_use]
    pub fn from_value(body: &[u8]) -> Self {
        Self { eap: body.to_vec() }
    }

    /// Serialize to a [`RawTlv`].
    #[must_use]
    pub fn to_tlv(&self, mandatory: bool) -> RawTlv {
        RawTlv::new(mandatory, Self::TYPE, self.eap.clone())
    }
}

/// Intermediate-Result TLV: a status plus any enclosed TLVs (typically a
/// Crypto-Binding TLV for the just-completed inner method).
///
/// SECURITY (milestone 2): a `Success` status with **no** enclosed
/// Crypto-Binding TLV is structurally valid here but must be rejected by the
/// state machine — accepting a success without its crypto-binding would be a
/// fail-open. The codec only guarantees structure; presence is policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntermediateResultTlv {
    /// Result of the inner method.
    pub status: ResultStatus,
    /// Enclosed TLVs (parsed but not interpreted here).
    pub tlvs: Vec<RawTlv>,
}

impl IntermediateResultTlv {
    /// The TLV type number for Intermediate-Result.
    pub const TYPE: u16 = type_id::INTERMEDIATE_RESULT;

    /// Parse from a raw value.
    ///
    /// # Errors
    /// [`TlvError::BadBodyLength`] if shorter than the 2-octet status, or any
    /// codec error from the enclosed TLVs.
    pub fn from_value(body: &[u8]) -> Result<Self, TlvError> {
        let status = u16_at(body, 0).ok_or(TlvError::BadBodyLength {
            tlv_type: Self::TYPE,
            actual: body.len(),
            want: LenReq::AtLeast(2),
        })?;
        let rest = body.get(2..).unwrap_or(&[]);
        let tlvs = TlvReader::parse_all(rest)?;
        Ok(Self {
            status: ResultStatus::from_u16(status),
            tlvs,
        })
    }

    /// Serialize to a [`RawTlv`].
    ///
    /// # Errors
    /// Propagates encoding errors from the enclosed TLVs.
    pub fn to_tlv(&self, mandatory: bool) -> Result<RawTlv, TlvError> {
        let mut value = self.status.to_u16().to_be_bytes().to_vec();
        for tlv in &self.tlvs {
            tlv.encode_into(&mut value)?;
        }
        Ok(RawTlv::new(mandatory, Self::TYPE, value))
    }
}

/// Crypto-Binding TLV (RFC 7170 §4.2.13).
///
/// The two compound-MAC fields are equal length; their size is derived from
/// the TLV length, not fixed, so this works for any HMAC output size (e.g.
/// HMAC-SHA-384 = 48 octets under `usg-TEAP/1.3`). The codec does not verify
/// the MACs or the version/sub-type semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoBindingTlv {
    /// Protocol version.
    pub version: u8,
    /// Version the peer received.
    pub received_version: u8,
    /// Sub-type (request/response); semantics validated by the crypto layer.
    pub sub_type: u8,
    /// 32-octet nonce.
    pub nonce: [u8; 32],
    /// EMSK compound MAC.
    pub emsk_compound_mac: Vec<u8>,
    /// MSK compound MAC (equal length to `emsk_compound_mac`).
    pub msk_compound_mac: Vec<u8>,
}

impl CryptoBindingTlv {
    /// The TLV type number for Crypto-Binding.
    pub const TYPE: u16 = type_id::CRYPTO_BINDING;
    /// Fixed prefix: Reserved(1) + Version(1) + ReceivedVer(1) + SubType(1) + Nonce(32).
    const PREFIX_LEN: usize = 36;

    /// Parse from a raw value.
    ///
    /// # Errors
    /// [`TlvError::BadBodyLength`] if shorter than the 36-octet prefix, if the
    /// MAC region is empty (both compound MACs must be present and non-empty —
    /// no valid HMAC is zero-length), or if it is not evenly splittable.
    pub fn from_value(body: &[u8]) -> Result<Self, TlvError> {
        // Minimum valid body: 36-octet prefix + at least one octet per MAC.
        const MIN_LEN: usize = CryptoBindingTlv::PREFIX_LEN + 2;
        let bad = |actual: usize| TlvError::BadBodyLength {
            tlv_type: Self::TYPE,
            actual,
            want: LenReq::EvenAtLeast {
                min: MIN_LEN,
                base: Self::PREFIX_LEN,
            },
        };

        // Byte 0 is Reserved and ignored.
        let version = body.get(1).copied().ok_or_else(|| bad(body.len()))?;
        let received_version = body.get(2).copied().ok_or_else(|| bad(body.len()))?;
        let sub_type = body.get(3).copied().ok_or_else(|| bad(body.len()))?;
        let nonce_slice = body
            .get(4..Self::PREFIX_LEN)
            .ok_or_else(|| bad(body.len()))?;
        let nonce: [u8; 32] = nonce_slice.try_into().map_err(|_| bad(body.len()))?;

        let macs = body.get(Self::PREFIX_LEN..).unwrap_or(&[]);
        // Reject empty MAC region and odd splits: fail closed rather than hand
        // an empty/asymmetric MAC to the crypto layer.
        if macs.is_empty() || !macs.len().is_multiple_of(2) {
            return Err(bad(body.len()));
        }
        let half = macs.len() / 2;
        let emsk = macs.get(..half).ok_or_else(|| bad(body.len()))?;
        let msk = macs.get(half..).ok_or_else(|| bad(body.len()))?;

        Ok(Self {
            version,
            received_version,
            sub_type,
            nonce,
            emsk_compound_mac: emsk.to_vec(),
            msk_compound_mac: msk.to_vec(),
        })
    }

    /// Serialize to a [`RawTlv`].
    ///
    /// # Errors
    /// [`TlvError::FieldLengthMismatch`] if the two MAC fields differ in length.
    pub fn to_tlv(&self, mandatory: bool) -> Result<RawTlv, TlvError> {
        if self.emsk_compound_mac.len() != self.msk_compound_mac.len() {
            return Err(TlvError::FieldLengthMismatch {
                tlv_type: Self::TYPE,
                a: self.emsk_compound_mac.len(),
                b: self.msk_compound_mac.len(),
            });
        }
        let mut value = Vec::with_capacity(
            Self::PREFIX_LEN.saturating_add(self.emsk_compound_mac.len().saturating_mul(2)),
        );
        value.push(0); // Reserved
        value.push(self.version);
        value.push(self.received_version);
        value.push(self.sub_type);
        value.extend_from_slice(&self.nonce);
        value.extend_from_slice(&self.emsk_compound_mac);
        value.extend_from_slice(&self.msk_compound_mac);
        Ok(RawTlv::new(mandatory, Self::TYPE, value))
    }
}

/// NAK TLV (RFC 7170): rejects a TLV the peer cannot process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NakTlv {
    /// Vendor-Id (0 for standard TLVs).
    pub vendor_id: u32,
    /// The NAK'd TLV type.
    pub nak_type: u16,
    /// Optional enclosed TLVs.
    pub tlvs: Vec<RawTlv>,
}

impl NakTlv {
    /// The TLV type number for NAK.
    pub const TYPE: u16 = type_id::NAK;
    const PREFIX_LEN: usize = 6;

    /// Parse from a raw value.
    ///
    /// # Errors
    /// [`TlvError::BadBodyLength`] if shorter than the 6-octet prefix, or any
    /// codec error from the enclosed TLVs.
    pub fn from_value(body: &[u8]) -> Result<Self, TlvError> {
        let bad = TlvError::BadBodyLength {
            tlv_type: Self::TYPE,
            actual: body.len(),
            want: LenReq::AtLeast(Self::PREFIX_LEN),
        };
        let vendor_id = u32_at(body, 0).ok_or(bad.clone())?;
        let nak_type = u16_at(body, 4).ok_or(bad)?;
        let rest = body.get(Self::PREFIX_LEN..).unwrap_or(&[]);
        let tlvs = TlvReader::parse_all(rest)?;
        Ok(Self {
            vendor_id,
            nak_type,
            tlvs,
        })
    }

    /// Serialize to a [`RawTlv`].
    ///
    /// # Errors
    /// Propagates encoding errors from the enclosed TLVs.
    pub fn to_tlv(&self, mandatory: bool) -> Result<RawTlv, TlvError> {
        let mut value = Vec::with_capacity(Self::PREFIX_LEN);
        value.extend_from_slice(&self.vendor_id.to_be_bytes());
        value.extend_from_slice(&self.nak_type.to_be_bytes());
        for tlv in &self.tlvs {
            tlv.encode_into(&mut value)?;
        }
        Ok(RawTlv::new(mandatory, Self::TYPE, value))
    }
}

/// Vendor-Specific TLV: Vendor-Id (4 octets) + opaque vendor data.
///
/// This is the carrier for the Machine Authorization Ticket (MAT); the MAT
/// bytes are opaque to the client and live in `data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorSpecificTlv {
    /// SMI Private Enterprise Number.
    pub vendor_id: u32,
    /// Opaque vendor payload.
    pub data: Vec<u8>,
}

impl VendorSpecificTlv {
    /// The TLV type number for Vendor-Specific.
    pub const TYPE: u16 = type_id::VENDOR_SPECIFIC;
    const PREFIX_LEN: usize = 4;

    /// Parse from a raw value.
    ///
    /// # Errors
    /// [`TlvError::BadBodyLength`] if shorter than the 4-octet Vendor-Id.
    pub fn from_value(body: &[u8]) -> Result<Self, TlvError> {
        let vendor_id = u32_at(body, 0).ok_or(TlvError::BadBodyLength {
            tlv_type: Self::TYPE,
            actual: body.len(),
            want: LenReq::AtLeast(Self::PREFIX_LEN),
        })?;
        let data = body.get(Self::PREFIX_LEN..).unwrap_or(&[]).to_vec();
        Ok(Self { vendor_id, data })
    }

    /// Serialize to a [`RawTlv`].
    #[must_use]
    pub fn to_tlv(&self, mandatory: bool) -> RawTlv {
        let mut value = Vec::with_capacity(Self::PREFIX_LEN.saturating_add(self.data.len()));
        value.extend_from_slice(&self.vendor_id.to_be_bytes());
        value.extend_from_slice(&self.data);
        RawTlv::new(mandatory, Self::TYPE, value)
    }
}
