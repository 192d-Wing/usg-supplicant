//! EAP packet framing (RFC 3748 §4): the outer envelope TEAP rides in.
//!
//! ```text
//! 0               1               2               3
//! | Code (1) | Identifier(1) |        Length (2)        |
//! | Type (1) |  Type-Data ...   (Request/Response only) |
//! ```
//! `Length` covers the whole packet including the 4-octet header. Success and
//! Failure carry no Type/Type-Data (Length == 4).

use crate::tlv::TlvError;

/// EAP code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapCode {
    /// Request (server → peer).
    Request,
    /// Response (peer → server).
    Response,
    /// Success.
    Success,
    /// Failure.
    Failure,
    /// Any other code value.
    Unknown(u8),
}

impl EapCode {
    #[must_use]
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Request,
            2 => Self::Response,
            3 => Self::Success,
            4 => Self::Failure,
            other => Self::Unknown(other),
        }
    }
    #[must_use]
    fn to_u8(self) -> u8 {
        match self {
            Self::Request => 1,
            Self::Response => 2,
            Self::Success => 3,
            Self::Failure => 4,
            Self::Unknown(v) => v,
        }
    }
    #[must_use]
    fn carries_type(self) -> bool {
        matches!(self, Self::Request | Self::Response)
    }
}

/// Minimum EAP packet length (Code + Id + Length).
pub const EAP_HEADER_LEN: usize = 4;

/// A decoded EAP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapPacket {
    /// EAP code.
    pub code: EapCode,
    /// Identifier (echoed between request/response).
    pub id: u8,
    /// EAP method type (present for Request/Response only).
    pub type_: Option<u8>,
    /// Type-Data (empty for Success/Failure).
    pub data: Vec<u8>,
}

impl EapPacket {
    /// Decode an EAP packet, validating the length field against the buffer.
    ///
    /// # Errors
    /// [`TlvError::TruncatedHeader`] / [`TlvError::TruncatedValue`] on short or
    /// length-mismatched input.
    pub fn decode(bytes: &[u8]) -> Result<Self, TlvError> {
        let header = bytes
            .get(0..EAP_HEADER_LEN)
            .ok_or(TlvError::TruncatedHeader {
                offset: 0,
                available: bytes.len(),
            })?;
        // header is exactly 4 octets.
        let [code, id, hi, lo] =
            <[u8; 4]>::try_from(header).map_err(|_| TlvError::TruncatedHeader {
                offset: 0,
                available: bytes.len(),
            })?;
        let declared = usize::from(u16::from_be_bytes([hi, lo]));
        // The declared length must match the buffer exactly (the NAS frames each
        // EAP packet; trailing bytes are a malformed frame).
        if declared < EAP_HEADER_LEN || declared != bytes.len() {
            return Err(TlvError::TruncatedValue {
                tlv_type: 0,
                declared,
                available: bytes.len(),
            });
        }
        let code = EapCode::from_u8(code);
        let body = bytes.get(EAP_HEADER_LEN..).unwrap_or(&[]);
        if code.carries_type() {
            let type_ = body.first().copied().ok_or(TlvError::TruncatedValue {
                tlv_type: 0,
                declared,
                available: bytes.len(),
            })?;
            let data = body.get(1..).unwrap_or(&[]).to_vec();
            Ok(Self {
                code,
                id,
                type_: Some(type_),
                data,
            })
        } else {
            // Success/Failure must be header-only.
            Ok(Self {
                code,
                id,
                type_: None,
                data: Vec::new(),
            })
        }
    }

    /// Encode to bytes.
    ///
    /// # Errors
    /// [`TlvError::ValueTooLong`] if the total length exceeds 65535.
    pub fn encode(&self) -> Result<Vec<u8>, TlvError> {
        let type_len = usize::from(self.type_.is_some());
        let total = EAP_HEADER_LEN
            .saturating_add(type_len)
            .saturating_add(self.data.len());
        let length = u16::try_from(total).map_err(|_| TlvError::ValueTooLong {
            tlv_type: 0,
            len: total,
        })?;
        let mut out = Vec::with_capacity(total);
        out.push(self.code.to_u8());
        out.push(self.id);
        out.extend_from_slice(&length.to_be_bytes());
        if let Some(t) = self.type_ {
            out.push(t);
            out.extend_from_slice(&self.data);
        }
        Ok(out)
    }
}
