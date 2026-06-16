//! TEAP TLV framing (RFC 7170 §4.2) and typed bodies.
//!
//! Layering:
//! - [`raw`] — the generic `M|R|Type|Length|Value` frame. Security-critical;
//!   this is the only code that touches raw offsets.
//! - [`body`] — typed parsers that interpret a [`RawTlv`]'s value for the
//!   specific TLVs the supplicant produces/consumes.
//! - [`types`] — the TLV type-number registry.

mod body;
mod error;
mod raw;
mod types;

pub use body::{
    CryptoBindingTlv, EapPayloadTlv, ErrorTlv, IdentityType, IntermediateResultTlv, NakTlv,
    ResultStatus, ResultTlv, VendorSpecificTlv,
};
pub use error::{LenReq, TlvError};
pub use raw::{
    HEADER_LEN, MANDATORY_BIT, MAX_NESTING_DEPTH, MAX_TLVS, RESERVED_BIT, RawTlv, TYPE_MASK,
    TlvReader, encode_all,
};
pub use types::type_id;
