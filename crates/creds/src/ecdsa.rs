//! Convert a raw fixed-width ECDSA signature (`r || s`, IEEE P1363 — what
//! Windows CNG `NCryptSignHash` returns) into the ASN.1 DER `SEQUENCE { r, s }`
//! that TLS expects. Pure and panic-free.

use crate::error::CredError;

/// Coordinate length for P-256 (octets).
pub const P256_COORD_LEN: usize = 32;
/// Coordinate length for P-384 (octets).
pub const P384_COORD_LEN: usize = 48;

/// Encode a DER length (definite form, short or long).
fn der_len(n: usize, out: &mut Vec<u8>) {
    if n < 0x80 {
        // n < 128 fits the short form; cast cannot truncate.
        out.push(u8::try_from(n).unwrap_or(0));
        return;
    }
    let be = n.to_be_bytes();
    let first = be.iter().position(|&b| b != 0).unwrap_or(be.len());
    let trimmed = be.get(first..).unwrap_or_default();
    // Number of length octets fits in 7 bits for any usize.
    let count = u8::try_from(trimmed.len()).unwrap_or(0);
    out.push(0x80 | count);
    out.extend_from_slice(trimmed);
}

/// Encode one big-endian unsigned magnitude as a DER INTEGER.
fn der_integer(coord: &[u8], out: &mut Vec<u8>) {
    // Strip leading zero octets; an all-zero value becomes a single 0x00.
    let first = coord.iter().position(|&b| b != 0);
    let mag: &[u8] = match first {
        Some(i) => coord.get(i..).unwrap_or_default(),
        None => &[0x00],
    };
    out.push(0x02); // INTEGER tag
    let high_bit_set = mag.first().is_some_and(|&b| b & 0x80 != 0);
    if high_bit_set {
        // Prepend 0x00 so the integer stays positive.
        der_len(mag.len().saturating_add(1), out);
        out.push(0x00);
    } else {
        der_len(mag.len(), out);
    }
    out.extend_from_slice(mag);
}

/// Convert `r || s` (each `coord_len` octets, big-endian) to DER.
///
/// `coord_len` must be one of the approved curve sizes (P-256 / P-384) and
/// `raw.len()` must equal `2 * coord_len`.
///
/// # Errors
/// [`CredError::BadSignature`] if the length is wrong or the curve unsupported.
pub fn raw_to_der(raw: &[u8], coord_len: usize) -> Result<Vec<u8>, CredError> {
    if coord_len != P256_COORD_LEN && coord_len != P384_COORD_LEN {
        return Err(CredError::BadSignature);
    }
    let expected = coord_len.checked_mul(2).ok_or(CredError::BadSignature)?;
    if raw.len() != expected {
        return Err(CredError::BadSignature);
    }
    let r = raw.get(..coord_len).ok_or(CredError::BadSignature)?;
    let s = raw.get(coord_len..).ok_or(CredError::BadSignature)?;

    let mut body = Vec::with_capacity(expected.saturating_add(8));
    der_integer(r, &mut body);
    der_integer(s, &mut body);

    let mut out = Vec::with_capacity(body.len().saturating_add(4));
    out.push(0x30); // SEQUENCE tag
    der_len(body.len(), &mut out);
    out.extend_from_slice(&body);
    Ok(out)
}
