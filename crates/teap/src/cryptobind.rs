//! Crypto-Binding compute/verify for `usg-TEAP/1.3` (SERVER-CONTRACT.md §3.4).
//!
//! Single MSK-based path: the MSK Compound MAC is `HMAC-H(CMK, CB)` where `CB`
//! is the entire encoded Crypto-Binding TLV (header + value) with **both** MAC
//! fields zeroed to the negotiated hash length. The EMSK Compound MAC field is
//! unused and MUST be all zeros.

use crate::error::CryptoBindError;
use crate::keyschedule::{Cmk, TeapMac};
use crate::tlv::CryptoBindingTlv;

/// Constant-time equality. Runs in time dependent only on `a.len()`, never on
/// content, and is independent of where the first mismatch occurs.
#[must_use]
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Serialize the Crypto-Binding TLV for MAC input: both MAC fields set to
/// `mac_len` zero octets, then encoded as a full TLV (header + value).
fn mac_input(cb: &CryptoBindingTlv, mac_len: usize) -> Result<Vec<u8>, CryptoBindError> {
    let mut zeroed = cb.clone();
    zeroed.emsk_compound_mac = vec![0u8; mac_len];
    zeroed.msk_compound_mac = vec![0u8; mac_len];
    // `mandatory = true`: the Crypto-Binding TLV is always Mandatory on the wire,
    // and the M bit is part of the MAC'd header.
    Ok(zeroed.to_tlv(true)?.encode()?)
}

/// Compute the MSK Compound MAC for `cb` under `cmk`.
///
/// The returned MAC is `HashLen` octets. `cb`'s existing MAC fields are ignored
/// (zeroed for the computation).
///
/// # Errors
/// [`CryptoBindError::Encode`] if the TLV cannot be re-encoded.
pub fn compute_msk_compound_mac(
    mac: &dyn TeapMac,
    cmk: &Cmk,
    cb: &CryptoBindingTlv,
) -> Result<Vec<u8>, CryptoBindError> {
    let input = mac_input(cb, mac.hash_len())?;
    Ok(mac.hmac(cmk.as_bytes(), &input))
}

/// Fill in `cb`'s MAC fields for sending: MSK Compound MAC computed under `cmk`,
/// EMSK Compound MAC set to zeros (unused in `usg-TEAP/1.3`).
///
/// # Errors
/// Propagates [`compute_msk_compound_mac`].
pub fn seal(
    mac: &dyn TeapMac,
    cmk: &Cmk,
    cb: &mut CryptoBindingTlv,
) -> Result<(), CryptoBindError> {
    let computed = compute_msk_compound_mac(mac, cmk, cb)?;
    cb.emsk_compound_mac = vec![0u8; mac.hash_len()];
    cb.msk_compound_mac = computed;
    Ok(())
}

/// Verify a received Crypto-Binding TLV: structural checks then a constant-time
/// MAC comparison.
///
/// Fails closed if: the MAC fields are not `HashLen`, the EMSK Compound MAC is
/// non-zero, or the MSK Compound MAC does not match.
///
/// # Errors
/// [`CryptoBindError`] variants per the failure above.
pub fn verify(mac: &dyn TeapMac, cmk: &Cmk, cb: &CryptoBindingTlv) -> Result<(), CryptoBindError> {
    let hash_len = mac.hash_len();
    if cb.msk_compound_mac.len() != hash_len {
        return Err(CryptoBindError::BadMacLen {
            expected: hash_len,
            actual: cb.msk_compound_mac.len(),
        });
    }
    if cb.emsk_compound_mac.len() != hash_len {
        return Err(CryptoBindError::BadMacLen {
            expected: hash_len,
            actual: cb.emsk_compound_mac.len(),
        });
    }
    // EMSK Compound MAC must be all zeros in this profile.
    if cb.emsk_compound_mac.iter().any(|&b| b != 0) {
        return Err(CryptoBindError::EmskMacNotZero);
    }

    let expected = compute_msk_compound_mac(mac, cmk, cb)?;
    if ct_eq(&expected, &cb.msk_compound_mac) {
        Ok(())
    } else {
        Err(CryptoBindError::MacMismatch)
    }
}
