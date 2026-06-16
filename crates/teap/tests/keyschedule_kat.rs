//! Key-schedule + crypto-binding tests for `usg-TEAP/1.3`.
//!
//! These use an INDEPENDENT HMAC-SHA reference (`RustCrypto`, dev-only) to verify
//! the pure orchestration in `teap` against frozen vectors shared with
//! usg-radius via the `kat` crate. The reference is NOT a production dependency.
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc
)]

use hmac::{Hmac, Mac};
use kat::{from_hex, keyschedule_vectors as kv};
use sha2::{Sha256, Sha384};
use teap::cryptobind::{seal, verify};
use teap::error::{CryptoBindError, KeyScheduleError};
use teap::keyschedule::{KeySchedule, TeapMac};
use teap::tlv::CryptoBindingTlv;

/// Reference HMAC-SHA-384 (48-octet output).
struct RefSha384;
impl TeapMac for RefSha384 {
    fn hash_len(&self) -> usize {
        48
    }
    fn hmac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut m = Hmac::<Sha384>::new_from_slice(key).expect("HMAC accepts any key length");
        m.update(data);
        m.finalize().into_bytes().to_vec()
    }
}

/// Reference HMAC-SHA-256 (32-octet output).
struct RefSha256;
impl TeapMac for RefSha256 {
    fn hash_len(&self) -> usize {
        32
    }
    fn hmac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
        m.update(data);
        m.finalize().into_bytes().to_vec()
    }
}

fn seed() -> Vec<u8> {
    from_hex(kv::SEED_HEX).unwrap()
}
fn imsk() -> Vec<u8> {
    from_hex(kv::IMSK_HEX).unwrap()
}
fn fresh_cb() -> CryptoBindingTlv {
    CryptoBindingTlv {
        version: 1,
        received_version: 1,
        sub_type: 1,
        nonce: [0x10; 32],
        emsk_compound_mac: vec![],
        msk_compound_mac: vec![],
    }
}

// ---- Key-schedule KAT: orchestration must reproduce the frozen vectors ----

#[test]
fn sha384_key_schedule_matches_frozen_vectors() {
    let mut ks = KeySchedule::new(&seed()).unwrap();
    let cmk = ks.absorb_inner(&RefSha384, &imsk()).unwrap();
    assert_eq!(ks.methods(), 1);
    assert_eq!(cmk.as_bytes(), from_hex(kv::SHA384_CMK_HEX).unwrap());
    let (msk, emsk) = ks.derive_session_keys(&RefSha384).unwrap();
    assert_eq!(msk, from_hex(kv::SHA384_MSK_HEX).unwrap());
    assert_eq!(emsk, from_hex(kv::SHA384_EMSK_HEX).unwrap());
}

#[test]
fn sha256_key_schedule_matches_frozen_vectors() {
    let mut ks = KeySchedule::new(&seed()).unwrap();
    let cmk = ks.absorb_inner(&RefSha256, &imsk()).unwrap();
    assert_eq!(cmk.as_bytes(), from_hex(kv::SHA256_CMK_HEX).unwrap());
    let (msk, emsk) = ks.derive_session_keys(&RefSha256).unwrap();
    assert_eq!(msk, from_hex(kv::SHA256_MSK_HEX).unwrap());
    assert_eq!(emsk, from_hex(kv::SHA256_EMSK_HEX).unwrap());
}

#[test]
fn key_schedule_rejects_bad_lengths_and_order() {
    assert!(matches!(
        KeySchedule::new(&[0u8; 39]),
        Err(KeyScheduleError::BadSeedLen { .. })
    ));
    let mut ks = KeySchedule::new(&seed()).unwrap();
    assert!(matches!(
        ks.absorb_inner(&RefSha384, &[0u8; 31]),
        Err(KeyScheduleError::BadImskLen { .. })
    ));
    // Deriving keys before any inner method is rejected.
    let empty = KeySchedule::new(&seed()).unwrap();
    assert!(matches!(
        empty.derive_session_keys(&RefSha384),
        Err(KeyScheduleError::NoMethods)
    ));
}

// ---- Crypto-Binding ----

#[test]
fn crypto_binding_seal_matches_frozen_mac_and_zeros_emsk() {
    let mut ks = KeySchedule::new(&seed()).unwrap();
    let cmk = ks.absorb_inner(&RefSha384, &imsk()).unwrap();
    let mut cb = fresh_cb();
    seal(&RefSha384, &cmk, &mut cb).unwrap();
    assert_eq!(
        cb.msk_compound_mac,
        from_hex(kv::SHA384_CB_MSK_MAC_HEX).unwrap()
    );
    assert_eq!(cb.emsk_compound_mac, vec![0u8; 48]);
}

#[test]
fn crypto_binding_seal_then_verify_roundtrips() {
    let mut ks = KeySchedule::new(&seed()).unwrap();
    let cmk = ks.absorb_inner(&RefSha384, &imsk()).unwrap();
    let mut cb = fresh_cb();
    seal(&RefSha384, &cmk, &mut cb).unwrap();
    assert_eq!(verify(&RefSha384, &cmk, &cb), Ok(()));
}

#[test]
fn crypto_binding_verify_detects_tamper() {
    let mut ks = KeySchedule::new(&seed()).unwrap();
    let cmk = ks.absorb_inner(&RefSha384, &imsk()).unwrap();
    let mut cb = fresh_cb();
    seal(&RefSha384, &cmk, &mut cb).unwrap();

    // Flip a nonce bit -> MAC no longer covers the same content.
    let mut tampered = cb.clone();
    tampered.nonce[0] ^= 0x01;
    assert_eq!(
        verify(&RefSha384, &cmk, &tampered),
        Err(CryptoBindError::MacMismatch)
    );

    // Flip a MAC bit.
    let mut bad_mac = cb.clone();
    bad_mac.msk_compound_mac[0] ^= 0x01;
    assert_eq!(
        verify(&RefSha384, &cmk, &bad_mac),
        Err(CryptoBindError::MacMismatch)
    );
}

#[test]
fn crypto_binding_verify_rejects_wrong_key() {
    let mut ks = KeySchedule::new(&seed()).unwrap();
    let cmk = ks.absorb_inner(&RefSha384, &imsk()).unwrap();
    let mut cb = fresh_cb();
    seal(&RefSha384, &cmk, &mut cb).unwrap();

    // A different chain (different IMSK) yields a different CMK.
    let mut ks2 = KeySchedule::new(&seed()).unwrap();
    let other = ks2.absorb_inner(&RefSha384, &[0xFFu8; 32]).unwrap();
    assert_eq!(
        verify(&RefSha384, &other, &cb),
        Err(CryptoBindError::MacMismatch)
    );
}

#[test]
fn crypto_binding_verify_rejects_nonzero_emsk_and_bad_len() {
    let mut ks = KeySchedule::new(&seed()).unwrap();
    let cmk = ks.absorb_inner(&RefSha384, &imsk()).unwrap();
    let mut cb = fresh_cb();
    seal(&RefSha384, &cmk, &mut cb).unwrap();

    let mut nonzero_emsk = cb.clone();
    nonzero_emsk.emsk_compound_mac[0] = 0x01;
    assert_eq!(
        verify(&RefSha384, &cmk, &nonzero_emsk),
        Err(CryptoBindError::EmskMacNotZero)
    );

    let mut short_mac = cb.clone();
    short_mac.msk_compound_mac.truncate(47);
    assert!(matches!(
        verify(&RefSha384, &cmk, &short_mac),
        Err(CryptoBindError::BadMacLen { .. })
    ));
}

#[test]
fn verify_is_independent_of_suite_hash_len() {
    // SHA-256 path: MACs are 32 octets; SHA-384 verifier would reject length.
    let mut ks = KeySchedule::new(&seed()).unwrap();
    let cmk = ks.absorb_inner(&RefSha256, &imsk()).unwrap();
    let mut cb = fresh_cb();
    seal(&RefSha256, &cmk, &mut cb).unwrap();
    assert_eq!(cb.msk_compound_mac.len(), 32);
    assert_eq!(verify(&RefSha256, &cmk, &cb), Ok(()));
    assert!(matches!(
        verify(&RefSha384, &cmk, &cb),
        Err(CryptoBindError::BadMacLen { .. })
    ));
}
