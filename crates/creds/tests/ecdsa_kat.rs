//! Known-answer tests for the raw `r||s` -> DER ECDSA conversion (the CNG path).
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use creds::ecdsa::{P256_COORD_LEN, P384_COORD_LEN, raw_to_der};
use creds::error::CredError;

/// Build a `coord_len`-byte big-endian value with `tail` as the low bytes.
fn coord(coord_len: usize, tail: &[u8]) -> Vec<u8> {
    let mut v = vec![0u8; coord_len - tail.len()];
    v.extend_from_slice(tail);
    v
}

#[test]
fn small_values_encode_minimally() {
    // r = 5, s = 128 (0x80 -> needs a 0x00 sign prefix).
    let mut raw = coord(P256_COORD_LEN, &[0x05]);
    raw.extend(coord(P256_COORD_LEN, &[0x80]));
    let der = raw_to_der(&raw, P256_COORD_LEN).unwrap();
    assert_eq!(der, [0x30, 0x07, 0x02, 0x01, 0x05, 0x02, 0x02, 0x00, 0x80]);
}

#[test]
fn zero_values_become_single_zero_octet() {
    // r = 0, s = 1.
    let mut raw = coord(P256_COORD_LEN, &[0x00]);
    raw.extend(coord(P256_COORD_LEN, &[0x01]));
    let der = raw_to_der(&raw, P256_COORD_LEN).unwrap();
    assert_eq!(der, [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01]);
}

#[test]
fn high_bit_full_width_gets_sign_prefix() {
    // r = 0xFF*32 (high bit set, no leading zeros) -> 33-byte INTEGER with 0x00.
    let mut raw = vec![0xFFu8; P256_COORD_LEN];
    raw.extend(coord(P256_COORD_LEN, &[0x01]));
    let der = raw_to_der(&raw, P256_COORD_LEN).unwrap();
    // SEQ(0x30) len = 0x21(int r:35? ) ... compute: r INTEGER = 02 21 00 FF*32 = 35 bytes,
    // s INTEGER = 02 01 01 = 3 bytes, content = 38 = 0x26.
    assert_eq!(&der[..2], &[0x30, 0x26]);
    assert_eq!(&der[2..5], &[0x02, 0x21, 0x00]);
    assert_eq!(&der[5..37], &[0xFF; 32]);
    assert_eq!(&der[37..], &[0x02, 0x01, 0x01]);
}

#[test]
fn p384_length_is_accepted() {
    let mut raw = coord(P384_COORD_LEN, &[0x07]);
    raw.extend(coord(P384_COORD_LEN, &[0x09]));
    let der = raw_to_der(&raw, P384_COORD_LEN).unwrap();
    assert_eq!(der, [0x30, 0x06, 0x02, 0x01, 0x07, 0x02, 0x01, 0x09]);
}

#[test]
fn wrong_length_and_curve_are_rejected() {
    // coord_len mismatch with raw length.
    assert_eq!(
        raw_to_der(&[0u8; 10], P256_COORD_LEN),
        Err(CredError::BadSignature)
    );
    // odd / unsupported coord_len.
    assert_eq!(raw_to_der(&[0u8; 40], 20), Err(CredError::BadSignature));
    // empty.
    assert_eq!(
        raw_to_der(&[], P256_COORD_LEN),
        Err(CredError::BadSignature)
    );
}

/// Minimal DER ECDSA decoder for round-trip validation: returns (r, s) padded
/// to `coord_len`.
fn der_to_raw(der: &[u8], coord_len: usize) -> (Vec<u8>, Vec<u8>) {
    assert_eq!(der[0], 0x30);
    let mut i = 2; // skip SEQUENCE tag + (short-form) length
    let mut read_int = || {
        assert_eq!(der[i], 0x02);
        let len = der[i + 1] as usize;
        let start = i + 2;
        let bytes = &der[start..start + len];
        i = start + len;
        // Strip a leading sign byte, then left-pad to coord_len.
        let mag = if bytes[0] == 0x00 { &bytes[1..] } else { bytes };
        let mut out = vec![0u8; coord_len - mag.len()];
        out.extend_from_slice(mag);
        out
    };
    let r = read_int();
    let s = read_int();
    (r, s)
}

#[test]
fn roundtrip_recovers_coordinates() {
    let r = coord(P384_COORD_LEN, &[0xAB, 0xCD]);
    let s = {
        let mut v = vec![0x91u8]; // high bit set
        v.extend(vec![0x22u8; P384_COORD_LEN - 1]);
        v
    };
    let mut raw = r.clone();
    raw.extend_from_slice(&s);
    let der = raw_to_der(&raw, P384_COORD_LEN).unwrap();
    let (got_r, got_s) = der_to_raw(&der, P384_COORD_LEN);
    assert_eq!(got_r, r);
    assert_eq!(got_s, s);
}
