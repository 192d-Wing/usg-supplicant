//! Codec tests for the TEAP TLV layer: known-answer vectors, round-trips, and
//! adversarial/malformed inputs. Tests may index and unwrap freely.
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc
)]

use teap::tlv::{
    CryptoBindingTlv, ErrorTlv, IdentityType, IntermediateResultTlv, NakTlv, RawTlv, ResultStatus,
    ResultTlv, TlvError, TlvReader, VendorSpecificTlv, encode_all,
};
use usg_kat::tlv_vectors as v;

// ---- Known-answer vectors (shared with usg-radius) ----

#[test]
fn kat_result_success_decodes() {
    let tlvs = TlvReader::parse_all(v::RESULT_SUCCESS).unwrap();
    assert_eq!(tlvs.len(), 1);
    assert!(tlvs[0].mandatory);
    assert_eq!(tlvs[0].tlv_type, ResultTlv::TYPE);
    assert_eq!(
        ResultTlv::from_value(&tlvs[0].value).unwrap().0,
        ResultStatus::Success
    );
}

#[test]
fn kat_result_failure_decodes() {
    let tlvs = TlvReader::parse_all(v::RESULT_FAILURE).unwrap();
    assert_eq!(
        ResultTlv::from_value(&tlvs[0].value).unwrap().0,
        ResultStatus::Failure
    );
}

#[test]
fn kat_identity_type_machine_and_user() {
    let m = TlvReader::parse_all(v::IDENTITY_TYPE_MACHINE).unwrap();
    assert_eq!(
        IdentityType::from_value(&m[0].value).unwrap(),
        IdentityType::Machine
    );
    let u = TlvReader::parse_all(v::IDENTITY_TYPE_USER).unwrap();
    assert_eq!(
        IdentityType::from_value(&u[0].value).unwrap(),
        IdentityType::User
    );
}

#[test]
fn kat_error_code_decodes() {
    let tlvs = TlvReader::parse_all(v::ERROR_2001).unwrap();
    assert_eq!(ErrorTlv::from_value(&tlvs[0].value).unwrap().0, 2001);
}

#[test]
fn kat_eap_payload_is_opaque() {
    let tlvs = TlvReader::parse_all(v::EAP_PAYLOAD_IDENTITY).unwrap();
    assert_eq!(tlvs[0].tlv_type, teap::tlv::type_id::EAP_PAYLOAD);
    assert_eq!(tlvs[0].value.len(), 8);
}

#[test]
fn kat_vectors_re_encode_canonically() {
    // Every vector is canonical (M bit set, R bit clear) so decode→encode is identity.
    for vec in [
        v::RESULT_SUCCESS,
        v::RESULT_FAILURE,
        v::IDENTITY_TYPE_MACHINE,
        v::ERROR_2001,
    ] {
        let tlvs = TlvReader::parse_all(vec).unwrap();
        assert_eq!(encode_all(&tlvs).unwrap(), vec);
    }
}

// ---- Round-trips ----

#[test]
fn roundtrip_identity_type() {
    for it in [
        IdentityType::User,
        IdentityType::Machine,
        IdentityType::Unknown(7),
    ] {
        let tlv = it.to_tlv(true);
        assert_eq!(IdentityType::from_value(&tlv.value).unwrap(), it);
    }
}

#[test]
fn roundtrip_result_status_unknown_preserved() {
    let r = ResultTlv(ResultStatus::Unknown(0xABCD));
    let tlv = r.to_tlv(true);
    assert_eq!(ResultTlv::from_value(&tlv.value).unwrap(), r);
}

#[test]
fn roundtrip_crypto_binding_sha384_macs() {
    // usg-TEAP/1.3 with SHA-384 => 48-octet compound MACs.
    let cb = CryptoBindingTlv {
        version: 1,
        received_version: 1,
        sub_type: 2,
        nonce: [0x5A; 32],
        emsk_compound_mac: vec![0xAA; 48],
        msk_compound_mac: vec![0xBB; 48],
    };
    let tlv = cb.to_tlv(true).unwrap();
    // value = 36 prefix + 2*48
    assert_eq!(tlv.value.len(), 36 + 96);
    assert_eq!(CryptoBindingTlv::from_value(&tlv.value).unwrap(), cb);
}

#[test]
fn roundtrip_intermediate_result_with_nested_crypto_binding() {
    let cb = CryptoBindingTlv {
        version: 1,
        received_version: 1,
        sub_type: 1,
        nonce: [0x01; 32],
        emsk_compound_mac: vec![0x02; 32],
        msk_compound_mac: vec![0x03; 32],
    };
    let ir = IntermediateResultTlv {
        status: ResultStatus::Success,
        tlvs: vec![cb.to_tlv(true).unwrap()],
    };
    let tlv = ir.to_tlv(true).unwrap();
    let decoded = IntermediateResultTlv::from_value(&tlv.value).unwrap();
    assert_eq!(decoded.status, ResultStatus::Success);
    assert_eq!(decoded.tlvs.len(), 1);
    assert_eq!(
        CryptoBindingTlv::from_value(&decoded.tlvs[0].value).unwrap(),
        cb
    );
}

#[test]
fn roundtrip_nak_and_vendor_specific() {
    let nak = NakTlv {
        vendor_id: 0,
        nak_type: 14,
        tlvs: vec![],
    };
    let t = nak.to_tlv(true).unwrap();
    assert_eq!(NakTlv::from_value(&t.value).unwrap(), nak);

    let vs = VendorSpecificTlv {
        vendor_id: 0x0000_9999,
        data: b"opaque-MAT".to_vec(),
    };
    let t = vs.to_tlv(true);
    assert_eq!(VendorSpecificTlv::from_value(&t.value).unwrap(), vs);
}

#[test]
fn roundtrip_max_length_value() {
    let big = RawTlv::new(false, 11, vec![0x7F; 65535]);
    let bytes = big.encode().unwrap();
    assert_eq!(bytes.len(), 4 + 65535);
    let back = TlvReader::parse_all(&bytes).unwrap();
    assert_eq!(back[0], big);
}

#[test]
fn multiple_tlvs_in_stream() {
    let mut buf = Vec::new();
    buf.extend_from_slice(v::IDENTITY_TYPE_MACHINE);
    buf.extend_from_slice(v::RESULT_SUCCESS);
    let tlvs = TlvReader::parse_all(&buf).unwrap();
    assert_eq!(tlvs.len(), 2);
    assert_eq!(tlvs[0].tlv_type, IdentityType::TYPE);
    assert_eq!(tlvs[1].tlv_type, ResultTlv::TYPE);
}

// ---- Adversarial / malformed input (must never panic) ----

#[test]
fn empty_buffer_yields_no_tlvs() {
    assert!(TlvReader::parse_all(&[]).unwrap().is_empty());
}

#[test]
fn truncated_header_is_rejected() {
    for partial in [&[0x80u8][..], &[0x80, 0x03][..], &[0x80, 0x03, 0x00][..]] {
        match TlvReader::parse_all(partial) {
            Err(TlvError::TruncatedHeader { .. }) => {}
            other => panic!("expected TruncatedHeader, got {other:?}"),
        }
    }
}

#[test]
fn truncated_value_is_rejected() {
    // Declares 8 value octets but supplies only 2.
    let bytes = [0x80, 0x0B, 0x00, 0x08, 0xAA, 0xBB];
    match TlvReader::parse_all(&bytes) {
        Err(TlvError::TruncatedValue {
            tlv_type: 11,
            declared: 8,
            available: 2,
        }) => {}
        other => panic!("expected TruncatedValue, got {other:?}"),
    }
}

#[test]
fn declared_length_overflow_does_not_panic() {
    // Max declared length 0xFFFF with no value bytes following.
    let bytes = [0x80, 0x0B, 0xFF, 0xFF];
    match TlvReader::parse_all(&bytes) {
        Err(TlvError::TruncatedValue {
            declared: 65535,
            available: 0,
            ..
        }) => {}
        other => panic!("expected TruncatedValue, got {other:?}"),
    }
}

#[test]
fn reserved_type_zero_is_rejected_on_decode_and_encode() {
    let bytes = [0x00, 0x00, 0x00, 0x00];
    assert!(matches!(
        TlvReader::parse_all(&bytes),
        Err(TlvError::ReservedType)
    ));
    let tlv = RawTlv::new(false, 0, vec![]);
    assert!(matches!(tlv.encode(), Err(TlvError::ReservedType)));
}

#[test]
fn reserved_bit_is_ignored_on_decode_and_cleared_on_encode() {
    // 0x4003 = R bit set + type 3.
    let bytes = [0x40, 0x03, 0x00, 0x02, 0x00, 0x01];
    let tlvs = TlvReader::parse_all(&bytes).unwrap();
    assert_eq!(tlvs[0].tlv_type, 3);
    assert!(!tlvs[0].mandatory);
    // Re-encoding clears the reserved bit -> canonical form differs from input.
    assert_eq!(
        tlvs[0].encode().unwrap(),
        [0x00, 0x03, 0x00, 0x02, 0x00, 0x01]
    );
}

#[test]
fn mandatory_bit_roundtrips() {
    let m = RawTlv::new(true, 3, vec![0, 1]);
    let nm = RawTlv::new(false, 3, vec![0, 1]);
    assert_eq!(m.encode().unwrap()[0] & 0x80, 0x80);
    assert_eq!(nm.encode().unwrap()[0] & 0x80, 0x00);
}

#[test]
fn type_out_of_range_is_rejected_on_encode() {
    let tlv = RawTlv::new(false, 0x4000, vec![]); // needs 15 bits
    assert!(matches!(
        tlv.encode(),
        Err(TlvError::TypeOutOfRange { tlv_type: 0x4000 })
    ));
}

#[test]
fn value_too_long_is_rejected_on_encode() {
    let tlv = RawTlv::new(false, 11, vec![0; 65536]);
    assert!(matches!(
        tlv.encode(),
        Err(TlvError::ValueTooLong { len: 65536, .. })
    ));
}

#[test]
fn fixed_length_bodies_reject_wrong_sizes() {
    assert!(IdentityType::from_value(&[0x00]).is_err());
    assert!(IdentityType::from_value(&[0x00, 0x01, 0x02]).is_err());
    assert!(ResultTlv::from_value(&[]).is_err());
    assert!(ErrorTlv::from_value(&[0x00, 0x00, 0x00]).is_err());
}

#[test]
fn crypto_binding_rejects_short_odd_and_empty_mac_region() {
    // Shorter than the 36-octet prefix.
    assert!(CryptoBindingTlv::from_value(&[0u8; 20]).is_err());
    // 36 prefix + 1 trailing octet => odd MAC region.
    assert!(CryptoBindingTlv::from_value(&[0u8; 37]).is_err());
    // 36 prefix + 0 MAC octets: empty MACs are rejected (fail closed).
    assert!(CryptoBindingTlv::from_value(&[0u8; 36]).is_err());
    // 36 prefix + 2 MAC octets (1 per MAC) is the minimum valid form.
    assert!(CryptoBindingTlv::from_value(&[0u8; 38]).is_ok());
}

#[test]
fn parse_all_enforces_tlv_count_ceiling() {
    use teap::tlv::MAX_TLVS;
    // One more minimal (4-octet) TLV than the ceiling allows.
    let mut buf = Vec::new();
    for _ in 0..=MAX_TLVS {
        buf.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]); // type 3, length 0
    }
    assert!(matches!(
        TlvReader::parse_all(&buf),
        Err(TlvError::TooManyTlvs { .. })
    ));
}

#[test]
fn crypto_binding_unequal_macs_rejected_on_encode() {
    let cb = CryptoBindingTlv {
        version: 1,
        received_version: 1,
        sub_type: 1,
        nonce: [0; 32],
        emsk_compound_mac: vec![0; 32],
        msk_compound_mac: vec![0; 48],
    };
    assert!(matches!(
        cb.to_tlv(false),
        Err(TlvError::FieldLengthMismatch { .. })
    ));
}

#[test]
fn intermediate_result_trailing_partial_tlv_is_rejected() {
    // status(2) ok, then a partial nested TLV header.
    let body = [0x00, 0x01, 0x80, 0x0E, 0x00]; // nested header truncated
    assert!(IntermediateResultTlv::from_value(&body).is_err());
}
