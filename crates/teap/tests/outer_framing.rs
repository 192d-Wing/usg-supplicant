//! EAP packet codec and TEAP outer fragmentation/reassembly tests.
#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::panic)]

use teap::eap::{EapCode, EapPacket};
use teap::outer::{Reassembler, TEAP_EAP_TYPE, TEAP_VERSION, TeapOuter, fragment};
use teap::tlv::TlvError;

// ---- EAP packet codec ----

#[test]
fn eap_request_roundtrips() {
    let p = EapPacket {
        code: EapCode::Request,
        id: 7,
        type_: Some(TEAP_EAP_TYPE),
        data: vec![0x21, 0xAA, 0xBB],
    };
    let bytes = p.encode().unwrap();
    // code=1, id=7, len=0x0008, type=55, data...
    assert_eq!(&bytes[..4], &[0x01, 0x07, 0x00, 0x08]);
    assert_eq!(EapPacket::decode(&bytes).unwrap(), p);
}

#[test]
fn eap_success_is_header_only() {
    let p = EapPacket {
        code: EapCode::Success,
        id: 3,
        type_: None,
        data: vec![],
    };
    let bytes = p.encode().unwrap();
    assert_eq!(bytes, [0x03, 0x03, 0x00, 0x04]);
    assert_eq!(EapPacket::decode(&bytes).unwrap(), p);
}

#[test]
fn eap_rejects_length_mismatch_and_truncation() {
    // Length says 8 but only 6 bytes present.
    let bytes = [0x01, 0x01, 0x00, 0x08, 0x37, 0x21];
    assert!(matches!(
        EapPacket::decode(&bytes),
        Err(TlvError::TruncatedValue { .. })
    ));
    // Shorter than the 4-octet header.
    assert!(matches!(
        EapPacket::decode(&[0x01, 0x01]),
        Err(TlvError::TruncatedHeader { .. })
    ));
    // Request with no type byte (length 4, code Request).
    assert!(matches!(
        EapPacket::decode(&[0x01, 0x01, 0x00, 0x04]),
        Err(TlvError::TruncatedValue { .. })
    ));
}

// ---- TEAP outer flags ----

#[test]
fn teap_start_parses() {
    // Flags = S | version1 = 0x21, no data.
    let outer = TeapOuter::parse(&[0x21]).unwrap();
    assert!(outer.start);
    assert!(!outer.more_fragments);
    assert_eq!(outer.version, TEAP_VERSION);
    assert!(outer.tls_message_length.is_none());
}

#[test]
fn teap_outer_with_length_roundtrips() {
    let outer = TeapOuter {
        more_fragments: true,
        start: false,
        version: TEAP_VERSION,
        tls_message_length: Some(300),
        data: vec![0xDE; 100],
    };
    let bytes = outer.build();
    // flags = L|M|ver = 0x80|0x40|0x01 = 0xC1, then 4-byte length 300.
    assert_eq!(bytes[0], 0xC1);
    assert_eq!(&bytes[1..5], &300u32.to_be_bytes());
    assert_eq!(TeapOuter::parse(&bytes).unwrap(), outer);
}

#[test]
fn teap_outer_parse_rejects_short_length_field() {
    // L bit set but fewer than 4 length octets.
    assert!(matches!(
        TeapOuter::parse(&[0x81, 0x00, 0x01]),
        Err(TlvError::TruncatedValue { .. })
    ));
    // Empty type-data (no flags).
    assert!(matches!(
        TeapOuter::parse(&[]),
        Err(TlvError::TruncatedValue { .. })
    ));
}

#[test]
fn ack_is_recognized() {
    let ack = TeapOuter::ack(TEAP_VERSION);
    assert!(ack.is_ack());
    assert_eq!(ack.build(), [TEAP_VERSION]);
}

// ---- Fragmentation / reassembly ----

#[test]
fn single_fragment_message_has_no_l_or_m() {
    let msg = vec![0xAB; 50];
    let frags = fragment(&msg, 1000, TEAP_VERSION);
    assert_eq!(frags.len(), 1);
    assert!(!frags[0].more_fragments);
    assert!(frags[0].tls_message_length.is_none());

    let mut r = Reassembler::new(64 * 1024);
    assert_eq!(r.push(&frags[0]).unwrap(), Some(msg));
}

#[test]
fn multi_fragment_roundtrip() {
    let msg: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
    let frags = fragment(&msg, 300, TEAP_VERSION);
    // ceil(1000/300) = 4 fragments.
    assert_eq!(frags.len(), 4);
    // First carries L + total length; only the last clears M.
    assert_eq!(frags[0].tls_message_length, Some(1000));
    assert!(frags[0].more_fragments);
    assert!(frags[1].tls_message_length.is_none());
    assert!(!frags[3].more_fragments);

    let mut r = Reassembler::new(64 * 1024);
    assert_eq!(r.push(&frags[0]).unwrap(), None);
    assert_eq!(r.push(&frags[1]).unwrap(), None);
    assert_eq!(r.push(&frags[2]).unwrap(), None);
    assert_eq!(r.push(&frags[3]).unwrap(), Some(msg));
}

#[test]
fn reassembler_rejects_oversized_declared_total() {
    let mut r = Reassembler::new(512);
    let outer = TeapOuter {
        more_fragments: true,
        start: false,
        version: TEAP_VERSION,
        tls_message_length: Some(10_000),
        data: vec![0; 10],
    };
    assert!(matches!(
        r.push(&outer),
        Err(TlvError::TooManyTlvs { limit: 512 })
    ));
}

#[test]
fn reassembler_rejects_overflow_of_accumulated_data() {
    let mut r = Reassembler::new(16);
    // No declared total; just keep feeding data past the cap.
    let frag = TeapOuter {
        more_fragments: true,
        start: false,
        version: TEAP_VERSION,
        tls_message_length: None,
        data: vec![0u8; 10],
    };
    assert_eq!(r.push(&frag).unwrap(), None);
    assert!(matches!(
        r.push(&frag),
        Err(TlvError::TooManyTlvs { limit: 16 })
    ));
}

#[test]
fn reassembler_caps_fragment_count() {
    // A peer streams empty more-fragments packets forever; must be bounded.
    let mut r = Reassembler::new(64 * 1024);
    let empty_more = TeapOuter {
        more_fragments: true,
        start: false,
        version: TEAP_VERSION,
        tls_message_length: None,
        data: vec![],
    };
    let mut err = None;
    for _ in 0..5000 {
        match r.push(&empty_more) {
            Ok(_) => {}
            Err(e) => {
                err = Some(e);
                break;
            }
        }
    }
    assert!(
        matches!(err, Some(TlvError::TooManyTlvs { .. })),
        "fragment count must be capped"
    );
}

#[test]
fn reassembler_rejects_conflicting_declared_total() {
    let mut r = Reassembler::new(64 * 1024);
    let first = TeapOuter {
        more_fragments: true,
        start: false,
        version: TEAP_VERSION,
        tls_message_length: Some(100),
        data: vec![0u8; 10],
    };
    assert_eq!(r.push(&first).unwrap(), None);
    // A later fragment re-declares a different total -> protocol violation.
    let conflicting = TeapOuter {
        more_fragments: false,
        start: false,
        version: TEAP_VERSION,
        tls_message_length: Some(200),
        data: vec![0u8; 10],
    };
    assert!(matches!(
        r.push(&conflicting),
        Err(TlvError::TruncatedValue { .. })
    ));
}

#[test]
fn reassembler_is_reusable_after_completion() {
    let mut r = Reassembler::new(64 * 1024);
    // First message: declared total 6, delivered in one final fragment.
    let m1 = TeapOuter {
        more_fragments: false,
        start: false,
        version: TEAP_VERSION,
        tls_message_length: Some(6),
        data: vec![1, 2, 3, 4, 5, 6],
    };
    assert_eq!(r.push(&m1).unwrap(), Some(vec![1, 2, 3, 4, 5, 6]));
    // Second message on the SAME reassembler: stale expected_total must not leak.
    let m2 = TeapOuter {
        more_fragments: false,
        start: false,
        version: TEAP_VERSION,
        tls_message_length: Some(2),
        data: vec![9, 9],
    };
    assert_eq!(r.push(&m2).unwrap(), Some(vec![9, 9]));
}

#[test]
fn reassembler_rejects_total_mismatch() {
    let mut r = Reassembler::new(64 * 1024);
    // Declares 100 total but delivers only 10 in a final (M=0) fragment.
    let outer = TeapOuter {
        more_fragments: false,
        start: false,
        version: TEAP_VERSION,
        tls_message_length: Some(100),
        data: vec![0u8; 10],
    };
    assert!(matches!(
        r.push(&outer),
        Err(TlvError::TruncatedValue { .. })
    ));
}
