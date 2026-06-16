//! MAT record framing, store round-trips, and freshness logic.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use pac::error::PacError;
use pac::record::MatRecord;
use pac::store::{InMemoryMatStore, MatStore, fresh_ticket};

fn rec(ticket: &[u8], stored_at: u64) -> MatRecord {
    MatRecord {
        ticket: ticket.to_vec(),
        stored_at_unix: stored_at,
    }
}

#[test]
fn record_roundtrips() {
    let r = rec(b"opaque-server-ticket", 1_700_000_000);
    let bytes = r.encode().unwrap();
    assert_eq!(MatRecord::decode(&bytes).unwrap(), r);
}

#[test]
fn empty_ticket_roundtrips() {
    let r = rec(b"", 42);
    let bytes = r.encode().unwrap();
    let back = MatRecord::decode(&bytes).unwrap();
    assert_eq!(back, r);
    assert!(back.ticket.is_empty());
}

#[test]
fn decode_rejects_bad_magic_and_truncation() {
    assert!(matches!(
        MatRecord::decode(b"XXXX"),
        Err(PacError::BadRecord)
    ));
    assert!(matches!(MatRecord::decode(&[]), Err(PacError::BadRecord)));
    // Valid header claiming 10 ticket bytes, but none supplied.
    let mut bytes = b"MAT1".to_vec();
    bytes.extend_from_slice(&7u64.to_be_bytes());
    bytes.extend_from_slice(&10u32.to_be_bytes());
    assert!(matches!(
        MatRecord::decode(&bytes),
        Err(PacError::BadRecord)
    ));
}

#[test]
fn decode_rejects_trailing_garbage() {
    let mut bytes = rec(b"abc", 1).encode().unwrap();
    bytes.push(0xFF); // extra byte beyond the declared ticket
    assert!(matches!(
        MatRecord::decode(&bytes),
        Err(PacError::BadRecord)
    ));
}

#[test]
fn oversized_ticket_is_rejected() {
    let big = vec![0u8; 64 * 1024 + 1];
    assert!(matches!(
        rec(&big, 1).encode(),
        Err(PacError::TooLarge { .. })
    ));
}

#[test]
fn freshness_window() {
    let r = rec(b"t", 1000);
    assert!(r.is_fresh(1000, 60)); // same instant
    assert!(r.is_fresh(1060, 60)); // at the boundary
    assert!(!r.is_fresh(1061, 60)); // just past
    assert!(!r.is_fresh(999, 60)); // clock moved backwards -> not fresh
}

#[test]
fn in_memory_store_save_load_clear() {
    let store = InMemoryMatStore::default();
    assert!(store.load().unwrap().is_none());

    let r = rec(b"ticket-1", 5);
    store.save(&r).unwrap();
    assert_eq!(store.load().unwrap().unwrap(), r);

    store.clear().unwrap();
    assert!(store.load().unwrap().is_none());
}

#[test]
fn fresh_ticket_returns_only_when_fresh() {
    let store = InMemoryMatStore::default();
    store.save(&rec(b"present-me", 1000)).unwrap();

    assert_eq!(
        fresh_ticket(&store, 1030, 60).unwrap().as_deref(),
        Some(&b"present-me"[..])
    );
    // Stale -> not returned (server would reject anyway; we skip presenting).
    assert_eq!(fresh_ticket(&store, 2000, 60).unwrap(), None);
    // Empty store -> none.
    store.clear().unwrap();
    assert_eq!(fresh_ticket(&store, 1030, 60).unwrap(), None);
}
