//! Config-blob round-trip and fail-closed parsing.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use eaphost::config::SessionConfigBlob;
use eaphost::error::ConfigError;

fn sample() -> SessionConfigBlob {
    SessionConfigBlob {
        machine: false,
        server_name: "teap.test.local".to_string(),
        mat_vendor_id: 0x0000_9999,
        max_fragment: 1024,
        selector_subject: "USG-CNG-USER".to_string(),
        roots: vec![vec![0x30, 0x82, 0x01, 0x02], vec![0xAA; 40]],
        mat: Some(vec![0xBE, 0xEF]),
    }
}

#[test]
fn round_trips() {
    let cfg = sample();
    let bytes = cfg.to_bytes();
    assert_eq!(SessionConfigBlob::from_bytes(&bytes).unwrap(), cfg);
}

#[test]
fn round_trips_machine_no_mat_no_roots() {
    let cfg = SessionConfigBlob {
        machine: true,
        server_name: "radius.example".to_string(),
        mat_vendor_id: 1,
        max_fragment: 1400,
        selector_subject: "CN=machine".to_string(),
        roots: vec![],
        mat: None,
    };
    let bytes = cfg.to_bytes();
    assert_eq!(SessionConfigBlob::from_bytes(&bytes).unwrap(), cfg);
}

#[test]
fn rejects_bad_magic() {
    assert_eq!(
        SessionConfigBlob::from_bytes(b"XXXX\x01\x00"),
        Err(ConfigError::BadMagic)
    );
}

#[test]
fn rejects_truncated() {
    let bytes = sample().to_bytes();
    // Any prefix shorter than the whole blob must fail closed, never panic.
    for n in 0..bytes.len() {
        assert!(SessionConfigBlob::from_bytes(&bytes[..n]).is_err());
    }
}

#[test]
fn rejects_trailing_data() {
    let mut bytes = sample().to_bytes();
    bytes.push(0xFF);
    assert_eq!(
        SessionConfigBlob::from_bytes(&bytes),
        Err(ConfigError::TrailingData)
    );
}
