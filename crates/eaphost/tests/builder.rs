//! On-hardware validation of `build_driver` (`WINDOWS_DEV.md` §4.1): select a CNG
//! cert from the real store, acquire its non-exportable key, and build a
//! functional driver. Windows-only and `#[ignore]`d (needs a provisioned
//! client-auth cert). The platform-independent assembly is covered by
//! supplicant's `full_session` test, which now drives `assemble_driver` directly.
#![cfg(windows)]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use eaphost::builder::build_driver;
use rustls::RootCertStore;
use supplicant::driver::{DriverConfig, DriverStep};
use teap::eap::{EapCode, EapPacket};
use teap::outer::{TEAP_EAP_TYPE, TeapOuter};
use teap::session::Identity;

const SERVER_NAME: &str = "teap.test.local";

/// The opening EAP-Request/TEAP-Start that kicks off a session.
fn teap_start() -> Vec<u8> {
    let start = TeapOuter {
        more_fragments: false,
        start: true,
        version: 1,
        tls_message_length: None,
        data: vec![],
    };
    EapPacket {
        code: EapCode::Request,
        id: 1,
        type_: Some(TEAP_EAP_TYPE),
        data: start.build(),
    }
    .encode()
    .unwrap()
}

/// Drive the real `build_driver` user path: select a CNG cert from
/// `Current User\My` (no admin), acquire its key, and emit a `ClientHello`.
/// Provision a unique-subject client-auth cert and run:
/// `USG_CNG_TEST_SUBJECT=... cargo test -p eaphost --test builder -- --ignored --nocapture`.
#[test]
#[ignore = "on-hardware: needs a provisioned user client-auth cert; set USG_CNG_TEST_SUBJECT"]
fn build_user_driver_from_real_store() {
    let Ok(subject) = std::env::var("USG_CNG_TEST_SUBJECT") else {
        panic!("set USG_CNG_TEST_SUBJECT to the provisioned cert's subject substring");
    };
    let selector = creds::selection::CertSelector {
        require_client_auth_eku: true,
        subject_contains: Some(subject),
        ..Default::default()
    };
    // ClientHello does not verify the server cert, so empty trust anchors suffice.
    let cfg = DriverConfig {
        identity: Identity::User,
        server_name: SERVER_NAME.to_string(),
        mat_vendor_id: 0x0000_9999,
        mat_to_present: None,
        max_fragment: 1024,
    };
    let (mut driver, thumbprint) = build_driver(cfg, RootCertStore::empty(), &selector).unwrap();
    assert_eq!(thumbprint.len(), 64, "SHA-256 thumbprint is 64 hex chars");
    match driver.step(&teap_start()).unwrap() {
        DriverStep::Respond(resp) => assert!(!resp.is_empty(), "ClientHello response"),
        DriverStep::Finished { outcome, .. } => {
            panic!("expected Respond(ClientHello), got Finished: {outcome:?}")
        }
    }
    eprintln!("build_driver(User) selected a CNG cert and emitted a ClientHello — OK");
}
