//! Headless round-trip of the `EAPHost` config-DLL entry points
//! (`EapPeerConfigBlob2Xml` <-> `EapPeerConfigXml2Blob`) against real MSXML.
//!
//! Unlike the `real_eaphost` tests this needs only COM + in-box MSXML (no
//! elevation, FIPS, or `EAPHost` service), so it runs as a normal test on the
//! Windows CI runner and validates the COM glue end to end: our connection blob
//! becomes an `IXMLDOMDocument2` and parses back byte-for-byte.
#![cfg(windows)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use core::ffi::c_void;

use eaphost::config::SessionConfigBlob;
use eaphost::peer::{EapPeerConfigBlob2Xml, EapPeerConfigXml2Blob, EapPeerFreeMemory};
use windows::Win32::Security::ExtensibleAuthenticationProtocol::{
    EAP_ERROR, EAP_METHOD_TYPE, EAP_TYPE,
};
use windows::Win32::System::Com::{COINIT_APARTMENTTHREADED, CoInitializeEx, CoUninitialize};
use windows::core::Interface;

fn method_type() -> EAP_METHOD_TYPE {
    EAP_METHOD_TYPE {
        eapType: EAP_TYPE {
            r#type: 55,
            dwVendorId: 0,
            dwVendorType: 0,
        },
        dwAuthorId: 192_000,
    }
}

fn sample_blob() -> Vec<u8> {
    SessionConfigBlob {
        machine: true,
        server_name: "teap.test.local".to_string(),
        mat_vendor_id: 0x0000_9999,
        max_fragment: 64 * 1024,
        selector_subject: "USG-CNG-MACHINE".to_string(),
        // Non-trivial binary (incl. high bytes and 0x00) to exercise hex coding.
        roots: vec![vec![0x30, 0x82, 0x00, 0xff], vec![0xaa; 48]],
        mat: Some(vec![0xde, 0xad, 0xbe, 0xef]),
    }
    .to_bytes()
}

#[test]
fn config_blob_round_trips_through_msxml() {
    // SAFETY: COM init/teardown bracket the FFI round-trip; the FFI exports build
    // (Blob2Xml) and consume (Xml2Blob) a real MSXML document.
    unsafe {
        // S_FALSE (already initialized on this thread) is fine.
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
    }
    let blob = sample_blob();

    let recovered = unsafe {
        let mut doc: *mut c_void = core::ptr::null_mut();
        let mut err: *mut EAP_ERROR = core::ptr::null_mut();
        let rc = EapPeerConfigBlob2Xml(
            0,
            method_type(),
            blob.as_ptr(),
            blob.len() as u32,
            &raw mut doc,
            &raw mut err,
        );
        assert_eq!(rc, 0, "EapPeerConfigBlob2Xml");
        assert!(!doc.is_null(), "Blob2Xml produced a document");

        let mut out: *mut u8 = core::ptr::null_mut();
        let mut out_len = 0u32;
        let rc = EapPeerConfigXml2Blob(
            0,
            method_type(),
            doc,
            &raw mut out,
            &raw mut out_len,
            &raw mut err,
        );
        assert_eq!(rc, 0, "EapPeerConfigXml2Blob");
        assert!(!out.is_null(), "Xml2Blob produced a buffer");
        let recovered = core::slice::from_raw_parts(out, out_len as usize).to_vec();

        EapPeerFreeMemory(out.cast());
        // Release the COM document we took ownership of from Blob2Xml.
        drop(windows::Win32::Data::Xml::MsXml::IXMLDOMDocument2::from_raw(doc));
        recovered
    };

    assert_eq!(
        recovered, blob,
        "blob survives the XML round-trip byte-for-byte"
    );
    let parsed = SessionConfigBlob::from_bytes(&recovered).expect("recovered blob parses");
    assert_eq!(parsed.server_name, "teap.test.local");
    assert_eq!(parsed.mat.as_deref(), Some(&[0xde, 0xad, 0xbe, 0xef][..]));

    // SAFETY: balance the CoInitializeEx above.
    unsafe { CoUninitialize() };
}
