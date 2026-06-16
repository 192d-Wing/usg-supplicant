//! Certificate selection tests: pick the Client-Auth (PIV Authentication) cert
//! among several, by EKU and thumbprint, failing closed on none/ambiguous.
#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::panic)]

use creds::error::CredError;
use creds::selection::{CertSelector, thumbprint_sha256};
use rcgen::{CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair};
use rustls::pki_types::CertificateDer;

fn cert_with_eku(name: &str, eku: ExtendedKeyUsagePurpose) -> CertificateDer<'static> {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![name.to_string()]).unwrap();
    params.extended_key_usages = vec![eku];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, name);
    params.distinguished_name = dn;
    params.self_signed(&key).unwrap().der().clone()
}

#[test]
fn selects_the_client_auth_cert_among_several() {
    let auth = cert_with_eku("piv-auth", ExtendedKeyUsagePurpose::ClientAuth);
    let signing = cert_with_eku("piv-sign", ExtendedKeyUsagePurpose::EmailProtection);
    let server = cert_with_eku("srv", ExtendedKeyUsagePurpose::ServerAuth);
    let certs = vec![signing, auth.clone(), server];

    let selector = CertSelector {
        require_client_auth_eku: true,
        ..Default::default()
    };
    let picked = selector.select(&certs).unwrap();
    assert_eq!(*picked, auth);
}

#[test]
fn thumbprint_selects_exactly_one() {
    let a = cert_with_eku("a", ExtendedKeyUsagePurpose::ClientAuth);
    let b = cert_with_eku("b", ExtendedKeyUsagePurpose::ClientAuth);
    let want = thumbprint_sha256(b.as_ref());
    let certs = vec![a, b.clone()];

    let selector = CertSelector {
        thumbprint_sha256: Some(want),
        ..Default::default()
    };
    assert_eq!(*selector.select(&certs).unwrap(), b);
}

#[test]
fn no_match_fails_closed() {
    let server = cert_with_eku("srv", ExtendedKeyUsagePurpose::ServerAuth);
    let selector = CertSelector {
        require_client_auth_eku: true,
        ..Default::default()
    };
    assert_eq!(selector.select(&[server]), Err(CredError::NoMatchingCert));
}

#[test]
fn ambiguous_match_fails_closed() {
    let a = cert_with_eku("a", ExtendedKeyUsagePurpose::ClientAuth);
    let b = cert_with_eku("b", ExtendedKeyUsagePurpose::ClientAuth);
    let selector = CertSelector {
        require_client_auth_eku: true,
        ..Default::default()
    };
    assert!(matches!(
        selector.select(&[a, b]),
        Err(CredError::AmbiguousMatch { count: 2 })
    ));
}

#[test]
fn subject_substring_narrows_selection() {
    let auth1 = cert_with_eku("piv-auth-alice", ExtendedKeyUsagePurpose::ClientAuth);
    let auth2 = cert_with_eku("piv-auth-bob", ExtendedKeyUsagePurpose::ClientAuth);
    let selector = CertSelector {
        require_client_auth_eku: true,
        subject_contains: Some("alice".to_string()),
        ..Default::default()
    };
    assert_eq!(*selector.select(&[auth1.clone(), auth2]).unwrap(), auth1);
}
