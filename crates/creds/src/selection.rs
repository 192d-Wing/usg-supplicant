//! Select the right certificate from a store among several (e.g. a CAC/PIV card
//! exposes an Authentication cert, a Signature cert, and an Encryption cert).
//!
//! For 802.1X we want the **PIV Authentication** certificate, distinguished by
//! the Client Authentication EKU (`1.3.6.1.5.5.7.3.2`). Selection can be further
//! constrained by SHA-256 thumbprint and subject/issuer substrings.

use aws_lc_rs::digest;
use rustls::pki_types::CertificateDer;
use x509_parser::prelude::*;

use crate::error::CredError;

/// Criteria for picking one certificate from a candidate set.
#[derive(Debug, Clone, Default)]
pub struct CertSelector {
    /// Exact SHA-256 thumbprint of the certificate DER, if pinned.
    pub thumbprint_sha256: Option<[u8; 32]>,
    /// Require the Client Authentication EKU (the PIV Authentication cert).
    pub require_client_auth_eku: bool,
    /// Require this substring in the subject DN (case-sensitive).
    pub subject_contains: Option<String>,
    /// Require this substring in the issuer DN (case-sensitive).
    pub issuer_contains: Option<String>,
}

impl CertSelector {
    /// Whether `cert_der` satisfies every set criterion.
    ///
    /// # Errors
    /// [`CredError::BadCertificate`] if a criterion requires parsing and the
    /// certificate is not valid X.509.
    pub fn matches(&self, cert_der: &[u8]) -> Result<bool, CredError> {
        if let Some(want) = self.thumbprint_sha256 {
            let got = digest::digest(&digest::SHA256, cert_der);
            if got.as_ref() != want.as_slice() {
                return Ok(false);
            }
        }

        // Parse only if a criterion needs the certificate's contents.
        let needs_parse = self.require_client_auth_eku
            || self.subject_contains.is_some()
            || self.issuer_contains.is_some();
        if !needs_parse {
            return Ok(true);
        }

        let (_, cert) =
            X509Certificate::from_der(cert_der).map_err(|_| CredError::BadCertificate)?;

        if self.require_client_auth_eku {
            let has_client_auth = cert
                .extended_key_usage()
                .ok()
                .flatten()
                .is_some_and(|eku| eku.value.client_auth);
            if !has_client_auth {
                return Ok(false);
            }
        }
        if let Some(sub) = &self.subject_contains
            && !cert.subject().to_string().contains(sub.as_str())
        {
            return Ok(false);
        }
        if let Some(iss) = &self.issuer_contains
            && !cert.issuer().to_string().contains(iss.as_str())
        {
            return Ok(false);
        }
        Ok(true)
    }

    /// Select the single matching certificate. Fails closed if zero or more than
    /// one match (an ambiguous match must never silently pick one).
    ///
    /// # Errors
    /// [`CredError::NoMatchingCert`], [`CredError::AmbiguousMatch`], or
    /// [`CredError::BadCertificate`].
    pub fn select<'a>(
        &self,
        certs: &'a [CertificateDer<'a>],
    ) -> Result<&'a CertificateDer<'a>, CredError> {
        let mut found: Option<&'a CertificateDer<'a>> = None;
        let mut count: usize = 0;
        for cert in certs {
            if self.matches(cert.as_ref())? {
                count = count.saturating_add(1);
                found = Some(cert);
            }
        }
        match (found, count) {
            (Some(cert), 1) => Ok(cert),
            (_, 0) => Err(CredError::NoMatchingCert),
            (_, n) => Err(CredError::AmbiguousMatch { count: n }),
        }
    }
}

/// SHA-256 thumbprint of a certificate DER.
#[must_use]
pub fn thumbprint_sha256(cert_der: &[u8]) -> [u8; 32] {
    let d = digest::digest(&digest::SHA256, cert_der);
    let mut out = [0u8; 32];
    // SHA-256 is exactly 32 octets.
    out.copy_from_slice(d.as_ref());
    out
}
