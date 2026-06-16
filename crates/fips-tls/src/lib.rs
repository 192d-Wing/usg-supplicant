//! FIPS TLS 1.3 backend for EAP-TEAP.
//!
//! Provides the restricted crypto provider (TLS 1.3 only, AES-GCM suites,
//! FIPS-approved ML-KEM post-quantum-hybrid key exchange), the RFC 8446 keying
//! exporter that produces `session_key_seed`, an aws-lc-rs-backed
//! [`teap::keyschedule::TeapMac`], and the client TLS tunnel with the
//! CNG/smartcard signing seam.
//!
//! All cryptography runs through aws-lc-rs; a `--features fips` build routes it
//! through the FIPS 140-3 validated AWS-LC module. [`provider::assert_fips`]
//! fails closed when the validated module is not active.
#![forbid(unsafe_code)]

// Fail closed at build time: a release binary MUST use the validated AWS-LC
// module. Debug and test builds may run the non-FIPS provider for local
// development (the runtime self-check still reports it as non-FIPS).
#[cfg(all(not(feature = "fips"), not(debug_assertions), not(test)))]
compile_error!(
    "fips-tls release builds must enable the `fips` feature (validated AWS-LC). Build with `--features fips`."
);

pub mod backend;
pub mod error;
pub mod mac;
pub mod provider;
pub mod signer;
