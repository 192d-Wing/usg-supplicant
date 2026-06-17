//! The restricted FIPS crypto provider, re-exported from the canonical
//! [`usg_fips_tls`] core so the supplicant, usg-radius, and usg-authenticator
//! share one definition of the TLS 1.3 / AES-256-GCM / ML-KEM-1024-only
//! allow-list. The library-level pieces are not redefined here; this module adds
//! only the supplicant-specific OS FIPS-policy gate.

use rustls::crypto::CryptoProvider;

pub use usg_fips_tls::provider::{
    fips_cipher_suites, fips_kx_groups, fips_provider, fips_provider_arc,
};

use crate::error::FipsTlsError;

/// Fail-closed FIPS gate for the crypto provider: returns `Ok` only when
/// `provider` is the FIPS-validated AWS-LC module (a `--features fips` build).
/// Call at startup and before each authentication.
///
/// Thin wrapper over [`usg_fips_tls::provider::assert_fips`] that surfaces the
/// crate-local [`FipsTlsError`] so callers keep a single error type. This checks
/// the **library** crypto module only. The **OS** FIPS policy (Windows
/// `FipsAlgorithmPolicy`), which governs the CNG/smartcard signing half of the
/// FIPS boundary, is a separate, live gate implemented where the platform registry
/// dependency lives — `eaphost::os_fips::assert_fips_policy` (asserted at
/// `EapPeerInitialize` and per `BeginSession`).
///
/// # Errors
/// [`FipsTlsError::NotFips`] when the provider is not FIPS-validated.
pub fn assert_fips(provider: &CryptoProvider) -> Result<(), FipsTlsError> {
    usg_fips_tls::provider::assert_fips(provider).map_err(Into::into)
}
