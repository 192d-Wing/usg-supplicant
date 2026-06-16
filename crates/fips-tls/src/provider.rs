//! The restricted FIPS crypto provider: TLS 1.3 only, AES-GCM suites, and
//! FIPS-approved post-quantum-hybrid key exchange.
//!
//! Centralized so the single allow-list governs both the rustls config and the
//! self-check, and so ML-KEM-1024 (`SecP384r1MLKEM1024`) can be added in exactly
//! one place once rustls ships the 0x11ed codepoint.

use std::sync::Arc;

use rustls::SupportedCipherSuite;
use rustls::crypto::aws_lc_rs;
use rustls::crypto::{CryptoProvider, SupportedKxGroup};

use crate::error::FipsTlsError;

/// FIPS-approved TLS 1.3 cipher suites (AEAD only), preference order.
/// AES-256-GCM-SHA384 first to match our P-384 / SHA-384 posture.
#[must_use]
pub fn fips_cipher_suites() -> Vec<SupportedCipherSuite> {
    vec![
        aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
        aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
    ]
}

/// FIPS-approved key-exchange groups, preference order.
///
/// Standalone **ML-KEM-1024** (FIPS 203, `NamedGroup` `0x0202`, NIST PQ category
/// 5). ML-KEM is FIPS-approved on its own, so no classical curve is required for
/// FIPS compliance. We deliberately do not offer X25519/secp hybrids or
/// classical-only groups: the handshake is post-quantum or it fails.
///
/// Trade-off (accepted): a pure (non-hybrid) PQ exchange has no classical
/// fallback if ML-KEM were broken. Both ends are ours and require ML-KEM-1024.
#[must_use]
pub fn fips_kx_groups() -> Vec<&'static dyn SupportedKxGroup> {
    vec![aws_lc_rs::kx_group::MLKEM1024]
}

/// Build the restricted FIPS crypto provider.
///
/// In a `--features fips` build the base provider is the FIPS-validated AWS-LC
/// module; otherwise it is the standard AWS-LC build (and [`assert_fips`] will
/// fail closed at runtime).
#[must_use]
pub fn fips_provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: fips_cipher_suites(),
        kx_groups: fips_kx_groups(),
        ..aws_lc_rs::default_provider()
    }
}

/// Build the provider behind an `Arc`, ready to install in a rustls config.
#[must_use]
pub fn fips_provider_arc() -> Arc<CryptoProvider> {
    Arc::new(fips_provider())
}

/// Fail-closed FIPS gate for the crypto provider: returns `Ok` only when
/// `provider` is the FIPS-validated AWS-LC module (a `--features fips` build).
/// Call at startup and before each authentication.
///
/// This checks the **library** crypto module only. The **OS** FIPS policy
/// (Windows `FipsAlgorithmPolicy`), which governs the CNG/smartcard signing half
/// of the FIPS boundary, is a separate gate — see [`assert_os_fips_mode`].
///
/// # Errors
/// [`FipsTlsError::NotFips`] when the provider is not FIPS-validated.
pub fn assert_fips(provider: &CryptoProvider) -> Result<(), FipsTlsError> {
    if provider.fips() {
        Ok(())
    } else {
        Err(FipsTlsError::NotFips)
    }
}

/// Fail-closed gate for the host OS FIPS policy (DESIGN.md §3).
///
/// TODO(windows-fips-policy, milestone 6 / eaphost): read
/// `HKLM\System\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy\Enabled` and
/// return [`FipsTlsError::NotFips`] unless it is `1`. Implemented with the
/// Windows `EAPHost` integration, where the platform registry dependency lives.
/// Until then this is intentionally a no-op so non-Windows dev builds run; it
/// MUST be wired before production use so CNG/smartcard signing is gated too.
///
/// # Errors
/// Currently never; see the TODO above.
pub fn assert_os_fips_mode() -> Result<(), FipsTlsError> {
    Ok(())
}
