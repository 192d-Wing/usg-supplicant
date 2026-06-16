//! The OS FIPS gate must fail closed where it cannot confirm FIPS mode.
//! (On Windows these would assert against the real registry; here we verify the
//! non-Windows fail-closed contract.)

use eaphost::error::EapHostError;
use eaphost::os_fips::{assert_fips_policy, fips_policy_enabled};

#[cfg(not(windows))]
#[test]
fn non_windows_reports_unsupported_and_fails_closed() {
    assert_eq!(fips_policy_enabled(), Err(EapHostError::NotWindows));
    assert_eq!(assert_fips_policy(), Err(EapHostError::NotWindows));
}

#[cfg(windows)]
#[test]
fn windows_gate_returns_a_definite_answer() {
    // On a real host this is Ok(()) only when FipsAlgorithmPolicy is enabled;
    // either way it must not panic and must be deterministic.
    let _ = fips_policy_enabled();
    let _ = assert_fips_policy();
}

/// On-hardware validation (`WINDOWS_DEV.md` §4.3): read the real
/// `FipsAlgorithmPolicy\Enabled` and assert the gate is consistent with it.
/// `#[ignore]`d so CI (unknown/var policy) doesn't depend on the host state; run
/// explicitly: `cargo test -p eaphost --test os_fips -- --ignored --nocapture`.
#[cfg(windows)]
#[test]
#[ignore = "on-hardware: reflects this host's real OS FIPS policy"]
fn os_fips_gate_matches_real_policy() {
    let enabled = fips_policy_enabled();
    eprintln!("fips_policy_enabled() => {enabled:?}");
    eprintln!("assert_fips_policy()  => {:?}", assert_fips_policy());

    // Whatever the host reports, the gate MUST be consistent and fail closed
    // unless policy is definitively enabled.
    match enabled {
        Ok(true) => assert_eq!(assert_fips_policy(), Ok(()), "policy enabled => gate open"),
        Ok(false) => assert_eq!(
            assert_fips_policy(),
            Err(EapHostError::OsFipsDisabled),
            "policy disabled => gate fails closed"
        ),
        Err(e) => assert_eq!(
            assert_fips_policy(),
            Err(e),
            "read error => gate propagates the error (fail closed)"
        ),
    }
}
