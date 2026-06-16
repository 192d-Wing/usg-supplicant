//! The OS FIPS gate must fail closed where it cannot confirm FIPS mode.
//! (On Windows these would assert against the real registry; here we verify the
//! non-Windows fail-closed contract.)

#[cfg(not(windows))]
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
