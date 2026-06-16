//! OS-level FIPS-policy gate (DESIGN.md §3).
//!
//! Reads `HKLM\System\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy\Enabled`.
//! This complements `fips_tls`'s provider self-check: the TLS module being
//! FIPS-validated is necessary but not sufficient — the CNG/smartcard signing
//! half of the boundary is only validated when the OS itself is in FIPS mode.
//! The supplicant must gate authentication on both.

use crate::error::EapHostError;

/// Whether the OS FIPS policy is enabled.
///
/// # Errors
/// [`EapHostError::Win32`] if the registry value cannot be read,
/// [`EapHostError::NotWindows`] off Windows.
#[cfg(windows)]
pub fn fips_policy_enabled() -> Result<bool, EapHostError> {
    use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RegGetValueW};
    use windows::core::w;

    let mut value: u32 = 0;
    let mut size: u32 = u32::try_from(core::mem::size_of::<u32>()).unwrap_or(4);
    // SAFETY: out-params are owned locals; `value`/`size` are sized for a DWORD,
    // and RRF_RT_REG_DWORD restricts the type so DPAPI writes at most 4 octets.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            w!(r"System\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy"),
            w!("Enabled"),
            RRF_RT_REG_DWORD,
            None,
            Some((&raw mut value).cast()),
            Some(&raw mut size),
        )
    };
    if status.0 == 0 {
        Ok(value == 1)
    } else {
        Err(EapHostError::Win32 { code: status.0 })
    }
}

/// Off Windows there is no `FipsAlgorithmPolicy`; always reports unsupported so
/// the gate fails closed in dev builds.
///
/// # Errors
/// Always [`EapHostError::NotWindows`].
#[cfg(not(windows))]
pub fn fips_policy_enabled() -> Result<bool, EapHostError> {
    Err(EapHostError::NotWindows)
}

/// Fail-closed gate: returns `Ok` only when the OS FIPS policy is enabled.
/// A read failure or a non-Windows host is treated as "not in FIPS mode".
///
/// # Errors
/// [`EapHostError::OsFipsDisabled`] when policy is off, otherwise the underlying
/// read error (also fail-closed).
pub fn assert_fips_policy() -> Result<(), EapHostError> {
    match fips_policy_enabled() {
        Ok(true) => Ok(()),
        Ok(false) => Err(EapHostError::OsFipsDisabled),
        Err(e) => Err(e),
    }
}
