//! Errors for the Windows `EAPHost` integration.

/// Errors from the OS FIPS-policy gate and method registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EapHostError {
    /// The OS is not in FIPS mode (`FipsAlgorithmPolicy\Enabled` != 1).
    OsFipsDisabled,
    /// A Win32 call failed; carries the status code.
    Win32 {
        /// `WIN32_ERROR` / `HRESULT` status.
        code: u32,
    },
    /// This operation is only supported on Windows.
    NotWindows,
}

impl core::fmt::Display for EapHostError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OsFipsDisabled => {
                write!(f, "OS FIPS policy is not enabled (FipsAlgorithmPolicy)")
            }
            Self::Win32 { code } => write!(f, "Win32 error (status {code})"),
            Self::NotWindows => write!(f, "operation supported only on Windows"),
        }
    }
}

impl std::error::Error for EapHostError {}
