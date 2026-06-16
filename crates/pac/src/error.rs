//! Errors for MAT persistence.

/// Errors from storing, loading, sealing, or decoding a Machine Authorization
/// Ticket.
#[derive(Debug)]
pub enum PacError {
    /// The stored bytes are not a valid MAT record (bad magic / truncated).
    BadRecord,
    /// The ticket exceeds the maximum encodable size.
    TooLarge {
        /// The oversized length.
        len: usize,
    },
    /// Sealing (DPAPI protect) failed.
    Seal {
        /// Platform status / HRESULT.
        detail: i32,
    },
    /// Unsealing (DPAPI unprotect) failed — wrong machine, tampered, or corrupt.
    Unseal {
        /// Platform status / HRESULT.
        detail: i32,
    },
    /// Filesystem I/O error.
    Io(std::io::ErrorKind),
    /// The in-memory store lock was poisoned by a panic in another thread.
    Locked,
}

impl core::fmt::Display for PacError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadRecord => write!(f, "stored MAT record is malformed"),
            Self::TooLarge { len } => write!(f, "MAT ticket length {len} exceeds maximum"),
            Self::Seal { detail } => write!(f, "DPAPI protect failed (status {detail})"),
            Self::Unseal { detail } => write!(f, "DPAPI unprotect failed (status {detail})"),
            Self::Io(kind) => write!(f, "MAT storage I/O error: {kind:?}"),
            Self::Locked => write!(f, "MAT store lock poisoned"),
        }
    }
}

impl std::error::Error for PacError {}

impl From<std::io::Error> for PacError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.kind())
    }
}
