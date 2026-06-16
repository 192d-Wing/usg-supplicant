//! Errors for credential discovery, selection, and signing.

/// Errors from the credential providers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredError {
    /// No certificate in the store matched the selection criteria.
    NoMatchingCert,
    /// More than one certificate matched and the criteria were not unique.
    AmbiguousMatch {
        /// How many certs matched.
        count: usize,
    },
    /// A certificate could not be parsed as X.509.
    BadCertificate,
    /// The selected certificate has no usable signing key in the store.
    NoSigningKey,
    /// The key store / platform API failed.
    StoreFailure {
        /// Platform status/HRESULT or a short description.
        detail: i32,
    },
    /// A raw ECDSA signature could not be DER-encoded.
    BadSignature,
    /// The certificate's key algorithm/curve is not supported.
    UnsupportedKey,
}

impl core::fmt::Display for CredError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoMatchingCert => write!(f, "no certificate matched the selection criteria"),
            Self::AmbiguousMatch { count } => {
                write!(f, "{count} certificates matched; criteria not unique")
            }
            Self::BadCertificate => write!(f, "certificate could not be parsed as X.509"),
            Self::NoSigningKey => write!(f, "selected certificate has no usable signing key"),
            Self::StoreFailure { detail } => write!(f, "key store failure (status {detail})"),
            Self::BadSignature => write!(f, "raw ECDSA signature could not be DER-encoded"),
            Self::UnsupportedKey => write!(f, "unsupported certificate key algorithm/curve"),
        }
    }
}

impl std::error::Error for CredError {}
