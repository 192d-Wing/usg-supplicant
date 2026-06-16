//! `teap::keyschedule::TeapMac` backed by the aws-lc-rs (FIPS) HMAC, so the
//! TEAP key schedule and crypto-binding run entirely inside the validated module.

use aws_lc_rs::hmac;
use teap::keyschedule::TeapMac;

/// HMAC over the negotiated suite hash, selected to match the cipher suite PRF
/// hash (SHA-256 for AES-128-GCM, SHA-384 for AES-256-GCM).
#[derive(Debug, Clone, Copy)]
pub struct AwsLcMac {
    algo: hmac::Algorithm,
    hash_len: usize,
}

impl AwsLcMac {
    /// HMAC-SHA-256 (32-octet output).
    #[must_use]
    pub fn sha256() -> Self {
        Self {
            algo: hmac::HMAC_SHA256,
            hash_len: 32,
        }
    }

    /// HMAC-SHA-384 (48-octet output).
    #[must_use]
    pub fn sha384() -> Self {
        Self {
            algo: hmac::HMAC_SHA384,
            hash_len: 48,
        }
    }
}

impl TeapMac for AwsLcMac {
    fn hash_len(&self) -> usize {
        self.hash_len
    }

    fn hmac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        let k = hmac::Key::new(self.algo, key);
        hmac::sign(&k, data).as_ref().to_vec()
    }
}
