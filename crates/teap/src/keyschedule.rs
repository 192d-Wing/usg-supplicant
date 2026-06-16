//! `usg-TEAP/1.3` key schedule (SERVER-CONTRACT.md §3).
//!
//! This module owns the *orchestration* only: the S-IMCK compound-key chain,
//! HKDF-Expand (RFC 5869 §2.3, built on HMAC-H), and the MSK/EMSK export. The
//! single cryptographic primitive — `HMAC-H` over the negotiated suite hash —
//! is injected via [`TeapMac`] so the production build can route it through the
//! FIPS-validated module while tests use an independent reference.
//!
//! Sizes (octets), pinned by contract:
//! - `session_key_seed` / `S-IMCK`: 40
//! - `IMSK` (per inner method): 32
//! - `IMCK` block: 60  →  `S-IMCK' = IMCK[0..40]`, `CMK = IMCK[40..60]`
//! - `MSK` / `EMSK`: 64

use crate::error::KeyScheduleError;
use zeroize::Zeroizing;

/// Length of `session_key_seed` and each `S-IMCK` (octets).
pub const S_IMCK_LEN: usize = 40;
/// Length of an inner method's `IMSK` (octets).
pub const IMSK_LEN: usize = 32;
/// Length of a derived `IMCK` block (octets): `S-IMCK'(40) || CMK(20)`.
pub const IMCK_LEN: usize = 60;
/// Length of a `CMK` (octets).
pub const CMK_LEN: usize = IMCK_LEN - S_IMCK_LEN;
/// Length of the exported `MSK` / `EMSK` (octets).
pub const SESSION_KEY_LEN: usize = 64;

/// Label fed to the TLS exporter to obtain `session_key_seed` (used by the
/// TLS backend in a later milestone; defined here as the single source of truth).
pub const EXPORTER_LABEL_SESSION_KEY_SEED: &[u8] = b"EXPORTER: teap session key seed";
/// HKDF-Expand label for the compound-key chain.
pub const LABEL_INNER_METHODS_COMPOUND_KEYS: &[u8] = b"Inner Methods Compound Keys";
/// HKDF-Expand label for the exported MSK.
pub const LABEL_MSK: &[u8] = b"Session Key Generating Function";
/// HKDF-Expand label for the exported EMSK.
pub const LABEL_EMSK: &[u8] = b"Extended Session Key Generating Function";

/// The single cryptographic primitive the key schedule needs: `HMAC-H` over the
/// negotiated cipher suite's hash. Implementations MUST be FIPS-validated on the
/// production path; tests inject an independent reference.
///
/// `Send`: a session (and the driver owning it) moves across `EAPHost`/`dot3svc`
/// threads, so the boxed MAC must be sendable.
pub trait TeapMac: Send {
    /// Output length of `H` in octets (32 for SHA-256, 48 for SHA-384).
    fn hash_len(&self) -> usize;
    /// `HMAC-H(key, data)`. `key` may be any length.
    fn hmac(&self, key: &[u8], data: &[u8]) -> Vec<u8>;
}

/// A Compound MAC Key (`CMK[j]`), used to MAC the Crypto-Binding TLV. The key
/// material is scrubbed on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct Cmk(Zeroizing<Vec<u8>>);

impl Cmk {
    /// The raw key octets.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

// Avoid leaking key material via Debug.
impl core::fmt::Debug for Cmk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Cmk({} octets, redacted)", self.0.len())
    }
}

/// RFC 5869 §2.3 HKDF-Expand built on `HMAC-H`.
///
/// Used without the "`prk` length ≥ `HashLen`" recommendation: `S-IMCK` is 40
/// octets and HMAC accepts any key length (contract §3.3 pin).
///
/// # Errors
/// [`KeyScheduleError::OutputTooLong`] if `len > 255 * HashLen`, or
/// [`KeyScheduleError::BadHashLen`] if the MAC reports a zero hash length.
fn hkdf_expand(
    mac: &dyn TeapMac,
    prk: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>, KeyScheduleError> {
    let hash_len = mac.hash_len();
    if hash_len == 0 {
        return Err(KeyScheduleError::BadHashLen);
    }
    // RFC 5869: L <= 255 * HashLen.
    let max = hash_len.saturating_mul(255);
    if len > max {
        return Err(KeyScheduleError::OutputTooLong {
            requested: len,
            max,
        });
    }

    let blocks = len.div_ceil(hash_len);
    let mut okm = Vec::with_capacity(blocks.saturating_mul(hash_len));
    let mut t: Vec<u8> = Vec::new();
    for i in 1..=blocks {
        // i <= blocks <= ceil(len/hash_len); len <= 255*hash_len => i <= 255.
        let counter = u8::try_from(i).map_err(|_| KeyScheduleError::OutputTooLong {
            requested: len,
            max,
        })?;
        let mut input = Vec::with_capacity(t.len().saturating_add(info.len()).saturating_add(1));
        input.extend_from_slice(&t);
        input.extend_from_slice(info);
        input.push(counter);
        t = mac.hmac(prk, &input);
        okm.extend_from_slice(&t);
    }
    okm.truncate(len);
    Ok(okm)
}

/// The evolving `S-IMCK` compound-key chain for one TEAP session.
///
/// Construct from `session_key_seed`, then [`KeySchedule::absorb_inner`] once
/// per completed inner method (exactly once in the two-session model), then
/// [`KeySchedule::derive_session_keys`].
#[derive(Clone)]
pub struct KeySchedule {
    /// Current `S-IMCK` (always [`S_IMCK_LEN`] octets), scrubbed on drop.
    s_imck: Zeroizing<Vec<u8>>,
    /// Number of inner methods absorbed.
    methods: usize,
}

impl core::fmt::Debug for KeySchedule {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeySchedule")
            .field("methods", &self.methods)
            .field("s_imck", &"redacted")
            .finish()
    }
}

impl KeySchedule {
    /// Seed the chain: `S-IMCK[0] = session_key_seed`.
    ///
    /// # Errors
    /// [`KeyScheduleError::BadSeedLen`] unless `session_key_seed` is exactly
    /// [`S_IMCK_LEN`] octets.
    pub fn new(session_key_seed: &[u8]) -> Result<Self, KeyScheduleError> {
        if session_key_seed.len() != S_IMCK_LEN {
            return Err(KeyScheduleError::BadSeedLen {
                actual: session_key_seed.len(),
            });
        }
        Ok(Self {
            s_imck: Zeroizing::new(session_key_seed.to_vec()),
            methods: 0,
        })
    }

    /// Number of inner methods absorbed so far.
    #[must_use]
    pub fn methods(&self) -> usize {
        self.methods
    }

    /// Fold one inner method's `IMSK` into the chain and return its `CMK[j]`.
    ///
    /// `IMCK[j] = HKDF-Expand(S-IMCK[j-1], "Inner Methods Compound Keys" || IMSK, 60)`,
    /// then `S-IMCK[j] = IMCK[0..40]`, `CMK[j] = IMCK[40..60]`.
    ///
    /// # Errors
    /// [`KeyScheduleError::BadImskLen`] unless `imsk` is exactly [`IMSK_LEN`];
    /// propagates [`hkdf_expand`] errors.
    pub fn absorb_inner(
        &mut self,
        mac: &dyn TeapMac,
        imsk: &[u8],
    ) -> Result<Cmk, KeyScheduleError> {
        if imsk.len() != IMSK_LEN {
            return Err(KeyScheduleError::BadImskLen { actual: imsk.len() });
        }
        let mut info = Vec::with_capacity(
            LABEL_INNER_METHODS_COMPOUND_KEYS
                .len()
                .saturating_add(IMSK_LEN),
        );
        info.extend_from_slice(LABEL_INNER_METHODS_COMPOUND_KEYS);
        info.extend_from_slice(imsk);

        let imck_block = hkdf_expand(mac, &self.s_imck, &info, IMCK_LEN)?;
        // imck_block is exactly IMCK_LEN; both splits are in range.
        let next = imck_block
            .get(..S_IMCK_LEN)
            .ok_or(KeyScheduleError::Internal)?;
        let cmk = imck_block
            .get(S_IMCK_LEN..IMCK_LEN)
            .ok_or(KeyScheduleError::Internal)?;

        self.s_imck = Zeroizing::new(next.to_vec());
        self.methods = self.methods.saturating_add(1);
        Ok(Cmk(Zeroizing::new(cmk.to_vec())))
    }

    /// Derive the exported `(MSK, EMSK)` from the final `S-IMCK`.
    ///
    /// # Errors
    /// [`KeyScheduleError::NoMethods`] if no inner method has been absorbed;
    /// propagates [`hkdf_expand`] errors.
    pub fn derive_session_keys(
        &self,
        mac: &dyn TeapMac,
    ) -> Result<(Vec<u8>, Vec<u8>), KeyScheduleError> {
        if self.methods == 0 {
            return Err(KeyScheduleError::NoMethods);
        }
        let msk = hkdf_expand(mac, &self.s_imck, LABEL_MSK, SESSION_KEY_LEN)?;
        let emsk = hkdf_expand(mac, &self.s_imck, LABEL_EMSK, SESSION_KEY_LEN)?;
        Ok((msk, emsk))
    }
}
