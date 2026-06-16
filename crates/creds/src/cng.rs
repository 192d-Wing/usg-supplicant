//! Windows CNG credential providers (machine cert + smartcard user cert).
//!
//! Opens a system certificate store (`Local Machine\My` for the machine cert,
//! `Current User\My` for the smartcard user cert — CAC/PIV / SIPR token certs
//! surface there via the ActivClient / 90Meter minidrivers), selects the cert
//! with [`crate::selection::CertSelector`], acquires its **non-exportable**
//! CNG key handle, and signs the TLS transcript with `NCryptSignHash`. The
//! private key never leaves the store.
//!
//! `unsafe` here is confined to the documented FFI calls. This module compiles
//! only on Windows; it is type-checked from other hosts via
//! `cargo check --target x86_64-pc-windows-msvc`.

use std::sync::Mutex;

use aws_lc_rs::digest;
use fips_tls::signer::{RemoteSigner, SignerError};
use rustls::SignatureScheme;
use rustls::pki_types::CertificateDer;

use windows::Win32::Security::Cryptography::{
    CERT_CONTEXT, CERT_OPEN_STORE_FLAGS, CERT_QUERY_ENCODING_TYPE, CERT_STORE_PROV_SYSTEM_W,
    CERT_SYSTEM_STORE_CURRENT_USER_ID, CERT_SYSTEM_STORE_LOCAL_MACHINE_ID,
    CERT_SYSTEM_STORE_LOCATION_SHIFT, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
    CRYPT_ACQUIRE_SILENT_FLAG, CertCloseStore, CertDuplicateCertificateContext,
    CertEnumCertificatesInStore, CertFreeCertificateContext, CertOpenStore,
    CryptAcquireCertificatePrivateKey, HCERTSTORE, NCRYPT_FLAGS, NCRYPT_KEY_HANDLE,
    NCRYPT_SILENT_FLAG, NCryptSignHash, X509_ASN_ENCODING,
};
use windows::core::PCWSTR;

use crate::error::CredError;
use crate::selection::CertSelector;
use crate::{CredKind, ecdsa};

/// Which Windows system store to open.
#[derive(Debug, Clone, Copy)]
enum StoreLocation {
    LocalMachine,
    CurrentUser,
}

impl StoreLocation {
    fn flags(self) -> CERT_OPEN_STORE_FLAGS {
        let id = match self {
            Self::LocalMachine => CERT_SYSTEM_STORE_LOCAL_MACHINE_ID,
            Self::CurrentUser => CERT_SYSTEM_STORE_CURRENT_USER_ID,
        };
        // The system-store location is encoded in the high bits of the flags.
        CERT_OPEN_STORE_FLAGS(id << CERT_SYSTEM_STORE_LOCATION_SHIFT)
    }
}

/// Wide, NUL-terminated UTF-16 for a static store name.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(core::iter::once(0)).collect()
}

/// A CNG-backed signer: a selected certificate plus its non-exportable key.
///
/// We own a duplicated `CERT_CONTEXT` for the signer's whole lifetime. This is
/// required for correctness: when `CryptAcquireCertificatePrivateKey` reports
/// `caller_free == FALSE`, the returned key handle's lifetime is tied to the
/// certificate context, so the context must outlive every signing call.
pub struct CngSigner {
    kind: CredKind,
    cert_der: Vec<u8>,
    scheme: SignatureScheme,
    coord_len: usize,
    // NCRYPT_KEY_HANDLE is not Sync; serialize signing through a mutex.
    key: Mutex<NCRYPT_KEY_HANDLE>,
    /// Whether we (the caller) must free `key`. If false, the handle is owned by
    /// the cert context and freed when we free `cert_ctx`.
    caller_free_key: bool,
    /// Duplicated cert context, kept alive for the key's lifetime; freed on drop.
    cert_ctx: *const CERT_CONTEXT,
}

impl core::fmt::Debug for CngSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CngSigner")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

// SAFETY: `key` is only accessed under the Mutex; `cert_ctx` is only touched at
// construction and in Drop (no aliasing), and CNG handles are process-global and
// usable from any thread. So the type is safe to send/share across threads.
unsafe impl Send for CngSigner {}
unsafe impl Sync for CngSigner {}

impl Drop for CngSigner {
    fn drop(&mut self) {
        // Free the key handle only if we own it (honoring caller_free).
        if self.caller_free_key {
            if let Ok(handle) = self.key.lock() {
                if handle.0 != 0 {
                    // SAFETY: we own this NCRYPT handle (caller_free was TRUE);
                    // free exactly once.
                    let _ = unsafe {
                        windows::Win32::Security::Cryptography::NCryptFreeObject(
                            windows::Win32::Security::Cryptography::NCRYPT_HANDLE(handle.0),
                        )
                    };
                }
            }
        }
        // Free our duplicated cert context exactly once.
        if !self.cert_ctx.is_null() {
            // SAFETY: `cert_ctx` came from CertDuplicateCertificateContext and is
            // freed once here.
            let _ = unsafe { CertFreeCertificateContext(Some(self.cert_ctx)) };
        }
    }
}

/// Open the machine store and build a signer for the matching machine cert.
///
/// # Errors
/// [`CredError`] if the store cannot be opened, no/ambiguous cert matches, or
/// the key cannot be acquired.
pub fn machine_signer(selector: &CertSelector) -> Result<CngSigner, CredError> {
    open_and_select(StoreLocation::LocalMachine, CredKind::Machine, selector)
}

/// Open the user store and build a signer for the matching smartcard user cert.
///
/// # Errors
/// See [`machine_signer`].
pub fn user_signer(selector: &CertSelector) -> Result<CngSigner, CredError> {
    open_and_select(StoreLocation::CurrentUser, CredKind::User, selector)
}

fn open_and_select(
    location: StoreLocation,
    kind: CredKind,
    selector: &CertSelector,
) -> Result<CngSigner, CredError> {
    let store = CertStore::open(location, "MY")?;

    // Select the unique matching cert. We DUPLICATE the matched context so it
    // survives past enumeration: CertEnumCertificatesInStore frees the previous
    // context on each step, so the raw enumerated pointer would dangle.
    let mut chosen: Option<(Vec<u8>, *const CERT_CONTEXT)> = None;
    let mut matches = 0usize;
    for (der, ctx) in store.iter() {
        if selector.matches(&der)? {
            matches = matches.saturating_add(1);
            if let Some((_, prev)) = chosen.take() {
                // SAFETY: `prev` is a prior duplicate we own; free it.
                let _ = unsafe { CertFreeCertificateContext(Some(prev)) };
            }
            // SAFETY: `ctx` is the live enumerated context; duplicate bumps its
            // refcount so our copy outlives the iterator.
            let dup = unsafe { CertDuplicateCertificateContext(Some(ctx)) };
            chosen = Some((der, dup));
        }
    }

    // Fail closed on zero/ambiguous, freeing any held duplicate first.
    if matches != 1 {
        if let Some((_, dup)) = chosen {
            // SAFETY: free the duplicate we own.
            let _ = unsafe { CertFreeCertificateContext(Some(dup)) };
        }
        return match matches {
            0 => Err(CredError::NoMatchingCert),
            n => Err(CredError::AmbiguousMatch { count: n }),
        };
    }
    let (cert_der, cert_ctx) = chosen.ok_or(CredError::NoMatchingCert)?;

    // From here, free `cert_ctx` on any error path before returning.
    let build = || -> Result<CngSigner, CredError> {
        let (scheme, coord_len) = crate::keyinfo::ecdsa_scheme_for_cert(&cert_der)?;
        let (key, caller_free_key) = acquire_key(cert_ctx)?;
        Ok(CngSigner {
            kind,
            cert_der: cert_der.clone(),
            scheme,
            coord_len,
            key: Mutex::new(key),
            caller_free_key,
            cert_ctx,
        })
    };
    build().inspect_err(|_| {
        // SAFETY: on failure nothing owns `cert_ctx`; free the duplicate.
        let _ = unsafe { CertFreeCertificateContext(Some(cert_ctx)) };
    })
}

/// Acquire the non-exportable CNG key handle for a certificate context.
/// Returns the handle and whether the caller must free it (`caller_free`).
fn acquire_key(ctx: *const CERT_CONTEXT) -> Result<(NCRYPT_KEY_HANDLE, bool), CredError> {
    use windows::Win32::Security::Cryptography::{
        CERT_KEY_SPEC, CRYPT_ACQUIRE_FLAGS, HCRYPTPROV_OR_NCRYPT_KEY_HANDLE,
    };
    let mut handle = HCRYPTPROV_OR_NCRYPT_KEY_HANDLE::default();
    let mut key_spec = CERT_KEY_SPEC::default();
    let mut caller_free = windows::core::BOOL::default();
    let flags: CRYPT_ACQUIRE_FLAGS = CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG;
    // SAFETY: `ctx` is a valid cert context from the open store; out-params are
    // owned locals. We request an NCRYPT key handle (silent, no UI).
    unsafe {
        CryptAcquireCertificatePrivateKey(
            ctx,
            flags,
            None,
            &mut handle,
            Some(&mut key_spec),
            Some(&mut caller_free),
        )
        .map_err(|e| CredError::StoreFailure { detail: e.code().0 })?;
    }
    Ok((NCRYPT_KEY_HANDLE(handle.0), caller_free.as_bool()))
}

impl RemoteSigner for CngSigner {
    fn cert_chain(&self) -> Vec<CertificateDer<'static>> {
        vec![CertificateDer::from(self.cert_der.clone())]
    }
    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        self.sign_inner(message)
            .map_err(|_| SignerError::SigningFailed)
    }
}

impl CngSigner {
    /// The credential kind (machine or user).
    #[must_use]
    pub fn kind(&self) -> CredKind {
        self.kind
    }

    /// Hash in the validated module, then sign the digest in CNG. For ECDSA,
    /// `NCryptSignHash` signs the raw digest and returns `r||s`, which we DER-encode.
    fn sign_inner(&self, message: &[u8]) -> Result<Vec<u8>, CredError> {
        let digest = match self.scheme {
            SignatureScheme::ECDSA_NISTP256_SHA256 => {
                digest::digest(&digest::SHA256, message).as_ref().to_vec()
            }
            SignatureScheme::ECDSA_NISTP384_SHA384 => {
                digest::digest(&digest::SHA384, message).as_ref().to_vec()
            }
            _ => return Err(CredError::UnsupportedKey),
        };
        let raw = self.ncrypt_sign(&digest)?;
        ecdsa::raw_to_der(&raw, self.coord_len)
    }

    /// Call `NCryptSignHash` (size query, then sign) returning the raw `r||s`.
    fn ncrypt_sign(&self, digest: &[u8]) -> Result<Vec<u8>, CredError> {
        let handle = *self.key.lock().map_err(|_| CredError::NoSigningKey)?;
        let flags = NCRYPT_FLAGS(NCRYPT_SILENT_FLAG.0);
        let mut needed: u32 = 0;
        // SAFETY: handle is a live NCRYPT key; first call (None signature)
        // returns the required buffer size in `needed`.
        unsafe {
            NCryptSignHash(handle, None, digest, None, &mut needed, flags)
                .map_err(|e| CredError::StoreFailure { detail: e.code().0 })?;
        }
        let mut sig = vec![0u8; needed as usize];
        let mut written: u32 = 0;
        // SAFETY: `sig` is sized to `needed`; ECDSA has no padding info.
        unsafe {
            NCryptSignHash(handle, None, digest, Some(&mut sig), &mut written, flags)
                .map_err(|e| CredError::StoreFailure { detail: e.code().0 })?;
        }
        sig.truncate(written as usize);
        Ok(sig)
    }
}

/// RAII wrapper over an open `HCERTSTORE`.
struct CertStore {
    handle: HCERTSTORE,
}

impl CertStore {
    fn open(location: StoreLocation, name: &str) -> Result<Self, CredError> {
        let name_w = wide(name);
        // SAFETY: provider + name pointers are valid for the call; flags select
        // the system store location. Returns a store handle or an error.
        let handle = unsafe {
            CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                CERT_QUERY_ENCODING_TYPE(0),
                None,
                location.flags(),
                Some(name_w.as_ptr().cast()),
            )
        }
        .map_err(|e| CredError::StoreFailure { detail: e.code().0 })?;
        Ok(Self { handle })
    }

    /// Iterate the store, yielding (DER, context) pairs.
    fn iter(&self) -> CertStoreIter<'_> {
        CertStoreIter {
            store: self,
            prev: core::ptr::null(),
        }
    }
}

impl Drop for CertStore {
    fn drop(&mut self) {
        // SAFETY: closing a store handle we opened; flags 0 = default.
        let _ = unsafe { CertCloseStore(Some(self.handle), 0) };
    }
}

struct CertStoreIter<'a> {
    store: &'a CertStore,
    prev: *const CERT_CONTEXT,
}

impl Iterator for CertStoreIter<'_> {
    type Item = (Vec<u8>, *const CERT_CONTEXT);

    fn next(&mut self) -> Option<Self::Item> {
        // SAFETY: `prev` is null on first call, else the previous context owned
        // by the store; CertEnumCertificatesInStore frees the previous context.
        let ctx = unsafe { CertEnumCertificatesInStore(self.store.handle, Some(self.prev)) };
        if ctx.is_null() {
            return None;
        }
        self.prev = ctx;
        // SAFETY: a non-null context exposes a valid encoded-cert pointer/length.
        let der = unsafe {
            let c = &*ctx;
            core::slice::from_raw_parts(c.pbCertEncoded, c.cbCertEncoded as usize).to_vec()
        };
        let _ = X509_ASN_ENCODING; // documents the expected encoding
        Some((der, ctx.cast_const()))
    }
}

impl Drop for CertStoreIter<'_> {
    fn drop(&mut self) {
        if !self.prev.is_null() {
            // SAFETY: free the last enumerated context not consumed by a further
            // enum call.
            let _ = unsafe { CertFreeCertificateContext(Some(self.prev)) };
        }
    }
}
