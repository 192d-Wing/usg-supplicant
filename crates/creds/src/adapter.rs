//! Bridge a [`fips_tls::signer::RemoteSigner`] (CNG/smartcard key) into the
//! rustls client-certificate machinery, so a non-exportable key signs the TLS
//! 1.3 client handshake without the private key ever leaving its store.

use std::sync::Arc;

use fips_tls::backend::ClientAuth;
use fips_tls::signer::RemoteSigner;
use rustls::client::ResolvesClientCert;
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{Error as RustlsError, SignatureAlgorithm, SignatureScheme};

/// Map a `SignatureScheme` to its `SignatureAlgorithm` (rustls keeps its own
/// mapping crate-private). Covers the ECDSA/RSA schemes a CNG or PIV key uses.
fn scheme_algorithm(scheme: SignatureScheme) -> SignatureAlgorithm {
    match scheme {
        SignatureScheme::RSA_PKCS1_SHA256
        | SignatureScheme::RSA_PKCS1_SHA384
        | SignatureScheme::RSA_PKCS1_SHA512
        | SignatureScheme::RSA_PSS_SHA256
        | SignatureScheme::RSA_PSS_SHA384
        | SignatureScheme::RSA_PSS_SHA512 => SignatureAlgorithm::RSA,
        SignatureScheme::ED25519 => SignatureAlgorithm::ED25519,
        // ECDSA P-256/P-384/P-521 (what our CNG/PIV keys use) and any other
        // scheme fall here; this supplicant only issues ECDSA and RSA keys.
        _ => SignatureAlgorithm::ECDSA,
    }
}

/// A rustls [`SigningKey`] backed by a [`RemoteSigner`].
#[derive(Debug)]
struct RemoteSigningKey {
    signer: Arc<dyn RemoteSigner>,
}

impl SigningKey for RemoteSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let scheme = self.signer.scheme();
        if offered.contains(&scheme) {
            Some(Box::new(RemoteSignerHandle {
                signer: Arc::clone(&self.signer),
            }))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        scheme_algorithm(self.signer.scheme())
    }
}

/// The per-signature handle rustls invokes once a scheme is chosen.
#[derive(Debug)]
struct RemoteSignerHandle {
    signer: Arc<dyn RemoteSigner>,
}

impl Signer for RemoteSignerHandle {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, RustlsError> {
        self.signer
            .sign(message)
            .map_err(|e| RustlsError::General(format!("remote signing failed: {e}")))
    }

    fn scheme(&self) -> SignatureScheme {
        self.signer.scheme()
    }
}

/// A client-cert resolver that always presents one [`RemoteSigner`]'s identity.
#[derive(Debug)]
pub struct RemoteCertResolver {
    certified: Arc<CertifiedKey>,
    /// The exact scheme our key signs with (the key supports only this one).
    scheme: SignatureScheme,
}

impl RemoteCertResolver {
    /// Build a resolver from a remote signer (its certificate chain + key).
    #[must_use]
    pub fn new(signer: Arc<dyn RemoteSigner>) -> Self {
        let chain = signer.cert_chain();
        let scheme = signer.scheme();
        let key: Arc<dyn SigningKey> = Arc::new(RemoteSigningKey { signer });
        Self {
            certified: Arc::new(CertifiedKey::new(chain, key)),
            scheme,
        }
    }

    /// Wrap as a [`ClientAuth`] for `fips_tls::backend::client_config`.
    #[must_use]
    pub fn into_client_auth(self) -> ClientAuth {
        ClientAuth::Resolver(Arc::new(self))
    }
}

impl ResolvesClientCert for RemoteCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        // Present our identity only if the server offers the EXACT scheme our key
        // can sign. Matching by algorithm (ECDSA) would let us present, say, a
        // P-384 cert when the server only offers ECDSA P-256, then fail to sign
        // in choose_scheme and break the handshake. Decline cleanly instead.
        if sigschemes.contains(&self.scheme) {
            Some(Arc::clone(&self.certified))
        } else {
            None
        }
    }

    fn has_certs(&self) -> bool {
        true
    }
}
