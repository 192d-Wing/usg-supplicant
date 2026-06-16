//! The client TLS 1.3 tunnel for the TEAP outer method.
//!
//! Wraps a rustls `ClientConnection` configured with the restricted FIPS
//! provider, exposes a byte-oriented interface (TEAP carries TLS records inside
//! EAP), enforces the FIPS/PQ allow-list on the *negotiated* parameters, and
//! produces `session_key_seed` via the RFC 8446 exporter.

use std::io;
use std::io::{Read as _, Write as _};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::version::TLS13;
use rustls::{CipherSuite, ClientConfig, ClientConnection, NamedGroup, RootCertStore};

use teap::keyschedule::{EXPORTER_LABEL_SESSION_KEY_SEED, S_IMCK_LEN};
use zeroize::Zeroizing;

use crate::error::FipsTlsError;
use crate::mac::AwsLcMac;
use crate::provider::fips_provider_arc;

/// Cap on rustls's internal plaintext/handshake buffering, so a flood of records
/// fed before a drain cannot grow memory without bound. EAP frames are small.
const TLS_BUFFER_LIMIT: usize = 64 * 1024;

/// How the client authenticates to the EAP server (inner EAP-TLS).
#[expect(
    missing_debug_implementations,
    reason = "holds private key material; intentionally not Debug-printable"
)]
pub enum ClientAuth {
    /// No client certificate (the tunnel's outer handshake; inner auth carries
    /// the identity).
    None,
    /// A software-resident certificate + key. Test/non-HSM use only — production
    /// machine/user keys never leave CNG/smartcard (see `creds`, milestone 4,
    /// which supplies a key via the rustls client-cert resolver).
    SoftwareCert {
        /// The client certificate chain (leaf first).
        chain: Vec<CertificateDer<'static>>,
        /// The matching private key.
        key: PrivateKeyDer<'static>,
    },
    /// A custom client-certificate resolver. The `creds` crate supplies one that
    /// presents a CNG/smartcard certificate and signs via a non-exportable key
    /// (the production path: keys never leave their store).
    Resolver(Arc<dyn rustls::client::ResolvesClientCert>),
}

/// Build a TLS 1.3 client config pinned to the FIPS provider and the given trust
/// anchors. The server certificate is verified against `roots` and (by rustls)
/// against the server name supplied to [`TeapTlsClient::connect`].
///
/// # Errors
/// [`FipsTlsError::Rustls`] if the builder rejects the parameters.
pub fn client_config(
    roots: RootCertStore,
    client_auth: ClientAuth,
) -> Result<Arc<ClientConfig>, FipsTlsError> {
    let builder = ClientConfig::builder_with_provider(fips_provider_arc())
        .with_protocol_versions(&[&TLS13])?
        .with_root_certificates(roots);
    let config = match client_auth {
        ClientAuth::None => builder.with_no_client_auth(),
        ClientAuth::SoftwareCert { chain, key } => builder.with_client_auth_cert(chain, key)?,
        ClientAuth::Resolver(resolver) => builder.with_client_cert_resolver(resolver),
    };
    Ok(Arc::new(config))
}

/// The TEAP outer TLS tunnel.
///
/// Secret-producing methods ([`TeapTlsClient::session_key_seed`],
/// [`TeapTlsClient::protect`], [`TeapTlsClient::unprotect`],
/// [`TeapTlsClient::negotiated_mac`]) refuse to run until
/// [`TeapTlsClient::finish_handshake`] has verified the negotiated parameters
/// against the FIPS/PQ allow-list — the fail-closed gate is structural, not a
/// documented convention.
pub struct TeapTlsClient {
    conn: ClientConnection,
    established: bool,
}

// Manual, redacting Debug: never expose the live connection's internals.
impl core::fmt::Debug for TeapTlsClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TeapTlsClient")
            .field("handshaking", &self.conn.is_handshaking())
            .field("established", &self.established)
            .finish()
    }
}

impl TeapTlsClient {
    /// Start a handshake to `server_name`.
    ///
    /// # Errors
    /// [`FipsTlsError::BadServerName`] for an invalid name, or
    /// [`FipsTlsError::Rustls`] if the connection cannot be created.
    pub fn connect(config: Arc<ClientConfig>, server_name: &str) -> Result<Self, FipsTlsError> {
        let name = ServerName::try_from(server_name.to_owned())
            .map_err(|_| FipsTlsError::BadServerName)?;
        let mut conn = ClientConnection::new(config, name)?;
        conn.set_buffer_limit(Some(TLS_BUFFER_LIMIT));
        Ok(Self {
            conn,
            established: false,
        })
    }

    /// Finalize the handshake: enforce the FIPS/PQ allow-list on the negotiated
    /// parameters, unlocking the Phase-2 / secret-producing methods. Drain
    /// [`TeapTlsClient::take_outgoing`] for the final flight before calling this.
    ///
    /// # Errors
    /// [`FipsTlsError::HandshakeIncomplete`] if still handshaking, or a
    /// [`FipsTlsError::DisallowedParameter`] if a negotiated parameter is not
    /// FIPS-approved.
    pub fn finish_handshake(&mut self) -> Result<(), FipsTlsError> {
        if self.conn.is_handshaking() {
            return Err(FipsTlsError::HandshakeIncomplete);
        }
        self.enforce_fips_parameters()?;
        self.established = true;
        Ok(())
    }

    /// Whether the handshake is still in progress.
    #[must_use]
    pub fn is_handshaking(&self) -> bool {
        self.conn.is_handshaking()
    }

    /// Feed inbound TLS record bytes (carried in TEAP) into the connection.
    ///
    /// # Errors
    /// [`FipsTlsError::Rustls`] on a TLS protocol error.
    pub fn feed_incoming(&mut self, records: &[u8]) -> Result<(), FipsTlsError> {
        let mut cursor = io::Cursor::new(records);
        loop {
            let read = self.conn.read_tls(&mut cursor).map_err(io_to_rustls)?;
            if read == 0 {
                break;
            }
            self.conn.process_new_packets()?;
        }
        Ok(())
    }

    /// Take any outbound TLS record bytes the connection wants to send.
    ///
    /// # Errors
    /// [`FipsTlsError::Rustls`] on a TLS protocol error.
    pub fn take_outgoing(&mut self) -> Result<Vec<u8>, FipsTlsError> {
        let mut out = Vec::new();
        while self.conn.wants_write() {
            self.conn.write_tls(&mut out).map_err(io_to_rustls)?;
        }
        Ok(out)
    }

    /// Encrypt Phase-2 application data (TEAP TLVs) into TLS records.
    ///
    /// # Errors
    /// [`FipsTlsError::NotEstablished`] before [`TeapTlsClient::finish_handshake`],
    /// or [`FipsTlsError::Rustls`] if the write fails.
    pub fn protect(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, FipsTlsError> {
        self.require_established()?;
        self.conn
            .writer()
            .write_all(plaintext)
            .map_err(io_to_rustls)?;
        self.take_outgoing()
    }

    /// Decrypt inbound TLS records into Phase-2 application data.
    ///
    /// # Errors
    /// [`FipsTlsError::NotEstablished`] before [`TeapTlsClient::finish_handshake`],
    /// or [`FipsTlsError::Rustls`] on a TLS protocol error.
    pub fn unprotect(&mut self, records: &[u8]) -> Result<Vec<u8>, FipsTlsError> {
        self.require_established()?;
        self.feed_incoming(records)?;
        let mut plaintext = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let read = match self.conn.reader().read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => n,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(io_to_rustls(e)),
            };
            plaintext.extend_from_slice(chunk.get(..read).unwrap_or_default());
        }
        Ok(plaintext)
    }

    /// Derive `session_key_seed` (40 octets) from the TLS exporter (RFC 8446
    /// §7.5), feeding the `usg-TEAP/1.3` key schedule. The seed is scrubbed on
    /// drop; pass it straight to `KeySchedule::new`.
    ///
    /// # Errors
    /// [`FipsTlsError::NotEstablished`] before [`TeapTlsClient::finish_handshake`],
    /// or [`FipsTlsError::Rustls`] if the exporter fails.
    pub fn session_key_seed(&self) -> Result<Zeroizing<[u8; S_IMCK_LEN]>, FipsTlsError> {
        self.require_established()?;
        let seed = self.conn.export_keying_material(
            [0u8; S_IMCK_LEN],
            EXPORTER_LABEL_SESSION_KEY_SEED,
            None,
        )?;
        Ok(Zeroizing::new(seed))
    }

    /// Generic RFC 8446 keying-material export (gated on a finalized tunnel).
    /// Used by the inner EAP-TLS method to derive its `IMSK` with the EAP-TLS
    /// exporter label. The output is scrubbed on drop.
    ///
    /// # Errors
    /// [`FipsTlsError::NotEstablished`] before [`TeapTlsClient::finish_handshake`],
    /// or [`FipsTlsError::Rustls`] if the exporter fails.
    pub fn export_keying_material(
        &self,
        label: &[u8],
        len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, FipsTlsError> {
        self.require_established()?;
        let out = self
            .conn
            .export_keying_material(vec![0u8; len], label, None)?;
        Ok(Zeroizing::new(out))
    }

    /// Fail-closed gate: secret-producing methods require a finalized tunnel.
    fn require_established(&self) -> Result<(), FipsTlsError> {
        if self.established {
            Ok(())
        } else {
            Err(FipsTlsError::NotEstablished)
        }
    }

    /// The negotiated key-exchange group (e.g. ML-KEM-1024).
    #[must_use]
    pub fn negotiated_group(&self) -> Option<NamedGroup> {
        self.conn
            .negotiated_key_exchange_group()
            .map(rustls::crypto::SupportedKxGroup::name)
    }

    /// The negotiated cipher suite code.
    #[must_use]
    pub fn negotiated_suite(&self) -> Option<CipherSuite> {
        self.conn.negotiated_cipher_suite().map(|s| s.suite())
    }

    /// The HMAC primitive matching the negotiated suite PRF hash, for the key
    /// schedule and crypto-binding.
    ///
    /// # Errors
    /// [`FipsTlsError::NoNegotiatedParameters`] before the suite is known, or
    /// [`FipsTlsError::DisallowedParameter`] for a suite outside the allow-list.
    pub fn negotiated_mac(&self) -> Result<AwsLcMac, FipsTlsError> {
        self.require_established()?;
        match self
            .negotiated_suite()
            .ok_or(FipsTlsError::NoNegotiatedParameters)?
        {
            CipherSuite::TLS13_AES_256_GCM_SHA384 => Ok(AwsLcMac::sha384()),
            _ => Err(FipsTlsError::DisallowedParameter {
                what: "cipher suite",
            }),
        }
    }

    /// Fail-closed enforcement of the FIPS/PQ allow-list on the *negotiated*
    /// parameters. Call once the handshake completes, before trusting the tunnel.
    ///
    /// # Errors
    /// [`FipsTlsError::DisallowedParameter`] if version, suite, or kx group is
    /// not allowed; [`FipsTlsError::NoNegotiatedParameters`] if absent.
    pub fn enforce_fips_parameters(&self) -> Result<(), FipsTlsError> {
        usg_fips_tls::params::enforce_fips_parameters(
            self.conn.protocol_version(),
            self.negotiated_suite(),
            self.negotiated_group(),
        )
        .map_err(Into::into)
    }
}

/// rustls byte I/O returns `io::Error`; wrap any inner rustls error, else carry
/// the I/O error as a rustls general error so the caller sees one error type.
///
/// Note: genuine TLS protocol failures (bad certificate, name mismatch, alert)
/// surface from `process_new_packets()` as `rustls::Error` directly, not through
/// this path — so they are never reduced to the generic message here. The only
/// errors that reach this function are buffer-limit / framing I/O conditions.
fn io_to_rustls(e: io::Error) -> FipsTlsError {
    match e
        .into_inner()
        .and_then(|inner| inner.downcast::<rustls::Error>().ok())
    {
        Some(tls) => FipsTlsError::Rustls(*tls),
        None => FipsTlsError::Rustls(rustls::Error::General("tls byte I/O error".into())),
    }
}
