//! Build a [`supplicant::driver::TeapDriver`] for an `EAPHost` session from the
//! session profile and the right credential.
//!
//! [`assemble_driver`] is platform-independent: it takes an already-built
//! client-auth resolver and wires the outer driver + inner EAP-TLS, so it is
//! unit-tested with a software credential. [`build_driver`] is the
//! `#[cfg(windows)]` entry that selects the machine CNG certificate (boot) or the
//! smartcard user certificate (logon) via [`creds::cng`] — the providers
//! hardware-validated in the on-device CNG tests — and delegates to it.

use fips_tls::backend::{ClientAuth, client_config};
use rustls::RootCertStore;
use supplicant::driver::{DriverConfig, TeapDriver};
use supplicant::inner_tls::EapTlsInner;
use teap::session::Identity;

use crate::error::BuildError;
use crate::session::SessionKind;

/// The per-session profile (from the wired 802.1X profile / `EAPHost` config
/// DLL): trust anchors, expected server name, and TEAP parameters.
pub struct PeerConfig {
    /// Expected EAP-server name, validated against the server certificate.
    pub server_name: String,
    /// Trust anchors for the server certificate (outer tunnel and inner EAP-TLS
    /// verify the server against these).
    pub roots: RootCertStore,
    /// SMI Private Enterprise Number for the MAT Vendor-Specific TLV.
    pub mat_vendor_id: u32,
    /// Max TLS-fragment payload per TEAP message (real EAP MTU, ~1024–1400).
    pub max_fragment: usize,
    /// For a user session: the stored MAT to present in-tunnel (`None` for a
    /// machine session, or if no ticket is held yet).
    pub mat_to_present: Option<Vec<u8>>,
}

// Manual Debug: never render the trust store internals or the opaque MAT bytes.
impl core::fmt::Debug for PeerConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PeerConfig")
            .field("server_name", &self.server_name)
            .field("mat_vendor_id", &self.mat_vendor_id)
            .field("max_fragment", &self.max_fragment)
            .field("has_mat", &self.mat_to_present.is_some())
            .finish_non_exhaustive()
    }
}

fn identity_of(kind: SessionKind) -> Identity {
    match kind {
        SessionKind::Machine => Identity::Machine,
        SessionKind::User => Identity::User,
    }
}

/// Assemble a driver from the profile and an already-built client-auth resolver
/// (the credential). Platform-independent.
///
/// The inner EAP-TLS verifies the server certificate against `cfg.roots` and
/// presents our client certificate via `client_auth`; the outer driver trusts
/// the same anchors and carries the session identity / MAT.
///
/// # Errors
/// [`BuildError`] if the TLS client config, the inner method, or the driver
/// cannot be built.
pub fn assemble_driver(
    kind: SessionKind,
    cfg: PeerConfig,
    client_auth: ClientAuth,
) -> Result<TeapDriver, BuildError> {
    let inner_config = client_config(cfg.roots.clone(), client_auth)
        .map_err(|e| BuildError::Tls(format!("{e:?}")))?;
    let inner = EapTlsInner::new(inner_config, &cfg.server_name, cfg.max_fragment)
        .map_err(|e| BuildError::Tls(format!("{e:?}")))?;

    let driver_cfg = DriverConfig {
        identity: identity_of(kind),
        server_name: cfg.server_name,
        mat_vendor_id: cfg.mat_vendor_id,
        mat_to_present: cfg.mat_to_present,
        max_fragment: cfg.max_fragment,
    };
    TeapDriver::new(driver_cfg, cfg.roots, Box::new(inner))
        .map_err(|e| BuildError::Driver(format!("{e:?}")))
}

/// Build a driver for `kind`, selecting the credential from the Windows
/// certificate store: the machine cert (`Local Machine\My`) for a machine
/// session, the smartcard user cert (`Current User\My`) for a user session. The
/// private key never leaves its store; it signs the inner handshake via CNG.
///
/// # Errors
/// [`BuildError::Credential`] if the certificate cannot be selected or its key
/// acquired; otherwise see [`assemble_driver`].
#[cfg(windows)]
pub fn build_driver(
    kind: SessionKind,
    cfg: PeerConfig,
    selector: &creds::selection::CertSelector,
) -> Result<TeapDriver, BuildError> {
    use std::sync::Arc;

    use creds::adapter::RemoteCertResolver;
    use fips_tls::signer::RemoteSigner;

    let signer: Arc<dyn RemoteSigner> = match kind {
        SessionKind::Machine => Arc::new(
            creds::cng::machine_signer(selector)
                .map_err(|e| BuildError::Credential(format!("{e:?}")))?,
        ),
        SessionKind::User => Arc::new(
            creds::cng::user_signer(selector)
                .map_err(|e| BuildError::Credential(format!("{e:?}")))?,
        ),
    };
    let client_auth = RemoteCertResolver::new(signer).into_client_auth();
    assemble_driver(kind, cfg, client_auth)
}
