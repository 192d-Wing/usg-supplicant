//! Assemble a fully-wired [`TeapDriver`] from a [`DriverConfig`], trust anchors,
//! and a client-auth credential.
//!
//! This is the platform-independent half of session setup: it builds the inner
//! EAP-TLS method (verifying the server certificate against `roots` and
//! presenting our client certificate via `client_auth`) and wires it into an
//! outer [`TeapDriver`] that trusts the same anchors. The outer tunnel is
//! server-authenticated only; the credential authenticates the inner method.
//!
//! The credential itself is supplied by the caller as a [`ClientAuth`] — a
//! software key in tests, or the Windows CNG / smartcard resolver in the
//! `eaphost` integration.

use std::sync::Arc;

use fips_tls::backend::{ClientAuth, client_config};
use rustls::RootCertStore;

use crate::driver::{DriverConfig, TeapDriver};
use crate::error::DriverError;
use crate::inner_tls::EapTlsInner;

/// Build the inner EAP-TLS method and wire it into an outer [`TeapDriver`].
///
/// `cfg` carries the session identity, server name, MAT, and fragment budget;
/// `roots` are the trust anchors (used for both the inner and outer server-cert
/// verification — the same RADIUS server); `client_auth` is the client
/// credential presented to the inner method.
///
/// # Errors
/// [`DriverError`] if the inner TLS config/method or the driver cannot be built.
pub fn assemble_driver(
    cfg: DriverConfig,
    roots: RootCertStore,
    client_auth: ClientAuth,
) -> Result<TeapDriver, DriverError> {
    let inner_config: Arc<_> = client_config(roots.clone(), client_auth)?;
    let inner = EapTlsInner::new(inner_config, &cfg.server_name, cfg.max_fragment)
        .map_err(|_| DriverError::Protocol("inner EAP-TLS construction failed"))?;
    TeapDriver::new(cfg, roots, Box::new(inner))
}
