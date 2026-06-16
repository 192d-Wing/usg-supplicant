//! Build a [`TeapDriver`] for an `EAPHost` session by selecting the Windows
//! credential (machine CNG cert / smartcard user cert) per the session identity,
//! then delegating the platform-independent wiring to
//! [`supplicant::builder::assemble_driver`].
//!
//! Windows-only: the credential comes from the CNG / smartcard store. The
//! profile (trust anchors, server name, MAT, fragment budget, identity) is a
//! [`supplicant::driver::DriverConfig`] the caller assembles from the `EAPHost`
//! session context — no separate near-duplicate config type.

use std::sync::Arc;

use creds::adapter::RemoteCertResolver;
use creds::selection::CertSelector;
use fips_tls::signer::RemoteSigner;
use rustls::RootCertStore;
use supplicant::builder::assemble_driver;
use supplicant::driver::{DriverConfig, TeapDriver};
use teap::session::Identity;

use crate::error::BuildError;

/// Build a driver, selecting the credential from the Windows certificate store
/// per `cfg.identity`: the machine cert (`Local Machine\My`) for a machine
/// session, the smartcard user cert (`Current User\My`) for a user session. The
/// private key never leaves its store; it signs the inner handshake via CNG.
///
/// # Errors
/// [`BuildError::Credential`] if the certificate cannot be selected or its key
/// acquired; [`BuildError::Driver`] if the driver cannot be assembled.
pub fn build_driver(
    cfg: DriverConfig,
    roots: RootCertStore,
    selector: &CertSelector,
) -> Result<TeapDriver, BuildError> {
    let signer: Arc<dyn RemoteSigner> = match cfg.identity {
        Identity::Machine => {
            Arc::new(creds::cng::machine_signer(selector).map_err(BuildError::Credential)?)
        }
        Identity::User => {
            Arc::new(creds::cng::user_signer(selector).map_err(BuildError::Credential)?)
        }
    };
    let client_auth = RemoteCertResolver::new(signer).into_client_auth();
    assemble_driver(cfg, roots, client_auth).map_err(|e| BuildError::Driver(format!("{e:?}")))
}
