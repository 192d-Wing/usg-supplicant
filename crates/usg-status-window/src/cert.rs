//! "View Certificate…" — open the in-use client certificate in the Windows
//! certificate viewer.
//!
//! The published status carries only the certificate subject, not the cert itself,
//! so we locate it by subject (CN) in the relevant system store (`LocalMachine\My`
//! for a machine session, `CurrentUser\My` for a user session), export its DER to a
//! temp `.cer`, and shell-open it — Windows then shows its native cert dialog. If we
//! can't find it, we fall back to opening the certificate manager for that store.

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use usg_status::Identity;
use windows::Win32::Security::Cryptography::{
    CERT_FIND_SUBJECT_STR, CERT_OPEN_STORE_FLAGS, CERT_QUERY_ENCODING_TYPE,
    CERT_STORE_PROV_SYSTEM_W, CERT_STORE_READONLY_FLAG, CERT_SYSTEM_STORE_CURRENT_USER,
    CERT_SYSTEM_STORE_LOCAL_MACHINE, CertCloseStore, CertFindCertificateInStore,
    CertFreeCertificateContext, CertOpenStore, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::core::{PCWSTR, w};

/// Open the certificate (matched by subject CN) in the Windows viewer, or fall back
/// to the certificate manager for the session's store.
pub fn view(identity: Identity, subject: &str) {
    if try_view_exact(identity, subject).is_none() {
        open_cert_manager(identity);
    }
}

/// Locate the cert by subject CN, export its DER, and shell-open it. `None` if the
/// store can't be opened or no cert matches.
///
/// Limitation: this matches the first cert whose subject contains the CN, without the
/// client-auth-EKU filter the supplicant applies when *selecting* the cert. If a store
/// holds several certs sharing that CN (e.g. a renewed pair), the viewer may show a
/// different one than was used to authenticate. A future change can publish the cert
/// thumbprint in the status to find it exactly.
fn try_view_exact(identity: Identity, subject: &str) -> Option<()> {
    let cn = common_name(subject);
    if cn.is_empty() {
        return None;
    }
    let cn_wide = wide(&cn);
    let store_name = wide("MY");
    let location = match identity {
        Identity::Machine => CERT_SYSTEM_STORE_LOCAL_MACHINE,
        Identity::User => CERT_SYSTEM_STORE_CURRENT_USER,
    };
    let enc = CERT_QUERY_ENCODING_TYPE(X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0);

    // SAFETY: open the read-only system store, find the cert by subject substring,
    // copy its DER, and free both the context and the store.
    unsafe {
        let store = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            CERT_QUERY_ENCODING_TYPE(0),
            None,
            CERT_OPEN_STORE_FLAGS(location | CERT_STORE_READONLY_FLAG.0),
            Some(store_name.as_ptr().cast::<c_void>()),
        )
        .ok()?;

        let ctx = CertFindCertificateInStore(
            store,
            enc,
            0,
            CERT_FIND_SUBJECT_STR,
            Some(cn_wide.as_ptr().cast::<c_void>()),
            None,
        );

        let result = if ctx.is_null() {
            None
        } else {
            let der =
                std::slice::from_raw_parts((*ctx).pbCertEncoded, (*ctx).cbCertEncoded as usize);
            let opened = write_and_open(identity, der);
            let _ = CertFreeCertificateContext(Some(ctx));
            opened
        };
        let _ = CertCloseStore(Some(store), 0);
        result
    }
}

/// Write the DER to a temp `.cer` and shell-open it (Windows shows its cert dialog).
/// The filename is per-identity so opening the computer and user certs in quick
/// succession can't have one write overwrite the other's file before its async
/// viewer reads it.
fn write_and_open(identity: Identity, der: &[u8]) -> Option<()> {
    let name = match identity {
        Identity::Machine => "usg-supplicant-view-machine.cer",
        Identity::User => "usg-supplicant-view-user.cer",
    };
    let path = std::env::temp_dir().join(name);
    std::fs::write(&path, der).ok()?;
    shell_open(&path);
    Some(())
}

/// Open the certificate manager for the session's store (machine vs. user).
fn open_cert_manager(identity: Identity) {
    let snapin = match identity {
        Identity::Machine => w!("certlm.msc"),
        Identity::User => w!("certmgr.msc"),
    };
    // SAFETY: shell-open a standard MMC snap-in by name.
    unsafe {
        ShellExecuteW(
            None,
            w!("open"),
            snapin,
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        );
    }
}

fn shell_open(path: &Path) {
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: shell-open a local file path with the default ("open") verb.
    unsafe {
        ShellExecuteW(
            None,
            w!("open"),
            PCWSTR(wide.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        );
    }
}

/// The `CN=` value from a distinguished name (trimmed), or the whole string if there
/// is no `CN`. Used as the subject substring to find the cert.
fn common_name(subject: &str) -> String {
    let lower = subject.to_ascii_lowercase();
    if let Some(pos) = lower.find("cn=") {
        let rest = &subject[pos.saturating_add(3)..];
        let end = rest.find(',').unwrap_or(rest.len());
        return rest.get(..end).unwrap_or(rest).trim().to_string();
    }
    subject.trim().to_string()
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
