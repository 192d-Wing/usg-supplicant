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
    CERT_CONTEXT, CERT_FIND_ANY, CERT_FIND_SUBJECT_STR, CERT_OPEN_STORE_FLAGS,
    CERT_QUERY_ENCODING_TYPE, CERT_SHA256_HASH_PROP_ID, CERT_STORE_PROV_SYSTEM_W,
    CERT_STORE_READONLY_FLAG, CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE,
    CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext,
    CertGetCertificateContextProperty, CertOpenStore, HCERTSTORE, PKCS_7_ASN_ENCODING,
    X509_ASN_ENCODING,
};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::core::{PCWSTR, w};

/// Open the in-use certificate in the Windows viewer. Prefer the exact cert by its
/// SHA-256 thumbprint; fall back to a subject-CN match, then to the certificate
/// manager for the session's store.
pub fn view(identity: Identity, subject: &str, thumbprint: &str) {
    if try_view_by_thumbprint(identity, thumbprint).is_some() {
        return;
    }
    if try_view_by_subject(identity, subject).is_some() {
        return;
    }
    open_cert_manager(identity);
}

/// Open the read-only `…\My` system store for the session identity.
fn open_store(identity: Identity) -> Option<HCERTSTORE> {
    let store_name = wide("MY");
    let location = match identity {
        Identity::Machine => CERT_SYSTEM_STORE_LOCAL_MACHINE,
        Identity::User => CERT_SYSTEM_STORE_CURRENT_USER,
    };
    // SAFETY: open the read-only system store; the caller closes it.
    unsafe {
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            CERT_QUERY_ENCODING_TYPE(0),
            None,
            CERT_OPEN_STORE_FLAGS(location | CERT_STORE_READONLY_FLAG.0),
            Some(store_name.as_ptr().cast::<c_void>()),
        )
        .ok()
    }
}

/// Find the *exact* cert whose SHA-256 thumbprint matches `thumbprint` (uppercase
/// hex), export its DER, and shell-open it. `None` if `thumbprint` is empty, the
/// store can't be opened, or no cert matches.
fn try_view_by_thumbprint(identity: Identity, thumbprint: &str) -> Option<()> {
    if thumbprint.is_empty() {
        return None;
    }
    let want = thumbprint.to_ascii_uppercase();
    let store = open_store(identity)?;
    let enc = CERT_QUERY_ENCODING_TYPE(X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0);
    // SAFETY: enumerate every cert in the store, comparing the Windows-computed
    // SHA-256 hash; free each context (the next find frees the previous) and the store.
    unsafe {
        let mut found = None;
        let mut ctx = CertFindCertificateInStore(store, enc, 0, CERT_FIND_ANY, None, None);
        while !ctx.is_null() {
            if cert_sha256_hex(ctx) == want {
                if let Some(der) = cert_der(ctx) {
                    found = write_and_open(identity, der);
                }
                let _ = CertFreeCertificateContext(Some(ctx));
                break;
            }
            ctx = CertFindCertificateInStore(store, enc, 0, CERT_FIND_ANY, None, Some(ctx));
        }
        let _ = CertCloseStore(Some(store), 0);
        found
    }
}

/// Fallback: find the first cert whose subject contains the CN, export its DER, and
/// shell-open it. Less precise than the thumbprint match (no EKU filter), but works
/// when no thumbprint was published.
fn try_view_by_subject(identity: Identity, subject: &str) -> Option<()> {
    let cn = common_name(subject);
    if cn.is_empty() {
        return None;
    }
    let cn_wide = wide(&cn);
    let store = open_store(identity)?;
    let enc = CERT_QUERY_ENCODING_TYPE(X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0);
    // SAFETY: find by subject substring, copy the DER, free the context and store.
    unsafe {
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
            let opened = cert_der(ctx).and_then(|der| write_and_open(identity, der));
            let _ = CertFreeCertificateContext(Some(ctx));
            opened
        };
        let _ = CertCloseStore(Some(store), 0);
        result
    }
}

/// The DER bytes of a cert context as a slice, or `None` if the store returned a
/// null pointer or zero length (defense-in-depth before forming a raw slice).
///
/// # Safety
/// `ctx` must be a valid cert context; the returned slice must not outlive it.
unsafe fn cert_der<'a>(ctx: *const CERT_CONTEXT) -> Option<&'a [u8]> {
    // SAFETY: `ctx` is a valid cert context per the caller.
    let (ptr, len) = unsafe { ((*ctx).pbCertEncoded, (*ctx).cbCertEncoded as usize) };
    if ptr.is_null() || len == 0 {
        return None;
    }
    // SAFETY: `ptr` points to `len` bytes of DER owned by the cert context.
    Some(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// The Windows-computed SHA-256 hash of a cert context, as uppercase hex (or empty).
///
/// # Safety
/// `ctx` must be a valid cert context.
unsafe fn cert_sha256_hex(ctx: *const CERT_CONTEXT) -> String {
    let mut buf = [0u8; 32];
    let mut len = buf.len() as u32;
    // SAFETY: `ctx` is a valid cert context; `buf` holds the 32-byte SHA-256.
    let ok = unsafe {
        CertGetCertificateContextProperty(
            ctx,
            CERT_SHA256_HASH_PROP_ID,
            Some(buf.as_mut_ptr().cast::<c_void>()),
            &mut len,
        )
    }
    .is_ok();
    if ok && len as usize == buf.len() {
        buf.iter().map(|b| format!("{b:02X}")).collect()
    } else {
        String::new()
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
