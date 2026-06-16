//! MAT storage: a [`Sealer`] (confidentiality/integrity at rest) plus a
//! [`MatStore`] (where the sealed bytes live). On Windows the sealer is DPAPI in
//! machine scope so the ticket is readable pre-logon yet bound to the host.

use std::path::PathBuf;
use std::sync::Mutex;

use crate::error::PacError;
use crate::record::MatRecord;

/// Confidentiality + integrity for the record at rest.
pub trait Sealer: Send + Sync {
    /// Seal plaintext (returns ciphertext).
    ///
    /// # Errors
    /// [`PacError::Seal`] on failure.
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, PacError>;
    /// Unseal ciphertext (returns plaintext).
    ///
    /// # Errors
    /// [`PacError::Unseal`] on failure (wrong host, tamper, corruption).
    fn unseal(&self, ciphertext: &[u8]) -> Result<Vec<u8>, PacError>;
}

/// Identity sealer — **no protection**. Compiled only in test builds
/// (`#[cfg(test)]`) so it cannot be wired into a production store; production
/// uses [`crate::dpapi::DpapiSealer`].
#[cfg(test)]
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopSealer;

#[cfg(test)]
impl Sealer for NoopSealer {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, PacError> {
        Ok(plaintext.to_vec())
    }
    fn unseal(&self, ciphertext: &[u8]) -> Result<Vec<u8>, PacError> {
        Ok(ciphertext.to_vec())
    }
}

/// Persisted store for a single machine's MAT.
pub trait MatStore {
    /// Persist (overwrite) the record.
    ///
    /// # Errors
    /// Sealing, encoding, or I/O failure.
    fn save(&self, record: &MatRecord) -> Result<(), PacError>;
    /// Load the record, or `None` if none is stored.
    ///
    /// # Errors
    /// Unsealing, decoding, or I/O failure.
    fn load(&self) -> Result<Option<MatRecord>, PacError>;
    /// Remove any stored record.
    ///
    /// # Errors
    /// I/O failure (a missing record is not an error).
    fn clear(&self) -> Result<(), PacError>;
}

/// Return the stored ticket only if present and fresh within `max_age_secs`
/// (relative to `now_unix`). Use this at user logon to decide whether to present
/// the MAT in-tunnel.
///
/// # Errors
/// Propagates load/unseal/decode errors.
pub fn fresh_ticket<S: MatStore>(
    store: &S,
    now_unix: u64,
    max_age_secs: u64,
) -> Result<Option<Vec<u8>>, PacError> {
    match store.load()? {
        Some(record) if record.is_fresh(now_unix, max_age_secs) => Ok(Some(record.ticket)),
        _ => Ok(None),
    }
}

/// In-memory store (tests / a process that holds the MAT only for its lifetime).
#[derive(Debug, Default)]
pub struct InMemoryMatStore {
    sealed: Mutex<Option<Vec<u8>>>,
}

impl MatStore for InMemoryMatStore {
    fn save(&self, record: &MatRecord) -> Result<(), PacError> {
        let bytes = record.encode()?;
        let mut guard = self.sealed.lock().map_err(|_| PacError::Locked)?;
        *guard = Some(bytes);
        Ok(())
    }
    fn load(&self) -> Result<Option<MatRecord>, PacError> {
        let guard = self.sealed.lock().map_err(|_| PacError::Locked)?;
        match guard.as_ref() {
            Some(bytes) => Ok(Some(MatRecord::decode(bytes)?)),
            None => Ok(None),
        }
    }
    fn clear(&self) -> Result<(), PacError> {
        let mut guard = self.sealed.lock().map_err(|_| PacError::Locked)?;
        *guard = None;
        Ok(())
    }
}

/// File-backed store: `encode -> seal -> write`, and `read -> unseal -> decode`.
/// On Windows, construct with [`crate::dpapi::DpapiSealer`] and a path under
/// `%ProgramData%` so the machine session can write it and the user session can
/// read it.
#[derive(Debug)]
pub struct FileMatStore<S: Sealer> {
    path: PathBuf,
    sealer: S,
}

impl<S: Sealer> FileMatStore<S> {
    /// Create a file store at `path` using `sealer`.
    #[must_use]
    pub fn new(path: PathBuf, sealer: S) -> Self {
        Self { path, sealer }
    }
}

impl<S: Sealer> MatStore for FileMatStore<S> {
    fn save(&self, record: &MatRecord) -> Result<(), PacError> {
        let sealed = self.sealer.seal(&record.encode()?)?;
        write_private(&self.path, &sealed)?;
        Ok(())
    }

    fn load(&self) -> Result<Option<MatRecord>, PacError> {
        let sealed = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let plaintext = self.sealer.unseal(&sealed)?;
        Ok(Some(MatRecord::decode(&plaintext)?))
    }

    fn clear(&self) -> Result<(), PacError> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// Write `data` to `path` with restrictive permissions.
///
/// On Unix the file is *created* with mode `0600` so there is no world-readable
/// window (creating then tightening would briefly expose it). On Windows
/// confidentiality comes from DPAPI plus the `%ProgramData%` ACL.
#[cfg(unix)]
fn write_private(path: &std::path::Path, data: &[u8]) -> Result<(), PacError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(data)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &std::path::Path, data: &[u8]) -> Result<(), PacError> {
    std::fs::write(path, data)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::{FileMatStore, MatStore, NoopSealer};
    use crate::record::MatRecord;

    #[test]
    fn file_store_roundtrip_and_clear() {
        let path = std::env::temp_dir().join(format!("usg-mat-{}.bin", std::process::id()));
        let store = FileMatStore::new(path, NoopSealer);
        let _ = store.clear(); // start clean

        assert!(store.load().unwrap().is_none());
        let record = MatRecord {
            ticket: b"ticket-on-disk".to_vec(),
            stored_at_unix: 12345,
        };
        store.save(&record).unwrap();
        assert_eq!(store.load().unwrap().unwrap(), record);

        store.clear().unwrap();
        assert!(store.load().unwrap().is_none());
        // Clearing a missing record is not an error.
        store.clear().unwrap();
    }
}
