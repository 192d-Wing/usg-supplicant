//! The on-disk Machine Authorization Ticket record.
//!
//! The ticket itself is **opaque** — server-encrypted bytes the client never
//! parses (SERVER-CONTRACT §1.2). We add only a small framed header so we can
//! store the ticket alongside the (client-clock) time it was issued, to skip
//! presenting an obviously-stale ticket. The server remains the authority on
//! freshness; this is just an optimization.

use crate::error::PacError;

/// Record magic + version.
const MAGIC: &[u8; 4] = b"MAT1";
/// Header: `magic(4)` + `stored_at(8)` + `ticket_len(4)`.
const HEADER_LEN: usize = 16;
/// Defensive ceiling on the opaque ticket size (well above any real MAT).
const MAX_TICKET_LEN: usize = 64 * 1024;

/// A stored MAT: the opaque server ticket plus the client time it was saved.
#[derive(Clone, PartialEq, Eq)]
pub struct MatRecord {
    /// Opaque server ticket bytes (never parsed by the client).
    pub ticket: Vec<u8>,
    /// Unix seconds (client clock) when the ticket was stored.
    pub stored_at_unix: u64,
}

// Don't print the (authorization-bearing) ticket.
impl core::fmt::Debug for MatRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MatRecord")
            .field("ticket_len", &self.ticket.len())
            .field("stored_at_unix", &self.stored_at_unix)
            .finish()
    }
}

impl MatRecord {
    /// Serialize to the framed record form (before sealing).
    ///
    /// # Errors
    /// [`PacError::TooLarge`] if the ticket exceeds [`MAX_TICKET_LEN`].
    pub fn encode(&self) -> Result<Vec<u8>, PacError> {
        if self.ticket.len() > MAX_TICKET_LEN {
            return Err(PacError::TooLarge {
                len: self.ticket.len(),
            });
        }
        // Length fits u32 by the check above.
        let len = u32::try_from(self.ticket.len()).map_err(|_| PacError::TooLarge {
            len: self.ticket.len(),
        })?;
        let mut out = Vec::with_capacity(HEADER_LEN.saturating_add(self.ticket.len()));
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.stored_at_unix.to_be_bytes());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.ticket);
        Ok(out)
    }

    /// Parse a framed record. Bounds-checked and panic-free.
    ///
    /// # Errors
    /// [`PacError::BadRecord`] on bad magic, truncation, or length mismatch.
    pub fn decode(bytes: &[u8]) -> Result<Self, PacError> {
        let magic = bytes.get(0..4).ok_or(PacError::BadRecord)?;
        if magic != MAGIC {
            return Err(PacError::BadRecord);
        }
        let stored = bytes.get(4..12).and_then(|s| <[u8; 8]>::try_from(s).ok());
        let stored_at_unix = u64::from_be_bytes(stored.ok_or(PacError::BadRecord)?);
        let len_bytes = bytes.get(12..16).and_then(|s| <[u8; 4]>::try_from(s).ok());
        let declared = usize::try_from(u32::from_be_bytes(len_bytes.ok_or(PacError::BadRecord)?))
            .map_err(|_| PacError::BadRecord)?;
        if declared > MAX_TICKET_LEN {
            return Err(PacError::BadRecord);
        }
        let end = HEADER_LEN
            .checked_add(declared)
            .ok_or(PacError::BadRecord)?;
        // The record must be exactly header + ticket (no trailing garbage).
        let ticket = bytes.get(HEADER_LEN..end).ok_or(PacError::BadRecord)?;
        if end != bytes.len() {
            return Err(PacError::BadRecord);
        }
        Ok(Self {
            ticket: ticket.to_vec(),
            stored_at_unix,
        })
    }

    /// Whether the ticket is within `max_age_secs` of its stored time, relative
    /// to `now_unix`. A clock that moved backwards (now < stored) is treated as
    /// not fresh (conservative).
    #[must_use]
    pub fn is_fresh(&self, now_unix: u64, max_age_secs: u64) -> bool {
        now_unix
            .checked_sub(self.stored_at_unix)
            .is_some_and(|age| age <= max_age_secs)
    }
}
