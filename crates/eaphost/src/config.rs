//! The `EAPHost` connection-data config blob: the per-session profile the config
//! DLL produces and the peer method parses in `EapPeerBeginSession`.
//!
//! `EAPHost` hands the method an opaque connection-data byte buffer; this is our
//! private, length-prefixed encoding of it (trust anchors, expected server name,
//! cert-selection subject, identity, MAT). Parsing is bounds-checked and
//! panic-free (the input is attacker-influenceable via the stored profile).

use crate::error::ConfigError;

/// Magic prefix identifying our blob format.
const MAGIC: &[u8; 4] = b"USGT";
/// Blob format version.
const VERSION: u8 = 1;
/// `flags` bit: set for a machine session, clear for a user session.
const FLAG_MACHINE: u8 = 0b0000_0001;

/// The decoded per-session profile.
///
/// `Debug` is hand-written to redact the MAT (an authorization-bearing ticket)
/// and the trust-anchor DER, matching `pac`'s treatment of the same ticket.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionConfigBlob {
    /// Machine session (boot) vs user session (logon).
    pub machine: bool,
    /// Expected EAP-server name (validated against the server certificate).
    pub server_name: String,
    /// SMI Private Enterprise Number for the MAT Vendor-Specific TLV.
    pub mat_vendor_id: u32,
    /// Max TLS-fragment payload per TEAP message.
    pub max_fragment: u32,
    /// Subject substring identifying the client certificate to select (combined
    /// with the Client-Auth EKU requirement).
    pub selector_subject: String,
    /// Trust-anchor certificates (DER) for the server certificate.
    pub roots: Vec<Vec<u8>>,
    /// For a user session: the stored MAT to present in-tunnel.
    pub mat: Option<Vec<u8>>,
}

impl core::fmt::Debug for SessionConfigBlob {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionConfigBlob")
            .field("machine", &self.machine)
            .field("server_name", &self.server_name)
            .field("mat_vendor_id", &self.mat_vendor_id)
            .field("max_fragment", &self.max_fragment)
            .field("selector_subject", &self.selector_subject)
            .field("roots", &self.roots.len())
            .field("has_mat", &self.mat.is_some())
            .finish()
    }
}

impl SessionConfigBlob {
    /// Serialize to the wire format.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.push(if self.machine { FLAG_MACHINE } else { 0 });
        out.extend_from_slice(&self.mat_vendor_id.to_le_bytes());
        out.extend_from_slice(&self.max_fragment.to_le_bytes());
        put_bytes(&mut out, self.server_name.as_bytes());
        put_bytes(&mut out, self.selector_subject.as_bytes());
        put_u32(
            &mut out,
            u32::try_from(self.roots.len()).unwrap_or(u32::MAX),
        );
        for der in &self.roots {
            put_bytes(&mut out, der);
        }
        match &self.mat {
            Some(mat) => {
                out.push(1);
                put_bytes(&mut out, mat);
            }
            None => out.push(0),
        }
        out
    }

    /// Parse the wire format. Bounds-checked and panic-free.
    ///
    /// # Errors
    /// [`ConfigError`] on a bad magic/version or a truncated/oversized field.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ConfigError> {
        let mut r = Reader::new(bytes);
        if r.take(4).ok_or(ConfigError::Truncated)? != MAGIC {
            return Err(ConfigError::BadMagic);
        }
        if r.u8().ok_or(ConfigError::Truncated)? != VERSION {
            return Err(ConfigError::BadVersion);
        }
        let flags = r.u8().ok_or(ConfigError::Truncated)?;
        let mat_vendor_id = r.u32().ok_or(ConfigError::Truncated)?;
        let max_fragment = r.u32().ok_or(ConfigError::Truncated)?;
        let server_name = r.string()?;
        let selector_subject = r.string()?;

        let num_roots = r.u32().ok_or(ConfigError::Truncated)?;
        // Do NOT pre-allocate from the (attacker-influenceable) count; grow as
        // each root is actually read, so a bogus count fails fast on the first
        // truncated read instead of forcing a large up-front allocation.
        let mut roots = Vec::new();
        for _ in 0..num_roots {
            roots.push(r.bytes()?.to_vec());
        }
        let mat = match r.u8().ok_or(ConfigError::Truncated)? {
            0 => None,
            _ => Some(r.bytes()?.to_vec()),
        };
        // Reject trailing garbage so a malformed profile fails closed.
        if !r.is_empty() {
            return Err(ConfigError::TrailingData);
        }
        Ok(Self {
            machine: flags & FLAG_MACHINE != 0,
            server_name,
            mat_vendor_id,
            max_fragment,
            selector_subject,
            roots,
            mat,
        })
    }
}

fn put_u32(out: &mut Vec<u8>, n: u32) {
    out.extend_from_slice(&n.to_le_bytes());
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_u32(out, u32::try_from(b.len()).unwrap_or(u32::MAX));
    out.extend_from_slice(b);
}

/// A bounds-checked, panic-free cursor over the blob bytes.
struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.b.len()
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.b.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).and_then(|s| s.first().copied())
    }

    fn u32(&mut self) -> Option<u32> {
        let s: [u8; 4] = self.take(4)?.try_into().ok()?;
        Some(u32::from_le_bytes(s))
    }

    /// A `u32`-length-prefixed byte slice.
    fn bytes(&mut self) -> Result<&'a [u8], ConfigError> {
        let len = self.u32().ok_or(ConfigError::Truncated)?;
        let len = usize::try_from(len).map_err(|_| ConfigError::Truncated)?;
        self.take(len).ok_or(ConfigError::Truncated)
    }

    /// A `u32`-length-prefixed UTF-8 string.
    fn string(&mut self) -> Result<String, ConfigError> {
        let raw = self.bytes()?;
        core::str::from_utf8(raw)
            .map(str::to_owned)
            .map_err(|_| ConfigError::BadUtf8)
    }
}
