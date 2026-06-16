//! TEAP outer framing and fragmentation (RFC 7170 §3.3 / §4.1), the EAP-TLS-style
//! envelope that carries the TLS handshake records and, post-handshake, the
//! protected Phase-2 data.
//!
//! TEAP Type-Data:
//! ```text
//!  0 1 2 3 4 5 6 7
//! +-+-+-+-+-+-+-+-+
//! |L M S R R R Ver|   L=Length-included, M=More-fragments, S=Start
//! +-+-+-+-+-+-+-+-+   Ver = TEAP version (low 3 bits)
//! | TLS Message Length (4 octets, present iff L) |
//! | Data (a TLS-message fragment) ...            |
//! ```

use crate::tlv::TlvError;

/// EAP method type for TEAP (IANA).
pub const TEAP_EAP_TYPE: u8 = 55;
/// TEAP version this implementation speaks.
pub const TEAP_VERSION: u8 = 1;

const FLAG_L: u8 = 0x80;
const FLAG_M: u8 = 0x40;
const FLAG_S: u8 = 0x20;
const VERSION_MASK: u8 = 0x07;
const TLS_LEN_FIELD: usize = 4;
/// Cap on fragments per reassembled message. Bounds a peer that streams
/// `more-fragments` packets (even empty ones) without ever terminating.
const MAX_FRAGMENTS: usize = 1024;

/// A parsed TEAP outer message (the Type-Data of an EAP TEAP packet).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeapOuter {
    /// `M` — more fragments follow.
    pub more_fragments: bool,
    /// `S` — TEAP Start (server's first message).
    pub start: bool,
    /// TEAP version (low 3 bits of flags).
    pub version: u8,
    /// Total length of the whole TLS message, present iff the `L` bit is set
    /// (only on the first fragment).
    pub tls_message_length: Option<u32>,
    /// This fragment's data.
    pub data: Vec<u8>,
}

impl TeapOuter {
    /// An empty acknowledgement (no flags but version), sent to request the next
    /// fragment from the peer.
    #[must_use]
    pub fn ack(version: u8) -> Self {
        Self {
            more_fragments: false,
            start: false,
            version: version & VERSION_MASK,
            tls_message_length: None,
            data: Vec::new(),
        }
    }

    /// Whether this is an acknowledgement (no start, no data, no more-fragments).
    #[must_use]
    pub fn is_ack(&self) -> bool {
        !self.start && !self.more_fragments && self.data.is_empty()
    }

    /// Parse from the EAP TEAP Type-Data.
    ///
    /// # Errors
    /// [`TlvError::TruncatedValue`] if the flags or declared TLS length are
    /// missing/short.
    pub fn parse(type_data: &[u8]) -> Result<Self, TlvError> {
        let flags = *type_data.first().ok_or(TlvError::TruncatedValue {
            tlv_type: u16::from(TEAP_EAP_TYPE),
            declared: 1,
            available: 0,
        })?;
        let length_included = flags & FLAG_L != 0;
        let more_fragments = flags & FLAG_M != 0;
        let start = flags & FLAG_S != 0;
        let version = flags & VERSION_MASK;

        let mut offset = 1usize;
        let tls_message_length = if length_included {
            let end = offset.saturating_add(TLS_LEN_FIELD);
            let len_bytes = type_data
                .get(offset..end)
                .and_then(|s| <[u8; 4]>::try_from(s).ok())
                .ok_or(TlvError::TruncatedValue {
                    tlv_type: u16::from(TEAP_EAP_TYPE),
                    declared: end,
                    available: type_data.len(),
                })?;
            offset = end;
            Some(u32::from_be_bytes(len_bytes))
        } else {
            None
        };
        let data = type_data.get(offset..).unwrap_or(&[]).to_vec();
        Ok(Self {
            more_fragments,
            start,
            version,
            tls_message_length,
            data,
        })
    }

    /// Build the EAP TEAP Type-Data (the `L` bit is derived from
    /// `tls_message_length`).
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let mut flags = self.version & VERSION_MASK;
        if self.more_fragments {
            flags |= FLAG_M;
        }
        if self.start {
            flags |= FLAG_S;
        }
        if self.tls_message_length.is_some() {
            flags |= FLAG_L;
        }
        let cap = TLS_LEN_FIELD
            .saturating_add(1)
            .saturating_add(self.data.len());
        let mut out = Vec::with_capacity(cap);
        out.push(flags);
        if let Some(len) = self.tls_message_length {
            out.extend_from_slice(&len.to_be_bytes());
        }
        out.extend_from_slice(&self.data);
        out
    }
}

/// Reassembles a fragmented TLS message from inbound TEAP fragments.
#[derive(Debug)]
pub struct Reassembler {
    buf: Vec<u8>,
    expected_total: Option<usize>,
    max_total: usize,
    fragments: usize,
}

impl Reassembler {
    /// Create a reassembler bounding the total message to `max_total` octets.
    #[must_use]
    pub fn new(max_total: usize) -> Self {
        Self {
            buf: Vec::new(),
            expected_total: None,
            max_total,
            fragments: 0,
        }
    }

    /// Push one inbound fragment. Returns `Some(message)` when the final fragment
    /// (M not set) completes the message, else `None` (more expected).
    ///
    /// # Errors
    /// [`TlvError::TooManyTlvs`] used as the over-limit signal if the declared or
    /// accumulated length exceeds `max_total`, or [`TlvError::TruncatedValue`] if
    /// the final length does not match the declared total.
    pub fn push(&mut self, outer: &TeapOuter) -> Result<Option<Vec<u8>>, TlvError> {
        // Bound the fragment count so a peer cannot stream more-fragments
        // packets (even empty ones) forever without terminating.
        self.fragments = self.fragments.saturating_add(1);
        if self.fragments > MAX_FRAGMENTS {
            return Err(TlvError::TooManyTlvs {
                limit: MAX_FRAGMENTS,
            });
        }

        if let Some(declared) = outer.tls_message_length {
            let declared = usize::try_from(declared).unwrap_or(usize::MAX);
            if declared > self.max_total {
                return Err(TlvError::TooManyTlvs {
                    limit: self.max_total,
                });
            }
            match self.expected_total {
                // First fragment carries the total; record it once.
                None => self.expected_total = Some(declared),
                // RFC 7170: the length appears only on the first fragment. A
                // later, differing total is a protocol violation — reject it.
                Some(prev) if prev != declared => {
                    return Err(TlvError::TruncatedValue {
                        tlv_type: u16::from(TEAP_EAP_TYPE),
                        declared,
                        available: prev,
                    });
                }
                Some(_) => {}
            }
        }
        let new_len = self.buf.len().saturating_add(outer.data.len());
        if new_len > self.max_total {
            return Err(TlvError::TooManyTlvs {
                limit: self.max_total,
            });
        }
        self.buf.extend_from_slice(&outer.data);

        if outer.more_fragments {
            return Ok(None);
        }
        // Final fragment: if a total was declared, it must match.
        if let Some(total) = self.expected_total
            && self.buf.len() != total
        {
            return Err(TlvError::TruncatedValue {
                tlv_type: u16::from(TEAP_EAP_TYPE),
                declared: total,
                available: self.buf.len(),
            });
        }
        // Reset per-message state so the reassembler is safe to reuse.
        self.expected_total = None;
        self.fragments = 0;
        Ok(Some(core::mem::take(&mut self.buf)))
    }
}

/// Fragment a complete outbound TLS message into TEAP outer messages, each
/// carrying at most `max_fragment` octets of data. The first of several
/// fragments carries the `L` bit + total length and `M`; the last clears `M`.
/// A message that fits in one fragment is returned without `L`/`M`.
///
/// `max_fragment` is clamped to at least 1.
#[must_use]
pub fn fragment(message: &[u8], max_fragment: usize, version: u8) -> Vec<TeapOuter> {
    let chunk = max_fragment.max(1);
    let version = version & VERSION_MASK;
    if message.len() <= chunk {
        return vec![TeapOuter {
            more_fragments: false,
            start: false,
            version,
            tls_message_length: None,
            data: message.to_vec(),
        }];
    }
    let total = u32::try_from(message.len()).ok();
    let mut out = Vec::new();
    let mut chunks = message.chunks(chunk).peekable();
    let mut first = true;
    while let Some(piece) = chunks.next() {
        let more = chunks.peek().is_some();
        out.push(TeapOuter {
            more_fragments: more,
            start: false,
            version,
            // Only the first fragment carries the total length.
            tls_message_length: if first { total } else { None },
            data: piece.to_vec(),
        });
        first = false;
    }
    out
}
