//! TEAP TLV type-number registry (RFC 7170 §4.2 / IANA "TEAP TLV Types").
//!
//! NOTE FOR MILESTONE 2: the values marked `// VERIFY` must be checked against
//! RFC 7170 and the IANA registry before any crypto-binding work depends on
//! them. The codec itself does not rely on these numbers being correct — it
//! parses any type generically — but the typed-body dispatch does.

/// TLV type numbers (the low 14 bits of the TLV type field).
pub mod type_id {
    /// Authority-ID TLV — server identity hint (opaque value).
    pub const AUTHORITY_ID: u16 = 1;
    /// Identity-Type TLV — requests User vs Machine identity. Drives chaining.
    pub const IDENTITY_TYPE: u16 = 2;
    /// Result TLV — overall success/failure.
    pub const RESULT: u16 = 3;
    /// NAK TLV — reject a TLV the peer cannot process.
    pub const NAK: u16 = 4;
    /// Error TLV — 4-octet error code.
    pub const ERROR: u16 = 5;
    /// Channel-Binding TLV. // VERIFY
    pub const CHANNEL_BINDING: u16 = 7;
    /// Vendor-Specific TLV — Vendor-Id + vendor data (carries our MAT).
    pub const VENDOR_SPECIFIC: u16 = 9;
    /// Request-Action TLV. // VERIFY
    pub const REQUEST_ACTION: u16 = 10;
    /// EAP-Payload TLV — encapsulates an inner EAP packet.
    pub const EAP_PAYLOAD: u16 = 11;
    /// Intermediate-Result TLV — per-inner-method result (+ nested TLVs).
    pub const INTERMEDIATE_RESULT: u16 = 12;
    /// PAC TLV. // VERIFY — our chaining uses a Vendor-Specific MAT, not this.
    pub const PAC: u16 = 13;
    /// Crypto-Binding TLV — compound MAC binding inner keys to the tunnel.
    pub const CRYPTO_BINDING: u16 = 14;
    /// Trusted-Server-Root TLV. // VERIFY
    pub const TRUSTED_SERVER_ROOT: u16 = 18;
}
