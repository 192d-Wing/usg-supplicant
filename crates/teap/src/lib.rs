//! EAP-TEAP (RFC 7170) protocol core.
//!
//! Milestone 1 provides the **TLV codec**: a bounds-checked, panic-free
//! encoder/decoder for the TEAP TLV framing plus typed bodies for the TLVs
//! this supplicant uses. Later milestones add the per-session state machine,
//! crypto-binding, and the `usg-TEAP/1.3` key schedule.
//!
//! Design rules for this crate:
//! - **Pure**: no I/O, no OS calls, no `unsafe`.
//! - **Panic-free on input**: every decode path returns [`tlv::TlvError`];
//!   no `unwrap`/`expect`/slice-index can abort on malformed bytes.
//! - **Structure, not policy**: the codec validates framing and fixed-field
//!   sizes. Semantic validation (versions, sub-types, MAC verification) is the
//!   crypto/state-machine layer's job in later milestones.
#![forbid(unsafe_code)]

pub mod tlv;
