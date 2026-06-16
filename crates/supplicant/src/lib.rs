//! TEAP supplicant orchestration.
//!
//! [`driver::TeapDriver`] sequences a full EAP-TEAP authentication: it consumes
//! inbound EAP request packets (from `EAPHost` / `dot3svc`) and produces EAP
//! responses, driving the FIPS TLS 1.3 handshake (Phase 1) and the protected
//! Phase-2 TLV exchange ([`teap::session`]) to a terminal
//! [`teap::session::Outcome`]. The inner EAP-TLS method (machine cert via CNG, or
//! smartcard user cert) is injected.
#![forbid(unsafe_code)]

pub mod driver;
pub mod error;
pub mod inner_tls;
