//! The XML envelope our `EAPHost` configuration entry points
//! ([`crate::peer::EapPeerConfigXml2Blob`] / `EapPeerConfigBlob2Xml`) speak.
//!
//! `EAPHost` stores a method's connection data inside an XML connection profile
//! and round-trips it through the method's config DLL. We carry our
//! [`crate::config::SessionConfigBlob`] verbatim as a single hex-encoded element
//! — a thin, lossless envelope EAPHost can wrap in the connection-data structure
//! its host-API identity path (`EapHostPeerConfigXml2Blob`) requires. The XML is
//! authored and consumed only by us, so a hex blob (no human-facing schema) is
//! sufficient for now.
//!
//! This module is platform-independent and unit-tested everywhere; the COM glue
//! that adapts `IXMLDOMDocument2` to these functions lives in [`crate::peer`].

/// The single element holding the hex-encoded connection blob.
pub const BLOB_ELEMENT: &str = "UsgTeapConfigBlob";

/// Lowercase hex, no separators.
fn to_hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        // Infallible: writing to a String never errors.
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decode hex (either case) to bytes. Returns `None` on odd length or any
/// non-hex character.
fn from_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() & 1 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.as_bytes().chunks_exact(2) {
        // Reject anything `from_str_radix` would otherwise accept but isn't a hex
        // digit (a leading `+`/`-`, whitespace), so malformed text fails closed.
        if !pair.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        let text = core::str::from_utf8(pair).ok()?;
        out.push(u8::from_str_radix(text, 16).ok()?);
    }
    Some(out)
}

/// Wrap a connection blob as the XML document text our config DLL emits:
/// `<UsgTeapConfigBlob>HEX</UsgTeapConfigBlob>`. Hex is `[0-9a-f]` only, so no XML
/// escaping is required.
#[must_use]
pub fn blob_to_xml(blob: &[u8]) -> String {
    format!("<{BLOB_ELEMENT}>{}</{BLOB_ELEMENT}>", to_hex(blob))
}

/// Recover the connection blob from the `<UsgTeapConfigBlob>` element's text (the
/// hex string). Returns `None` if the text is not valid hex, or if it decodes to
/// an empty blob — an empty connection blob is never a valid `SessionConfigBlob`,
/// so we fail closed rather than report a meaningless zero-length config.
#[must_use]
pub fn xml_text_to_blob(doc_text: &str) -> Option<Vec<u8>> {
    let blob = from_hex(doc_text)?;
    if blob.is_empty() { None } else { Some(blob) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_including_empty_and_high_bytes() {
        for case in [
            vec![],
            vec![0x00],
            vec![0xff, 0x00, 0xa5],
            (0u8..=255).collect(),
        ] {
            let hex = to_hex(&case);
            assert!(
                hex.chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            );
            assert_eq!(from_hex(&hex).as_deref(), Some(case.as_slice()));
        }
    }

    #[test]
    fn xml_envelope_round_trips() {
        let blob = vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x7f];
        let xml = blob_to_xml(&blob);
        assert_eq!(xml, "<UsgTeapConfigBlob>deadbeef007f</UsgTeapConfigBlob>");
        // The document's text content is exactly the hex run.
        assert_eq!(
            xml_text_to_blob("deadbeef007f").as_deref(),
            Some(blob.as_slice())
        );
    }

    #[test]
    fn xml_text_tolerates_surrounding_whitespace() {
        assert_eq!(
            xml_text_to_blob("  0a0b\n").as_deref(),
            Some(&[0x0a, 0x0b][..])
        );
    }

    #[test]
    fn rejects_malformed_hex() {
        assert_eq!(from_hex("abc"), None); // odd length
        assert_eq!(from_hex("zz"), None); // non-hex
        assert_eq!(from_hex("0g"), None);
        // `from_str_radix` would accept these signs/space, but they aren't hex.
        assert_eq!(from_hex("+a"), None);
        assert_eq!(from_hex("-1"), None);
        assert_eq!(from_hex("a b c d"), None);
    }

    #[test]
    fn xml_text_to_blob_rejects_empty_config() {
        // An empty / whitespace-only document is not a valid connection blob.
        assert_eq!(xml_text_to_blob(""), None);
        assert_eq!(xml_text_to_blob("   \n"), None);
        // ...but `from_hex` itself still treats empty input as an empty decode.
        assert_eq!(from_hex(""), Some(vec![]));
    }
}
