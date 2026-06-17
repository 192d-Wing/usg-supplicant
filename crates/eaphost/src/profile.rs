//! Provisioning XML for the `dot3svc`-driven (production) path.
//!
//! In production the supplicant isn't us calling `EapHostPeer*` — it's Windows'
//! Wired `AutoConfig` service (`dot3svc`) driving `EAPHost`, which loads our peer
//! method, when an 802.1X wired network is present. `dot3svc` is configured with a
//! **LAN profile** that embeds an `EapHostConfig` selecting our method and carrying
//! our connection blob. This module builds both XML documents.
//!
//! These are pure string builders (no Windows deps), so they're unit-tested on
//! every platform. To provision: register the method ([`crate::register`]), write
//! [`lan_profile_xml`] to a file, and `netsh lan add profile filename=… interface=…`.

use crate::{USG_AUTHOR_ID, USG_TYPE_ID};

/// The `EapHostConfig` document that names our method and embeds `connection_blob`
/// (our [`crate::config::SessionConfigBlob`] bytes) in `<Config>`. This is the XML
/// `EapHostPeerConfigXml2Blob` consumes (and that `dot3svc` stores in a profile);
/// `EAPHost` reads `<EapMethod>` to locate us and hands `<Config>` to our
/// `EapPeerConfigXml2Blob`.
#[must_use]
pub fn eap_host_config_xml(connection_blob: &[u8]) -> String {
    const COMMON: &str = "http://www.microsoft.com/provisioning/EapCommon";
    format!(
        "<EapHostConfig xmlns=\"http://www.microsoft.com/provisioning/EapHostConfig\">\
           <EapMethod>\
             <Type xmlns=\"{COMMON}\">{USG_TYPE_ID}</Type>\
             <VendorId xmlns=\"{COMMON}\">0</VendorId>\
             <VendorType xmlns=\"{COMMON}\">0</VendorType>\
             <AuthorId xmlns=\"{COMMON}\">{USG_AUTHOR_ID}</AuthorId>\
           </EapMethod>\
           <Config>{}</Config>\
         </EapHostConfig>",
        crate::config_xml::blob_to_xml(connection_blob)
    )
}

/// A `dot3svc` wired **LAN profile** that enables 802.1X with machine
/// authentication and our EAP method, embedding [`eap_host_config_xml`]. Install
/// with `netsh lan add profile filename=<this> interface=<adapter>`.
///
/// The structure mirrors Microsoft's canonical wired machine-certificate sample
/// (the `<security>` child order, `authMode` before `<EAPConfig>`, the `http://`
/// namespaces). The embedded `EapHostConfig` half is validated live against
/// `EapHostPeerConfigXml2Blob`; the surrounding `LANProfile`/`OneX` wrapper is
/// pending live `netsh lan add profile` validation (`WINDOWS_DEV.md` §4.6). Only a
/// machine-auth profile is emitted (the boot path); a user-auth variant would set
/// `authMode` to `user`/`machineOrUser`.
#[must_use]
pub fn lan_profile_xml(connection_blob: &[u8]) -> String {
    format!(
        "<?xml version=\"1.0\"?>\
         <LANProfile xmlns=\"http://www.microsoft.com/networking/LAN/profile/v1\">\
           <MSM>\
             <security>\
               <OneXEnforced>false</OneXEnforced>\
               <OneXEnabled>true</OneXEnabled>\
               <OneX xmlns=\"http://www.microsoft.com/networking/OneX/v1\">\
                 <authMode>machine</authMode>\
                 <EAPConfig>{}</EAPConfig>\
               </OneX>\
             </security>\
           </MSM>\
         </LANProfile>",
        eap_host_config_xml(connection_blob)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOB: &[u8] = &[0xab, 0xcd, 0x01, 0x00];

    #[test]
    fn eap_host_config_names_our_method_and_embeds_the_blob() {
        let xml = eap_host_config_xml(BLOB);
        assert!(xml.contains("<EapHostConfig"));
        assert!(xml.contains(&format!(">{USG_TYPE_ID}</Type>")));
        assert!(xml.contains(&format!(">{USG_AUTHOR_ID}</AuthorId>")));
        // The <Config> carries our blob via the config_xml envelope.
        assert!(xml.contains("<Config><UsgTeapConfigBlob>abcd0100</UsgTeapConfigBlob></Config>"));
    }

    #[test]
    fn lan_profile_enables_onex_machine_auth_and_wraps_the_eap_config() {
        let xml = lan_profile_xml(BLOB);
        assert!(xml.starts_with("<?xml version=\"1.0\"?>"));
        assert!(xml.contains("<LANProfile"));
        assert!(xml.contains("<OneXEnabled>true</OneXEnabled>"));
        assert!(xml.contains("<authMode>machine</authMode>"));
        // The EAPConfig contains the full EapHostConfig naming our method.
        assert!(xml.contains("<EAPConfig><EapHostConfig"));
        assert!(xml.contains("abcd0100"));
    }
}
