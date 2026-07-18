//! Official Rust SDK for `MissionWeaveProtocol`.

mod bundle;
mod canonical;
mod conformance;
mod frame;
mod schema;
mod strict_json;

pub use bundle::{
    BundleError, BundleSummary, CryptographyBundleSummary, CryptographyPin, ProtocolBundle,
    ProtocolPin,
};
pub use canonical::{
    CanonicalError, Ed25519Signer, canonical_bytes, canonical_sha256, signature_input,
};
pub use conformance::{ConformanceReport, ConformanceRunner, VectorResult};
pub use frame::{FrameCodec, FrameError};
pub use schema::{SchemaCatalog, SchemaError};
pub use strict_json::{StrictJsonError, parse_strict_json};

/// SDK package version.
pub const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Supported `MissionWeaveProtocol` wire version.
pub const PROTOCOL_VERSION: &str = "0.1";

/// Canonical `MissionWeaveProtocol` wire namespace.
pub const WIRE_NAMESPACE: &str = "missionweaveprotocol";

#[cfg(test)]
mod tests {
    use super::{PROTOCOL_VERSION, SDK_VERSION, WIRE_NAMESPACE};

    #[test]
    fn exposes_canonical_identity() {
        assert_eq!(SDK_VERSION, "0.1.0");
        assert_eq!(PROTOCOL_VERSION, "0.1");
        assert_eq!(WIRE_NAMESPACE, "missionweaveprotocol");
    }
}
