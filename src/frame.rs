//! Strict, schema-validating `MissionWeaveProtocol` frame codec.

use serde_json::Value;
use thiserror::Error;

use crate::{
    CanonicalError, SchemaCatalog, SchemaError, StrictJsonError, canonical_bytes, parse_strict_json,
};

/// Frame decoding, validation, or canonical encoding failure.
#[derive(Debug, Error)]
pub enum FrameError {
    /// Incoming bytes were not one strict JSON value.
    #[error(transparent)]
    StrictJson(#[from] StrictJsonError),
    /// The frame did not satisfy the normative WebSocket frame schema.
    #[error(transparent)]
    Schema(#[from] SchemaError),
    /// Canonical encoding failed.
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
}

/// Codec for strict JSON WebSocket frames with offline schema validation.
pub struct FrameCodec {
    catalog: SchemaCatalog,
}

impl FrameCodec {
    /// Create a codec from the SDK's exact embedded schema catalog.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError`] if the embedded schema registry cannot be prepared.
    pub fn new() -> Result<Self, FrameError> {
        Ok(Self {
            catalog: SchemaCatalog::new()?,
        })
    }

    /// Strictly decode and validate one WebSocket frame.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError`] for invalid UTF-8, duplicate members, malformed JSON, or a frame
    /// that fails the normative schema.
    pub fn decode(&self, input: &[u8]) -> Result<Value, FrameError> {
        let value = parse_strict_json(input)?;
        self.catalog
            .validate("websocket-frame.schema.json", &value)?;
        Ok(value)
    }

    /// Validate and encode one WebSocket frame as RFC 8785 canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError`] if validation or canonical serialization fails.
    pub fn encode(&self, frame: &Value) -> Result<Vec<u8>, FrameError> {
        self.catalog
            .validate("websocket-frame.schema.json", frame)?;
        Ok(canonical_bytes(frame)?)
    }

    /// Validate a durable protocol document against one named normative schema.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError`] when validation fails.
    pub fn validate_document(&self, schema_name: &str, document: &Value) -> Result<(), FrameError> {
        Ok(self.catalog.validate(schema_name, document)?)
    }
}

impl Default for FrameCodec {
    fn default() -> Self {
        Self::new().expect("embedded schemas must build a frame codec")
    }
}

#[cfg(test)]
mod tests {
    use super::FrameCodec;
    use crate::ProtocolBundle;

    #[test]
    fn round_trips_a_canonical_valid_frame() {
        let codec = FrameCodec::new().expect("codec");
        let bytes =
            ProtocolBundle::conformance("vectors/valid/websocket-frame.json").expect("vector");
        let frame = codec.decode(bytes).expect("valid frame");
        let encoded = codec.encode(&frame).expect("canonical frame");
        let decoded = codec
            .decode(&encoded)
            .expect("canonical frame remains valid");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn rejects_duplicate_members_before_schema_validation() {
        let codec = FrameCodec::new().expect("codec");
        let duplicate = br#"{
          "protocolVersion":"0.1",
          "frameType":"PING",
          "frameType":"PING",
          "frameId":"urn:missionweaveprotocol:frame:test",
          "sentAt":"2026-07-17T00:00:00Z"
        }"#;
        assert!(codec.decode(duplicate).is_err());
    }
}
