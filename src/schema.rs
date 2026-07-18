//! Offline Draft 2020-12 schema registry and document validation.

use std::collections::BTreeMap;

use jsonschema::{Draft, Registry};
use serde_json::Value;
use thiserror::Error;

use crate::{ProtocolBundle, StrictJsonError, parse_strict_json};

/// Schema catalog construction or validation failure.
#[derive(Debug, Error)]
pub enum SchemaError {
    /// An embedded schema could not be read.
    #[error("embedded schema `{0}` is missing")]
    MissingSchema(String),
    /// An embedded schema or instance was not strict JSON.
    #[error(transparent)]
    InvalidJson(#[from] StrictJsonError),
    /// A schema lacked its canonical `$id`.
    #[error("schema `{0}` has no canonical $id")]
    MissingIdentifier(String),
    /// The offline reference registry could not be prepared.
    #[error("schema registry error: {0}")]
    Registry(String),
    /// A schema could not be compiled.
    #[error("schema `{schema}` could not be compiled: {message}")]
    Compile {
        /// Schema file name.
        schema: String,
        /// Validator error.
        message: String,
    },
    /// A document failed schema validation.
    #[error("document does not satisfy `{schema}`: {message}")]
    Validation {
        /// Schema file name.
        schema: String,
        /// First validation failure.
        message: String,
    },
}

/// Offline registry of every normative `MissionWeaveProtocol` JSON Schema.
pub struct SchemaCatalog {
    schemas: BTreeMap<String, Value>,
    registry: Registry<'static>,
}

impl SchemaCatalog {
    /// Load all 21 embedded schemas and prepare their exact `$id` resources.
    ///
    /// # Errors
    ///
    /// Returns [`SchemaError`] if any schema is missing, malformed, lacks `$id`, or cannot be
    /// registered offline.
    pub fn new() -> Result<Self, SchemaError> {
        let mut schemas = BTreeMap::new();
        let mut registry = Registry::new();

        for name in ProtocolBundle::schema_names() {
            let bytes = ProtocolBundle::schema(&name)
                .ok_or_else(|| SchemaError::MissingSchema(name.clone()))?;
            let schema = parse_strict_json(bytes)?;
            let identifier = schema
                .get("$id")
                .and_then(Value::as_str)
                .ok_or_else(|| SchemaError::MissingIdentifier(name.clone()))?;
            registry = registry
                .add(identifier, schema.clone())
                .map_err(|error| SchemaError::Registry(error.to_string()))?;
            schemas.insert(name, schema);
        }

        let registry = registry
            .prepare()
            .map_err(|error| SchemaError::Registry(error.to_string()))?;
        Ok(Self { schemas, registry })
    }

    /// Validate an already parsed JSON value against one named schema.
    ///
    /// # Errors
    ///
    /// Returns [`SchemaError`] for an unknown schema, compilation failure, or invalid document.
    pub fn validate(&self, schema_name: &str, instance: &Value) -> Result<(), SchemaError> {
        let schema = self
            .schemas
            .get(schema_name)
            .ok_or_else(|| SchemaError::MissingSchema(schema_name.to_owned()))?;
        let validator = jsonschema::options()
            .with_draft(Draft::Draft202012)
            .with_registry(&self.registry)
            .with_format("date-time", crate::signed_document::is_protocol_rfc3339)
            .should_validate_formats(true)
            .build(schema)
            .map_err(|error| SchemaError::Compile {
                schema: schema_name.to_owned(),
                message: error.to_string(),
            })?;
        validator
            .validate(instance)
            .map_err(|error| SchemaError::Validation {
                schema: schema_name.to_owned(),
                message: error.to_string(),
            })
    }

    /// Strictly parse and validate one JSON byte sequence.
    ///
    /// # Errors
    ///
    /// Returns [`SchemaError`] when parsing or validation fails.
    pub fn validate_bytes(&self, schema_name: &str, input: &[u8]) -> Result<Value, SchemaError> {
        let value = parse_strict_json(input)?;
        self.validate(schema_name, &value)?;
        Ok(value)
    }

    /// Return the canonical `$id` for one embedded schema.
    #[must_use]
    pub fn identifier(&self, schema_name: &str) -> Option<&str> {
        self.schemas.get(schema_name)?.get("$id")?.as_str()
    }
}

impl Default for SchemaCatalog {
    fn default() -> Self {
        Self::new().expect("embedded MissionWeaveProtocol schemas must be valid")
    }
}

#[cfg(test)]
mod tests {
    use super::SchemaCatalog;
    use crate::ProtocolBundle;

    #[test]
    fn registers_all_schema_identifiers_offline() {
        let catalog = SchemaCatalog::new().expect("catalog should compile");
        for name in ProtocolBundle::schema_names() {
            assert!(catalog.identifier(&name).is_some(), "missing ID for {name}");
        }
    }

    #[test]
    fn validates_a_known_document_and_rejects_bad_format() {
        let catalog = SchemaCatalog::new().expect("catalog should compile");
        let valid = ProtocolBundle::conformance("vectors/valid/presence-record.json")
            .expect("valid vector");
        catalog
            .validate_bytes("presence-record.schema.json", valid)
            .expect("known vector should pass");

        let invalid = br#"{
          "protocolVersion":"0.1",
          "agentId":"urn:missionweaveprotocol:agent:test",
          "agentCardVersion":"1.0.0",
          "status":"available",
          "observedAt":"not-a-date"
        }"#;
        assert!(
            catalog
                .validate_bytes("presence-record.schema.json", invalid)
                .is_err()
        );
    }
}
