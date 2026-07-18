//! Implementation-neutral schema conformance vector runner.

use std::collections::BTreeSet;

use serde::Deserialize;
use thiserror::Error;

use crate::{ProtocolBundle, SchemaCatalog, SchemaError, StrictJsonError, parse_strict_json};

/// Result of one schema conformance vector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VectorResult {
    /// Stable vector name from the manifest.
    pub name: String,
    /// Validity expected by the canonical manifest.
    pub expected_valid: bool,
    /// Validity observed from the SDK validator.
    pub actual_valid: bool,
    /// Validation error for an invalid instance, when available.
    pub error: Option<String>,
}

impl VectorResult {
    /// Whether observed and expected validity agree.
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.expected_valid == self.actual_valid
    }
}

/// Complete conformance-vector report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceReport {
    /// Ordered results from the canonical manifest.
    pub results: Vec<VectorResult>,
}

impl ConformanceReport {
    /// Whether every vector matched its expected validity.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.results.iter().all(VectorResult::passed)
    }

    /// Human-readable result count.
    #[must_use]
    pub fn summary(&self) -> String {
        let passed = self.results.iter().filter(|result| result.passed()).count();
        format!("{passed}/{} conformance vectors passed", self.results.len())
    }
}

/// Conformance runner failure unrelated to expected instance invalidity.
#[derive(Debug, Error)]
pub enum ConformanceError {
    /// An embedded manifest or vector could not be parsed as strict JSON.
    #[error(transparent)]
    InvalidJson(#[from] StrictJsonError),
    /// The manifest could not be deserialized.
    #[error("invalid conformance manifest: {0}")]
    InvalidManifest(#[from] serde_json::Error),
    /// A referenced embedded file was missing.
    #[error("embedded conformance artifact `{0}` is missing")]
    MissingArtifact(String),
    /// A manifest entry used an unsafe or unexpected path.
    #[error("unsafe conformance path `{0}`")]
    UnsafePath(String),
    /// Two manifest entries used the same stable name.
    #[error("duplicate conformance case name `{0}`")]
    DuplicateName(String),
    /// Schema registry construction or compilation failed.
    #[error(transparent)]
    Schema(#[from] SchemaError),
}

#[derive(Debug, Deserialize)]
struct ManifestEntry {
    name: String,
    schema: String,
    instance: String,
    valid: bool,
}

/// Runner for the SDK's exact embedded manifest and vectors.
pub struct ConformanceRunner {
    catalog: SchemaCatalog,
}

impl ConformanceRunner {
    /// Build a runner using the embedded offline schema catalog.
    ///
    /// # Errors
    ///
    /// Returns `ConformanceError` if the embedded schema registry cannot be prepared.
    pub fn new() -> Result<Self, ConformanceError> {
        Ok(Self {
            catalog: SchemaCatalog::new()?,
        })
    }

    /// Run every canonical schema conformance vector.
    ///
    /// Passing this suite demonstrates schema-and-vector conformance, not behavioral protocol
    /// conformance.
    ///
    /// # Errors
    ///
    /// Returns `ConformanceError` if the manifest, its paths, embedded assets, or schemas are
    /// malformed.
    pub fn run(&self) -> Result<ConformanceReport, ConformanceError> {
        let manifest_bytes = ProtocolBundle::conformance("manifest.json")
            .ok_or_else(|| ConformanceError::MissingArtifact("manifest.json".to_owned()))?;
        let manifest_value = parse_strict_json(manifest_bytes)?;
        let entries: Vec<ManifestEntry> = serde_json::from_value(manifest_value)?;
        let mut names = BTreeSet::new();
        let mut results = Vec::with_capacity(entries.len());

        for entry in entries {
            if !names.insert(entry.name.clone()) {
                return Err(ConformanceError::DuplicateName(entry.name));
            }
            let schema_name = strip_safe_prefix(&entry.schema, "schemas/")?;
            let instance_path = strip_safe_prefix(&entry.instance, "conformance/")?;
            let instance_bytes = ProtocolBundle::conformance(instance_path)
                .ok_or_else(|| ConformanceError::MissingArtifact(instance_path.to_owned()))?;
            let instance = parse_strict_json(instance_bytes)?;

            let (actual_valid, error) = match self.catalog.validate(schema_name, &instance) {
                Ok(()) => (true, None),
                Err(SchemaError::Validation { message, .. }) => (false, Some(message)),
                Err(error) => return Err(error.into()),
            };
            results.push(VectorResult {
                name: entry.name,
                expected_valid: entry.valid,
                actual_valid,
                error,
            });
        }

        Ok(ConformanceReport { results })
    }
}

impl Default for ConformanceRunner {
    fn default() -> Self {
        Self::new().expect("embedded conformance assets must be valid")
    }
}

fn strip_safe_prefix<'a>(path: &'a str, prefix: &str) -> Result<&'a str, ConformanceError> {
    let relative = path
        .strip_prefix(prefix)
        .ok_or_else(|| ConformanceError::UnsafePath(path.to_owned()))?;
    if relative.is_empty()
        || relative.starts_with('/')
        || relative.split('/').any(|segment| segment == "..")
    {
        return Err(ConformanceError::UnsafePath(path.to_owned()));
    }
    Ok(relative)
}

#[cfg(test)]
mod tests {
    use super::ConformanceRunner;

    #[test]
    fn passes_all_embedded_vectors() {
        let report = ConformanceRunner::new()
            .expect("runner")
            .run()
            .expect("manifest");
        assert!(report.passed(), "{}", report.summary());
        assert_eq!(report.results.len(), 52);
        assert_eq!(
            report
                .results
                .iter()
                .filter(|result| result.expected_valid)
                .count(),
            25
        );
    }
}
