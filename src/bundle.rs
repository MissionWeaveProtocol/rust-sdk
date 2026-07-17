//! Embedded normative protocol assets and pin verification.

use std::path::Path;

use include_dir::{Dir, File, include_dir};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

static SCHEMAS: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/schemas");
static CONFORMANCE: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/conformance");
const PIN_BYTES: &[u8] = include_bytes!("../PROTOCOL_PIN.json");

/// Exact protocol source and content digests bundled with the SDK.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolPin {
    /// Canonical protocol repository URL.
    pub repository: String,
    /// Exact protocol commit binding schemas, vectors, and normative prose.
    pub commit: String,
    /// Supported wire protocol version.
    pub protocol_version: String,
    /// Canonical wire namespace.
    pub wire_namespace: String,
    /// Individually pinned artifact trees.
    pub artifacts: ArtifactPins,
    /// Digest covering all schema and conformance JSON files.
    pub bundle_sha256: String,
}

/// Pins for each embedded artifact tree.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct ArtifactPins {
    /// Normative JSON Schemas.
    pub schemas: ArtifactPin,
    /// Schema conformance manifest and vectors.
    pub conformance: ArtifactPin,
}

/// One embedded artifact tree pin.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct ArtifactPin {
    /// Logical root path in the protocol repository.
    pub path: String,
    /// Number of JSON files in the tree.
    pub files: usize,
    /// Path-and-byte-sensitive SHA-256 digest.
    pub sha256: String,
}

/// Verified facts about the embedded protocol bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleSummary {
    /// Number of normative schema files.
    pub schema_files: usize,
    /// Number of conformance manifest and vector files.
    pub conformance_files: usize,
    /// Digest of every embedded protocol JSON artifact.
    pub bundle_sha256: String,
}

/// Protocol bundle verification failure.
#[derive(Debug, Error)]
pub enum BundleError {
    /// The embedded pin is not valid JSON.
    #[error("embedded PROTOCOL_PIN.json is invalid: {0}")]
    InvalidPin(#[from] serde_json::Error),
    /// An artifact tree contains a different number of files than its pin.
    #[error("{tree} contains {actual} JSON files; expected {expected}")]
    FileCount {
        /// Logical artifact tree name.
        tree: &'static str,
        /// Expected number of JSON files.
        expected: usize,
        /// Actual number of JSON files.
        actual: usize,
    },
    /// An artifact digest differs from its pin.
    #[error("{tree} digest is {actual}; expected {expected}")]
    Digest {
        /// Logical artifact tree name.
        tree: &'static str,
        /// Expected lowercase SHA-256 digest.
        expected: String,
        /// Actual lowercase SHA-256 digest.
        actual: String,
    },
}

/// Access to the SDK's exact embedded `MissionWeaveProtocol` artifact bundle.
pub struct ProtocolBundle;

impl ProtocolBundle {
    /// Parse the embedded pin.
    ///
    /// # Errors
    ///
    /// Returns [`BundleError::InvalidPin`] if the bundled pin is malformed.
    pub fn pin() -> Result<ProtocolPin, BundleError> {
        Ok(serde_json::from_slice(PIN_BYTES)?)
    }

    /// Verify file counts and digests for every embedded protocol artifact.
    ///
    /// # Errors
    ///
    /// Returns a [`BundleError`] when any embedded asset differs from the exact pin.
    pub fn verify() -> Result<BundleSummary, BundleError> {
        let pin = Self::pin()?;
        let schemas = json_files(&SCHEMAS, "schemas");
        let conformance = json_files(&CONFORMANCE, "conformance");

        verify_tree("schemas", &schemas, &pin.artifacts.schemas)?;
        verify_tree("conformance", &conformance, &pin.artifacts.conformance)?;

        let mut all = schemas.clone();
        all.extend(conformance.clone());
        all.sort_by(|left, right| left.0.cmp(&right.0));
        let bundle_sha256 = tree_digest(&all);
        if bundle_sha256 != pin.bundle_sha256 {
            return Err(BundleError::Digest {
                tree: "bundle",
                expected: pin.bundle_sha256,
                actual: bundle_sha256,
            });
        }

        Ok(BundleSummary {
            schema_files: schemas.len(),
            conformance_files: conformance.len(),
            bundle_sha256,
        })
    }

    /// Read one embedded schema by its repository-relative file name.
    #[must_use]
    pub fn schema(name: &str) -> Option<&'static [u8]> {
        SCHEMAS.get_file(Path::new(name)).map(File::contents)
    }

    /// List every embedded normative schema file name in lexical order.
    #[must_use]
    pub fn schema_names() -> Vec<String> {
        let mut names = SCHEMAS
            .files()
            .filter(|file| {
                file.path()
                    .extension()
                    .is_some_and(|extension| extension == "json")
            })
            .map(|file| file.path().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    /// Read one embedded conformance artifact by its path below `conformance/`.
    #[must_use]
    pub fn conformance(path: &str) -> Option<&'static [u8]> {
        CONFORMANCE.get_file(Path::new(path)).map(File::contents)
    }
}

fn verify_tree(
    tree: &'static str,
    files: &[(String, &'static [u8])],
    pin: &ArtifactPin,
) -> Result<(), BundleError> {
    if files.len() != pin.files {
        return Err(BundleError::FileCount {
            tree,
            expected: pin.files,
            actual: files.len(),
        });
    }
    let actual = tree_digest(files);
    if actual != pin.sha256 {
        return Err(BundleError::Digest {
            tree,
            expected: pin.sha256.clone(),
            actual,
        });
    }
    Ok(())
}

fn json_files(dir: &'static Dir<'static>, prefix: &str) -> Vec<(String, &'static [u8])> {
    let mut files = Vec::new();
    collect_json_files(dir, prefix, &mut files);
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
}

fn collect_json_files(
    dir: &'static Dir<'static>,
    prefix: &str,
    files: &mut Vec<(String, &'static [u8])>,
) {
    for file in dir.files() {
        if file
            .path()
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            files.push((
                format!("{prefix}/{}", file.path().to_string_lossy()),
                file.contents(),
            ));
        }
    }
    for child in dir.dirs() {
        collect_json_files(child, prefix, files);
    }
}

fn tree_digest(files: &[(String, &'static [u8])]) -> String {
    let mut digest = Sha256::new();
    for (path, contents) in files {
        digest.update(path.as_bytes());
        digest.update([0]);
        digest.update(contents);
        digest.update([0]);
    }
    let bytes = digest.finalize();
    format!("{bytes:x}")
}

#[cfg(test)]
mod tests {
    use super::ProtocolBundle;

    #[test]
    fn verifies_exact_embedded_bundle() {
        let summary = ProtocolBundle::verify().expect("bundle should match its pin");
        assert_eq!(summary.schema_files, 21);
        assert_eq!(summary.conformance_files, 44);
        assert_eq!(
            summary.bundle_sha256,
            "281fb1ec9b73e07f7a2897e576dbbad021085cf7293c1e9450ba3fbdec7f2cda"
        );
    }

    #[test]
    fn exposes_runtime_resources() {
        assert!(ProtocolBundle::schema("mission.schema.json").is_some());
        assert!(ProtocolBundle::conformance("manifest.json").is_some());
        assert!(ProtocolBundle::conformance("vectors/valid/mission.json").is_some());
    }
}
