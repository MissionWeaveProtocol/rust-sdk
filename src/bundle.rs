//! Embedded normative protocol assets and pin verification.

use std::{collections::HashSet, path::Path};

use include_dir::{Dir, File, include_dir};
use serde::{Deserialize, de::Error as _};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{canonical::canonical_sha256, strict_json::parse_strict_json};

static SCHEMAS: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/schemas");
static CONFORMANCE: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/conformance");
static CRYPTOGRAPHY: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/cryptography");
const PIN_BYTES: &[u8] = include_bytes!("../PROTOCOL_PIN.json");

/// Exact protocol source and content digests bundled with the SDK.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
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
    /// Independent signed-document cryptography bundle pin.
    pub cryptography: CryptographyPin,
    /// Digest covering all schema and conformance JSON files.
    pub bundle_sha256: String,
}

/// Independent signed-document cryptography bundle pin.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct CryptographyPin {
    /// Repository-relative cryptography manifest path.
    pub path: String,
    /// Protocol commit that published the cryptography bundle.
    pub source_commit: String,
    /// Signed Document Verification Profile identifier.
    pub profile_id: String,
    /// Cryptography manifest format version.
    pub manifest_version: u64,
    /// RFC 8785 digest of the manifest without its top-level `artifactDigest` member.
    pub artifact_digest: String,
    /// Number of digest-protected artifact entries.
    pub artifact_count: usize,
    /// Number of cryptography cases.
    pub case_count: usize,
    /// Number of independently evaluated case entries.
    pub evaluation_count: usize,
}

/// Pins for each embedded artifact tree.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactPins {
    /// Normative JSON Schemas.
    pub schemas: ArtifactPin,
    /// Schema conformance manifest and vectors.
    pub conformance: ArtifactPin,
}

/// One embedded artifact tree pin.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
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

/// Verified facts about the independent signed-document cryptography bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CryptographyBundleSummary {
    /// Number of digest-protected artifacts.
    pub artifact_count: usize,
    /// Number of cryptography cases.
    pub case_count: usize,
    /// Number of independently evaluated entries.
    pub evaluation_count: usize,
    /// RFC 8785 digest of the manifest without its top-level `artifactDigest` member.
    pub artifact_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CryptographyManifest {
    manifest_version: u64,
    profile_id: String,
    protocol_version: String,
    artifact_digest: String,
    artifacts: Vec<CryptographyArtifact>,
    cases: Vec<CryptographyCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CryptographyArtifact {
    path: String,
    byte_length: usize,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct CryptographyCase {
    evaluations: Vec<Value>,
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
    /// The independent cryptography pin is incomplete or malformed.
    #[error("embedded cryptography pin is invalid: {0}")]
    InvalidCryptographyPin(String),
    /// The independent cryptography manifest is not strict JSON or has invalid fields.
    #[error("embedded cryptography manifest is invalid: {0}")]
    InvalidCryptographyManifest(String),
    /// A manifest artifact path escapes its approved embedded roots.
    #[error("cryptography manifest contains unsafe artifact path `{0}`")]
    UnsafeArtifactPath(String),
    /// A manifest artifact is absent from the embedded bundle.
    #[error("embedded cryptography artifact `{0}` is missing")]
    MissingCryptographyArtifact(String),
    /// A manifest artifact byte length differs from its declaration.
    #[error("cryptography artifact `{path}` contains {actual} bytes; expected {expected}")]
    CryptographyByteLength {
        /// Repository-relative artifact path.
        path: String,
        /// Declared byte length.
        expected: usize,
        /// Embedded byte length.
        actual: usize,
    },
    /// A manifest artifact digest differs from its declaration.
    #[error("cryptography artifact `{path}` digest is {actual}; expected {expected}")]
    CryptographyArtifactDigest {
        /// Repository-relative artifact path.
        path: String,
        /// Declared `sha256:` identifier.
        expected: String,
        /// Digest of the embedded bytes.
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
        parse_protocol_pin(PIN_BYTES)
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

    /// Verify the independent signed-document cryptography manifest and every declared artifact.
    ///
    /// # Errors
    ///
    /// Returns a [`BundleError`] when the manifest, pin, count, path, byte length, or digest is
    /// invalid.
    pub fn verify_cryptography() -> Result<CryptographyBundleSummary, BundleError> {
        let pin = Self::pin()?;
        validate_cryptography_pin(&pin.cryptography)?;
        let manifest_bytes = embedded_artifact(&pin.cryptography.path).ok_or_else(|| {
            BundleError::MissingCryptographyArtifact(pin.cryptography.path.clone())
        })?;
        let mut manifest_value = parse_strict_json(manifest_bytes)
            .map_err(|error| BundleError::InvalidCryptographyManifest(error.to_string()))?;
        let manifest: CryptographyManifest = serde_json::from_value(manifest_value.clone())
            .map_err(|error| BundleError::InvalidCryptographyManifest(error.to_string()))?;
        verify_cryptography_metadata(&pin, &manifest)?;

        let mut seen = HashSet::with_capacity(manifest.artifacts.len());
        for artifact in &manifest.artifacts {
            validate_cryptography_artifact_path(&artifact.path)?;
            if !seen.insert(artifact.path.as_str()) {
                return Err(BundleError::InvalidCryptographyManifest(format!(
                    "duplicate artifact path `{}`",
                    artifact.path
                )));
            }
            let contents = embedded_artifact(&artifact.path)
                .ok_or_else(|| BundleError::MissingCryptographyArtifact(artifact.path.clone()))?;
            if contents.len() != artifact.byte_length {
                return Err(BundleError::CryptographyByteLength {
                    path: artifact.path.clone(),
                    expected: artifact.byte_length,
                    actual: contents.len(),
                });
            }
            let actual = sha256_identifier(contents);
            if actual != artifact.sha256 {
                return Err(BundleError::CryptographyArtifactDigest {
                    path: artifact.path.clone(),
                    expected: artifact.sha256.clone(),
                    actual,
                });
            }
        }

        let object = manifest_value.as_object_mut().ok_or_else(|| {
            BundleError::InvalidCryptographyManifest("top-level value must be an object".into())
        })?;
        object.remove("artifactDigest").ok_or_else(|| {
            BundleError::InvalidCryptographyManifest("missing artifactDigest".into())
        })?;
        let actual_digest = canonical_sha256(&manifest_value)
            .map_err(|error| BundleError::InvalidCryptographyManifest(error.to_string()))?;
        if actual_digest != pin.cryptography.artifact_digest {
            return Err(BundleError::Digest {
                tree: "cryptography manifest",
                expected: pin.cryptography.artifact_digest,
                actual: actual_digest,
            });
        }

        Ok(CryptographyBundleSummary {
            artifact_count: manifest.artifacts.len(),
            case_count: manifest.cases.len(),
            evaluation_count: manifest
                .cases
                .iter()
                .map(|test_case| test_case.evaluations.len())
                .sum(),
            artifact_digest: manifest.artifact_digest,
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

    /// Read one embedded cryptography resource by its path below `cryptography/`.
    #[must_use]
    pub fn cryptography(path: &str) -> Option<&'static [u8]> {
        if !safe_relative_resource_path(path) {
            return None;
        }
        CRYPTOGRAPHY.get_file(Path::new(path)).map(File::contents)
    }
}

fn parse_protocol_pin(input: &[u8]) -> Result<ProtocolPin, BundleError> {
    let value = parse_strict_json(input)
        .map_err(|error| BundleError::InvalidPin(serde_json::Error::custom(error.to_string())))?;
    serde_json::from_value(value).map_err(BundleError::InvalidPin)
}

fn validate_cryptography_pin(pin: &CryptographyPin) -> Result<(), BundleError> {
    let expected = CryptographyPin {
        path: "cryptography/manifest.json".into(),
        source_commit: "235aee85ba88934641822e1639e08efd2c9e29b6".into(),
        profile_id: "missionweaveprotocol.signed-document-verification.v0.1".into(),
        manifest_version: 1,
        artifact_digest: "sha256:487e18c1ea7053432953f28d1496ae4fdb8e9d42c2eeb8e94f9b21f8cc2596a2"
            .into(),
        artifact_count: 94,
        case_count: 22,
        evaluation_count: 58,
    };
    if pin != &expected {
        return Err(BundleError::InvalidCryptographyPin(
            "entry does not match the published bundle".into(),
        ));
    }
    Ok(())
}

fn verify_cryptography_metadata(
    pin: &ProtocolPin,
    manifest: &CryptographyManifest,
) -> Result<(), BundleError> {
    let cryptography = &pin.cryptography;
    if manifest.manifest_version != cryptography.manifest_version
        || manifest.profile_id != cryptography.profile_id
        || manifest.protocol_version != pin.protocol_version
        || manifest.artifact_digest != cryptography.artifact_digest
    {
        return Err(BundleError::InvalidCryptographyManifest(
            "identity does not match PROTOCOL_PIN.json".into(),
        ));
    }
    if manifest.artifacts.len() != cryptography.artifact_count {
        return Err(BundleError::FileCount {
            tree: "cryptography artifacts",
            expected: cryptography.artifact_count,
            actual: manifest.artifacts.len(),
        });
    }
    if manifest.cases.len() != cryptography.case_count {
        return Err(BundleError::FileCount {
            tree: "cryptography cases",
            expected: cryptography.case_count,
            actual: manifest.cases.len(),
        });
    }
    let evaluations = manifest
        .cases
        .iter()
        .map(|test_case| test_case.evaluations.len())
        .sum::<usize>();
    if evaluations != cryptography.evaluation_count {
        return Err(BundleError::FileCount {
            tree: "cryptography evaluations",
            expected: cryptography.evaluation_count,
            actual: evaluations,
        });
    }
    Ok(())
}

fn validate_cryptography_artifact_path(path: &str) -> Result<(), BundleError> {
    if !safe_relative_resource_path(path)
        || path == "cryptography/README.md"
        || path == "cryptography/manifest.json"
        || !(path.starts_with("cryptography/") || path.starts_with("schemas/"))
    {
        return Err(BundleError::UnsafeArtifactPath(path.into()));
    }
    Ok(())
}

fn safe_relative_resource_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains(['\\', ':'])
        && path
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

fn embedded_artifact(path: &str) -> Option<&'static [u8]> {
    if !safe_relative_resource_path(path) {
        return None;
    }
    if let Some(path) = path.strip_prefix("cryptography/") {
        return CRYPTOGRAPHY.get_file(Path::new(path)).map(File::contents);
    }
    if let Some(path) = path.strip_prefix("schemas/") {
        return SCHEMAS.get_file(Path::new(path)).map(File::contents);
    }
    None
}

fn sha256_identifier(contents: &[u8]) -> String {
    let digest = Sha256::digest(contents);
    format!("sha256:{digest:x}")
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
    use super::{
        ProtocolBundle, parse_protocol_pin, validate_cryptography_artifact_path,
        validate_cryptography_pin,
    };

    #[test]
    fn protocol_pin_rejects_duplicate_decoded_members() {
        let error =
            parse_protocol_pin(br#"{"cryptography":{"path":"first","\u0070ath":"second"}}"#)
                .expect_err("duplicate decoded members must be rejected before deserialization");

        assert!(
            error.to_string().contains("duplicate object member `path`"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn verifies_exact_embedded_bundle() {
        let summary = ProtocolBundle::verify().expect("bundle should match its pin");
        assert_eq!(summary.schema_files, 21);
        assert_eq!(summary.conformance_files, 53);
        assert_eq!(
            summary.bundle_sha256,
            "b5590fae29ae09e8c2ec77973405878f4dcb13d23e8acdfb888d563ec770bba7"
        );
    }

    #[test]
    fn exposes_runtime_resources() {
        assert!(ProtocolBundle::schema("mission.schema.json").is_some());
        assert!(ProtocolBundle::conformance("manifest.json").is_some());
        assert!(ProtocolBundle::conformance("vectors/valid/mission.json").is_some());
    }

    #[test]
    fn verifies_exact_embedded_cryptography_bundle() {
        let summary = ProtocolBundle::verify_cryptography()
            .expect("cryptography bundle should match its independent pin");
        assert_eq!(summary.artifact_count, 94);
        assert_eq!(summary.case_count, 22);
        assert_eq!(summary.evaluation_count, 58);
        assert_eq!(
            summary.artifact_digest,
            "sha256:487e18c1ea7053432953f28d1496ae4fdb8e9d42c2eeb8e94f9b21f8cc2596a2"
        );

        let pin = ProtocolBundle::pin().expect("pin should parse");
        assert_eq!(pin.cryptography.path, "cryptography/manifest.json");
        assert_eq!(
            pin.cryptography.source_commit,
            "235aee85ba88934641822e1639e08efd2c9e29b6"
        );
        assert_eq!(
            pin.cryptography.profile_id,
            "missionweaveprotocol.signed-document-verification.v0.1"
        );

        for path in [
            "vectors/signed-documents/invalid/command-invalid-utf8.bin",
            "vectors/canonicalization/command.signing.jcs",
            "README.md",
        ] {
            assert!(
                ProtocolBundle::cryptography(path).is_some(),
                "embedded cryptography resource {path} should be available"
            );
        }
    }

    #[test]
    fn cryptography_artifact_paths_stay_within_pinned_roots() {
        for path in [
            "../schemas/command.schema.json",
            "/schemas/command.schema.json",
            "cryptography\\..\\PROTOCOL_PIN.json",
            "conformance/manifest.json",
            "cryptography/README.md",
            "cryptography/manifest.json",
        ] {
            assert!(
                validate_cryptography_artifact_path(path).is_err(),
                "artifact path {path} should be rejected"
            );
        }
        for path in [
            "schemas/command.schema.json",
            "cryptography/keys/registry-valid.json",
            "cryptography/vectors/signed-documents/invalid/command-invalid-utf8.bin",
            "cryptography/vectors/canonicalization/command.signing.jcs",
        ] {
            assert!(
                validate_cryptography_artifact_path(path).is_ok(),
                "artifact path {path} should be accepted"
            );
        }
        assert!(ProtocolBundle::cryptography("../PROTOCOL_PIN.json").is_none());
    }

    #[test]
    fn cryptography_pin_rejects_published_identity_drift() {
        let mut pin = ProtocolBundle::pin()
            .expect("pin should parse")
            .cryptography;
        pin.source_commit = "335aee85ba88934641822e1639e08efd2c9e29b6".into();
        assert!(validate_cryptography_pin(&pin).is_err());
    }
}
