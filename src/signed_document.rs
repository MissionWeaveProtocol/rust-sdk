//! Signed Document construction through a deliberately narrow key adapter.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap},
    error::Error as StdError,
    fmt,
    sync::Arc,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use curve25519_dalek::{edwards::CompressedEdwardsY, scalar::Scalar, traits::IsIdentity as _};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{CanonicalError, SchemaCatalog, SchemaError, canonical_bytes, parse_strict_json};

/// The nine signature-required protocol document profiles.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SignedDocumentKind {
    /// Agent Card.
    AgentCard,
    /// Approval.
    Approval,
    /// Artifact manifest.
    Artifact,
    /// Command.
    Command,
    /// Context Package.
    ContextPackage,
    /// Event.
    Event,
    /// Evidence.
    Evidence,
    /// Extension Profile.
    ExtensionProfile,
    /// Group Snapshot.
    GroupSnapshot,
}

/// Boxed application-adapter failure.
pub type AdapterError = Box<dyn StdError + Send + Sync + 'static>;

/// The sole application adapter used by [`SignedDocumentCodec`] when signing.
pub trait SigningKey {
    /// Signature algorithm identifier.
    fn algorithm(&self) -> &str;

    /// Organization-controlled immutable key identifier.
    fn key_id(&self) -> &str;

    /// Sign the exact RFC 8785 bytes supplied by the codec.
    ///
    /// # Errors
    ///
    /// Returns an application-defined adapter failure when signing is unavailable.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, AdapterError>;
}

/// One normative Signed Document verification stage.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum VerificationStage {
    /// Strict UTF-8 JSON parsing.
    Parse,
    /// Normative JSON Schema validation.
    Schema,
    /// Signature-envelope and protected-time validation.
    SignatureEnvelope,
    /// Signing-key resolution and Registry validation.
    KeyResolution,
    /// RFC 8785 canonicalization.
    Canonicalization,
    /// Pure Ed25519 signature verification.
    Signature,
    /// All six stages completed.
    Complete,
}

/// Non-oracular protocol error code safe to expose on the wire.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum WireErrorCode {
    /// The input is not one protocol-compliant JSON/JCS value.
    ProtocolViolation,
    /// The selected normative schema rejected the document.
    SchemaValidationFailed,
    /// Authentication failed without revealing which authentication check failed.
    AuthInvalidSignature,
}

impl WireErrorCode {
    /// Return the canonical wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProtocolViolation => "PROTOCOL_VIOLATION",
            Self::SchemaValidationFailed => "SCHEMA_VALIDATION_FAILED",
            Self::AuthInvalidSignature => "AUTH_INVALID_SIGNATURE",
        }
    }
}

impl fmt::Display for WireErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Protected first-failure evidence for diagnostics and audit logs.
///
/// This detail is deliberately separate from [`VerificationError`]'s wire-safe display and must
/// not be returned to untrusted peers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationDiagnostic {
    stage: VerificationStage,
    reason: String,
}

impl VerificationDiagnostic {
    /// First normative stage that failed.
    #[must_use]
    pub const fn stage(&self) -> VerificationStage {
        self.stage
    }

    /// Protected diagnostic reason.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// Signed Document verification failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationError {
    wire_code: WireErrorCode,
    diagnostic: VerificationDiagnostic,
}

impl VerificationError {
    /// Non-oracular code safe to expose on the protocol wire.
    #[must_use]
    pub const fn wire_code(&self) -> WireErrorCode {
        self.wire_code
    }

    /// Protected first-failure diagnostic.
    #[must_use]
    pub const fn diagnostic(&self) -> &VerificationDiagnostic {
        &self.diagnostic
    }

    fn at(stage: VerificationStage, reason: impl Into<String>) -> Self {
        let wire_code = match stage {
            VerificationStage::Parse | VerificationStage::Canonicalization => {
                WireErrorCode::ProtocolViolation
            }
            VerificationStage::Schema => WireErrorCode::SchemaValidationFailed,
            VerificationStage::SignatureEnvelope
            | VerificationStage::KeyResolution
            | VerificationStage::Signature => WireErrorCode::AuthInvalidSignature,
            VerificationStage::Complete => WireErrorCode::ProtocolViolation,
        };
        Self {
            wire_code,
            diagnostic: VerificationDiagnostic {
                stage,
                reason: reason.into(),
            },
        }
    }
}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.wire_code.fmt(formatter)
    }
}

impl StdError for VerificationError {}

/// `MissionWeaveProtocol` Principal type.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PrincipalKind {
    /// Agent Principal.
    Agent,
    /// Human Principal.
    Human,
    /// Organization service Principal.
    Service,
}

/// Exact Principal evidence retained from the Registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Principal {
    kind: PrincipalKind,
    id: String,
}

/// Expected signer selected from the Signed Document profile and protected content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeySignerExpectation {
    /// Agent Card requires an Organization service Principal; authorization follows verification.
    OrganizationService,
    /// Every other profile requires this exact Principal.
    Exact(Principal),
}

/// Complete context supplied to the one application key-resolution adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyResolutionRequest {
    kind: SignedDocumentKind,
    key_id: String,
    expected_signer: KeySignerExpectation,
    protected_time_text: String,
    protected_time: Rfc3339Instant,
}

impl KeyResolutionRequest {
    /// Explicit Signed Document profile.
    #[must_use]
    pub const fn kind(&self) -> SignedDocumentKind {
        self.kind
    }

    /// Pinned signature key ID.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Profile-selected signer requirement.
    #[must_use]
    pub const fn expected_signer(&self) -> &KeySignerExpectation {
        &self.expected_signer
    }

    /// Exact protected signed-time text.
    #[must_use]
    pub fn protected_time_text(&self) -> &str {
        &self.protected_time_text
    }

    /// Parsed protected signed-time instant.
    #[must_use]
    pub const fn protected_time(&self) -> &Rfc3339Instant {
        &self.protected_time
    }
}

/// Resolver assertion about how much organization-wide Agent Registry state a snapshot covers.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum KeyRegistryCompleteness {
    /// Complete Organization-wide key IDs, public keys, aliases, and validity history.
    OrganizationWide,
    /// Known to contain only a subset of Registry state.
    Partial,
    /// The adapter cannot assert the snapshot's coverage.
    Unspecified,
}

/// Untrusted Registry bytes plus an explicit coverage assertion from the adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyRegistrySnapshot {
    bytes: Vec<u8>,
    completeness: KeyRegistryCompleteness,
}

impl KeyRegistrySnapshot {
    /// Construct one snapshot with an explicit completeness assertion.
    #[must_use]
    pub fn new(bytes: Vec<u8>, completeness: KeyRegistryCompleteness) -> Self {
        Self {
            bytes,
            completeness,
        }
    }

    /// Construct a snapshot asserted to cover the complete Agent Registry.
    #[must_use]
    pub fn organization_wide(bytes: Vec<u8>) -> Self {
        Self::new(bytes, KeyRegistryCompleteness::OrganizationWide)
    }

    /// Exact untrusted Registry bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Adapter's explicit coverage assertion.
    #[must_use]
    pub const fn completeness(&self) -> KeyRegistryCompleteness {
        self.completeness
    }
}

/// The sole application adapter used by [`SignedDocumentCodec`] when verifying.
///
/// The codec requires an Organization-wide snapshot so it can establish key-ID immutability,
/// Organization-wide public-key uniqueness, aliases, and historical validity itself. A partial or
/// unspecified snapshot fails closed at key-resolution.
pub trait KeyResolver {
    /// Resolve complete Agent Registry evidence for one fully described verification request.
    ///
    /// # Errors
    ///
    /// Returns an application-defined adapter failure when Agent Registry evidence is unavailable.
    fn resolve(&self, request: &KeyResolutionRequest) -> Result<KeyRegistrySnapshot, AdapterError>;
}

impl Principal {
    /// Principal type.
    #[must_use]
    pub const fn kind(&self) -> PrincipalKind {
        self.kind
    }

    /// Principal identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

/// Parsed RFC 3339 instant preserving arbitrary fractional-second precision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rfc3339Instant {
    epoch_second: i64,
    fraction: String,
}

impl Rfc3339Instant {
    /// Whole seconds since the Unix epoch.
    #[must_use]
    pub const fn epoch_second(&self) -> i64 {
        self.epoch_second
    }

    /// Fractional digits with insignificant trailing zeroes removed.
    #[must_use]
    pub fn fraction(&self) -> &str {
        &self.fraction
    }
}

impl Ord for Rfc3339Instant {
    fn cmp(&self, other: &Self) -> Ordering {
        self.epoch_second.cmp(&other.epoch_second).then_with(|| {
            let width = self.fraction.len().max(other.fraction.len());
            (0..width)
                .map(|index| self.fraction.as_bytes().get(index).copied().unwrap_or(b'0'))
                .cmp((0..width).map(|index| {
                    other
                        .fraction
                        .as_bytes()
                        .get(index)
                        .copied()
                        .unwrap_or(b'0')
                }))
        })
    }
}

impl PartialOrd for Rfc3339Instant {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Exact signature-envelope material retained after verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureEvidence {
    algorithm: String,
    key_id: String,
    created_at: String,
    value: String,
    bytes: Arc<[u8]>,
}

impl SignatureEvidence {
    /// Algorithm identifier.
    #[must_use]
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// Immutable Registry key identifier.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Exact `signature.createdAt` text.
    #[must_use]
    pub fn created_at(&self) -> &str {
        &self.created_at
    }

    /// Exact canonical base64url signature text.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Decoded 64-byte pure-Ed25519 signature.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Registry key and Principal evidence retained after verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedKeyEvidence {
    organization_id: String,
    registry_bytes: Arc<[u8]>,
    registry_completeness: KeyRegistryCompleteness,
    key_id: String,
    principal: Principal,
    algorithm: String,
    public_key_text: String,
    public_key_bytes: Arc<[u8]>,
    valid_from_text: String,
    valid_from: Rfc3339Instant,
    valid_until_text: Option<String>,
    valid_until: Option<Rfc3339Instant>,
    revoked_at_text: Option<String>,
    revoked_at: Option<Rfc3339Instant>,
}

impl ResolvedKeyEvidence {
    /// Organization whose Registry supplied this binding.
    #[must_use]
    pub fn organization_id(&self) -> &str {
        &self.organization_id
    }

    /// Exact Registry bytes supplied by the adapter.
    #[must_use]
    pub fn registry_bytes(&self) -> &[u8] {
        &self.registry_bytes
    }

    /// Coverage assertion that was required before this evidence was accepted.
    #[must_use]
    pub const fn registry_completeness(&self) -> KeyRegistryCompleteness {
        self.registry_completeness
    }

    /// Immutable key identifier.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Bound Principal.
    #[must_use]
    pub const fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Algorithm identifier.
    #[must_use]
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// Exact canonical base64url public-key text.
    #[must_use]
    pub fn public_key_text(&self) -> &str {
        &self.public_key_text
    }

    /// Decoded 32-byte Ed25519 public key.
    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key_bytes
    }

    /// Exact immutable `validFrom` text.
    #[must_use]
    pub fn valid_from_text(&self) -> &str {
        &self.valid_from_text
    }

    /// Parsed immutable `validFrom` instant.
    #[must_use]
    pub const fn valid_from(&self) -> &Rfc3339Instant {
        &self.valid_from
    }

    /// Exact effective `validUntil` text, when present.
    #[must_use]
    pub fn valid_until_text(&self) -> Option<&str> {
        self.valid_until_text.as_deref()
    }

    /// Parsed effective `validUntil` instant, when present.
    #[must_use]
    pub const fn valid_until(&self) -> Option<&Rfc3339Instant> {
        self.valid_until.as_ref()
    }

    /// Exact effective `revokedAt` text, when present.
    #[must_use]
    pub fn revoked_at_text(&self) -> Option<&str> {
        self.revoked_at_text.as_deref()
    }

    /// Parsed effective `revokedAt` instant, when present.
    #[must_use]
    pub const fn revoked_at(&self) -> Option<&Rfc3339Instant> {
        self.revoked_at.as_ref()
    }
}

/// Immutable result of all six Signed Document verification stages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSignedDocument {
    kind: SignedDocumentKind,
    document: Value,
    received_bytes: Arc<[u8]>,
    signing_bytes: Arc<[u8]>,
    signing_hash: String,
    complete_document_bytes: Arc<[u8]>,
    complete_document_hash: String,
    protected_time_text: String,
    protected_time: Rfc3339Instant,
    signature: SignatureEvidence,
    resolved_key: ResolvedKeyEvidence,
}

impl VerifiedSignedDocument {
    /// Explicit Signed Document profile used for verification.
    #[must_use]
    pub const fn kind(&self) -> SignedDocumentKind {
        self.kind
    }

    /// Strictly parsed complete Signed Document.
    #[must_use]
    pub const fn document(&self) -> &Value {
        &self.document
    }

    /// Exact received UTF-8 JSON bytes.
    #[must_use]
    pub fn received_bytes(&self) -> &[u8] {
        &self.received_bytes
    }

    /// Exact stage-5 JCS bytes with only the top-level `signature` omitted.
    #[must_use]
    pub fn signing_bytes(&self) -> &[u8] {
        &self.signing_bytes
    }

    /// `sha256:` identifier over [`Self::signing_bytes`].
    #[must_use]
    pub fn signing_hash(&self) -> &str {
        &self.signing_hash
    }

    /// RFC 8785 bytes of the complete signed document.
    #[must_use]
    pub fn complete_document_bytes(&self) -> &[u8] {
        &self.complete_document_bytes
    }

    /// `sha256:` identifier over [`Self::complete_document_bytes`].
    #[must_use]
    pub fn complete_document_hash(&self) -> &str {
        &self.complete_document_hash
    }

    /// Exact protected signed-time text from the document.
    #[must_use]
    pub fn protected_time_text(&self) -> &str {
        &self.protected_time_text
    }

    /// Parsed protected signed-time instant.
    #[must_use]
    pub const fn protected_time(&self) -> &Rfc3339Instant {
        &self.protected_time
    }

    /// Retained signature material.
    #[must_use]
    pub const fn signature(&self) -> &SignatureEvidence {
        &self.signature
    }

    /// Retained resolved key and Principal evidence.
    #[must_use]
    pub const fn resolved_key(&self) -> &ResolvedKeyEvidence {
        &self.resolved_key
    }
}

/// Signed Document construction failure.
#[derive(Debug, Error)]
pub enum SigningError {
    /// Input was not an unsigned JSON object.
    #[error("unsigned document must be a JSON object without a top-level signature")]
    InvalidInput,
    /// The adapter did not identify a usable Ed25519 key.
    #[error("SigningKey must identify one Ed25519 key")]
    InvalidKey,
    /// A required protected signed time was absent or not a string.
    #[error("protected signed time must be a string")]
    ProtectedTime,
    /// RFC 8785 serialization failed.
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
    /// The application key adapter failed.
    #[error("SigningKey failed: {0}")]
    Adapter(#[source] AdapterError),
    /// The key adapter returned a signature of the wrong size.
    #[error("SigningKey returned {actual} signature bytes; expected 64")]
    SignatureLength {
        /// Returned byte count.
        actual: usize,
    },
    /// The adapter returned a 64-byte signature with an invalid Ed25519 R or S encoding.
    #[error("SigningKey returned an invalid Ed25519 signature envelope: {0}")]
    InvalidSignatureEnvelope(String),
    /// The constructed document did not satisfy its selected normative schema.
    #[error(transparent)]
    Schema(#[from] SchemaError),
}

#[derive(Clone, Copy)]
struct Profile {
    protected_time: &'static str,
    schema: &'static str,
    signer: SignerSelector,
}

#[derive(Clone, Copy)]
enum SignerSelector {
    ServicePrincipal,
    Principal(&'static str),
    AgentId(&'static [&'static str]),
}

impl SignedDocumentKind {
    const fn profile(self) -> Profile {
        match self {
            Self::AgentCard => Profile {
                protected_time: "issuedAt",
                schema: "agent-card.schema.json",
                signer: SignerSelector::ServicePrincipal,
            },
            Self::Approval => Profile {
                protected_time: "occurredAt",
                schema: "approval.schema.json",
                signer: SignerSelector::Principal("approver"),
            },
            Self::Artifact => Profile {
                protected_time: "createdAt",
                schema: "artifact.schema.json",
                signer: SignerSelector::AgentId(&["producer", "agentId"]),
            },
            Self::Command => Profile {
                protected_time: "issuedAt",
                schema: "command.schema.json",
                signer: SignerSelector::Principal("actor"),
            },
            Self::ContextPackage => Profile {
                protected_time: "generatedAt",
                schema: "context-package.schema.json",
                signer: SignerSelector::Principal("generatedBy"),
            },
            Self::Event => Profile {
                protected_time: "occurredAt",
                schema: "event.schema.json",
                signer: SignerSelector::Principal("acceptedBy"),
            },
            Self::Evidence => Profile {
                protected_time: "createdAt",
                schema: "evidence.schema.json",
                signer: SignerSelector::Principal("generatedBy"),
            },
            Self::ExtensionProfile => Profile {
                protected_time: "approvedAt",
                schema: "extension-profile.schema.json",
                signer: SignerSelector::Principal("approvedBy"),
            },
            Self::GroupSnapshot => Profile {
                protected_time: "createdAt",
                schema: "group-snapshot.schema.json",
                signer: SignerSelector::Principal("createdBy"),
            },
        }
    }
}

struct Envelope {
    protected_time_text: String,
    protected_time: Rfc3339Instant,
    evidence: SignatureEvidence,
    signature_bytes: [u8; 64],
    expected_signer: KeySignerExpectation,
}

/// Deep module owning profile selection, schema validation, JCS, and signature envelopes.
pub struct SignedDocumentCodec {
    schemas: SchemaCatalog,
}

impl SignedDocumentCodec {
    /// Build a codec over the exact schemas embedded in this SDK build.
    ///
    /// # Errors
    ///
    /// Returns [`SigningError`] if the embedded schema catalog cannot be prepared.
    pub fn new() -> Result<Self, SigningError> {
        Ok(Self {
            schemas: SchemaCatalog::new()?,
        })
    }

    /// Sign an unsigned JSON object under an explicitly selected profile.
    ///
    /// The input value is cloned and never modified.
    ///
    /// # Errors
    ///
    /// Returns [`SigningError`] for invalid input, adapter failure, canonicalization failure, or
    /// a constructed document that does not satisfy its normative schema.
    pub fn sign(
        &self,
        kind: SignedDocumentKind,
        unsigned_document: &Value,
        signing_key: &dyn SigningKey,
    ) -> Result<Value, SigningError> {
        let profile = kind.profile();
        let object = unsigned_document
            .as_object()
            .filter(|object| !object.contains_key("signature"))
            .ok_or(SigningError::InvalidInput)?;
        let protected_time = object
            .get(profile.protected_time)
            .and_then(Value::as_str)
            .ok_or(SigningError::ProtectedTime)?
            .to_owned();
        if !protected_time.ends_with('Z') || parse_rfc3339(&protected_time).is_err() {
            return Err(SigningError::ProtectedTime);
        }
        let signing_bytes = canonical_bytes(unsigned_document)?;
        let algorithm = signing_key.algorithm();
        let key_id = signing_key.key_id().to_owned();
        if algorithm != "Ed25519" || key_id.is_empty() {
            return Err(SigningError::InvalidKey);
        }
        let signature = signing_key
            .sign(&signing_bytes)
            .map_err(SigningError::Adapter)?;
        if signature.len() != 64 {
            return Err(SigningError::SignatureLength {
                actual: signature.len(),
            });
        }
        strict_ed25519_point(
            &signature[..32],
            true,
            VerificationStage::SignatureEnvelope,
            "signature R",
        )
        .map_err(|error| {
            SigningError::InvalidSignatureEnvelope(error.diagnostic().reason().to_owned())
        })?;
        let scalar_bytes: [u8; 32] = signature
            .get(32..)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| {
                SigningError::InvalidSignatureEnvelope("signature S is not 32 bytes".to_owned())
            })?;
        if !bool::from(Scalar::from_canonical_bytes(scalar_bytes).is_some()) {
            return Err(SigningError::InvalidSignatureEnvelope(
                "signature S is outside the Ed25519 scalar range".to_owned(),
            ));
        }

        let mut signed = unsigned_document.clone();
        signed
            .as_object_mut()
            .ok_or(SigningError::InvalidInput)?
            .insert(
                "signature".to_owned(),
                json!({
                    "algorithm": "Ed25519",
                    "createdAt": protected_time,
                    "keyId": key_id,
                    "value": URL_SAFE_NO_PAD.encode(signature),
                }),
            );
        self.schemas.validate(profile.schema, &signed)?;
        Ok(signed)
    }

    /// Verify a Signed Document under an explicitly selected one of the nine profiles.
    ///
    /// The codec owns strict parsing, normative schema selection, envelope checks, Agent Registry
    /// validation, JCS, and Ed25519 verification. The First-Admission Record, freshness, and
    /// authorization are intentionally outside this module.
    ///
    /// # Errors
    ///
    /// Returns a wire-safe [`VerificationError`] retaining a protected first-failure diagnostic.
    pub fn verify(
        &self,
        kind: SignedDocumentKind,
        raw_document: &[u8],
        key_resolver: &dyn KeyResolver,
    ) -> Result<VerifiedSignedDocument, VerificationError> {
        let profile = kind.profile();
        let (document, deferred_canonicalization_failure) =
            parse_verification_document(raw_document)?;

        self.schemas
            .validate(profile.schema, &document)
            .map_err(|error| VerificationError::at(VerificationStage::Schema, error.to_string()))?;
        validate_base_timestamp_profile(&document, profile)?;

        let envelope = signature_envelope(&document, profile)?;
        let resolution_request = KeyResolutionRequest {
            kind,
            key_id: envelope.evidence.key_id().to_owned(),
            expected_signer: envelope.expected_signer.clone(),
            protected_time_text: envelope.protected_time_text.clone(),
            protected_time: envelope.protected_time.clone(),
        };
        let registry_snapshot = key_resolver.resolve(&resolution_request).map_err(|error| {
            VerificationError::at(
                VerificationStage::KeyResolution,
                format!("KeyResolver failed: {error}"),
            )
        })?;
        if registry_snapshot.completeness() != KeyRegistryCompleteness::OrganizationWide {
            return Err(VerificationError::at(
                VerificationStage::KeyResolution,
                "KeyResolver did not assert Organization-wide Registry completeness",
            ));
        }
        let resolved_key = resolve_key(registry_snapshot.bytes(), &envelope)?;

        if let Some(reason) = deferred_canonicalization_failure {
            return Err(VerificationError::at(
                VerificationStage::Canonicalization,
                reason,
            ));
        }

        let mut unsigned = document.clone();
        unsigned
            .as_object_mut()
            .ok_or_else(|| {
                VerificationError::at(
                    VerificationStage::Canonicalization,
                    "Signed Document is not an object",
                )
            })?
            .remove("signature");
        let signing_bytes = canonical_bytes(&unsigned).map_err(|error| {
            VerificationError::at(VerificationStage::Canonicalization, error.to_string())
        })?;
        let complete_document_bytes = canonical_bytes(&document).map_err(|error| {
            VerificationError::at(VerificationStage::Canonicalization, error.to_string())
        })?;

        let public_key: [u8; 32] = resolved_key.public_key_bytes().try_into().map_err(|_| {
            VerificationError::at(
                VerificationStage::KeyResolution,
                "resolved public key is not 32 bytes",
            )
        })?;
        let verifying_key = VerifyingKey::from_bytes(&public_key).map_err(|error| {
            VerificationError::at(
                VerificationStage::KeyResolution,
                format!("resolved public key is invalid: {error}"),
            )
        })?;
        verifying_key
            .verify(
                &signing_bytes,
                &Signature::from_bytes(&envelope.signature_bytes),
            )
            .map_err(|_| {
                VerificationError::at(
                    VerificationStage::Signature,
                    "Ed25519 signature does not verify",
                )
            })?;

        Ok(VerifiedSignedDocument {
            kind,
            document,
            received_bytes: Arc::from(raw_document),
            signing_hash: sha256_identifier(&signing_bytes),
            signing_bytes: Arc::from(signing_bytes),
            complete_document_hash: sha256_identifier(&complete_document_bytes),
            complete_document_bytes: Arc::from(complete_document_bytes),
            protected_time_text: envelope.protected_time_text,
            protected_time: envelope.protected_time,
            signature: envelope.evidence,
            resolved_key,
        })
    }
}

impl Default for SignedDocumentCodec {
    fn default() -> Self {
        Self::new().expect("embedded schemas must build a Signed Document codec")
    }
}

fn parse_verification_document(raw: &[u8]) -> Result<(Value, Option<String>), VerificationError> {
    if raw.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err(VerificationError::at(
            VerificationStage::Parse,
            "JSON input starts with a UTF-8 byte-order mark",
        ));
    }
    let text = std::str::from_utf8(raw).map_err(|error| {
        VerificationError::at(
            VerificationStage::Parse,
            format!("JSON input is not valid UTF-8: {error}"),
        )
    })?;
    let (parseable, deferred_failure) = sanitize_deferred_jcs_faults(text);
    let document = parse_strict_json(&parseable)
        .map_err(|error| VerificationError::at(VerificationStage::Parse, error.to_string()))?;
    Ok((document, deferred_failure))
}

fn sanitize_deferred_jcs_faults(text: &str) -> (Vec<u8>, Option<String>) {
    let input = text.as_bytes();
    let mut output = Vec::with_capacity(input.len());
    let mut deferred = None;
    let mut in_string = false;
    let mut index = 0;

    while index < input.len() {
        let byte = input[index];
        if in_string {
            if byte == b'"' {
                in_string = false;
                output.push(byte);
                index += 1;
                continue;
            }
            if byte == b'\\' {
                if input.get(index + 1) == Some(&b'u') {
                    if let Some(code_unit) = parse_hex_code_unit(input, index + 2) {
                        let paired = (0xd800..=0xdbff).contains(&code_unit)
                            && input.get(index + 6) == Some(&b'\\')
                            && input.get(index + 7) == Some(&b'u')
                            && parse_hex_code_unit(input, index + 8)
                                .is_some_and(|low| (0xdc00..=0xdfff).contains(&low));
                        if paired {
                            output.extend_from_slice(&input[index..index + 12]);
                            index += 12;
                            continue;
                        }
                        if (0xd800..=0xdfff).contains(&code_unit) {
                            output.extend_from_slice(br"\uFFFD");
                            deferred.get_or_insert_with(|| {
                                "document contains an unpaired Unicode surrogate".to_owned()
                            });
                            index += 6;
                            continue;
                        }
                        output.extend_from_slice(&input[index..index + 6]);
                        index += 6;
                        continue;
                    }
                }
                output.push(byte);
                index += 1;
                if let Some(escaped) = input.get(index) {
                    output.push(*escaped);
                    index += 1;
                }
                continue;
            }
            output.push(byte);
            index += 1;
            continue;
        }

        if byte == b'"' {
            in_string = true;
            output.push(byte);
            index += 1;
            continue;
        }
        if byte == b'-' || byte.is_ascii_digit() {
            let start = index;
            index += 1;
            while index < input.len()
                && !matches!(
                    input[index],
                    b' ' | b'\t' | b'\r' | b'\n' | b',' | b']' | b'}' | b':'
                )
            {
                index += 1;
            }
            let token = &text[start..index];
            if is_json_number_token(token)
                && token.parse::<f64>().is_ok_and(|number| !number.is_finite())
            {
                output.push(b'0');
                deferred.get_or_insert_with(|| {
                    format!("number {token} is outside the finite binary64 domain")
                });
            } else {
                output.extend_from_slice(&input[start..index]);
            }
            continue;
        }

        output.push(byte);
        index += 1;
    }

    (output, deferred)
}

fn is_json_number_token(token: &str) -> bool {
    let bytes = token.as_bytes();
    let mut index = usize::from(bytes.first() == Some(&b'-'));
    match bytes.get(index) {
        Some(b'0') => {
            index += 1;
            if bytes.get(index).is_some_and(u8::is_ascii_digit) {
                return false;
            }
        }
        Some(b'1'..=b'9') => {
            index += 1;
            while bytes.get(index).is_some_and(u8::is_ascii_digit) {
                index += 1;
            }
        }
        _ => return false,
    }
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        let start = index;
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
        if index == start {
            return false;
        }
    }
    if matches!(bytes.get(index), Some(b'e' | b'E')) {
        index += 1;
        if matches!(bytes.get(index), Some(b'+' | b'-')) {
            index += 1;
        }
        let start = index;
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
        if index == start {
            return false;
        }
    }
    index == bytes.len()
}

fn parse_hex_code_unit(input: &[u8], start: usize) -> Option<u16> {
    let digits = input.get(start..start + 4)?;
    digits.iter().try_fold(0_u16, |value, digit| {
        let nibble = match digit {
            b'0'..=b'9' => u16::from(*digit - b'0'),
            b'a'..=b'f' => u16::from(*digit - b'a' + 10),
            b'A'..=b'F' => u16::from(*digit - b'A' + 10),
            _ => return None,
        };
        Some(value * 16 + nibble)
    })
}

fn validate_base_timestamp_profile(
    document: &Value,
    profile: Profile,
) -> Result<(), VerificationError> {
    let object = document.as_object().ok_or_else(|| {
        VerificationError::at(
            VerificationStage::Schema,
            "Signed Document is not an object",
        )
    })?;
    let protected = object
        .get(profile.protected_time)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            VerificationError::at(
                VerificationStage::Schema,
                "protected signed time is not a string",
            )
        })?;
    parse_rfc3339(protected).map_err(|reason| {
        VerificationError::at(
            VerificationStage::Schema,
            format!("protected signed time is invalid: {reason}"),
        )
    })?;
    let created_at = object
        .get("signature")
        .and_then(Value::as_object)
        .and_then(|signature| signature.get("createdAt"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            VerificationError::at(
                VerificationStage::Schema,
                "signature.createdAt is not a string",
            )
        })?;
    parse_rfc3339(created_at).map_err(|reason| {
        VerificationError::at(
            VerificationStage::Schema,
            format!("signature.createdAt is invalid: {reason}"),
        )
    })?;
    Ok(())
}

fn signature_envelope(document: &Value, profile: Profile) -> Result<Envelope, VerificationError> {
    let object = document.as_object().ok_or_else(|| {
        VerificationError::at(
            VerificationStage::SignatureEnvelope,
            "Signed Document is not an object",
        )
    })?;
    let signature = object
        .get("signature")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            VerificationError::at(
                VerificationStage::SignatureEnvelope,
                "signature is not an object",
            )
        })?;
    let (protected_time_text, protected_time, created_at) =
        protected_envelope_time(object, signature, profile.protected_time)?;
    let expected_signer = select_expected_signer(document, object, profile.signer)?;
    let (evidence, signature_bytes) = decode_signature_evidence(signature, created_at)?;

    Ok(Envelope {
        protected_time_text: protected_time_text.to_owned(),
        protected_time,
        evidence,
        signature_bytes,
        expected_signer,
    })
}

fn protected_envelope_time<'a>(
    document: &'a serde_json::Map<String, Value>,
    signature: &'a serde_json::Map<String, Value>,
    protected_field: &str,
) -> Result<(&'a str, Rfc3339Instant, &'a str), VerificationError> {
    let protected_time_text = document
        .get(protected_field)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            VerificationError::at(
                VerificationStage::SignatureEnvelope,
                "protected signed time is not a string",
            )
        })?;
    let created_at = signature
        .get("createdAt")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            VerificationError::at(
                VerificationStage::SignatureEnvelope,
                "signature.createdAt is not a string",
            )
        })?;
    let protected_time = parse_rfc3339(protected_time_text).map_err(|reason| {
        VerificationError::at(
            VerificationStage::SignatureEnvelope,
            format!("protected signed time is invalid: {reason}"),
        )
    })?;
    parse_rfc3339(created_at).map_err(|reason| {
        VerificationError::at(
            VerificationStage::SignatureEnvelope,
            format!("signature.createdAt is invalid: {reason}"),
        )
    })?;
    if !protected_time_text.ends_with('Z') || !created_at.ends_with('Z') {
        return Err(VerificationError::at(
            VerificationStage::SignatureEnvelope,
            "protected time and signature.createdAt must use uppercase Z",
        ));
    }
    if protected_time_text != created_at {
        return Err(VerificationError::at(
            VerificationStage::SignatureEnvelope,
            "protected time and signature.createdAt are not byte-equal",
        ));
    }
    Ok((protected_time_text, protected_time, created_at))
}

fn select_expected_signer(
    document: &Value,
    object: &serde_json::Map<String, Value>,
    selector: SignerSelector,
) -> Result<KeySignerExpectation, VerificationError> {
    let expectation = match selector {
        SignerSelector::ServicePrincipal => KeySignerExpectation::OrganizationService,
        SignerSelector::Principal(field) => KeySignerExpectation::Exact(parse_principal(
            object.get(field).ok_or_else(|| {
                VerificationError::at(
                    VerificationStage::SignatureEnvelope,
                    format!("expected signer field {field} is missing"),
                )
            })?,
            VerificationStage::SignatureEnvelope,
            "expected signer",
        )?),
        SignerSelector::AgentId(path) => {
            let mut selected = document;
            for field in path {
                selected = selected.get(*field).ok_or_else(|| {
                    VerificationError::at(
                        VerificationStage::SignatureEnvelope,
                        "expected Agent signer ID is missing",
                    )
                })?;
            }
            let id = selected.as_str().ok_or_else(|| {
                VerificationError::at(
                    VerificationStage::SignatureEnvelope,
                    "expected Agent signer ID is not a string",
                )
            })?;
            KeySignerExpectation::Exact(Principal {
                kind: PrincipalKind::Agent,
                id: id.to_owned(),
            })
        }
    };
    Ok(expectation)
}

fn decode_signature_evidence(
    signature: &serde_json::Map<String, Value>,
    created_at: &str,
) -> Result<(SignatureEvidence, [u8; 64]), VerificationError> {
    let algorithm = required_string(
        signature.get("algorithm"),
        VerificationStage::SignatureEnvelope,
        "signature.algorithm",
    )?;
    let key_id = required_string(
        signature.get("keyId"),
        VerificationStage::SignatureEnvelope,
        "signature.keyId",
    )?;
    let signature_text = required_string(
        signature.get("value"),
        VerificationStage::SignatureEnvelope,
        "signature.value",
    )?;
    let decoded = canonical_base64url(
        signature_text,
        VerificationStage::SignatureEnvelope,
        "signature.value",
    )?;
    let signature_bytes: [u8; 64] = decoded.try_into().map_err(|bytes: Vec<u8>| {
        VerificationError::at(
            VerificationStage::SignatureEnvelope,
            format!(
                "signature.value decodes to {} bytes; expected 64",
                bytes.len()
            ),
        )
    })?;
    strict_ed25519_point(
        signature_bytes.get(..32).ok_or_else(|| {
            VerificationError::at(
                VerificationStage::SignatureEnvelope,
                "signature R is not 32 bytes",
            )
        })?,
        true,
        VerificationStage::SignatureEnvelope,
        "signature R",
    )?;
    let scalar_bytes: [u8; 32] = signature_bytes
        .get(32..)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| {
            VerificationError::at(
                VerificationStage::SignatureEnvelope,
                "signature S is not 32 bytes",
            )
        })?;
    if !bool::from(Scalar::from_canonical_bytes(scalar_bytes).is_some()) {
        return Err(VerificationError::at(
            VerificationStage::SignatureEnvelope,
            "signature S is outside the Ed25519 scalar range",
        ));
    }

    Ok((
        SignatureEvidence {
            algorithm: algorithm.to_owned(),
            key_id: key_id.to_owned(),
            created_at: created_at.to_owned(),
            value: signature_text.to_owned(),
            bytes: Arc::from(signature_bytes),
        },
        signature_bytes,
    ))
}

#[derive(Clone)]
struct ParsedBoundary {
    text: String,
    instant: Rfc3339Instant,
}

#[derive(Clone)]
struct ValidityStatus {
    recorded_at: Rfc3339Instant,
    valid_until: Option<ParsedBoundary>,
    revoked_at: Option<ParsedBoundary>,
}

impl ValidityStatus {
    fn semantically_equals(&self, other: &Self) -> bool {
        self.recorded_at == other.recorded_at
            && optional_boundary_equals(self.valid_until.as_ref(), other.valid_until.as_ref())
            && optional_boundary_equals(self.revoked_at.as_ref(), other.revoked_at.as_ref())
    }
}

struct NormalizedBinding {
    principal: Principal,
    algorithm: String,
    public_key_text: String,
    public_key_bytes: [u8; 32],
    valid_from_text: String,
    valid_from: Rfc3339Instant,
    history: BTreeMap<u64, ValidityStatus>,
    valid_until: Option<ParsedBoundary>,
    revoked_at: Option<ParsedBoundary>,
}

#[allow(
    clippy::too_many_lines,
    reason = "the normative key-resolution stage is kept sequential so first-failure ordering remains auditable"
)]
fn resolve_key(
    raw_registry: &[u8],
    envelope: &Envelope,
) -> Result<ResolvedKeyEvidence, VerificationError> {
    let registry_value = parse_strict_json(raw_registry).map_err(|error| {
        VerificationError::at(VerificationStage::KeyResolution, error.to_string())
    })?;
    let registry = exact_object(
        &registry_value,
        &["organizationId", "bindings"],
        &[],
        VerificationStage::KeyResolution,
        "Agent Registry",
    )?;
    let organization_id = required_string(
        registry.get("organizationId"),
        VerificationStage::KeyResolution,
        "Registry organizationId",
    )?;
    let bindings = registry
        .get("bindings")
        .and_then(Value::as_array)
        .filter(|bindings| !bindings.is_empty())
        .ok_or_else(|| {
            VerificationError::at(
                VerificationStage::KeyResolution,
                "Registry bindings is not a non-empty array",
            )
        })?;

    let mut normalized = HashMap::<String, NormalizedBinding>::new();
    let mut public_key_owners = HashMap::<[u8; 32], (String, PrincipalKind, String)>::new();
    let mut tuple_ids = HashMap::<(PrincipalKind, String, [u8; 32]), String>::new();

    for (binding_index, binding_value) in bindings.iter().enumerate() {
        let label = format!("Registry bindings[{binding_index}]");
        let binding = exact_object(
            binding_value,
            &[
                "keyId",
                "principal",
                "algorithm",
                "publicKey",
                "validFrom",
                "validityHistory",
            ],
            &[],
            VerificationStage::KeyResolution,
            &label,
        )?;
        let key_id = required_string(
            binding.get("keyId"),
            VerificationStage::KeyResolution,
            &format!("{label}.keyId"),
        )?
        .to_owned();
        let principal = parse_principal(
            binding.get("principal").ok_or_else(|| {
                VerificationError::at(
                    VerificationStage::KeyResolution,
                    format!("{label}.principal is missing"),
                )
            })?,
            VerificationStage::KeyResolution,
            &format!("{label}.principal"),
        )?;
        let algorithm = required_string(
            binding.get("algorithm"),
            VerificationStage::KeyResolution,
            &format!("{label}.algorithm"),
        )?;
        if algorithm != "Ed25519" {
            return Err(VerificationError::at(
                VerificationStage::KeyResolution,
                format!("{label}.algorithm is not Ed25519"),
            ));
        }
        let public_key_text = required_string(
            binding.get("publicKey"),
            VerificationStage::KeyResolution,
            &format!("{label}.publicKey"),
        )?;
        let public_key = canonical_base64url(
            public_key_text,
            VerificationStage::KeyResolution,
            &format!("{label}.publicKey"),
        )?;
        let public_key_bytes: [u8; 32] = public_key.try_into().map_err(|bytes: Vec<u8>| {
            VerificationError::at(
                VerificationStage::KeyResolution,
                format!(
                    "{label}.publicKey decodes to {} bytes; expected 32",
                    bytes.len()
                ),
            )
        })?;
        strict_ed25519_point(
            &public_key_bytes,
            false,
            VerificationStage::KeyResolution,
            &format!("{label}.publicKey"),
        )?;
        let valid_from_text = required_string(
            binding.get("validFrom"),
            VerificationStage::KeyResolution,
            &format!("{label}.validFrom"),
        )?;
        let valid_from = parse_rfc3339(valid_from_text).map_err(|reason| {
            VerificationError::at(
                VerificationStage::KeyResolution,
                format!("{label}.validFrom is invalid: {reason}"),
            )
        })?;
        let history = binding
            .get("validityHistory")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                VerificationError::at(
                    VerificationStage::KeyResolution,
                    format!("{label}.validityHistory is not an array"),
                )
            })?;

        if let Some(existing) = normalized.get(&key_id) {
            if existing.principal != principal
                || existing.algorithm != algorithm
                || existing.public_key_bytes != public_key_bytes
                || existing.valid_from != valid_from
            {
                return Err(VerificationError::at(
                    VerificationStage::KeyResolution,
                    format!("key ID {key_id:?} is reused for another immutable binding"),
                ));
            }
        } else {
            normalized.insert(
                key_id.clone(),
                NormalizedBinding {
                    principal: principal.clone(),
                    algorithm: algorithm.to_owned(),
                    public_key_text: public_key_text.to_owned(),
                    public_key_bytes,
                    valid_from_text: valid_from_text.to_owned(),
                    valid_from: valid_from.clone(),
                    history: BTreeMap::new(),
                    valid_until: None,
                    revoked_at: None,
                },
            );
        }

        let owner = (key_id.clone(), principal.kind, principal.id.clone());
        if public_key_owners
            .insert(public_key_bytes, owner.clone())
            .is_some_and(|existing| existing != owner)
        {
            return Err(VerificationError::at(
                VerificationStage::KeyResolution,
                "the same public key is registered under another Principal or key ID",
            ));
        }
        let principal_key = (principal.kind, principal.id.clone(), public_key_bytes);
        if tuple_ids
            .insert(principal_key, key_id.clone())
            .is_some_and(|existing| existing != key_id)
        {
            return Err(VerificationError::at(
                VerificationStage::KeyResolution,
                "a Principal, algorithm, and public-key tuple has a key-ID alias",
            ));
        }

        let target = normalized
            .get_mut(&key_id)
            .expect("binding was inserted or already present");
        for (history_index, status_value) in history.iter().enumerate() {
            let status_label = format!("{label}.validityHistory[{history_index}]");
            let status = exact_object(
                status_value,
                &["sequence", "recordedAt"],
                &["validUntil", "revokedAt"],
                VerificationStage::KeyResolution,
                &status_label,
            )?;
            let sequence = positive_safe_integer(
                status.get("sequence"),
                VerificationStage::KeyResolution,
                &format!("{status_label}.sequence"),
            )?;
            let recorded_at = parse_registry_instant(
                status.get("recordedAt"),
                &format!("{status_label}.recordedAt"),
            )?;
            let parsed_status = ValidityStatus {
                recorded_at,
                valid_until: optional_registry_boundary(
                    status.get("validUntil"),
                    &format!("{status_label}.validUntil"),
                )?,
                revoked_at: optional_registry_boundary(
                    status.get("revokedAt"),
                    &format!("{status_label}.revokedAt"),
                )?,
            };
            if let Some(existing) = target.history.get(&sequence) {
                if !existing.semantically_equals(&parsed_status) {
                    return Err(VerificationError::at(
                        VerificationStage::KeyResolution,
                        format!("{status_label} rewrites an earlier status sequence"),
                    ));
                }
            } else {
                target.history.insert(sequence, parsed_status);
            }
        }
    }

    for (key_id, binding) in &mut normalized {
        let sequences: Vec<u64> = binding.history.keys().copied().collect();
        if sequences
            .iter()
            .copied()
            .ne(1..=u64::try_from(sequences.len()).expect("history length fits u64"))
        {
            return Err(VerificationError::at(
                VerificationStage::KeyResolution,
                format!("key {key_id:?} validity history is not contiguous from sequence 1"),
            ));
        }
        let mut previous_recorded_at: Option<&Rfc3339Instant> = None;
        for status in binding.history.values() {
            if previous_recorded_at.is_some_and(|previous| status.recorded_at < *previous) {
                return Err(VerificationError::at(
                    VerificationStage::KeyResolution,
                    format!("key {key_id:?} validity history is not append ordered"),
                ));
            }
            previous_recorded_at = Some(&status.recorded_at);
            apply_boundary(
                &mut binding.valid_until,
                status.valid_until.as_ref(),
                key_id,
                "validUntil",
            )?;
            apply_boundary(
                &mut binding.revoked_at,
                status.revoked_at.as_ref(),
                key_id,
                "revokedAt",
            )?;
        }
    }

    let selected = normalized
        .remove(envelope.evidence.key_id())
        .ok_or_else(|| {
            VerificationError::at(
                VerificationStage::KeyResolution,
                "signature.keyId is unknown",
            )
        })?;
    match &envelope.expected_signer {
        KeySignerExpectation::OrganizationService
            if selected.principal.kind != PrincipalKind::Service =>
        {
            return Err(VerificationError::at(
                VerificationStage::KeyResolution,
                "Agent Card signer is not a service Principal",
            ));
        }
        KeySignerExpectation::Exact(expected) if &selected.principal != expected => {
            return Err(VerificationError::at(
                VerificationStage::KeyResolution,
                "resolved key is bound to the wrong Principal",
            ));
        }
        KeySignerExpectation::OrganizationService | KeySignerExpectation::Exact(_) => {}
    }
    if envelope.protected_time < selected.valid_from {
        return Err(VerificationError::at(
            VerificationStage::KeyResolution,
            "signing key is not yet valid at the protected time",
        ));
    }
    if selected
        .valid_until
        .as_ref()
        .is_some_and(|boundary| envelope.protected_time >= boundary.instant)
    {
        return Err(VerificationError::at(
            VerificationStage::KeyResolution,
            "signing key is expired at the protected time",
        ));
    }
    if selected
        .revoked_at
        .as_ref()
        .is_some_and(|boundary| envelope.protected_time >= boundary.instant)
    {
        return Err(VerificationError::at(
            VerificationStage::KeyResolution,
            "signing key is revoked at the protected time",
        ));
    }

    let (valid_until_text, valid_until) = unzip_boundary(selected.valid_until);
    let (revoked_at_text, revoked_at) = unzip_boundary(selected.revoked_at);
    Ok(ResolvedKeyEvidence {
        organization_id: organization_id.to_owned(),
        registry_bytes: Arc::from(raw_registry),
        registry_completeness: KeyRegistryCompleteness::OrganizationWide,
        key_id: envelope.evidence.key_id().to_owned(),
        principal: selected.principal,
        algorithm: selected.algorithm,
        public_key_text: selected.public_key_text,
        public_key_bytes: Arc::from(selected.public_key_bytes),
        valid_from_text: selected.valid_from_text,
        valid_from: selected.valid_from,
        valid_until_text,
        valid_until,
        revoked_at_text,
        revoked_at,
    })
}

fn optional_boundary_equals(left: Option<&ParsedBoundary>, right: Option<&ParsedBoundary>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left.instant == right.instant,
        (None, None) => true,
        (Some(_), None) | (None, Some(_)) => false,
    }
}

fn apply_boundary(
    effective: &mut Option<ParsedBoundary>,
    candidate: Option<&ParsedBoundary>,
    key_id: &str,
    field: &str,
) -> Result<(), VerificationError> {
    let Some(candidate) = candidate else {
        return Ok(());
    };
    if effective
        .as_ref()
        .is_some_and(|current| candidate.instant > current.instant)
    {
        return Err(VerificationError::at(
            VerificationStage::KeyResolution,
            format!("key {key_id:?} moves {field} later in history"),
        ));
    }
    *effective = Some(candidate.clone());
    Ok(())
}

fn unzip_boundary(value: Option<ParsedBoundary>) -> (Option<String>, Option<Rfc3339Instant>) {
    match value {
        Some(ParsedBoundary { text, instant }) => (Some(text), Some(instant)),
        None => (None, None),
    }
}

fn exact_object<'a>(
    value: &'a Value,
    required: &[&str],
    optional: &[&str],
    stage: VerificationStage,
    label: &str,
) -> Result<&'a serde_json::Map<String, Value>, VerificationError> {
    let object = value
        .as_object()
        .ok_or_else(|| VerificationError::at(stage, format!("{label} is not an object")))?;
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|field| !object.contains_key(*field))
        .collect();
    let unknown: Vec<&str> = object
        .keys()
        .map(String::as_str)
        .filter(|field| !required.contains(field) && !optional.contains(field))
        .collect();
    if !missing.is_empty() || !unknown.is_empty() {
        let mut details = Vec::new();
        if !missing.is_empty() {
            details.push(format!("missing {}", missing.join(", ")));
        }
        if !unknown.is_empty() {
            details.push(format!("unknown {}", unknown.join(", ")));
        }
        return Err(VerificationError::at(
            stage,
            format!("{label} has invalid fields ({})", details.join("; ")),
        ));
    }
    Ok(object)
}

fn positive_safe_integer(
    value: Option<&Value>,
    stage: VerificationStage,
    label: &str,
) -> Result<u64, VerificationError> {
    value
        .and_then(Value::as_u64)
        .filter(|integer| (1..=9_007_199_254_740_991).contains(integer))
        .ok_or_else(|| {
            VerificationError::at(stage, format!("{label} is not a positive safe integer"))
        })
}

fn parse_registry_instant(
    value: Option<&Value>,
    label: &str,
) -> Result<Rfc3339Instant, VerificationError> {
    let text = required_string(value, VerificationStage::KeyResolution, label)?;
    parse_rfc3339(text).map_err(|reason| {
        VerificationError::at(
            VerificationStage::KeyResolution,
            format!("{label} is invalid: {reason}"),
        )
    })
}

fn optional_registry_boundary(
    value: Option<&Value>,
    label: &str,
) -> Result<Option<ParsedBoundary>, VerificationError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let text = value.as_str().ok_or_else(|| {
        VerificationError::at(
            VerificationStage::KeyResolution,
            format!("{label} is not a string"),
        )
    })?;
    let instant = parse_rfc3339(text).map_err(|reason| {
        VerificationError::at(
            VerificationStage::KeyResolution,
            format!("{label} is invalid: {reason}"),
        )
    })?;
    Ok(Some(ParsedBoundary {
        text: text.to_owned(),
        instant,
    }))
}

fn required_string<'a>(
    value: Option<&'a Value>,
    stage: VerificationStage,
    label: &str,
) -> Result<&'a str, VerificationError> {
    value
        .and_then(Value::as_str)
        .ok_or_else(|| VerificationError::at(stage, format!("{label} is not a string")))
}

fn parse_principal(
    value: &Value,
    stage: VerificationStage,
    label: &str,
) -> Result<Principal, VerificationError> {
    let principal = exact_object(value, &["type", "id"], &[], stage, label)?;
    let kind = match required_string(principal.get("type"), stage, &format!("{label}.type"))? {
        "agent" => PrincipalKind::Agent,
        "human" => PrincipalKind::Human,
        "service" => PrincipalKind::Service,
        _ => {
            return Err(VerificationError::at(
                stage,
                format!("{label}.type is unsupported"),
            ));
        }
    };
    let id = required_string(principal.get("id"), stage, &format!("{label}.id"))?;
    Ok(Principal {
        kind,
        id: id.to_owned(),
    })
}

fn canonical_base64url(
    value: &str,
    stage: VerificationStage,
    label: &str,
) -> Result<Vec<u8>, VerificationError> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || value.len() % 4 == 1
    {
        return Err(VerificationError::at(
            stage,
            format!("{label} is not canonical unpadded base64url"),
        ));
    }
    let decoded = URL_SAFE_NO_PAD.decode(value).map_err(|error| {
        VerificationError::at(stage, format!("{label} cannot be decoded: {error}"))
    })?;
    if URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(VerificationError::at(
            stage,
            format!("{label} has nonzero unused pad bits or a noncanonical spelling"),
        ));
    }
    Ok(decoded)
}

fn strict_ed25519_point(
    encoded: &[u8],
    allow_identity: bool,
    stage: VerificationStage,
    label: &str,
) -> Result<(), VerificationError> {
    let bytes: [u8; 32] = encoded.try_into().map_err(|_| {
        VerificationError::at(
            stage,
            format!("{label} does not encode a 32-byte Ed25519 point"),
        )
    })?;
    let compressed = CompressedEdwardsY(bytes);
    let point = compressed.decompress().ok_or_else(|| {
        VerificationError::at(
            stage,
            format!("{label} does not decode to an Edwards25519 point"),
        )
    })?;
    if point.compress().to_bytes() != bytes {
        return Err(VerificationError::at(
            stage,
            format!("{label} is not a canonical Ed25519 point encoding"),
        ));
    }
    if point.is_identity() && !allow_identity {
        return Err(VerificationError::at(
            stage,
            format!("{label} encodes the Ed25519 identity point"),
        ));
    }
    if !point.is_torsion_free() {
        return Err(VerificationError::at(
            stage,
            format!("{label} is not in the prime-order Ed25519 subgroup"),
        ));
    }
    Ok(())
}

fn parse_rfc3339(value: &str) -> Result<Rfc3339Instant, &'static str> {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || !matches!(bytes.get(10), Some(b'T' | b't'))
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return Err("not an RFC 3339 timestamp");
    }
    let year = decimal_digits(bytes, 0, 4)?;
    let month = decimal_digits(bytes, 5, 7)?;
    let day = decimal_digits(bytes, 8, 10)?;
    let hour = decimal_digits(bytes, 11, 13)?;
    let minute = decimal_digits(bytes, 14, 16)?;
    let second = decimal_digits(bytes, 17, 19)?;
    if year == 0 {
        return Err("year 0000 is not supported");
    }
    if !(1..=12).contains(&month) {
        return Err("month is outside 01 through 12");
    }
    let month_lengths = [
        31,
        if is_gregorian_leap_year(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if day == 0 || day > month_lengths[(month - 1) as usize] {
        return Err("day is invalid for the Gregorian month");
    }
    if hour > 23 || minute > 59 {
        return Err("time is outside 00:00 through 23:59");
    }
    if second > 59 {
        return Err("leap seconds are not supported");
    }

    let mut cursor = 19;
    let mut fraction = "";
    if bytes.get(cursor) == Some(&b'.') {
        let start = cursor + 1;
        cursor = start;
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
        if cursor == start {
            return Err("fractional seconds contain no digits");
        }
        fraction = &value[start..cursor];
    }

    let offset_seconds = match bytes.get(cursor) {
        Some(b'Z' | b'z') if cursor + 1 == bytes.len() => 0_i64,
        Some(sign @ (b'+' | b'-')) if cursor + 6 == bytes.len() => {
            if bytes.get(cursor + 3) != Some(&b':') {
                return Err("numeric offset is malformed");
            }
            let offset_hour = decimal_digits(bytes, cursor + 1, cursor + 3)?;
            let offset_minute = decimal_digits(bytes, cursor + 4, cursor + 6)?;
            if offset_hour > 23 || offset_minute > 59 {
                return Err("numeric offset is outside RFC 3339 bounds");
            }
            if *sign == b'-' && offset_hour == 0 && offset_minute == 0 {
                return Err("unknown local offset -00:00 is not an instant");
            }
            let magnitude = i64::from(offset_hour * 3_600 + offset_minute * 60);
            if *sign == b'+' { magnitude } else { -magnitude }
        }
        _ => return Err("RFC 3339 offset is malformed"),
    };
    let local_second = days_from_civil(i64::from(year), month, day) * 86_400
        + i64::from(hour * 3_600 + minute * 60 + second);
    Ok(Rfc3339Instant {
        epoch_second: local_second - offset_seconds,
        fraction: fraction.trim_end_matches('0').to_owned(),
    })
}

pub(crate) fn is_protocol_rfc3339(value: &str) -> bool {
    parse_rfc3339(value).is_ok()
}

fn decimal_digits(bytes: &[u8], start: usize, end: usize) -> Result<u32, &'static str> {
    let digits = bytes
        .get(start..end)
        .filter(|digits| digits.iter().all(u8::is_ascii_digit))
        .ok_or("timestamp contains a non-digit")?;
    Ok(digits
        .iter()
        .fold(0_u32, |value, digit| value * 10 + u32::from(*digit - b'0')))
}

const fn is_gregorian_leap_year(year: u32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = i64::from(month) + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn sha256_identifier(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
