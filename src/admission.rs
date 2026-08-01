//! First-admission creation and historical Admission Log verification.

use std::sync::Arc;

use serde_json::{Value, json};
use thiserror::Error;

use crate::{
    AdapterError, KeyRegistrySnapshot, KeyResolutionRequest, KeyResolver, Principal, PrincipalKind,
    Rfc3339Instant, SchemaCatalog, SignedDocumentCodec, SignedDocumentKind, VerificationError,
    VerifiedSignedDocument, WireErrorCode, canonical_bytes, parse_strict_json,
    signed_document::parse_rfc3339,
};

/// Stable protected reason for one Admission-stage failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AdmissionReason {
    /// Historical replay found authoritative absence.
    RecordMissing,
    /// The record did not bind the six-stage evidence exactly.
    RecordBindingMismatch,
    /// The trusted acceptance instant was outside the effective key interval.
    TrustedTimeOutsideKeyInterval,
    /// The trusted context supplied a malformed timestamp.
    MalformedTrustedTime,
    /// The Admission Log reported a conflicting record.
    RecordConflict,
    /// Record bytes were not strict JSON satisfying the normative Schema.
    RecordSchemaInvalid,
    /// The record's accepting service was not authenticated by the adapter.
    LogAuthenticationFailed,
    /// The append adapter could not establish append-only integrity.
    AppendIntegrityNotEstablished,
    /// The Admission Log was unavailable.
    LogUnavailable,
    /// The Admission Log could not establish found or authoritative absence.
    LogIndeterminate,
    /// The append operation did not establish a committed record.
    CommitFailed,
    /// A Signed Event attempted to authenticate itself as its Admission record.
    EventSelfAnchoring,
}

impl AdmissionReason {
    /// Return the stable protected identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RecordMissing => "record-missing",
            Self::RecordBindingMismatch => "record-binding-mismatch",
            Self::TrustedTimeOutsideKeyInterval => "trusted-time-outside-key-interval",
            Self::MalformedTrustedTime => "malformed-trusted-time",
            Self::RecordConflict => "record-conflict",
            Self::RecordSchemaInvalid => "record-schema-invalid",
            Self::LogAuthenticationFailed => "log-authentication-failed",
            Self::AppendIntegrityNotEstablished => "append-integrity-not-established",
            Self::LogUnavailable => "log-unavailable",
            Self::LogIndeterminate => "log-indeterminate",
            Self::CommitFailed => "commit-failed",
            Self::EventSelfAnchoring => "event-self-anchoring",
        }
    }
}

/// Protected local Admission evidence that must not be returned to peers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionDiagnostic {
    reason: AdmissionReason,
}

impl AdmissionDiagnostic {
    /// Return the stable Admission stage identifier.
    #[must_use]
    pub const fn stage(&self) -> &'static str {
        "admission"
    }

    /// Return the stable protected reason.
    #[must_use]
    pub const fn reason(&self) -> AdmissionReason {
        self.reason
    }
}

/// Deliberately non-oracular Admission-stage failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("signed document admission failed: AUTH_INVALID_SIGNATURE")]
pub struct AdmissionError {
    diagnostic: AdmissionDiagnostic,
}

impl AdmissionError {
    fn at(reason: AdmissionReason) -> Self {
        Self {
            diagnostic: AdmissionDiagnostic { reason },
        }
    }

    /// Return the stable wire-safe error code.
    #[must_use]
    pub const fn wire_code(&self) -> WireErrorCode {
        WireErrorCode::AuthInvalidSignature
    }

    /// Return protected Admission-stage evidence.
    #[must_use]
    pub const fn diagnostic(&self) -> &AdmissionDiagnostic {
        &self.diagnostic
    }
}

/// Error from a public Admission orchestration path.
///
/// Six-stage verification failures remain distinct from failures in the Admission layer.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AdmissionOperationError {
    /// The unchanged Signed Document verifier rejected the input.
    #[error(transparent)]
    Verification(#[from] VerificationError),
    /// Six-stage verification completed and the Admission layer rejected the operation.
    #[error(transparent)]
    Admission(#[from] AdmissionError),
}

impl AdmissionOperationError {
    /// Return an Admission-stage failure when this operation reached that layer.
    #[must_use]
    pub const fn admission_error(&self) -> Option<&AdmissionError> {
        match self {
            Self::Admission(error) => Some(error),
            Self::Verification(_) => None,
        }
    }

    /// Return a six-stage verification failure when Admission was never reached.
    #[must_use]
    pub const fn verification_error(&self) -> Option<&VerificationError> {
        match self {
            Self::Verification(error) => Some(error),
            Self::Admission(_) => None,
        }
    }

    /// Return the wire-safe code of the underlying failure.
    #[must_use]
    pub const fn wire_code(&self) -> WireErrorCode {
        match self {
            Self::Verification(error) => error.wire_code(),
            Self::Admission(error) => error.wire_code(),
        }
    }
}

/// Protected application-adapter failure remapped by [`AdmissionService`].
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("Admission adapter failed: {detail}")]
pub struct AdmissionAdapterError {
    reason: AdmissionReason,
    detail: String,
}

impl AdmissionAdapterError {
    /// Construct one typed adapter failure with local-only detail.
    #[must_use]
    pub fn new(reason: AdmissionReason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }

    /// Return the stable reason remapped by [`AdmissionService`].
    #[must_use]
    pub const fn reason(&self) -> AdmissionReason {
        self.reason
    }

    /// Return protected local adapter detail.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

/// Trusted deployment context used to prepare a new First-Admission Record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionContextValue {
    admission_record_id: String,
    trusted_accepted_at: String,
    accepted_by: Principal,
}

impl AdmissionContextValue {
    /// Construct context authenticated as one Organization service.
    #[must_use]
    pub fn new(
        admission_record_id: impl Into<String>,
        trusted_accepted_at: impl Into<String>,
        accepted_by_service_id: impl Into<String>,
    ) -> Self {
        Self {
            admission_record_id: admission_record_id.into(),
            trusted_accepted_at: trusted_accepted_at.into(),
            accepted_by: Principal::from_parts(PrincipalKind::Service, accepted_by_service_id),
        }
    }

    /// Durable record identifier supplied by the trusted deployment.
    #[must_use]
    pub fn admission_record_id(&self) -> &str {
        &self.admission_record_id
    }

    /// Exact trusted acceptance timestamp text.
    #[must_use]
    pub fn trusted_accepted_at(&self) -> &str {
        &self.trusted_accepted_at
    }

    /// Authenticated service accepting the record.
    #[must_use]
    pub const fn accepted_by(&self) -> &Principal {
        &self.accepted_by
    }
}

/// Adapter-authenticated First-Admission Record bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedAdmissionRecord {
    record_bytes: Arc<[u8]>,
    authenticated_service: Principal,
}

impl AuthenticatedAdmissionRecord {
    /// Construct record bytes authenticated as one Organization service.
    #[must_use]
    pub fn new(
        record_bytes: impl Into<Vec<u8>>,
        authenticated_service_id: impl Into<String>,
    ) -> Self {
        Self {
            record_bytes: Arc::from(record_bytes.into()),
            authenticated_service: Principal::from_parts(
                PrincipalKind::Service,
                authenticated_service_id,
            ),
        }
    }

    /// Exact adapter-returned bytes.
    #[must_use]
    pub fn record_bytes(&self) -> &[u8] {
        &self.record_bytes
    }

    /// Service identity authenticated by the adapter.
    #[must_use]
    pub const fn authenticated_service(&self) -> &Principal {
        &self.authenticated_service
    }
}

/// Result of an authenticated Admission Log lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmissionLookup {
    /// One authenticated record was found.
    Found(AuthenticatedAdmissionRecord),
    /// The log authoritatively established that no record exists.
    AuthoritativeAbsence,
}

/// Complete current Registry evidence applicable to a new admission.
pub trait AdmissionCurrentKeyResolver {
    /// Resolve current complete Registry evidence for the six-stage pass.
    ///
    /// # Errors
    ///
    /// Returns an application adapter failure when current evidence is unavailable.
    fn resolve_current(
        &self,
        request: &KeyResolutionRequest,
    ) -> Result<KeyRegistrySnapshot, AdapterError>;
}

/// Trusted deployment seam invoked only after authoritative absence.
pub trait TrustedAdmissionContext {
    /// Issue the exact trusted record context for one verified signing hash.
    ///
    /// # Errors
    ///
    /// Returns a typed Admission adapter failure.
    fn issue(
        &self,
        organization_id: &str,
        signing_hash: &str,
    ) -> Result<AdmissionContextValue, AdmissionAdapterError>;
}

/// Authenticated, append-only Admission Log adapter.
pub trait AdmissionLog {
    /// Lookup one organization and signing hash.
    ///
    /// # Errors
    ///
    /// Returns a typed Admission adapter failure.
    fn lookup(
        &self,
        organization_id: &str,
        signing_hash: &str,
    ) -> Result<AdmissionLookup, AdmissionAdapterError>;

    /// Commit a candidate or return the already committed authenticated record.
    ///
    /// # Errors
    ///
    /// Returns a typed Admission adapter failure.
    fn append_or_return_existing(
        &self,
        organization_id: &str,
        signing_hash: &str,
        candidate_bytes: &[u8],
    ) -> Result<AuthenticatedAdmissionRecord, AdmissionAdapterError>;
}

/// Immutable validated First-Admission Record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FirstAdmissionRecord {
    bytes: Arc<[u8]>,
    protocol_version: String,
    admission_record_id: String,
    organization_id: String,
    document_kind: String,
    signing_hash: String,
    key_id: String,
    principal: Principal,
    trusted_accepted_at: String,
    accepted_by: Principal,
}

impl FirstAdmissionRecord {
    /// Exact validated record bytes returned by the adapter or prepared for append.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Protocol version.
    #[must_use]
    pub fn protocol_version(&self) -> &str {
        &self.protocol_version
    }

    /// Durable record identifier.
    #[must_use]
    pub fn admission_record_id(&self) -> &str {
        &self.admission_record_id
    }

    /// Organization identifier bound by the record.
    #[must_use]
    pub fn organization_id(&self) -> &str {
        &self.organization_id
    }

    /// Stable Signed Document profile identifier.
    #[must_use]
    pub fn document_kind(&self) -> &str {
        &self.document_kind
    }

    /// Six-stage signing hash.
    #[must_use]
    pub fn signing_hash(&self) -> &str {
        &self.signing_hash
    }

    /// Registry key identifier.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Registry Principal bound to the selected key.
    #[must_use]
    pub const fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Exact trusted acceptance timestamp text.
    #[must_use]
    pub fn trusted_accepted_at(&self) -> &str {
        &self.trusted_accepted_at
    }

    /// Service accepting the record.
    #[must_use]
    pub const fn accepted_by(&self) -> &Principal {
        &self.accepted_by
    }
}

/// A verified Signed Document plus the candidate record prepared for append.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedFirstAdmission {
    verified: VerifiedSignedDocument,
    record: FirstAdmissionRecord,
}

impl PreparedFirstAdmission {
    /// Immutable six-stage evidence.
    #[must_use]
    pub const fn verified(&self) -> &VerifiedSignedDocument {
        &self.verified
    }

    /// Validated candidate record.
    #[must_use]
    pub const fn record(&self) -> &FirstAdmissionRecord {
        &self.record
    }

    /// Canonical candidate bytes supplied to the Admission Log.
    #[must_use]
    pub fn record_bytes(&self) -> &[u8] {
        self.record.bytes()
    }
}

/// Immutable admitted evidence returned after validating an authenticated record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedSignedDocument {
    verified: VerifiedSignedDocument,
    record: FirstAdmissionRecord,
}

impl AdmittedSignedDocument {
    /// Immutable six-stage evidence.
    #[must_use]
    pub const fn verified(&self) -> &VerifiedSignedDocument {
        &self.verified
    }

    /// Validated authenticated First-Admission Record.
    #[must_use]
    pub const fn record(&self) -> &FirstAdmissionRecord {
        &self.record
    }
}

/// Public first-admission and historical-replay orchestration service.
pub struct AdmissionService {
    codec: SignedDocumentCodec,
    schemas: SchemaCatalog,
}

impl AdmissionService {
    /// Build a service over the exact schemas embedded in this SDK build.
    ///
    /// # Errors
    ///
    /// Returns an Admission failure if the embedded catalog cannot be prepared.
    pub fn new() -> Result<Self, AdmissionError> {
        let codec = SignedDocumentCodec::new()
            .map_err(|_| AdmissionError::at(AdmissionReason::RecordSchemaInvalid))?;
        let schemas = SchemaCatalog::new()
            .map_err(|_| AdmissionError::at(AdmissionReason::RecordSchemaInvalid))?;
        Ok(Self { codec, schemas })
    }

    /// Prepare but do not commit a new First-Admission Record.
    ///
    /// # Errors
    ///
    /// Returns a typed Admission failure for trusted-context, record, binding, or interval faults.
    pub fn prepare_first_admission(
        &self,
        verified: &VerifiedSignedDocument,
        trusted_context: &dyn TrustedAdmissionContext,
    ) -> Result<PreparedFirstAdmission, AdmissionError> {
        let context = trusted_context
            .issue(
                verified.resolved_key().organization_id(),
                verified.signing_hash(),
            )
            .map_err(|error| remap_adapter(&error))?;
        parse_rfc3339(context.trusted_accepted_at())
            .map_err(|_| AdmissionError::at(AdmissionReason::MalformedTrustedTime))?;

        let record_value = json!({
            "protocolVersion": crate::PROTOCOL_VERSION,
            "admissionRecordId": context.admission_record_id(),
            "organizationId": verified.resolved_key().organization_id(),
            "documentKind": verified.kind().as_str(),
            "signingHash": verified.signing_hash(),
            "keyId": verified.resolved_key().key_id(),
            "principal": principal_value(verified.resolved_key().principal()),
            "trustedAcceptedAt": context.trusted_accepted_at(),
            "acceptedBy": principal_value(context.accepted_by()),
        });
        let record_bytes = canonical_bytes(&record_value)
            .map_err(|_| AdmissionError::at(AdmissionReason::RecordSchemaInvalid))?;
        let parsed = self.parse_record(&record_bytes)?;
        Self::validate_bindings(&parsed, verified, context.accepted_by())?;
        Ok(PreparedFirstAdmission {
            verified: verified.clone(),
            record: parsed.record,
        })
    }

    /// Verify a Signed Document with current Registry evidence and admit it exactly once.
    ///
    /// # Errors
    ///
    /// Returns the original six-stage failure or a typed Admission-stage failure.
    pub fn admit_first(
        &self,
        kind: SignedDocumentKind,
        document_bytes: &[u8],
        registry: &dyn AdmissionCurrentKeyResolver,
        log: &dyn AdmissionLog,
        trusted_context: &dyn TrustedAdmissionContext,
    ) -> Result<AdmittedSignedDocument, AdmissionOperationError> {
        let verified = self.codec.verify(
            kind,
            document_bytes,
            &CurrentResolverAdapter { resolver: registry },
        )?;
        match log
            .lookup(
                verified.resolved_key().organization_id(),
                verified.signing_hash(),
            )
            .map_err(|error| remap_adapter(&error))?
        {
            AdmissionLookup::Found(record) => {
                Ok(self.validate_authenticated_record(&record, verified)?)
            }
            AdmissionLookup::AuthoritativeAbsence => {
                let prepared = self.prepare_first_admission(&verified, trusted_context)?;
                let committed = log
                    .append_or_return_existing(
                        verified.resolved_key().organization_id(),
                        verified.signing_hash(),
                        prepared.record_bytes(),
                    )
                    .map_err(|error| remap_adapter(&error))?;
                Ok(self.validate_authenticated_record(&committed, verified)?)
            }
        }
    }

    /// Rerun six-stage verification and require an existing historical Admission record.
    ///
    /// # Errors
    ///
    /// Returns the original six-stage failure or a typed Admission-stage failure.
    pub fn verify_historical_admission(
        &self,
        kind: SignedDocumentKind,
        document_bytes: &[u8],
        registry: &dyn KeyResolver,
        log: &dyn AdmissionLog,
    ) -> Result<AdmittedSignedDocument, AdmissionOperationError> {
        let verified = self.codec.verify(kind, document_bytes, registry)?;
        match log
            .lookup(
                verified.resolved_key().organization_id(),
                verified.signing_hash(),
            )
            .map_err(|error| remap_adapter(&error))?
        {
            AdmissionLookup::Found(record) => {
                Ok(self.validate_authenticated_record(&record, verified)?)
            }
            AdmissionLookup::AuthoritativeAbsence => {
                Err(AdmissionError::at(AdmissionReason::RecordMissing).into())
            }
        }
    }

    fn validate_authenticated_record(
        &self,
        authenticated: &AuthenticatedAdmissionRecord,
        verified: VerifiedSignedDocument,
    ) -> Result<AdmittedSignedDocument, AdmissionError> {
        if is_event_self_anchoring(authenticated.record_bytes(), &verified) {
            return Err(AdmissionError::at(AdmissionReason::EventSelfAnchoring));
        }
        let parsed = self.parse_record(authenticated.record_bytes())?;
        Self::validate_bindings(&parsed, &verified, authenticated.authenticated_service())?;
        Ok(AdmittedSignedDocument {
            verified,
            record: parsed.record,
        })
    }

    fn parse_record(&self, raw: &[u8]) -> Result<ParsedAdmissionRecord, AdmissionError> {
        let value = parse_strict_json(raw)
            .map_err(|_| AdmissionError::at(AdmissionReason::RecordSchemaInvalid))?;
        self.schemas
            .validate("first-admission-record.schema.json", &value)
            .map_err(|_| AdmissionError::at(AdmissionReason::RecordSchemaInvalid))?;
        let object = value
            .as_object()
            .ok_or_else(|| AdmissionError::at(AdmissionReason::RecordSchemaInvalid))?;
        let protocol_version = record_string(object, "protocolVersion")?;
        let admission_record_id = record_string(object, "admissionRecordId")?;
        let organization_id = record_string(object, "organizationId")?;
        let document_kind = record_string(object, "documentKind")?;
        let signing_hash = record_string(object, "signingHash")?;
        let key_id = record_string(object, "keyId")?;
        let principal = record_principal(object.get("principal"))?;
        let trusted_accepted_at = record_string(object, "trustedAcceptedAt")?;
        let accepted_at = parse_rfc3339(&trusted_accepted_at)
            .map_err(|_| AdmissionError::at(AdmissionReason::RecordSchemaInvalid))?;
        let accepted_by = record_principal(object.get("acceptedBy"))?;
        if accepted_by.kind() != PrincipalKind::Service {
            return Err(AdmissionError::at(AdmissionReason::RecordSchemaInvalid));
        }
        Ok(ParsedAdmissionRecord {
            record: FirstAdmissionRecord {
                bytes: Arc::from(raw.to_vec()),
                protocol_version,
                admission_record_id,
                organization_id,
                document_kind,
                signing_hash,
                key_id,
                principal,
                trusted_accepted_at,
                accepted_by,
            },
            accepted_at,
        })
    }

    fn validate_bindings(
        parsed: &ParsedAdmissionRecord,
        verified: &VerifiedSignedDocument,
        authenticated_service: &Principal,
    ) -> Result<(), AdmissionError> {
        let record = &parsed.record;
        let resolved = verified.resolved_key();
        if record.organization_id() != resolved.organization_id()
            || record.document_kind() != verified.kind().as_str()
            || record.signing_hash() != verified.signing_hash()
            || record.key_id() != resolved.key_id()
            || record.principal() != resolved.principal()
        {
            return Err(AdmissionError::at(AdmissionReason::RecordBindingMismatch));
        }
        if record.accepted_by() != authenticated_service {
            return Err(AdmissionError::at(AdmissionReason::LogAuthenticationFailed));
        }
        if parsed.accepted_at < *resolved.valid_from()
            || resolved
                .valid_until()
                .is_some_and(|boundary| parsed.accepted_at >= *boundary)
            || resolved
                .revoked_at()
                .is_some_and(|boundary| parsed.accepted_at >= *boundary)
        {
            return Err(AdmissionError::at(
                AdmissionReason::TrustedTimeOutsideKeyInterval,
            ));
        }
        Ok(())
    }
}

struct CurrentResolverAdapter<'a> {
    resolver: &'a dyn AdmissionCurrentKeyResolver,
}

impl KeyResolver for CurrentResolverAdapter<'_> {
    fn resolve(&self, request: &KeyResolutionRequest) -> Result<KeyRegistrySnapshot, AdapterError> {
        self.resolver.resolve_current(request)
    }
}

struct ParsedAdmissionRecord {
    record: FirstAdmissionRecord,
    accepted_at: Rfc3339Instant,
}

fn remap_adapter(error: &AdmissionAdapterError) -> AdmissionError {
    AdmissionError::at(error.reason())
}

fn principal_value(principal: &Principal) -> Value {
    json!({
        "type": principal_kind_id(principal.kind()),
        "id": principal.id(),
    })
}

const fn principal_kind_id(kind: PrincipalKind) -> &'static str {
    match kind {
        PrincipalKind::Agent => "agent",
        PrincipalKind::Human => "human",
        PrincipalKind::Service => "service",
    }
}

fn record_string(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<String, AdmissionError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| AdmissionError::at(AdmissionReason::RecordSchemaInvalid))
}

fn record_principal(value: Option<&Value>) -> Result<Principal, AdmissionError> {
    let object = value
        .and_then(Value::as_object)
        .ok_or_else(|| AdmissionError::at(AdmissionReason::RecordSchemaInvalid))?;
    let kind = match object.get("type").and_then(Value::as_str) {
        Some("agent") => PrincipalKind::Agent,
        Some("human") => PrincipalKind::Human,
        Some("service") => PrincipalKind::Service,
        _ => return Err(AdmissionError::at(AdmissionReason::RecordSchemaInvalid)),
    };
    let id = object
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| AdmissionError::at(AdmissionReason::RecordSchemaInvalid))?;
    Ok(Principal::from_parts(kind, id))
}

fn is_event_self_anchoring(raw_record: &[u8], verified: &VerifiedSignedDocument) -> bool {
    if verified.kind() != SignedDocumentKind::Event {
        return false;
    }
    if raw_record == verified.received_bytes() || raw_record == verified.complete_document_bytes() {
        return true;
    }
    parse_strict_json(raw_record)
        .ok()
        .and_then(|value| canonical_bytes(&value).ok())
        .is_some_and(|canonical| canonical == verified.complete_document_bytes())
}
