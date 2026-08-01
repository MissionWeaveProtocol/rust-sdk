use std::{cell::RefCell, collections::BTreeMap, fs, path::Path};

use missionweaveprotocol::{
    AdapterError, AdmissionAdapterError, AdmissionContextValue, AdmissionCurrentKeyResolver,
    AdmissionError, AdmissionLog, AdmissionLookup, AdmissionOperationError, AdmissionReason,
    AdmissionService, AuthenticatedAdmissionRecord, KeyRegistrySnapshot, KeyResolutionRequest,
    KeyResolver, SignedDocumentCodec, SignedDocumentKind, TrustedAdmissionContext,
    VerificationStage, WireErrorCode, canonical_bytes, parse_strict_json,
};
use serde::Deserialize;

const ADMISSION_SERVICE_ID: &str = "urn:missionweaveprotocol:service:admission";

#[derive(Clone)]
struct FixtureRegistry {
    bytes: Vec<u8>,
}

impl AdmissionCurrentKeyResolver for FixtureRegistry {
    fn resolve_current(
        &self,
        _request: &KeyResolutionRequest,
    ) -> Result<KeyRegistrySnapshot, AdapterError> {
        Ok(KeyRegistrySnapshot::organization_wide(self.bytes.clone()))
    }
}

impl KeyResolver for FixtureRegistry {
    fn resolve(
        &self,
        _request: &KeyResolutionRequest,
    ) -> Result<KeyRegistrySnapshot, AdapterError> {
        Ok(KeyRegistrySnapshot::organization_wide(self.bytes.clone()))
    }
}

struct FixedTrustedContext {
    value: AdmissionContextValue,
    issue_calls: RefCell<usize>,
}

impl FixedTrustedContext {
    fn command_at(trusted_accepted_at: &str) -> Self {
        Self {
            value: AdmissionContextValue::new(
                "urn:missionweaveprotocol:admission-record:crypto-vector-command",
                trusted_accepted_at,
                ADMISSION_SERVICE_ID,
            ),
            issue_calls: RefCell::new(0),
        }
    }

    fn issue_calls(&self) -> usize {
        *self.issue_calls.borrow()
    }
}

impl TrustedAdmissionContext for FixedTrustedContext {
    fn issue(
        &self,
        _organization_id: &str,
        _signing_hash: &str,
    ) -> Result<AdmissionContextValue, AdmissionAdapterError> {
        *self.issue_calls.borrow_mut() += 1;
        Ok(self.value.clone())
    }
}

enum LogBehavior {
    AuthoritativeAbsence,
    Commit(Vec<u8>),
    Found(Vec<u8>),
    Unavailable,
}

struct RecordingAdmissionLog {
    behavior: LogBehavior,
    calls: RefCell<Vec<&'static str>>,
    appended_candidate: RefCell<Option<Vec<u8>>>,
}

impl RecordingAdmissionLog {
    fn authoritative_absence() -> Self {
        Self::new(LogBehavior::AuthoritativeAbsence)
    }

    fn authoritative_absence_then_commit(record: Vec<u8>) -> Self {
        Self::new(LogBehavior::Commit(record))
    }

    fn found(record: Vec<u8>) -> Self {
        Self::new(LogBehavior::Found(record))
    }

    fn unavailable() -> Self {
        Self::new(LogBehavior::Unavailable)
    }

    fn new(behavior: LogBehavior) -> Self {
        Self {
            behavior,
            calls: RefCell::new(Vec::new()),
            appended_candidate: RefCell::new(None),
        }
    }

    fn calls(&self) -> Vec<&'static str> {
        self.calls.borrow().clone()
    }

    fn append_calls(&self) -> usize {
        self.calls
            .borrow()
            .iter()
            .filter(|call| **call == "append-or-return-existing")
            .count()
    }

    fn appended_candidate(&self) -> Option<Vec<u8>> {
        self.appended_candidate.borrow().clone()
    }
}

impl AdmissionLog for RecordingAdmissionLog {
    fn lookup(
        &self,
        _organization_id: &str,
        _signing_hash: &str,
    ) -> Result<AdmissionLookup, AdmissionAdapterError> {
        self.calls.borrow_mut().push("lookup");
        match &self.behavior {
            LogBehavior::AuthoritativeAbsence | LogBehavior::Commit(_) => {
                Ok(AdmissionLookup::AuthoritativeAbsence)
            }
            LogBehavior::Found(record) => Ok(AdmissionLookup::Found(
                AuthenticatedAdmissionRecord::new(record.clone(), ADMISSION_SERVICE_ID),
            )),
            LogBehavior::Unavailable => Err(AdmissionAdapterError::new(
                AdmissionReason::LogUnavailable,
                "fixture Admission Log is unavailable",
            )),
        }
    }

    fn append_or_return_existing(
        &self,
        _organization_id: &str,
        _signing_hash: &str,
        candidate_bytes: &[u8],
    ) -> Result<AuthenticatedAdmissionRecord, AdmissionAdapterError> {
        self.calls.borrow_mut().push("append-or-return-existing");
        self.appended_candidate
            .borrow_mut()
            .replace(candidate_bytes.to_vec());
        match &self.behavior {
            LogBehavior::Commit(record) => Ok(AuthenticatedAdmissionRecord::new(
                record.clone(),
                ADMISSION_SERVICE_ID,
            )),
            _ => panic!("append was called for a fixture that cannot commit"),
        }
    }
}

#[test]
fn first_admission_returns_only_the_validated_committed_record() {
    let committed = read_bytes("admission/records/valid/command.json");
    let log = RecordingAdmissionLog::authoritative_absence_then_commit(committed.clone());
    let context = FixedTrustedContext::command_at("2026-07-15T00:05:00Z");

    let admitted = AdmissionService::new()
        .expect("Admission service")
        .admit_first(
            SignedDocumentKind::Command,
            &golden_command(),
            &current_registry(),
            &log,
            &context,
        )
        .expect("first admission");

    assert_eq!(
        admitted.record().signing_hash(),
        admitted.verified().signing_hash()
    );
    assert_eq!(admitted.record().bytes(), committed);
    assert_eq!(log.calls(), ["lookup", "append-or-return-existing"]);
    assert_eq!(context.issue_calls(), 1);

    let expected_candidate = canonical_bytes(
        &parse_strict_json(&committed).expect("strict committed First-Admission Record"),
    )
    .expect("canonical First-Admission Record");
    assert_eq!(log.appended_candidate(), Some(expected_candidate));
}

#[test]
fn historical_replay_never_creates_a_missing_record() {
    let log = RecordingAdmissionLog::authoritative_absence();
    let error = AdmissionService::new()
        .expect("Admission service")
        .verify_historical_admission(
            SignedDocumentKind::Command,
            &golden_command(),
            &historical_registry(),
            &log,
        )
        .expect_err("missing historical record must fail");

    assert_admission_error(&error, AdmissionReason::RecordMissing);
    assert_eq!(log.calls(), ["lookup"]);
    assert_eq!(log.append_calls(), 0);
}

#[test]
fn existing_record_binding_mismatch_is_rejected() {
    let log =
        RecordingAdmissionLog::found(read_bytes("admission/records/invalid/key-id-mismatch.json"));

    let error = AdmissionService::new()
        .expect("Admission service")
        .verify_historical_admission(
            SignedDocumentKind::Command,
            &golden_command(),
            &historical_registry(),
            &log,
        )
        .expect_err("key ID mismatch must fail");

    assert_admission_error(&error, AdmissionReason::RecordBindingMismatch);
    assert_eq!(log.calls(), ["lookup"]);
    assert_eq!(log.append_calls(), 0);
}

#[test]
fn historical_replay_accepts_retained_later_revocation() {
    let log = RecordingAdmissionLog::found(read_bytes("admission/records/valid/command.json"));

    let admitted = AdmissionService::new()
        .expect("Admission service")
        .verify_historical_admission(
            SignedDocumentKind::Command,
            &golden_command(),
            &registry("admission/registries/registry-later-revocation.json"),
            &log,
        )
        .expect("later revocation must not invalidate earlier trusted admission");

    assert_eq!(
        admitted.record().trusted_accepted_at(),
        "2026-07-15T00:05:00Z"
    );
    assert_eq!(
        admitted.verified().resolved_key().valid_from_text(),
        "2026-07-15T08:00:00+08:00"
    );
    assert_eq!(
        admitted.verified().resolved_key().valid_until_text(),
        Some("2026-07-16T00:00:00Z")
    );
    assert_eq!(
        admitted.verified().resolved_key().revoked_at_text(),
        Some("2026-07-15T01:00:00Z")
    );
    assert_eq!(log.calls(), ["lookup"]);
    assert_eq!(log.append_calls(), 0);
}

#[test]
fn unavailable_log_fails_first_admission() {
    let log = RecordingAdmissionLog::unavailable();
    let context = FixedTrustedContext::command_at("2026-07-15T00:05:00Z");

    let error = AdmissionService::new()
        .expect("Admission service")
        .admit_first(
            SignedDocumentKind::Command,
            &golden_command(),
            &current_registry(),
            &log,
            &context,
        )
        .expect_err("an unavailable Admission Log must fail closed");

    assert_admission_error(&error, AdmissionReason::LogUnavailable);
    assert_eq!(log.calls(), ["lookup"]);
    assert_eq!(context.issue_calls(), 0);
}

#[test]
fn append_return_value_is_revalidated_before_admission() {
    let log = RecordingAdmissionLog::authoritative_absence_then_commit(read_bytes(
        "admission/records/invalid/key-id-mismatch.json",
    ));
    let context = FixedTrustedContext::command_at("2026-07-15T00:05:00Z");

    let error = AdmissionService::new()
        .expect("Admission service")
        .admit_first(
            SignedDocumentKind::Command,
            &golden_command(),
            &current_registry(),
            &log,
            &context,
        )
        .expect_err("adapter-returned record must be validated after append");

    assert_admission_error(&error, AdmissionReason::RecordBindingMismatch);
    assert_eq!(log.calls(), ["lookup", "append-or-return-existing"]);
}

#[test]
fn event_self_anchoring_rejects_canonically_equivalent_bytes() {
    let event = read_bytes("cryptography/vectors/signed-documents/valid/event.json");
    let canonical_event = canonical_bytes(&parse_strict_json(&event).expect("strict Event"))
        .expect("canonical Event");
    assert_ne!(
        event, canonical_event,
        "fixture must exercise byte inequality"
    );
    let log = RecordingAdmissionLog::found(canonical_event);

    let error = AdmissionService::new()
        .expect("Admission service")
        .verify_historical_admission(
            SignedDocumentKind::Event,
            &event,
            &historical_registry(),
            &log,
        )
        .expect_err("an Event cannot authenticate a canonically equivalent copy of itself");

    assert_admission_error(&error, AdmissionReason::EventSelfAnchoring);
    assert_eq!(log.calls(), ["lookup"]);
}

#[test]
fn trusted_time_equal_valid_until_is_rejected() {
    let registry = historical_registry();
    let verified = SignedDocumentCodec::new()
        .expect("Signed Document codec")
        .verify(SignedDocumentKind::Command, &golden_command(), &registry)
        .expect("golden Command verification");
    let context = FixedTrustedContext::command_at("2026-07-16T00:00:00Z");

    let error = AdmissionService::new()
        .expect("Admission service")
        .prepare_first_admission(&verified, &context)
        .expect_err("validUntil is exclusive");

    assert_direct_admission_error(&error, AdmissionReason::TrustedTimeOutsideKeyInterval);
    assert_eq!(context.issue_calls(), 1);
}

#[test]
fn signed_document_failure_precedes_admission_log_access() {
    let log = RecordingAdmissionLog::authoritative_absence();
    let context = FixedTrustedContext::command_at("2026-07-15T00:05:00Z");

    let error = AdmissionService::new()
        .expect("Admission service")
        .admit_first(
            SignedDocumentKind::Command,
            br"{}",
            &current_registry(),
            &log,
            &context,
        )
        .expect_err("invalid Signed Document must fail before Admission");

    let verification = error
        .verification_error()
        .expect("six-stage verification error must be preserved");
    assert_eq!(verification.diagnostic().stage(), VerificationStage::Schema);
    assert_eq!(
        verification.wire_code(),
        WireErrorCode::SchemaValidationFailed
    );
    assert!(log.calls().is_empty());
    assert_eq!(context.issue_calls(), 0);
}

#[test]
fn satisfies_all_vendored_admission_manifest_evaluations() {
    let manifest_value =
        parse_strict_json(&read_bytes("admission/manifest.json")).expect("strict manifest");
    let manifest: AdmissionManifest =
        serde_json::from_value(manifest_value).expect("Admission manifest fields");
    let mut totals = EvaluationTotals::default();
    let mut call_totals = BTreeMap::<&'static str, usize>::new();

    for case in &manifest.cases {
        assert!(!case.id.is_empty(), "Admission case ID must not be empty");
        for evaluation in &case.evaluations {
            totals.evaluations += 1;
            let calls = RefCell::new(Vec::new());
            let resolver = ManifestRegistry {
                bytes: read_bytes(&evaluation.registry),
                calls: &calls,
            };
            let log = ManifestAdmissionLog {
                evaluation,
                calls: &calls,
            };
            let context = ManifestTrustedContext {
                value: evaluation.trusted_context.as_ref(),
                calls: &calls,
            };
            let result = execute_manifest_evaluation(evaluation, &resolver, &log, &context);

            if evaluation.expect.stage == "complete" {
                let admitted = result.unwrap_or_else(|error| {
                    panic!(
                        "{}/{} expected complete Admission: {error}",
                        case.id, evaluation.id
                    )
                });
                let expected_record = evaluation
                    .expect
                    .record
                    .as_deref()
                    .expect("complete evaluation record");
                assert_eq!(
                    admitted.record().bytes(),
                    read_bytes(expected_record),
                    "{}/{} retained record bytes",
                    case.id,
                    evaluation.id
                );
                totals.complete += 1;
            } else {
                let error = result.expect_err("rejected Admission evaluation must fail");
                let admission = error.admission_error().unwrap_or_else(|| {
                    panic!(
                        "{}/{} returned a six-stage error instead of Admission",
                        case.id, evaluation.id
                    )
                });
                assert_eq!(
                    admission.wire_code().as_str(),
                    evaluation.expect.wire_code.as_deref().expect("wire code"),
                    "{}/{} wire code",
                    case.id,
                    evaluation.id
                );
                assert_eq!(admission.diagnostic().stage(), evaluation.expect.stage);
                assert_eq!(
                    admission.diagnostic().reason(),
                    admission_reason(evaluation.expect.reason.as_deref().expect("reason")),
                    "{}/{} Admission reason",
                    case.id,
                    evaluation.id
                );
                totals.rejected += 1;
            }

            assert_eq!(
                calls.borrow().as_slice(),
                expected_manifest_calls(evaluation),
                "{}/{} public call order",
                case.id,
                evaluation.id
            );
            for call in calls.borrow().iter().copied() {
                *call_totals.entry(call).or_default() += 1;
            }
        }
    }

    assert_eq!(
        totals,
        EvaluationTotals {
            evaluations: 30,
            complete: 12,
            rejected: 18,
        }
    );
    assert_eq!(call_totals.get("resolve-current"), Some(&18));
    assert_eq!(call_totals.get("resolve"), Some(&12));
    assert_eq!(call_totals.get("lookup"), Some(&30));
    assert_eq!(call_totals.get("issue"), Some(&17));
    assert_eq!(call_totals.get("append-or-return-existing"), Some(&11));
}

fn assert_admission_error(error: &AdmissionOperationError, reason: AdmissionReason) {
    let error = error
        .admission_error()
        .expect("expected an Admission-stage rejection");
    assert_direct_admission_error(error, reason);
}

fn assert_direct_admission_error(error: &AdmissionError, reason: AdmissionReason) {
    assert_eq!(error.wire_code().as_str(), "AUTH_INVALID_SIGNATURE");
    assert_eq!(error.diagnostic().stage(), "admission");
    assert_eq!(error.diagnostic().reason(), reason);
}

fn golden_command() -> Vec<u8> {
    read_bytes("cryptography/vectors/signed-documents/valid/command.json")
}

fn current_registry() -> FixtureRegistry {
    historical_registry()
}

fn historical_registry() -> FixtureRegistry {
    registry("cryptography/keys/registry-valid.json")
}

fn registry(relative: &str) -> FixtureRegistry {
    FixtureRegistry {
        bytes: read_bytes(relative),
    }
}

fn read_bytes(relative: &str) -> Vec<u8> {
    fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)).expect("fixture bytes")
}

#[derive(Deserialize)]
struct AdmissionManifest {
    cases: Vec<ManifestCase>,
}

#[derive(Deserialize)]
struct ManifestCase {
    id: String,
    evaluations: Vec<ManifestEvaluation>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManifestEvaluation {
    id: String,
    profile_id: String,
    mode: String,
    document: String,
    registry: String,
    trusted_context: Option<ManifestContextValue>,
    lookup: ManifestLookup,
    append: Option<ManifestAppend>,
    expect: ManifestExpectation,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManifestContextValue {
    admission_record_id: String,
    trusted_accepted_at: String,
    accepted_by: ManifestPrincipal,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManifestLookup {
    status: String,
    record: Option<String>,
    authenticated_service: Option<ManifestPrincipal>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManifestAppend {
    status: String,
    record: Option<String>,
    authenticated_service: Option<ManifestPrincipal>,
}

#[derive(Deserialize)]
struct ManifestPrincipal {
    #[serde(rename = "type")]
    kind: String,
    id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManifestExpectation {
    stage: String,
    wire_code: Option<String>,
    reason: Option<String>,
    record: Option<String>,
}

#[derive(Debug, Default, Eq, PartialEq)]
struct EvaluationTotals {
    evaluations: usize,
    complete: usize,
    rejected: usize,
}

struct ManifestRegistry<'a> {
    bytes: Vec<u8>,
    calls: &'a RefCell<Vec<&'static str>>,
}

impl AdmissionCurrentKeyResolver for ManifestRegistry<'_> {
    fn resolve_current(
        &self,
        _request: &KeyResolutionRequest,
    ) -> Result<KeyRegistrySnapshot, AdapterError> {
        self.calls.borrow_mut().push("resolve-current");
        Ok(KeyRegistrySnapshot::organization_wide(self.bytes.clone()))
    }
}

impl KeyResolver for ManifestRegistry<'_> {
    fn resolve(
        &self,
        _request: &KeyResolutionRequest,
    ) -> Result<KeyRegistrySnapshot, AdapterError> {
        self.calls.borrow_mut().push("resolve");
        Ok(KeyRegistrySnapshot::organization_wide(self.bytes.clone()))
    }
}

struct ManifestTrustedContext<'a> {
    value: Option<&'a ManifestContextValue>,
    calls: &'a RefCell<Vec<&'static str>>,
}

impl TrustedAdmissionContext for ManifestTrustedContext<'_> {
    fn issue(
        &self,
        organization_id: &str,
        signing_hash: &str,
    ) -> Result<AdmissionContextValue, AdmissionAdapterError> {
        self.calls.borrow_mut().push("issue");
        assert!(!organization_id.is_empty());
        assert!(!signing_hash.is_empty());
        let value = self.value.expect("trusted context must be declared");
        assert_eq!(value.accepted_by.kind, "service");
        Ok(AdmissionContextValue::new(
            value.admission_record_id.clone(),
            value.trusted_accepted_at.clone(),
            value.accepted_by.id.clone(),
        ))
    }
}

struct ManifestAdmissionLog<'a> {
    evaluation: &'a ManifestEvaluation,
    calls: &'a RefCell<Vec<&'static str>>,
}

impl AdmissionLog for ManifestAdmissionLog<'_> {
    fn lookup(
        &self,
        organization_id: &str,
        signing_hash: &str,
    ) -> Result<AdmissionLookup, AdmissionAdapterError> {
        self.calls.borrow_mut().push("lookup");
        assert!(!organization_id.is_empty());
        assert!(!signing_hash.is_empty());
        match self.evaluation.lookup.status.as_str() {
            "found" => Ok(AdmissionLookup::Found(manifest_authenticated_record(
                self.evaluation
                    .lookup
                    .record
                    .as_deref()
                    .expect("found record path"),
                self.evaluation
                    .lookup
                    .authenticated_service
                    .as_ref()
                    .expect("found authenticated service"),
            ))),
            "authoritative-absence" => Ok(AdmissionLookup::AuthoritativeAbsence),
            status => Err(AdmissionAdapterError::new(
                lookup_reason(status),
                format!("manifest lookup outcome {status}"),
            )),
        }
    }

    fn append_or_return_existing(
        &self,
        organization_id: &str,
        signing_hash: &str,
        candidate_bytes: &[u8],
    ) -> Result<AuthenticatedAdmissionRecord, AdmissionAdapterError> {
        self.calls.borrow_mut().push("append-or-return-existing");
        assert!(!organization_id.is_empty());
        assert!(!signing_hash.is_empty());
        let candidate = parse_strict_json(candidate_bytes).expect("strict append candidate");
        assert_eq!(
            canonical_bytes(&candidate).expect("canonical append candidate"),
            candidate_bytes
        );
        let expected_path = format!(
            "admission/records/valid/{}.json",
            self.evaluation.profile_id
        );
        let expected = parse_strict_json(&read_bytes(&expected_path)).expect("expected record");
        assert_eq!(
            candidate_bytes,
            canonical_bytes(&expected).expect("canonical expected record")
        );

        let append = self
            .evaluation
            .append
            .as_ref()
            .expect("append outcome must be declared");
        match append.status.as_str() {
            "committed" | "existing" => Ok(manifest_authenticated_record(
                append.record.as_deref().expect("append record path"),
                append
                    .authenticated_service
                    .as_ref()
                    .expect("append authenticated service"),
            )),
            status => Err(AdmissionAdapterError::new(
                append_reason(status),
                format!("manifest append outcome {status}"),
            )),
        }
    }
}

fn manifest_authenticated_record(
    relative: &str,
    service: &ManifestPrincipal,
) -> AuthenticatedAdmissionRecord {
    assert_eq!(service.kind, "service");
    AuthenticatedAdmissionRecord::new(read_bytes(relative), service.id.clone())
}

fn execute_manifest_evaluation(
    evaluation: &ManifestEvaluation,
    resolver: &ManifestRegistry<'_>,
    log: &ManifestAdmissionLog<'_>,
    context: &ManifestTrustedContext<'_>,
) -> Result<missionweaveprotocol::AdmittedSignedDocument, AdmissionOperationError> {
    let service = AdmissionService::new().expect("Admission service");
    let kind = signed_document_kind(&evaluation.profile_id);
    let document = read_bytes(&evaluation.document);
    match evaluation.mode.as_str() {
        "first-admission" => service.admit_first(kind, &document, resolver, log, context),
        "historical-replay" => service.verify_historical_admission(kind, &document, resolver, log),
        mode => panic!("unsupported Admission mode {mode}"),
    }
}

fn expected_manifest_calls(evaluation: &ManifestEvaluation) -> &'static [&'static str] {
    if evaluation.mode == "historical-replay" {
        return &["resolve", "lookup"];
    }
    if evaluation.lookup.status != "authoritative-absence" {
        return &["resolve-current", "lookup"];
    }
    if evaluation.append.is_some() {
        return &[
            "resolve-current",
            "lookup",
            "issue",
            "append-or-return-existing",
        ];
    }
    &["resolve-current", "lookup", "issue"]
}

fn signed_document_kind(profile_id: &str) -> SignedDocumentKind {
    match profile_id {
        "agent-card" => SignedDocumentKind::AgentCard,
        "approval" => SignedDocumentKind::Approval,
        "artifact" => SignedDocumentKind::Artifact,
        "command" => SignedDocumentKind::Command,
        "context-package" => SignedDocumentKind::ContextPackage,
        "event" => SignedDocumentKind::Event,
        "evidence" => SignedDocumentKind::Evidence,
        "extension-profile" => SignedDocumentKind::ExtensionProfile,
        "group-snapshot" => SignedDocumentKind::GroupSnapshot,
        value => panic!("unsupported Signed Document kind {value}"),
    }
}

fn admission_reason(value: &str) -> AdmissionReason {
    match value {
        "record-missing" => AdmissionReason::RecordMissing,
        "record-binding-mismatch" => AdmissionReason::RecordBindingMismatch,
        "trusted-time-outside-key-interval" => AdmissionReason::TrustedTimeOutsideKeyInterval,
        "malformed-trusted-time" => AdmissionReason::MalformedTrustedTime,
        "record-conflict" => AdmissionReason::RecordConflict,
        "record-schema-invalid" => AdmissionReason::RecordSchemaInvalid,
        "log-authentication-failed" => AdmissionReason::LogAuthenticationFailed,
        "append-integrity-not-established" => AdmissionReason::AppendIntegrityNotEstablished,
        "log-unavailable" => AdmissionReason::LogUnavailable,
        "log-indeterminate" => AdmissionReason::LogIndeterminate,
        "commit-failed" => AdmissionReason::CommitFailed,
        "event-self-anchoring" => AdmissionReason::EventSelfAnchoring,
        reason => panic!("unsupported Admission reason {reason}"),
    }
}

fn lookup_reason(status: &str) -> AdmissionReason {
    match status {
        "unauthenticated" | "integrity-failed" => AdmissionReason::LogAuthenticationFailed,
        "unavailable" => AdmissionReason::LogUnavailable,
        "indeterminate" => AdmissionReason::LogIndeterminate,
        value => panic!("unsupported lookup status {value}"),
    }
}

fn append_reason(status: &str) -> AdmissionReason {
    match status {
        "conflict" => AdmissionReason::RecordConflict,
        "unauthenticated" => AdmissionReason::LogAuthenticationFailed,
        "integrity-failed" => AdmissionReason::AppendIntegrityNotEstablished,
        "unavailable" => AdmissionReason::LogUnavailable,
        "indeterminate" => AdmissionReason::LogIndeterminate,
        value => panic!("unsupported append status {value}"),
    }
}
