use std::{cell::Cell, fs, path::Path};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use missionweaveprotocol::{
    AdapterError, Ed25519Signer, KeyRegistryCompleteness, KeyRegistrySnapshot,
    KeyResolutionRequest, KeyResolver, KeySignerExpectation, PrincipalKind, SignedDocumentCodec,
    SignedDocumentKind, SigningError, SigningKey, VerificationStage, WireErrorCode,
    canonical_bytes, canonical_sha256, parse_strict_json,
};
use serde_json::Value;

struct FixtureSigningKey {
    key_id: String,
    signer: Ed25519Signer,
}

impl SigningKey for FixtureSigningKey {
    fn algorithm(&self) -> &'static str {
        "Ed25519"
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.signer.sign_bytes(message).to_vec())
    }
}

struct FixtureKeyResolver {
    registry: Vec<u8>,
}

impl KeyResolver for FixtureKeyResolver {
    fn resolve(
        &self,
        _request: &KeyResolutionRequest,
    ) -> Result<KeyRegistrySnapshot, AdapterError> {
        Ok(KeyRegistrySnapshot::new(
            self.registry.clone(),
            KeyRegistryCompleteness::OrganizationWide,
        ))
    }
}

struct IncompleteKeyResolver {
    registry: Vec<u8>,
    completeness: KeyRegistryCompleteness,
}

impl KeyResolver for IncompleteKeyResolver {
    fn resolve(
        &self,
        _request: &KeyResolutionRequest,
    ) -> Result<KeyRegistrySnapshot, AdapterError> {
        Ok(KeyRegistrySnapshot::new(
            self.registry.clone(),
            self.completeness,
        ))
    }
}

struct RequestCheckingResolver {
    registry: Vec<u8>,
}

impl KeyResolver for RequestCheckingResolver {
    fn resolve(&self, request: &KeyResolutionRequest) -> Result<KeyRegistrySnapshot, AdapterError> {
        assert_eq!(request.kind(), SignedDocumentKind::Command);
        assert_eq!(
            request.key_id(),
            "urn:missionweaveprotocol:key:crypto-vector-rfc8032-1"
        );
        assert_eq!(request.protected_time_text(), "2026-07-15T00:00:00Z");
        assert!(matches!(
            request.expected_signer(),
            KeySignerExpectation::Exact(principal)
                if principal.kind() == PrincipalKind::Agent
                    && principal.id()
                        == "urn:missionweaveprotocol:agent:crypto-vector-coordinator"
        ));
        Ok(KeyRegistrySnapshot::organization_wide(
            self.registry.clone(),
        ))
    }
}

struct CountingSigningKey<'a> {
    calls: &'a Cell<usize>,
    signature: Vec<u8>,
}

impl SigningKey for CountingSigningKey<'_> {
    fn algorithm(&self) -> &'static str {
        "Ed25519"
    }

    fn key_id(&self) -> &'static str {
        "urn:missionweaveprotocol:key:test"
    }

    fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, AdapterError> {
        self.calls.set(self.calls.get() + 1);
        Ok(self.signature.clone())
    }
}

#[test]
fn signs_the_golden_command_through_the_public_adapter() {
    let expected = read_json("cryptography/vectors/signed-documents/valid/command.json");
    let mut unsigned = expected.clone();
    unsigned
        .as_object_mut()
        .expect("Command object")
        .remove("signature");
    let before = unsigned.clone();
    let fixture = read_json("cryptography/keys/signing-coordinator.json");
    let seed: [u8; 32] = URL_SAFE_NO_PAD
        .decode(fixture["seed"].as_str().expect("seed string"))
        .expect("base64url seed")
        .try_into()
        .expect("32-byte seed");
    let key = FixtureSigningKey {
        key_id: fixture["keyId"].as_str().expect("key ID").to_owned(),
        signer: Ed25519Signer::from_seed(seed),
    };

    let signed = SignedDocumentCodec::new()
        .expect("codec")
        .sign(SignedDocumentKind::Command, &unsigned, &key)
        .expect("golden Command should sign");

    assert_eq!(signed, expected);
    assert_eq!(unsigned, before, "sign mutated the caller's document");
}

#[test]
fn verifies_the_golden_command_and_retains_complete_evidence() {
    let raw = read_bytes("cryptography/vectors/signed-documents/valid/command.json");
    let expected = parse_strict_json(&raw).expect("strict Command fixture");
    let expected_signing_bytes =
        read_bytes("cryptography/vectors/canonicalization/command.signing.jcs");
    let resolver = FixtureKeyResolver {
        registry: read_bytes("cryptography/keys/registry-valid.json"),
    };

    let verified = SignedDocumentCodec::new()
        .expect("codec")
        .verify(SignedDocumentKind::Command, &raw, &resolver)
        .expect("golden Command should verify");

    assert_eq!(verified.kind(), SignedDocumentKind::Command);
    assert_eq!(verified.document(), &expected);
    assert_eq!(verified.received_bytes(), raw);
    assert_eq!(verified.signing_bytes(), expected_signing_bytes);
    assert_eq!(
        verified.signing_hash(),
        "sha256:6655c5d67ae3ecc19a4ed04bda7f1372aeaafc7adf939a77715de96ef2100695"
    );
    assert_eq!(
        verified.complete_document_hash(),
        "sha256:1d17d0bd5379e554d48d14a6b328671f12860c6c3278bc1e7ca4e1163a74353f"
    );
    assert_eq!(verified.protected_time_text(), "2026-07-15T00:00:00Z");
    assert_eq!(verified.protected_time().epoch_second(), 1_784_073_600);
    assert_eq!(
        verified.signature().value(),
        "PMeeKgpw-HlGNwHbQbEMrfAxbw1815fBdFhOSTHy31ss90eTcuQ4rWeRZbmqFFtHgLKzd0gNm67-HenzwGVhAg"
    );
    assert_eq!(
        verified.resolved_key().key_id(),
        "urn:missionweaveprotocol:key:crypto-vector-rfc8032-1"
    );
    assert_eq!(
        verified.resolved_key().registry_completeness(),
        KeyRegistryCompleteness::OrganizationWide
    );
    assert_eq!(
        verified.resolved_key().principal().kind(),
        PrincipalKind::Agent
    );
    assert_eq!(
        verified.resolved_key().principal().id(),
        "urn:missionweaveprotocol:agent:crypto-vector-coordinator"
    );
}

#[test]
fn requests_exact_resolution_context_and_rejects_incomplete_registry_snapshots() {
    let raw = read_bytes("cryptography/vectors/signed-documents/valid/command.json");
    let registry = read_bytes("cryptography/keys/registry-valid.json");
    let codec = SignedDocumentCodec::new().expect("codec");

    codec
        .verify(
            SignedDocumentKind::Command,
            &raw,
            &RequestCheckingResolver {
                registry: registry.clone(),
            },
        )
        .expect("organization-wide snapshot should verify");

    for completeness in [
        KeyRegistryCompleteness::Partial,
        KeyRegistryCompleteness::Unspecified,
    ] {
        let error = codec
            .verify(
                SignedDocumentKind::Command,
                &raw,
                &IncompleteKeyResolver {
                    registry: registry.clone(),
                    completeness,
                },
            )
            .expect_err("incomplete Registry evidence must fail closed");
        assert_eq!(error.diagnostic().stage(), VerificationStage::KeyResolution);
        assert_eq!(error.wire_code(), WireErrorCode::AuthInvalidSignature);
    }
}

#[test]
fn signing_validates_protected_time_before_calling_the_adapter() {
    let mut unsigned = read_json("cryptography/vectors/signed-documents/valid/command.json");
    let object = unsigned.as_object_mut().expect("Command object");
    object.remove("signature");
    object.insert(
        "issuedAt".to_owned(),
        Value::String("2026-07-15T00:00:00+00:00".to_owned()),
    );
    let calls = Cell::new(0);
    let key = CountingSigningKey {
        calls: &calls,
        signature: vec![0; 64],
    };

    let error = SignedDocumentCodec::new()
        .expect("codec")
        .sign(SignedDocumentKind::Command, &unsigned, &key)
        .expect_err("protected time without uppercase Z must fail");

    assert!(matches!(error, SigningError::ProtectedTime));
    assert_eq!(calls.get(), 0, "adapter was called before time validation");
}

#[test]
fn signing_rejects_a_non_prime_order_signature_from_the_adapter() {
    let mut unsigned = read_json("cryptography/vectors/signed-documents/valid/command.json");
    unsigned
        .as_object_mut()
        .expect("Command object")
        .remove("signature");
    let calls = Cell::new(0);
    let key = CountingSigningKey {
        calls: &calls,
        signature: vec![0; 64],
    };

    let error = SignedDocumentCodec::new()
        .expect("codec")
        .sign(SignedDocumentKind::Command, &unsigned, &key)
        .expect_err("small-order R must not be emitted");

    assert!(matches!(error, SigningError::InvalidSignatureEnvelope(_)));
    assert_eq!(calls.get(), 1);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the protocol manifest is intentionally exercised as one end-to-end public-interface contract"
)]
fn satisfies_every_vendored_cryptography_manifest_evaluation() {
    let manifest = read_json("cryptography/manifest.json");
    let cases = manifest["cases"].as_array().expect("manifest cases");
    let codec = SignedDocumentCodec::new().expect("codec");
    let mut evaluations = 0;
    let mut completed = 0;
    let mut rejected = 0;

    for case in cases {
        let case_id = case["id"].as_str().expect("case ID");
        for evaluation in case["evaluations"].as_array().expect("evaluations") {
            evaluations += 1;
            if case["kind"] == "canonicalization" {
                let input = read_json(evaluation["input"].as_str().expect("input path"));
                let actual = canonical_bytes(&input).expect("RFC 8785 canonical bytes");
                assert_eq!(
                    actual,
                    read_bytes(evaluation["expectedJcs"].as_str().expect("JCS path")),
                    "{case_id} canonical bytes"
                );
                assert_eq!(
                    canonical_sha256(&input).expect("canonical hash"),
                    evaluation["sha256"].as_str().expect("expected hash"),
                    "{case_id} canonical hash"
                );
                completed += 1;
                continue;
            }

            let kind = signed_kind(evaluation["profileId"].as_str().expect("profile ID"));
            let raw = read_bytes(evaluation["document"].as_str().expect("document path"));
            let resolver = FixtureKeyResolver {
                registry: read_bytes(evaluation["registry"].as_str().expect("Registry path")),
            };
            let expected = &evaluation["expect"];
            if expected["stage"] == "complete" {
                let verified = codec.verify(kind, &raw, &resolver).unwrap_or_else(|error| {
                    panic!(
                        "{case_id} failed at {:?}: {}",
                        error.diagnostic().stage(),
                        error.diagnostic().reason()
                    )
                });
                let evidence = &expected["verified"];
                assert_eq!(
                    verified.resolved_key().key_id(),
                    evidence["keyId"].as_str().expect("key ID"),
                    "{case_id} key ID"
                );
                assert_eq!(
                    verified.resolved_key().principal().kind(),
                    principal_kind(
                        evidence["principal"]["type"]
                            .as_str()
                            .expect("Principal type")
                    ),
                    "{case_id} Principal type"
                );
                assert_eq!(
                    verified.resolved_key().principal().id(),
                    evidence["principal"]["id"].as_str().expect("Principal ID"),
                    "{case_id} Principal ID"
                );
                assert_eq!(
                    verified.protected_time_text(),
                    evidence["protectedTime"].as_str().expect("protected time"),
                    "{case_id} protected time"
                );
                assert_eq!(
                    verified.signing_bytes(),
                    read_bytes(
                        evidence["signingBytes"]
                            .as_str()
                            .expect("signing bytes path")
                    ),
                    "{case_id} signing bytes"
                );
                assert_eq!(
                    verified.signing_hash(),
                    evidence["signingHash"].as_str().expect("signing hash"),
                    "{case_id} signing hash"
                );
                assert_eq!(
                    verified.signature().value(),
                    evidence["signature"].as_str().expect("signature"),
                    "{case_id} signature"
                );
                assert_eq!(
                    verified.complete_document_hash(),
                    evidence["signedDocumentHash"]
                        .as_str()
                        .expect("document hash"),
                    "{case_id} complete document hash"
                );

                let signing_fixture = read_json(
                    evaluation["signingKey"]
                        .as_str()
                        .expect("signing-key fixture path"),
                );
                let signing_key = fixture_signing_key(&signing_fixture);
                let mut unsigned = verified.document().clone();
                unsigned
                    .as_object_mut()
                    .expect("signed object")
                    .remove("signature");
                assert_eq!(
                    codec
                        .sign(kind, &unsigned, &signing_key)
                        .expect("positive vector should reproduce through sign"),
                    *verified.document(),
                    "{case_id} sign reproduction"
                );
                completed += 1;
            } else {
                let error = codec
                    .verify(kind, &raw, &resolver)
                    .expect_err("negative vector should fail");
                assert_eq!(
                    error.diagnostic().stage(),
                    verification_stage(expected["stage"].as_str().expect("expected stage")),
                    "{case_id}: {}",
                    error.diagnostic().reason()
                );
                assert_eq!(
                    error.wire_code(),
                    wire_code(expected["wireCode"].as_str().expect("expected wire code")),
                    "{case_id}: {}",
                    error.diagnostic().reason()
                );
                assert_eq!(
                    error.to_string(),
                    expected["wireCode"].as_str().expect("expected wire code"),
                    "{case_id} display must remain non-oracular"
                );
                rejected += 1;
            }
        }
    }

    assert_eq!(
        (cases.len(), evaluations, completed, rejected),
        (22, 58, 12, 46)
    );
}

fn read_json(relative: &str) -> Value {
    parse_strict_json(&read_bytes(relative)).expect("strict fixture JSON")
}

fn read_bytes(relative: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    fs::read(path).expect("fixture bytes")
}

fn fixture_signing_key(fixture: &Value) -> FixtureSigningKey {
    let seed: [u8; 32] = URL_SAFE_NO_PAD
        .decode(fixture["seed"].as_str().expect("seed string"))
        .expect("base64url seed")
        .try_into()
        .expect("32-byte seed");
    FixtureSigningKey {
        key_id: fixture["keyId"].as_str().expect("key ID").to_owned(),
        signer: Ed25519Signer::from_seed(seed),
    }
}

fn signed_kind(profile_id: &str) -> SignedDocumentKind {
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
        _ => panic!("unknown profile ID: {profile_id}"),
    }
}

fn principal_kind(value: &str) -> PrincipalKind {
    match value {
        "agent" => PrincipalKind::Agent,
        "human" => PrincipalKind::Human,
        "service" => PrincipalKind::Service,
        _ => panic!("unknown Principal type: {value}"),
    }
}

fn verification_stage(value: &str) -> VerificationStage {
    match value {
        "parse" => VerificationStage::Parse,
        "schema" => VerificationStage::Schema,
        "signature-envelope" => VerificationStage::SignatureEnvelope,
        "key-resolution" => VerificationStage::KeyResolution,
        "canonicalization" => VerificationStage::Canonicalization,
        "signature" => VerificationStage::Signature,
        _ => panic!("unknown verification stage: {value}"),
    }
}

fn wire_code(value: &str) -> WireErrorCode {
    match value {
        "PROTOCOL_VIOLATION" => WireErrorCode::ProtocolViolation,
        "SCHEMA_VALIDATION_FAILED" => WireErrorCode::SchemaValidationFailed,
        "AUTH_INVALID_SIGNATURE" => WireErrorCode::AuthInvalidSignature,
        _ => panic!("unknown wire code: {value}"),
    }
}
