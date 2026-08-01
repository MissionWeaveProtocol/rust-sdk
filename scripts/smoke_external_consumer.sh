#!/usr/bin/env bash
set -euo pipefail

package_input="${1:-.}"
package_dir="$(cd "${package_input}" && pwd -P)"
consumer_dir="$(mktemp -d "${TMPDIR:-/tmp}/missionweaveprotocol-rust-consumer.XXXXXX")"
consumer_target="$(mktemp -d "${TMPDIR:-/tmp}/missionweaveprotocol-rust-consumer-target.XXXXXX")"

cleanup() {
  rm -rf -- "${consumer_dir}" "${consumer_target}"
}
trap cleanup EXIT

mkdir -p "${consumer_dir}/src"

cat >"${consumer_dir}/Cargo.toml" <<EOF
[package]
name = "missionweaveprotocol-external-consumer"
version = "0.0.0"
edition = "2024"
rust-version = "1.85"
publish = false

[dependencies]
missionweaveprotocol = { path = "${package_dir}" }
EOF

cat >"${consumer_dir}/src/main.rs" <<'EOF'
use missionweaveprotocol::{
    AdapterError, AdmissionAdapterError, AdmissionContextValue, AdmissionCurrentKeyResolver,
    AdmissionLog, AdmissionLookup, AdmissionService, AuthenticatedAdmissionRecord,
    KeyRegistrySnapshot, KeyResolutionRequest, ProtocolBundle, SignedDocumentKind,
    TrustedAdmissionContext,
};

const SERVICE_ID: &str = "urn:missionweaveprotocol:service:admission";

struct CurrentRegistry(Vec<u8>);

impl AdmissionCurrentKeyResolver for CurrentRegistry {
    fn resolve_current(
        &self,
        _request: &KeyResolutionRequest,
    ) -> Result<KeyRegistrySnapshot, AdapterError> {
        Ok(KeyRegistrySnapshot::organization_wide(self.0.clone()))
    }
}

struct FixedContext;

impl TrustedAdmissionContext for FixedContext {
    fn issue(
        &self,
        _organization_id: &str,
        _signing_hash: &str,
    ) -> Result<AdmissionContextValue, AdmissionAdapterError> {
        Ok(AdmissionContextValue::new(
            "urn:missionweaveprotocol:admission-record:crypto-vector-command",
            "2026-07-15T00:05:00Z",
            SERVICE_ID,
        ))
    }
}

struct CommitLog(Vec<u8>);

impl AdmissionLog for CommitLog {
    fn lookup(
        &self,
        _organization_id: &str,
        _signing_hash: &str,
    ) -> Result<AdmissionLookup, AdmissionAdapterError> {
        Ok(AdmissionLookup::AuthoritativeAbsence)
    }

    fn append_or_return_existing(
        &self,
        _organization_id: &str,
        _signing_hash: &str,
        _candidate_bytes: &[u8],
    ) -> Result<AuthenticatedAdmissionRecord, AdmissionAdapterError> {
        Ok(AuthenticatedAdmissionRecord::new(
            self.0.clone(),
            SERVICE_ID,
        ))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bundle = ProtocolBundle::verify()?;
    let cryptography = ProtocolBundle::verify_cryptography()?;
    let admission = ProtocolBundle::verify_admission()?;
    assert_eq!((bundle.schema_files, bundle.conformance_files), (22, 59));
    assert_eq!(
        (
            cryptography.artifact_count,
            cryptography.case_count,
            cryptography.evaluation_count,
        ),
        (98, 22, 62)
    );
    assert_eq!(
        (
            admission.artifact_count,
            admission.case_count,
            admission.evaluation_count,
        ),
        (19, 5, 30)
    );

    let document = ProtocolBundle::cryptography(
        "vectors/signed-documents/valid/command.json",
    )
    .ok_or("packaged Command fixture is missing")?;
    let registry = ProtocolBundle::cryptography("keys/registry-valid.json")
        .ok_or("packaged Registry fixture is missing")?;
    let committed = ProtocolBundle::admission("records/valid/command.json")
        .ok_or("packaged Admission record is missing")?;
    let admitted = AdmissionService::new()?.admit_first(
        SignedDocumentKind::Command,
        document,
        &CurrentRegistry(registry.to_vec()),
        &CommitLog(committed.to_vec()),
        &FixedContext,
    )?;
    assert_eq!(
        admitted.record().signing_hash(),
        admitted.verified().signing_hash()
    );
    assert_eq!(admitted.record().bytes(), committed);
    println!("external Rust consumer verified protocol, cryptography, and Admission bundles");
    Ok(())
}
EOF

(
  cd "${consumer_dir}"
  CARGO_TARGET_DIR="${consumer_target}" cargo generate-lockfile
  CARGO_TARGET_DIR="${consumer_target}" cargo run --locked --quiet
)
