//! Sign and verify one protocol-owned golden Command through `SignedDocumentCodec`.
//!
//! The embedded seed is test-only vector material. Never ship production private keys in an SDK
//! binary or source repository.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use missionweaveprotocol::{
    AdapterError, Ed25519Signer, KeyRegistrySnapshot, KeyResolutionRequest, KeyResolver,
    ProtocolBundle, SignedDocumentCodec, SignedDocumentKind, SigningKey, parse_strict_json,
};

struct ExampleSigningKey {
    key_id: String,
    signer: Ed25519Signer,
}

impl SigningKey for ExampleSigningKey {
    fn algorithm(&self) -> &'static str {
        "Ed25519"
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, AdapterError> {
        Ok(self.signer.sign_bytes(message).to_vec())
    }
}

struct ExampleKeyResolver {
    agent_registry: Vec<u8>,
}

impl KeyResolver for ExampleKeyResolver {
    fn resolve(&self, request: &KeyResolutionRequest) -> Result<KeyRegistrySnapshot, AdapterError> {
        eprintln!(
            "resolving {} at {}",
            request.key_id(),
            request.protected_time_text()
        );
        Ok(KeyRegistrySnapshot::organization_wide(
            self.agent_registry.clone(),
        ))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let expected = embedded_json("vectors/signed-documents/valid/command.json")?;
    let mut unsigned = expected.clone();
    unsigned
        .as_object_mut()
        .expect("golden Command is an object")
        .remove("signature");

    let signing_fixture = embedded_json("keys/signing-coordinator.json")?;
    let seed: [u8; 32] = URL_SAFE_NO_PAD
        .decode(
            signing_fixture["seed"]
                .as_str()
                .expect("fixture seed is a string"),
        )?
        .try_into()
        .map_err(|_| "fixture seed is not 32 bytes")?;
    let signing_key = ExampleSigningKey {
        key_id: signing_fixture["keyId"]
            .as_str()
            .expect("fixture keyId is a string")
            .to_owned(),
        signer: Ed25519Signer::from_seed(seed),
    };
    let resolver = ExampleKeyResolver {
        agent_registry: ProtocolBundle::cryptography("keys/registry-valid.json")
            .expect("embedded Registry fixture")
            .to_vec(),
    };

    let codec = SignedDocumentCodec::new()?;
    let signed = codec.sign(SignedDocumentKind::Command, &unsigned, &signing_key)?;
    let received = serde_json::to_vec(&signed)?;
    let verified = match codec.verify(SignedDocumentKind::Command, &received, &resolver) {
        Ok(verified) => verified,
        Err(error) => {
            // `Display` and `wire_code()` are non-oracular and safe for an untrusted peer.
            eprintln!("wire error: {error}");
            // The stage/reason are protected diagnostics for local audit and operations only.
            eprintln!(
                "protected diagnostic: {:?}: {}",
                error.diagnostic().stage(),
                error.diagnostic().reason()
            );
            return Err(Box::new(error));
        }
    };

    assert_eq!(verified.document(), &expected);
    println!("signing hash: {}", verified.signing_hash());
    println!(
        "complete document hash: {}",
        verified.complete_document_hash()
    );
    Ok(())
}

fn embedded_json(path: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let bytes = ProtocolBundle::cryptography(path).ok_or("missing embedded cryptography file")?;
    Ok(parse_strict_json(bytes)?)
}
