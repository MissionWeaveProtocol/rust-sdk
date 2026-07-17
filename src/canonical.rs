//! RFC 8785 canonical JSON, content hashes, and Ed25519 signatures.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Canonicalization or signature failure.
#[derive(Debug, Error)]
pub enum CanonicalError {
    /// RFC 8785 serialization failed.
    #[error("canonical JSON serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    /// A signed protocol document was not a JSON object.
    #[error("signed protocol document must be a JSON object")]
    NotObject,
    /// A signature object or one of its fields was absent or malformed.
    #[error("invalid signature object: {0}")]
    InvalidSignature(String),
    /// Signature verification failed.
    #[error("Ed25519 signature verification failed")]
    Verification,
}

/// Serialize a JSON value using RFC 8785 JSON Canonicalization Scheme.
///
/// # Errors
///
/// Returns [`CanonicalError`] when the value cannot be represented as canonical JSON.
pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>, CanonicalError> {
    Ok(serde_json_canonicalizer::to_vec(value)?)
}

/// Return a `sha256:` content identifier over RFC 8785 canonical bytes.
///
/// # Errors
///
/// Returns [`CanonicalError`] when canonicalization fails.
pub fn canonical_sha256(value: &Value) -> Result<String, CanonicalError> {
    let bytes = canonical_bytes(value)?;
    let digest = Sha256::digest(bytes);
    Ok(format!("sha256:{digest:x}"))
}

/// Clone a protocol document and omit its top-level `signature` member.
///
/// # Errors
///
/// Returns [`CanonicalError::NotObject`] for non-object documents.
pub fn signature_input(value: &Value) -> Result<Value, CanonicalError> {
    let mut unsigned = value.clone();
    unsigned
        .as_object_mut()
        .ok_or(CanonicalError::NotObject)?
        .remove("signature");
    Ok(unsigned)
}

/// Ed25519 signing key and protocol signature helpers.
pub struct Ed25519Signer {
    signing_key: SigningKey,
}

impl Ed25519Signer {
    /// Construct a signer from a 32-byte Ed25519 seed.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
        }
    }

    /// Return the raw 32-byte public key.
    #[must_use]
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Sign arbitrary bytes and return a raw 64-byte Ed25519 signature.
    #[must_use]
    pub fn sign_bytes(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }

    /// Verify one raw Ed25519 signature.
    #[must_use]
    pub fn verify_bytes(public_key: [u8; 32], message: &[u8], signature: [u8; 64]) -> bool {
        let Ok(verifying_key) = VerifyingKey::from_bytes(&public_key) else {
            return false;
        };
        verifying_key
            .verify(message, &Signature::from_bytes(&signature))
            .is_ok()
    }

    /// Sign a protocol document after omitting its top-level `signature` member.
    ///
    /// # Errors
    ///
    /// Returns [`CanonicalError`] for non-object documents or canonicalization failures.
    pub fn sign_document(
        &self,
        document: &Value,
        key_id: &str,
        created_at: &str,
    ) -> Result<Value, CanonicalError> {
        let unsigned = signature_input(document)?;
        let bytes = canonical_bytes(&unsigned)?;
        let signature = URL_SAFE_NO_PAD.encode(self.sign_bytes(&bytes));
        let mut signed = unsigned;
        signed
            .as_object_mut()
            .ok_or(CanonicalError::NotObject)?
            .insert(
                "signature".to_owned(),
                json!({
                    "algorithm": "Ed25519",
                    "keyId": key_id,
                    "createdAt": created_at,
                    "value": signature,
                }),
            );
        Ok(signed)
    }

    /// Verify a signed protocol document using a raw Ed25519 public key.
    ///
    /// # Errors
    ///
    /// Returns [`CanonicalError`] for malformed signature metadata, canonicalization errors, or an
    /// invalid signature.
    pub fn verify_document(document: &Value, public_key: [u8; 32]) -> Result<(), CanonicalError> {
        let signature = document
            .get("signature")
            .and_then(Value::as_object)
            .ok_or_else(|| CanonicalError::InvalidSignature("missing signature".to_owned()))?;
        if signature.get("algorithm").and_then(Value::as_str) != Some("Ed25519") {
            return Err(CanonicalError::InvalidSignature(
                "algorithm must be Ed25519".to_owned(),
            ));
        }
        let encoded = signature
            .get("value")
            .and_then(Value::as_str)
            .ok_or_else(|| CanonicalError::InvalidSignature("missing value".to_owned()))?;
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|error| CanonicalError::InvalidSignature(error.to_string()))?;
        let signature: [u8; 64] = bytes.try_into().map_err(|bytes: Vec<u8>| {
            CanonicalError::InvalidSignature(format!(
                "signature is {} bytes; expected 64",
                bytes.len()
            ))
        })?;
        let unsigned = signature_input(document)?;
        let message = canonical_bytes(&unsigned)?;
        if Self::verify_bytes(public_key, &message, signature) {
            Ok(())
        } else {
            Err(CanonicalError::Verification)
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{Ed25519Signer, canonical_bytes, canonical_sha256};

    fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
        assert_eq!(value.len(), N * 2);
        let mut output = [0_u8; N];
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).expect("hex");
        }
        output
    }

    #[test]
    fn matches_rfc_8785_serialization_example() {
        let value = json!({
            "numbers": [333_333_333.333_333_3_f64, 1E30_f64, 4.50_f64, 2e-3_f64, 1e-27_f64],
            "string": "€$\u{000f}\nA'B\"\\\"/",
            "literals": [null, true, false]
        });
        let canonical = canonical_bytes(&value).expect("canonical JSON");
        assert_eq!(
            String::from_utf8(canonical).expect("UTF-8"),
            "{\"literals\":[null,true,false],\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],\"string\":\"€$\\u000f\\nA'B\\\"\\\\\\\"/\"}"
        );
    }

    #[test]
    fn matches_rfc_8032_ed25519_vector_one() {
        let seed =
            decode_hex::<32>("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let public_key =
            decode_hex::<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let signature = decode_hex::<64>(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
                .replace([' ', '\n'], "")
                .as_str(),
        );
        let signer = Ed25519Signer::from_seed(seed);
        assert_eq!(signer.verifying_key_bytes(), public_key);
        assert_eq!(signer.sign_bytes(b""), signature);
        assert!(Ed25519Signer::verify_bytes(public_key, b"", signature));
    }

    #[test]
    fn signs_and_verifies_protocol_documents() {
        let signer = Ed25519Signer::from_seed([7_u8; 32]);
        let document = json!({
            "protocolVersion": "0.1",
            "frameType": "PING",
            "frameId": "urn:missionweaveprotocol:frame:test",
            "sentAt": "2026-07-17T00:00:00Z"
        });
        let signed_document = signer
            .sign_document(
                &document,
                "urn:missionweaveprotocol:key:test",
                "2026-07-17T00:00:00Z",
            )
            .expect("signed document");
        Ed25519Signer::verify_document(&signed_document, signer.verifying_key_bytes())
            .expect("valid signature");
        assert!(
            canonical_sha256(&document)
                .expect("hash")
                .starts_with("sha256:")
        );
    }
}
