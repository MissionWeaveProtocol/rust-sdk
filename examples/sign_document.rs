//! Sign one in-memory protocol document and verify the result.

use missionweaveprotocol::Ed25519Signer;
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signer = Ed25519Signer::from_seed([7_u8; 32]);
    let document = json!({
        "protocolVersion": "0.1",
        "frameType": "PING",
        "frameId": "urn:missionweaveprotocol:frame:example",
        "sentAt": "2026-07-17T00:00:00Z"
    });
    let signed_document = signer.sign_document(
        &document,
        "urn:missionweaveprotocol:key:example",
        "2026-07-17T00:00:00Z",
    )?;
    Ed25519Signer::verify_document(&signed_document, signer.verifying_key_bytes())?;
    println!("{}", serde_json::to_string_pretty(&signed_document)?);
    Ok(())
}
