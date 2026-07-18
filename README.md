**English** | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md) |
[日本語](README.ja.md) | [Español](README.es.md) | [Français](README.fr.md) |
[Deutsch](README.de.md)

# MissionWeaveProtocol Rust SDK

The official Rust protocol SDK for
[MissionWeaveProtocol](https://github.com/missionweaveprotocol/missionweaveprotocol).
It provides strict JSON parsing, the exact pinned protocol bundle, offline Draft 2020-12
validation, the complete schema conformance runner, RFC 8785 canonical JSON, SHA-256 content IDs,
Ed25519 helpers, the nine-profile `SignedDocumentCodec`, and a schema-validating frame codec.

> The current release demonstrates **schema and signed-document cryptography vector conformance**.
> It does not yet claim the
> authoritative Core, Worker runtime, Scheduler, storage, or WebSocket client behavior implemented
> by the Python reference implementation.

- Website: <https://missionweaveprotocol.github.io/>
- Protocol: <https://github.com/missionweaveprotocol/missionweaveprotocol>
- Repository: <https://github.com/missionweaveprotocol/rust-sdk>
- License: Apache-2.0

## Compatibility

| Rust SDK | MissionWeaveProtocol |
| --- | --- |
| `0.1.x` | `0.1` |

[`PROTOCOL_PIN.json`](PROTOCOL_PIN.json) binds this SDK to protocol commit
`6f10987627d62fb296e3490ceceb5539b1e94b70`, 21 schemas, and 52 conformance vectors. SDK and
protocol releases are versioned independently.

## Use the crate

Until a crates.io release is published, depend on the repository:

```toml
[dependencies]
missionweaveprotocol = { git = "https://github.com/missionweaveprotocol/rust-sdk", branch = "main" }
```

Validate and canonically encode a WebSocket frame:

```rust
use missionweaveprotocol::FrameCodec;

let codec = FrameCodec::new()?;
let frame = codec.decode(input.as_bytes())?;
let canonical = codec.encode(&frame)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Validate another durable document:

```rust
use missionweaveprotocol::{SchemaCatalog, parse_strict_json};

let catalog = SchemaCatalog::new()?;
let mission = parse_strict_json(mission_bytes)?;
catalog.validate("mission.schema.json", &mission)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Create and verify an Ed25519 protocol signature:

```rust
use missionweaveprotocol::Ed25519Signer;

let signer = Ed25519Signer::from_seed(seed);
let signed = signer.sign_document(
    &document,
    "urn:missionweaveprotocol:key:example",
    "2026-07-17T00:00:00Z",
)?;
Ed25519Signer::verify_document(&signed, signer.verifying_key_bytes())?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Sign and verify a schema-required durable document through the normative six-stage profile:

```rust
use missionweaveprotocol::{
    KeyRegistrySnapshot, KeyResolutionRequest, KeyResolver, SignedDocumentCodec,
    SignedDocumentKind,
};

impl KeyResolver for RegistryResolver {
    fn resolve(&self, request: &KeyResolutionRequest) -> Result<KeyRegistrySnapshot, AdapterError> {
        let complete_registry = self.load_complete_agent_registry(request)?;
        Ok(KeyRegistrySnapshot::organization_wide(complete_registry))
    }
}

let codec = SignedDocumentCodec::new()?;
let signed = codec.sign(SignedDocumentKind::Command, &unsigned_command, &signing_key)?;
let received = serde_json::to_vec(&signed)?;
match codec.verify(SignedDocumentKind::Command, &received, &registry_resolver) {
    Ok(verified) => println!("{}", verified.signing_hash()),
    Err(error) => {
        send_to_peer(error.wire_code()); // non-oracular
        audit_locally(error.diagnostic()); // protected stage and reason
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

The kind is always explicit; the codec never infers one of the nine profiles. `SigningKey` and
`KeyResolver` are the only application adapters. A resolver must return a snapshot explicitly
asserted as `OrganizationWide`; partial or unspecified evidence fails closed at key resolution.
The verified result immutably retains the parsed and received document, signing and complete JCS
bytes/hashes, exact and parsed protected time, signature material, and resolved Agent Registry evidence.
The First-Admission Record, freshness, and authorization remain separate checks. See the runnable
[`sign_document` example](examples/sign_document.rs).

## Run schema conformance

```bash
cargo run --locked --bin missionweaveprotocol-conformance
```

Expected result:

```text
52/52 conformance vectors passed
```

The 52 vectors prove structural schema behavior only. Full protocol conformance also requires the
normative state machines, authority checks, fencing, budgets, ordering, replay, delivery recovery,
and human approval rules.

## Public surface

- `ProtocolBundle`: embedded pin, schema/vector resources, and byte-exact digest verification.
- `parse_strict_json`: UTF-8 parsing that rejects duplicate members and trailing data.
- `SchemaCatalog`: offline Draft 2020-12 `$id` registry with format assertions.
- `ConformanceRunner`: all 25 valid and 27 invalid canonical vectors.
- `canonical_bytes` / `canonical_sha256`: RFC 8785 and `sha256:` content IDs.
- `Ed25519Signer`: raw signatures and top-level `signature` omission rules.
- `SignedDocumentCodec`: explicit nine-profile signing and six-stage verification with complete
  immutable evidence and non-oracular wire errors.
- `SigningKey` / `KeyResolver`: the only application adapters; key resolution requires an
  Organization-wide `KeyRegistrySnapshot`.
- `FrameCodec`: strict decode and canonical encode around the normative frame schema.

## Develop and verify

Rust 1.85 or newer is required.

```bash
node scripts/check-repository-policy.mjs
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo run --locked --quiet --bin missionweaveprotocol-conformance
cargo package --locked
```

The crate includes the pinned schemas and conformance vectors, so validation and the CLI work
without network access at runtime.

## Security

Report vulnerabilities privately through GitHub Security Advisories for this repository. Do not
include production credentials, private keys, or sensitive Mission data in public issues.
