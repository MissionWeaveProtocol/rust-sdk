[English](README.md) | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md) |
[日本語](README.ja.md) | [Español](README.es.md) | [Français](README.fr.md) |
**Deutsch**

# MissionWeaveProtocol Rust SDK

Offizielles Rust-Protokoll-SDK für
[MissionWeaveProtocol](https://github.com/missionweaveprotocol/missionweaveprotocol).
Es bietet striktes JSON-Parsing, das exakt gepinnte Protokoll-Bundle, Offline-Validierung nach
Draft 2020-12, den vollständigen Schema-Konformitätsrunner, kanonisches JSON nach RFC 8785,
SHA-256-Inhalts-IDs, Ed25519-Helfer und einen schema-validierenden FrameCodec.

> Die aktuelle Version weist **schema-and-vector conformance** nach. Sie beansprucht noch nicht,
> den autoritativen Core, die Worker Runtime, den Scheduler, Storage oder den WebSocket Client der
> Python-Referenzimplementierung umzusetzen.

- Website: <https://missionweaveprotocol.github.io/>
- Protokoll: <https://github.com/missionweaveprotocol/missionweaveprotocol>
- Repository: <https://github.com/missionweaveprotocol/rust-sdk>
- Lizenz: Apache-2.0

## Kompatibilität

| Rust SDK | MissionWeaveProtocol |
| --- | --- |
| `0.1.x` | `0.1` |

[`PROTOCOL_PIN.json`](PROTOCOL_PIN.json) bindet das SDK an Commit
`00964ea9064cbf1f0eca8af21a0c57367ee14752`, 21 Schemas und 43 Konformitätsvektoren. SDK und
Protokoll werden unabhängig versioniert.

## Verwendung

Vor einer Veröffentlichung auf crates.io kann das Repository direkt verwendet werden:

```toml
[dependencies]
missionweaveprotocol = { git = "https://github.com/missionweaveprotocol/rust-sdk", tag = "v0.1.0" }
```

```rust
use missionweaveprotocol::FrameCodec;

let codec = FrameCodec::new()?;
let frame = codec.decode(input.as_bytes())?;
let canonical = codec.encode(&frame)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Die öffentliche API umfasst `ProtocolBundle`, `parse_strict_json`, `SchemaCatalog`,
`ConformanceRunner`, `canonical_bytes`, `canonical_sha256`, `Ed25519Signer` und `FrameCodec`.

## Konformität und Entwicklung

```bash
cargo run --locked --bin missionweaveprotocol-conformance
```

Das erwartete Ergebnis ist `43/43 conformance vectors passed`. Vollständige Konformität erfordert
zusätzlich Zustandsautomaten, Autorität, Fencing, Budgets, Reihenfolge, Replay, Wiederherstellung
und menschliche Approval.

```bash
node scripts/check-repository-policy.mjs
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo package --locked
```

Rust 1.85 oder neuer ist erforderlich. Schemas und Vektoren sind für Offline-Nutzung eingebettet.
