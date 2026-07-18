[English](README.md) | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md) |
[日本語](README.ja.md) | [Español](README.es.md) | [Français](README.fr.md) |
**Deutsch**

# MissionWeaveProtocol Rust SDK

Offizielles Rust-Protokoll-SDK für
[MissionWeaveProtocol](https://github.com/missionweaveprotocol/missionweaveprotocol).
Es bietet striktes JSON-Parsing, das exakt gepinnte Protokoll-Bundle, Offline-Validierung nach
Draft 2020-12, den vollständigen Schema-Konformitätsrunner, kanonisches JSON nach RFC 8785,
SHA-256-Inhalts-IDs, Ed25519-Helfer und einen schema-validierenden FrameCodec.

> Die aktuelle Version weist ausschließlich **Schema- und Vektorkonformität** nach. Sie beansprucht
> noch nicht, den autoritativen Core, die Worker Runtime, den Scheduler, Storage oder den WebSocket
> Client der Python-Referenzimplementierung umzusetzen.

- Website: <https://missionweaveprotocol.github.io/>
- Protokoll: <https://github.com/missionweaveprotocol/missionweaveprotocol>
- Repository: <https://github.com/missionweaveprotocol/rust-sdk>
- Lizenz: Apache-2.0

## Kompatibilität

| Rust SDK | MissionWeaveProtocol |
| --- | --- |
| `0.1.x` | `0.1` |

[`PROTOCOL_PIN.json`](PROTOCOL_PIN.json) bindet das SDK an Commit
`6f10987627d62fb296e3490ceceb5539b1e94b70`, 21 Schemas und 52 Konformitätsvektoren. SDK und
Protokoll werden unabhängig versioniert.

## Verwendung

Vor einer Veröffentlichung auf crates.io kann das Repository direkt verwendet werden:

```toml
[dependencies]
missionweaveprotocol = { git = "https://github.com/missionweaveprotocol/rust-sdk", branch = "main" }
```

Einen WebSocket-Frame validieren und kanonisch kodieren:

```rust
use missionweaveprotocol::FrameCodec;

let codec = FrameCodec::new()?;
let frame = codec.decode(input.as_bytes())?;
let canonical = codec.encode(&frame)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Ein weiteres dauerhaftes Dokument validieren:

```rust
use missionweaveprotocol::{SchemaCatalog, parse_strict_json};

let catalog = SchemaCatalog::new()?;
let mission = parse_strict_json(mission_bytes)?;
catalog.validate("mission.schema.json", &mission)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Eine Ed25519-Protokollsignatur erstellen und prüfen:

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

## Schemakonformität ausführen

```bash
cargo run --locked --bin missionweaveprotocol-conformance
```

Erwartetes Ergebnis:

```text
52/52 conformance vectors passed
```

Die 52 Vektoren belegen nur das strukturelle Schemaverhalten. Vollständige Protokollkonformität
erfordert außerdem die normativen Zustandsautomaten, Autoritätsprüfungen, Fencing, Budgets,
Reihenfolge, Replay, Wiederherstellung der Zustellung und Regeln für menschliche Freigaben.

## Öffentliche API

- `ProtocolBundle`: eingebetteter Pin, Schema-/Vektorressourcen und bytegenaue Digest-Prüfung.
- `parse_strict_json`: UTF-8-Parsing, das doppelte Member und nachgestellte Daten ablehnt.
- `SchemaCatalog`: Offline-Draft-2020-12-`$id`-Registry mit Formatprüfungen.
- `ConformanceRunner`: alle 25 gültigen und 27 ungültigen kanonischen Vektoren.
- `canonical_bytes` / `canonical_sha256`: RFC 8785 und `sha256:`-Inhalts-IDs.
- `Ed25519Signer`: Rohsignaturen und Regeln zum Auslassen des obersten `signature`-Members.
- `FrameCodec`: striktes Dekodieren und kanonisches Kodieren anhand des normativen Frame-Schemas.

## Entwickeln und prüfen

Rust 1.85 oder neuer ist erforderlich.

```bash
node scripts/check-repository-policy.mjs
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo run --locked --quiet --bin missionweaveprotocol-conformance
cargo package --locked
```

Das Crate enthält die festgelegten Schemas und Konformitätsvektoren, sodass Validierung und CLI zur
Laufzeit ohne Netzwerkzugriff funktionieren.

## Sicherheit

Melde Schwachstellen vertraulich über GitHub Security Advisories für dieses Repository.
Veröffentliche keine Produktionszugangsdaten, privaten Schlüssel oder sensiblen Mission-Daten in
öffentlichen Issues.
