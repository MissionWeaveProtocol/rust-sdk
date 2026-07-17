[English](README.md) | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md) |
[日本語](README.ja.md) | **Español** | [Français](README.fr.md) |
[Deutsch](README.de.md)

# MissionWeaveProtocol Rust SDK

SDK oficial de protocolo en Rust para
[MissionWeaveProtocol](https://github.com/missionweaveprotocol/missionweaveprotocol).
Incluye análisis JSON estricto, el bundle de protocolo fijado exactamente, validación Draft
2020-12 sin red, el runner completo de conformidad de schemas, JSON canónico RFC 8785,
identificadores SHA-256, utilidades Ed25519 y un FrameCodec con validación de schema.

> La versión actual demuestra **schema-and-vector conformance**. Todavía no afirma implementar el
> Core autoritativo, el runtime de Worker, el Scheduler, el almacenamiento ni el cliente WebSocket
> de la implementación de referencia en Python.

- Sitio web: <https://missionweaveprotocol.github.io/>
- Protocolo: <https://github.com/missionweaveprotocol/missionweaveprotocol>
- Repositorio: <https://github.com/missionweaveprotocol/rust-sdk>
- Licencia: Apache-2.0

## Compatibilidad

| Rust SDK | MissionWeaveProtocol |
| --- | --- |
| `0.1.x` | `0.1` |

[`PROTOCOL_PIN.json`](PROTOCOL_PIN.json) fija el SDK al commit
`00964ea9064cbf1f0eca8af21a0c57367ee14752`, 21 schemas y 43 vectores de conformidad. Las
versiones del SDK y del protocolo son independientes.

## Uso

Antes de una publicación en crates.io, usa el repositorio directamente:

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

La superficie pública incluye `ProtocolBundle`, `parse_strict_json`, `SchemaCatalog`,
`ConformanceRunner`, `canonical_bytes`, `canonical_sha256`, `Ed25519Signer` y `FrameCodec`.

## Conformidad y desarrollo

```bash
cargo run --locked --bin missionweaveprotocol-conformance
```

El resultado esperado es `43/43 conformance vectors passed`. La conformidad completa también
requiere máquinas de estado, autoridad, fencing, presupuestos, orden, replay, recuperación y
Approval humana.

```bash
node scripts/check-repository-policy.mjs
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo package --locked
```

Requiere Rust 1.85 o posterior. Los schemas y vectores están incluidos para uso offline.
