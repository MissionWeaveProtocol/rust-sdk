[English](README.md) | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md) |
[日本語](README.ja.md) | [Español](README.es.md) | **Français** |
[Deutsch](README.de.md)

# MissionWeaveProtocol Rust SDK

SDK de protocole Rust officiel pour
[MissionWeaveProtocol](https://github.com/missionweaveprotocol/missionweaveprotocol).
Il fournit une analyse JSON stricte, le bundle de protocole épinglé exactement, la validation
Draft 2020-12 hors ligne, le runner complet de conformité des schemas, le JSON canonique RFC 8785,
les identifiants SHA-256, les outils Ed25519 et un FrameCodec validant les schemas.

> La version actuelle démontre la **schema-and-vector conformance**. Elle ne prétend pas encore
> implémenter le Core autoritatif, le runtime Worker, le Scheduler, le stockage ou le client
> WebSocket de l’implémentation de référence Python.

- Site officiel : <https://missionweaveprotocol.github.io/>
- Protocole : <https://github.com/missionweaveprotocol/missionweaveprotocol>
- Dépôt : <https://github.com/missionweaveprotocol/rust-sdk>
- Licence : Apache-2.0

## Compatibilité

| Rust SDK | MissionWeaveProtocol |
| --- | --- |
| `0.1.x` | `0.1` |

[`PROTOCOL_PIN.json`](PROTOCOL_PIN.json) lie le SDK au commit
`00964ea9064cbf1f0eca8af21a0c57367ee14752`, aux 21 schemas et aux 43 vecteurs de conformité. Les
versions du SDK et du protocole sont indépendantes.

## Utilisation

Avant une publication sur crates.io, référencez directement le dépôt :

```toml
[dependencies]
missionweaveprotocol = { git = "https://github.com/missionweaveprotocol/rust-sdk", branch = "main" }
```

```rust
use missionweaveprotocol::FrameCodec;

let codec = FrameCodec::new()?;
let frame = codec.decode(input.as_bytes())?;
let canonical = codec.encode(&frame)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

L’interface publique comprend `ProtocolBundle`, `parse_strict_json`, `SchemaCatalog`,
`ConformanceRunner`, `canonical_bytes`, `canonical_sha256`, `Ed25519Signer` et `FrameCodec`.

## Conformité et développement

```bash
cargo run --locked --bin missionweaveprotocol-conformance
```

Le résultat attendu est `43/43 conformance vectors passed`. La conformité complète exige aussi
les machines d’état, l’autorité, le fencing, les budgets, l’ordre, le replay, la reprise et
l’Approval humaine.

```bash
node scripts/check-repository-policy.mjs
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo package --locked
```

Rust 1.85 ou ultérieur est requis. Les schemas et vecteurs sont embarqués pour un usage hors ligne.
