[English](README.md) | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md) |
**日本語** | [Español](README.es.md) | [Français](README.fr.md) |
[Deutsch](README.de.md)

# MissionWeaveProtocol Rust SDK

[MissionWeaveProtocol](https://github.com/missionweaveprotocol/missionweaveprotocol)
公式の Rust プロトコル SDK です。strict JSON 解析、正確に pin されたプロトコル bundle、
オフライン Draft 2020-12 検証、完全な schema conformance runner、RFC 8785 canonical
JSON、SHA-256 content ID、Ed25519 ヘルパー、schema-validating FrameCodec を提供します。

> 現在のリリースが示すのは **schema-and-vector conformance** です。Python
> リファレンス実装の authoritative Core、Worker runtime、Scheduler、storage、
> WebSocket client の動作を実装したとはまだ表明しません。

- 公式サイト：<https://missionweaveprotocol.github.io/>
- プロトコル：<https://github.com/missionweaveprotocol/missionweaveprotocol>
- リポジトリ：<https://github.com/missionweaveprotocol/rust-sdk>
- ライセンス：Apache-2.0

## 互換性

| Rust SDK | MissionWeaveProtocol |
| --- | --- |
| `0.1.x` | `0.1` |

[`PROTOCOL_PIN.json`](PROTOCOL_PIN.json) は protocol commit
`00964ea9064cbf1f0eca8af21a0c57367ee14752`、21 schema、43 vector に SDK を固定します。
SDK とプロトコルは別々に versioning されます。

## 利用

crates.io 公開前はリポジトリを直接参照できます。

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

主な公開 API は `ProtocolBundle`、`parse_strict_json`、`SchemaCatalog`、
`ConformanceRunner`、`canonical_bytes`、`canonical_sha256`、`Ed25519Signer`、
`FrameCodec` です。

## Conformance と開発

```bash
cargo run --locked --bin missionweaveprotocol-conformance
```

期待される結果は `43/43 conformance vectors passed` です。完全なプロトコル適合には、
state machine、authority、fencing、budget、ordering、replay、recovery、人間の Approval
も必要です。

```bash
node scripts/check-repository-policy.mjs
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo package --locked
```

Rust 1.85 以降が必要です。schema と vector は crate に含まれ、runtime ではオフラインです。
