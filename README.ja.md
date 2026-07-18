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
`6f10987627d62fb296e3490ceceb5539b1e94b70`、21 schema、52 vector に SDK を固定します。
SDK とプロトコルは別々に versioning されます。

## 利用

crates.io 公開前はリポジトリを直接参照できます。

```toml
[dependencies]
missionweaveprotocol = { git = "https://github.com/missionweaveprotocol/rust-sdk", branch = "main" }
```

WebSocket frame を検証し、正規形式でエンコードします。

```rust
use missionweaveprotocol::FrameCodec;

let codec = FrameCodec::new()?;
let frame = codec.decode(input.as_bytes())?;
let canonical = codec.encode(&frame)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

別の永続ドキュメントを検証します。

```rust
use missionweaveprotocol::{SchemaCatalog, parse_strict_json};

let catalog = SchemaCatalog::new()?;
let mission = parse_strict_json(mission_bytes)?;
catalog.validate("mission.schema.json", &mission)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Ed25519 プロトコル署名を作成し、検証します。

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

## Schema conformance の実行

```bash
cargo run --locked --bin missionweaveprotocol-conformance
```

期待される結果：

```text
52/52 conformance vectors passed
```

52 個の vector が証明するのは構造的な Schema の動作だけです。完全なプロトコル適合には、
規範的な state machine、authority check、fencing、budget、ordering、replay、delivery
recovery、人間による Approval も必要です。

## 公開 API

- `ProtocolBundle`：埋め込み pin、Schema/vector リソース、バイト単位で正確な digest 検証。
- `parse_strict_json`：重複 member と trailing data を拒否する UTF-8 解析。
- `SchemaCatalog`：format assertion を有効にしたオフライン Draft 2020-12 `$id` registry。
- `ConformanceRunner`：25 個の valid vector と 27 個の invalid vector すべて。
- `canonical_bytes` / `canonical_sha256`：RFC 8785 と `sha256:` content ID。
- `Ed25519Signer`：raw signature と top-level の `signature` 省略規則。
- `FrameCodec`：規範的な frame Schema に対する strict decode と canonical encode。

## 開発と検証

Rust 1.85 以降が必要です。

```bash
node scripts/check-repository-policy.mjs
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo run --locked --quiet --bin missionweaveprotocol-conformance
cargo package --locked
```

crate には固定された Schema と conformance vector が含まれるため、検証と CLI は runtime
でネットワークアクセスを必要としません。

## セキュリティ

脆弱性は、このリポジトリの GitHub Security Advisories を通じて非公開で報告してください。
本番環境の認証情報、秘密鍵、機密性の高い Mission data を公開 issue に含めないでください。
