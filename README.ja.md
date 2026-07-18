[English](README.md) | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md) |
**日本語** | [Español](README.es.md) | [Français](README.fr.md) |
[Deutsch](README.de.md)

# MissionWeaveProtocol Rust SDK

[MissionWeaveProtocol](https://github.com/missionweaveprotocol/missionweaveprotocol)
公式の Rust プロトコル SDK です。厳密な JSON 解析、正確に固定された
プロトコルバンドル、
オフラインの Draft 2020-12 検証、完全な Schema 適合性ランナー、RFC 8785 正規 JSON、
SHA-256 コンテンツ ID、Ed25519 ヘルパー、Schema を検証する FrameCodec を提供します。

> 現在のリリースが示すのは **Schema とベクトルへの適合**です。Python
> リファレンス実装の正本として機能する Core、Worker ランタイム、
> スケジューラー、ストレージ、
> WebSocket クライアントの動作を実装したとはまだ表明しません。

- 公式サイト：<https://missionweaveprotocol.github.io/>
- プロトコル：<https://github.com/missionweaveprotocol/missionweaveprotocol>
- リポジトリ：<https://github.com/missionweaveprotocol/rust-sdk>
- ライセンス：Apache-2.0

## 互換性

| Rust SDK | MissionWeaveProtocol |
| --- | --- |
| `0.1.x` | `0.1` |

[`PROTOCOL_PIN.json`](PROTOCOL_PIN.json) は SDK をプロトコル commit
`6f10987627d62fb296e3490ceceb5539b1e94b70`、21 個の Schema、52 個の適合性ベクトルに
固定します。SDK とプロトコルは個別にバージョン管理されます。

## 利用

crates.io 公開前はリポジトリを直接参照できます。

```toml
[dependencies]
missionweaveprotocol = { git = "https://github.com/missionweaveprotocol/rust-sdk", branch = "main" }
```

WebSocket フレームを検証し、正規形式でエンコードします。

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

## Schema 適合性の実行

```bash
cargo run --locked --bin missionweaveprotocol-conformance
```

期待される結果：

```text
52/52 conformance vectors passed
```

52 個のベクトルが証明するのは構造的な Schema の動作だけです。
完全なプロトコル適合には、規範的な状態機械、権限検査、fencing、予算、順序付け、
リプレイ、配信の復旧、人による Approval の規則も必要です。

## 公開 API

- `ProtocolBundle`：埋め込みの固定情報、Schema とベクトルのリソース、バイト単位で正確な
  ダイジェスト検証。
- `parse_strict_json`：重複メンバーと末尾データを拒否する UTF-8 解析。
- `SchemaCatalog`：format アサーションを有効にしたオフライン Draft 2020-12 `$id` レジストリ。
- `ConformanceRunner`：25 個の有効なベクトルと 27 個の無効なベクトルすべて。
- `canonical_bytes` / `canonical_sha256`：RFC 8785 と `sha256:` コンテンツ ID。
- `Ed25519Signer`：生の署名とトップレベルの `signature` 省略規則。
- `FrameCodec`：規範的なフレーム Schema に対する厳密なデコードと正規エンコード。

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

crate には固定された Schema と適合性ベクトルが含まれるため、検証と CLI は実行時
でネットワークアクセスを必要としません。

## セキュリティ

脆弱性は、このリポジトリの GitHub Security Advisories を通じて非公開で報告してください。
本番環境の認証情報、秘密鍵、機密性の高い Mission データを公開 issue に含めないで
ください。
