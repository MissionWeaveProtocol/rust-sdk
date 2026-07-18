[English](README.md) | [简体中文](README.zh-CN.md) | **繁體中文** |
[日本語](README.ja.md) | [Español](README.es.md) | [Français](README.fr.md) |
[Deutsch](README.de.md)

# MissionWeaveProtocol Rust SDK

這是 [MissionWeaveProtocol](https://github.com/missionweaveprotocol/missionweaveprotocol)
的官方 Rust 協定 SDK。它提供嚴格 JSON 解析、精確固定的協定套件、離線 Draft 2020-12
驗證、完整的 Schema 符合性執行器、RFC 8785 正規 JSON、SHA-256 內容識別碼、
Ed25519 工具，以及執行 Schema 驗證的 FrameCodec。

> 目前版本證明的是 **Schema 與測試向量符合性**。它尚未宣稱實作 Python
> 參考實作中的權威 Core、Worker 執行階段、排程器、儲存或 WebSocket 用戶端行為。

- 官方網站：<https://missionweaveprotocol.github.io/>
- 協定：<https://github.com/missionweaveprotocol/missionweaveprotocol>
- 儲存庫：<https://github.com/missionweaveprotocol/rust-sdk>
- 授權條款：Apache-2.0

## 相容性

| Rust SDK | MissionWeaveProtocol |
| --- | --- |
| `0.1.x` | `0.1` |

[`PROTOCOL_PIN.json`](PROTOCOL_PIN.json) 將本 SDK 固定到協定 commit
`6f10987627d62fb296e3490ceceb5539b1e94b70`、21 個 Schema 與 52 個符合性向量。
SDK 與協定分別進行版本管理。

## 使用方式

發布至 crates.io 前，可直接依賴儲存庫：

```toml
[dependencies]
missionweaveprotocol = { git = "https://github.com/missionweaveprotocol/rust-sdk", branch = "main" }
```

驗證並規範編碼 WebSocket 訊框：

```rust
use missionweaveprotocol::FrameCodec;

let codec = FrameCodec::new()?;
let frame = codec.decode(input.as_bytes())?;
let canonical = codec.encode(&frame)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

驗證另一份持久化文件：

```rust
use missionweaveprotocol::{SchemaCatalog, parse_strict_json};

let catalog = SchemaCatalog::new()?;
let mission = parse_strict_json(mission_bytes)?;
catalog.validate("mission.schema.json", &mission)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

建立並驗證 Ed25519 協定簽章：

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

## 執行 Schema 符合性檢查

```bash
cargo run --locked --bin missionweaveprotocol-conformance
```

預期結果：

```text
52/52 conformance vectors passed
```

這 52 個向量僅證明結構化 Schema 行為。完整協定符合性還需要實作規範狀態機、權限檢查、
fencing、預算、排序、重播、交付復原與人工核准規則。

## 公開介面

- `ProtocolBundle`：內嵌的固定資訊、Schema/向量資源與逐位元組摘要驗證。
- `parse_strict_json`：拒絕重複成員與尾隨資料的 UTF-8 解析。
- `SchemaCatalog`：啟用格式斷言的離線 Draft 2020-12 `$id` 登錄。
- `ConformanceRunner`：全部 25 個有效與 27 個無效規範向量。
- `canonical_bytes` / `canonical_sha256`：RFC 8785 與 `sha256:` 內容識別碼。
- `Ed25519Signer`：原始簽章與頂層 `signature` 省略規則。
- `FrameCodec`：圍繞規範訊框 Schema 的嚴格解碼與規範編碼。

## 開發與驗證

需要 Rust 1.85 或更新版本。

```bash
node scripts/check-repository-policy.mjs
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo run --locked --quiet --bin missionweaveprotocol-conformance
cargo package --locked
```

`crate` 包含固定的 Schema 與符合性向量，因此驗證和 CLI 在執行階段不需要網路存取。

## 安全性

請透過本儲存庫的 GitHub Security Advisories 私下通報漏洞。請勿在公開 issue 中包含正式
環境憑證、私密金鑰或敏感 Mission 資料。
