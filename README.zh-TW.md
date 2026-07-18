[English](README.md) | [简体中文](README.zh-CN.md) | **繁體中文** |
[日本語](README.ja.md) | [Español](README.es.md) | [Français](README.fr.md) |
[Deutsch](README.de.md)

# MissionWeaveProtocol Rust SDK

這是 [MissionWeaveProtocol](https://github.com/missionweaveprotocol/missionweaveprotocol)
的官方 Rust 協定 SDK。它提供嚴格 JSON 解析、精確固定的協定套件、離線 Draft 2020-12
驗證、完整 schema conformance runner、RFC 8785 canonical JSON、SHA-256 內容 ID、
Ed25519 工具，以及 schema-validating FrameCodec。

> 目前版本證明的是 **schema-and-vector conformance**。它尚未宣稱實作 Python
> 參考實作中的權威 Core、Worker runtime、Scheduler、儲存或 WebSocket client 行為。

- 官方網站：<https://missionweaveprotocol.github.io/>
- 協定：<https://github.com/missionweaveprotocol/missionweaveprotocol>
- 儲存庫：<https://github.com/missionweaveprotocol/rust-sdk>
- 授權條款：Apache-2.0

## 相容性

| Rust SDK | MissionWeaveProtocol |
| --- | --- |
| `0.1.x` | `0.1` |

[`PROTOCOL_PIN.json`](PROTOCOL_PIN.json) 將本 SDK 固定到協定 commit
`6f10987627d62fb296e3490ceceb5539b1e94b70`、21 個 schema 與 52 個 conformance vector。
SDK 與協定分別進行版本管理。

## 使用方式

發布至 crates.io 前，可直接依賴儲存庫：

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

公開介面包括：

- `ProtocolBundle`：內嵌 pin、schema/vector 資源與逐位元組 digest 驗證；
- `parse_strict_json`：拒絕重複成員與尾隨資料的 UTF-8 JSON 解析；
- `SchemaCatalog`：啟用 format assertion 的離線 Draft 2020-12 `$id` registry；
- `ConformanceRunner`：25 個 valid 與 27 個 invalid 規範 vector；
- `canonical_bytes`、`canonical_sha256` 與 `Ed25519Signer`；
- `FrameCodec`：規範 frame schema 之上的嚴格 decode 與 canonical encode。

## 一致性與開發

```bash
cargo run --locked --bin missionweaveprotocol-conformance
```

預期輸出為 `52/52 conformance vectors passed`。這些 vector 僅證明結構化 schema 行為；
完整協定一致性還需要狀態機、權限、fencing、預算、排序、replay、復原與人類核准規則。

```bash
node scripts/check-repository-policy.mjs
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo package --locked
```

需要 Rust 1.85 或更新版本。schema 與 vector 已封裝，因此可在執行階段離線使用。
