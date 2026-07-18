[English](README.md) | **简体中文** | [繁體中文](README.zh-TW.md) |
[日本語](README.ja.md) | [Español](README.es.md) | [Français](README.fr.md) |
[Deutsch](README.de.md)

# MissionWeaveProtocol Rust SDK

这是 [MissionWeaveProtocol](https://github.com/missionweaveprotocol/missionweaveprotocol)
的官方 Rust 协议 SDK。它提供严格 JSON 解析、精确固定的协议包、离线 Draft 2020-12
校验、完整 schema conformance runner、RFC 8785 规范化 JSON、SHA-256 内容 ID、
Ed25519 工具以及 schema-validating FrameCodec。

> 当前版本证明的是 **schema-and-vector conformance**。它尚未声明实现 Python
> 参考实现中的权威 Core、Worker runtime、Scheduler、存储或 WebSocket client 行为。

- 官网：<https://missionweaveprotocol.github.io/>
- 协议：<https://github.com/missionweaveprotocol/missionweaveprotocol>
- 仓库：<https://github.com/missionweaveprotocol/rust-sdk>
- 许可证：Apache-2.0

## 兼容性

| Rust SDK | MissionWeaveProtocol |
| --- | --- |
| `0.1.x` | `0.1` |

[`PROTOCOL_PIN.json`](PROTOCOL_PIN.json) 将本 SDK 固定到协议 commit
`6f10987627d62fb296e3490ceceb5539b1e94b70`、21 个 schema 和 52 个 conformance vector。
SDK 与协议独立版本化。

## 使用

在发布到 crates.io 之前，可直接依赖仓库：

```toml
[dependencies]
missionweaveprotocol = { git = "https://github.com/missionweaveprotocol/rust-sdk", branch = "main" }
```

验证并规范编码 WebSocket 帧：

```rust
use missionweaveprotocol::FrameCodec;

let codec = FrameCodec::new()?;
let frame = codec.decode(input.as_bytes())?;
let canonical = codec.encode(&frame)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

验证另一个持久化文档：

```rust
use missionweaveprotocol::{SchemaCatalog, parse_strict_json};

let catalog = SchemaCatalog::new()?;
let mission = parse_strict_json(mission_bytes)?;
catalog.validate("mission.schema.json", &mission)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

创建并验证 Ed25519 协议签名：

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

## 运行 Schema 符合性检查

```bash
cargo run --locked --bin missionweaveprotocol-conformance
```

预期结果：

```text
52/52 conformance vectors passed
```

这 52 个向量仅证明结构化 Schema 行为。完整协议符合性还要求实现规范状态机、权限检查、
fencing、预算、排序、replay、交付恢复和人工批准规则。

## 公共接口

- `ProtocolBundle`：内嵌的 pin、Schema/向量资源与逐字节摘要验证。
- `parse_strict_json`：拒绝重复成员和尾随数据的 UTF-8 解析。
- `SchemaCatalog`：启用格式断言的离线 Draft 2020-12 `$id` 注册表。
- `ConformanceRunner`：全部 25 个有效和 27 个无效规范向量。
- `canonical_bytes` / `canonical_sha256`：RFC 8785 与 `sha256:` 内容 ID。
- `Ed25519Signer`：原始签名和顶层 `signature` 省略规则。
- `FrameCodec`：围绕规范帧 Schema 的严格解码与规范编码。

## 开发与验证

需要 Rust 1.85 或更高版本。

```bash
node scripts/check-repository-policy.mjs
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo run --locked --quiet --bin missionweaveprotocol-conformance
cargo package --locked
```

crate 包含固定的 Schema 和符合性向量，因此验证和 CLI 在运行时无需网络访问。

## 安全

请通过本仓库的 GitHub Security Advisories 私下报告漏洞。请勿在公开 issue 中包含生产环境
凭据、私钥或敏感 Mission 数据。
