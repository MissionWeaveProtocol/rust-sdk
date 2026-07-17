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
`00964ea9064cbf1f0eca8af21a0c57367ee14752`、21 个 schema 和 43 个 conformance vector。
SDK 与协议独立版本化。

## 使用

在发布到 crates.io 之前，可直接依赖仓库：

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

公开接口包括：

- `ProtocolBundle`：嵌入的 pin、schema/vector 资源与逐字节 digest 校验；
- `parse_strict_json`：拒绝重复成员和尾随数据的 UTF-8 JSON 解析；
- `SchemaCatalog`：启用 format assertion 的离线 Draft 2020-12 `$id` registry；
- `ConformanceRunner`：22 个 valid 与 21 个 invalid 规范 vector；
- `canonical_bytes`、`canonical_sha256` 与 `Ed25519Signer`；
- `FrameCodec`：规范 frame schema 之上的严格 decode 与 canonical encode。

## 一致性与开发

```bash
cargo run --locked --bin missionweaveprotocol-conformance
```

预期输出为 `43/43 conformance vectors passed`。这些 vector 只证明结构化 schema 行为；
完整协议一致性还要求状态机、权限、fencing、预算、排序、replay、恢复和人类批准规则。

```bash
node scripts/check-repository-policy.mjs
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo package --locked
```

需要 Rust 1.85 或更高版本。schema 与 vector 已打包，因此运行时离线可用。
