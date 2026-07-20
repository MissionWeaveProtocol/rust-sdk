[English](README.md) | **简体中文** | [繁體中文](README.zh-TW.md) |
[日本語](README.ja.md) | [Español](README.es.md) | [Français](README.fr.md) |
[Deutsch](README.de.md)

# MissionWeaveProtocol Rust SDK

这是 [MissionWeaveProtocol](https://github.com/missionweaveprotocol/missionweaveprotocol)
的官方 Rust 协议 SDK。它提供严格 JSON 解析、精确固定的协议包、离线 Draft 2020-12
校验、完整的 Schema 符合性运行器、RFC 8785 规范化 JSON、SHA-256 内容标识符、
Ed25519 工具、覆盖九种 profile 的 `SignedDocumentCodec`，以及执行 Schema 验证的 FrameCodec。

> 当前版本证明的是 **Schema 与签名文档密码学测试向量符合性**。它尚未声明实现 Python
> 参考实现中的权威 Core、Worker 运行时、调度器、存储或 WebSocket 客户端行为。

- 官网：<https://missionweaveprotocol.github.io/>
- 协议：<https://github.com/missionweaveprotocol/missionweaveprotocol>
- 仓库：<https://github.com/missionweaveprotocol/rust-sdk>
- 许可证：Apache-2.0

## 兼容性

| Rust SDK | MissionWeaveProtocol |
| --- | --- |
| `0.1.x` | `0.1` |

[`PROTOCOL_PIN.json`](PROTOCOL_PIN.json) 将本 SDK 固定到协议 commit
`33e47ad8a7318f942de77fb72dbb054d85881b40`、21 个 Schema 和 56 个符合性向量。
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

通过规范的六阶段 profile 签名并验证必须带签名的持久化文档：

```rust
use missionweaveprotocol::{
    KeyRegistrySnapshot, KeyResolutionRequest, KeyResolver, SignedDocumentCodec,
    SignedDocumentKind,
};

impl KeyResolver for RegistryResolver {
    fn resolve(&self, request: &KeyResolutionRequest) -> Result<KeyRegistrySnapshot, AdapterError> {
        let complete_registry = self.load_complete_agent_registry(request)?;
        Ok(KeyRegistrySnapshot::organization_wide(complete_registry))
    }
}

let codec = SignedDocumentCodec::new()?;
let signed = codec.sign(SignedDocumentKind::Command, &unsigned_command, &signing_key)?;
let received = serde_json::to_vec(&signed)?;
match codec.verify(SignedDocumentKind::Command, &received, &registry_resolver) {
    Ok(verified) => println!("{}", verified.signing_hash()),
    Err(error) => {
        send_to_peer(error.wire_code()); // 不泄露失败细节
        audit_locally(error.diagnostic()); // 仅用于受保护审计的阶段与原因
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

文档种类必须显式指定；Codec 不会推断九种 profile 中的任何一种。`SigningKey` 与
`KeyResolver` 是仅有的应用适配器。Resolver 必须返回明确声明为 `OrganizationWide`
的快照；部分或未声明完整性的证据会在密钥解析阶段失败关闭。验证结果不可变地保留解析后
文档与原始接收字节、签名输入及完整文档的 JCS 字节/哈希、精确文本及解析后的受保护时间、
签名材料和已解析的 Agent Registry 证据。首次准入记录（First-Admission Record）、时效性与授权仍是独立检查。可运行示例见
[`sign_document`](examples/sign_document.rs)。

## 运行 Schema 符合性检查

```bash
cargo run --locked --bin missionweaveprotocol-conformance
```

预期结果：

```text
56/56 conformance vectors passed
```

这 56 个向量仅证明结构化 Schema 行为。完整协议符合性还要求实现规范状态机、权限检查、
fencing、预算、排序、重放、交付恢复和人工批准规则。

## 公共接口

- `ProtocolBundle`：内嵌的固定信息、Schema/向量资源与逐字节摘要验证。
- `parse_strict_json`：拒绝重复成员和尾随数据的 UTF-8 解析。
- `SchemaCatalog`：启用格式断言的离线 Draft 2020-12 `$id` 注册表。
- `ConformanceRunner`：全部 26 个有效和 30 个无效规范向量。
- `canonical_bytes` / `canonical_sha256`：RFC 8785 与 `sha256:` 内容 ID。
- `Ed25519Signer`：原始签名和顶层 `signature` 省略规则。
- `SignedDocumentCodec`：显式九 profile 签名与六阶段验证，返回完整不可变证据，并使用
  不泄露验证细节的 wire 错误。
- `SigningKey` / `KeyResolver`：仅有的应用适配器；密钥解析要求组织范围完整的
  `KeyRegistrySnapshot`。
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

`crate` 包含固定的 Schema 和符合性向量，因此验证和 CLI 在运行时无需网络访问。

## 安全

请通过本仓库的 GitHub Security Advisories 私下报告漏洞。请勿在公开 issue 中包含生产环境
凭据、私钥或敏感 Mission 数据。
