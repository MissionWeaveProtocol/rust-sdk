[English](README.md) | [简体中文](README.zh-CN.md) | **繁體中文** |
[日本語](README.ja.md) | [Español](README.es.md) | [Français](README.fr.md) |
[Deutsch](README.de.md)

# MissionWeaveProtocol Rust SDK

這是 [MissionWeaveProtocol](https://github.com/missionweaveprotocol/missionweaveprotocol)
的官方 Rust 協定 SDK。它提供嚴格 JSON 解析、精確固定的協定套件、離線 Draft 2020-12
驗證、完整的 Schema 符合性執行器、RFC 8785 正規 JSON、SHA-256 內容識別碼、
Ed25519 工具、涵蓋九種 profile 的 `SignedDocumentCodec`、`AdmissionService`，以及執行 Schema 驗證的 FrameCodec。

> 目前版本證明的是 **Schema、簽署文件密碼學與 Admission 測試向量符合性**。它尚未宣稱實作 Python
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
[`f7e70a72c76bbeb5014c186cd820aac2112f0dde`](https://github.com/missionweaveprotocol/missionweaveprotocol/commit/f7e70a72c76bbeb5014c186cd820aac2112f0dde)、
22 個 Schema、58 個符合性向量、包含 62 項評估的[內嵌密碼學契約](cryptography/README.md)，
以及包含 30 項評估（12 項完成、18 項拒絕）的[內嵌 Admission 契約](admission/README.md)，其摘要為
`sha256:39971bfafb68ef6c18f9026220cccc4f023fd4d5c8074f8ff0276cb1129cd0a0`。SDK 與協定分別進行版本管理。

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

透過規範的六階段 profile 簽署並驗證必須帶有簽章的持久化文件：

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
        send_to_peer(error.wire_code()); // 不洩露失敗細節
        audit_locally(error.diagnostic()); // 僅供受保護稽核使用的階段與原因
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

文件種類必須明確指定；Codec 不會推斷九種 profile 中的任何一種。`SigningKey` 與
`KeyResolver` 是密碼學應用程式轉接器。Resolver 必須回傳明確宣告為
`OrganizationWide` 的快照；部分或未宣告完整性的證據會在金鑰解析階段失敗關閉。
驗證結果以不可變方式保留解析後文件與原始接收位元組、簽署輸入及完整文件的 JCS
位元組/雜湊、精確文字及解析後的受保護時間、簽章材料與已解析的 Agent Registry 證據。
Admission 是位於這個不變驗證器之上的獨立層。可執行範例請見
[`sign_document`](examples/sign_document.rs)。

## 首次准入與歷史信任

`AdmissionService::admit_first` 會先使用目前 Registry 證據重新執行全部六個 Signed Document
驗證階段，之後才查詢已驗證的僅追加 Admission Log。`verify_historical_admission` 使用保留的
Registry 歷史重新執行同一驗證器，要求存在經嚴格驗證的記錄，而且絕不追加記錄。
`AdmissionCurrentKeyResolver::resolve_current` 是新准入的明確信任介面；歷史重播繼續使用
`KeyResolver`。API 只接受型別化轉接器，不接受呼叫端提供的信任布林值。

```rust
use missionweaveprotocol::{AdmissionService, SignedDocumentKind};

let service = AdmissionService::new()?;
let admitted = service.admit_first(
    SignedDocumentKind::Command,
    command_bytes,
    &current_registry,
    &admission_log,
    &trusted_context,
)?;
let replayed = service.verify_historical_admission(
    SignedDocumentKind::Command,
    command_bytes,
    &historical_registry,
    &admission_log,
)?;
assert_eq!(admitted.record().signing_hash(), replayed.record().signing_hash());
# Ok::<(), Box<dyn std::error::Error>>(())
```

每個 Admission 拒絕都使用 wire code `AUTH_INVALID_SIGNATURE`、受保護階段 `admission` 和穩定的
`AdmissionReason`。`AdmissionOperationError` 會把六階段驗證錯誤與 Admission 階段錯誤明確分開。

## 執行 Schema 符合性檢查

```bash
cargo run --locked --bin missionweaveprotocol-conformance
```

預期結果：

```text
58/58 conformance vectors passed
```

這 58 個向量僅證明結構化 Schema 行為。完整協定符合性還需要實作規範狀態機、權限檢查、
fencing、預算、排序、重播、交付復原與人工核准規則。

## 公開介面

- `ProtocolBundle`：內嵌的固定資訊、Schema/向量/密碼學/Admission 資源與逐位元組摘要驗證。
- `parse_strict_json`：拒絕重複成員與尾隨資料的 UTF-8 解析。
- `SchemaCatalog`：啟用格式斷言的離線 Draft 2020-12 `$id` 登錄。
- `ConformanceRunner`：全部 27 個有效與 31 個無效規範向量。
- `canonical_bytes` / `canonical_sha256`：RFC 8785 與 `sha256:` 內容識別碼。
- `Ed25519Signer`：原始簽章與頂層 `signature` 省略規則。
- `SignedDocumentCodec`：明確九 profile 簽署與六階段驗證，回傳完整不可變證據，並使用
  不洩露驗證細節的 wire 錯誤。
- `AdmissionService`：透過型別化的目前 Registry、可信內容與日誌轉接器完成首次准入、
  歷史重播、嚴格記錄驗證和全部 30 項 Admission 評估。
- `SigningKey` / `KeyResolver`：密碼學應用程式轉接器；金鑰解析要求組織範圍完整的
  `KeyRegistrySnapshot`。
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

`crate` 包含固定的 Schema、符合性向量、密碼學 bundle 和 Admission bundle，因此驗證、
Admission 與 CLI 在執行階段不需要網路存取。

## 安全性

請透過本儲存庫的 GitHub Security Advisories 私下通報漏洞。請勿在公開 issue 中包含正式
環境憑證、私密金鑰或敏感 Mission 資料。
