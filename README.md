# MissionWeaveProtocol Rust SDK

The official Rust SDK for
[MissionWeaveProtocol](https://github.com/missionweaveprotocol/missionweaveprotocol).

This repository is under active development. Its first release will provide offline protocol
bundle verification, Draft 2020-12 schema validation, conformance vectors, canonical JSON,
Ed25519 primitives, and schema-validating frame codecs.

- Website: <https://missionweaveprotocol.github.io/>
- Protocol: <https://github.com/missionweaveprotocol/missionweaveprotocol>
- License: Apache-2.0

## Development

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo package
```
