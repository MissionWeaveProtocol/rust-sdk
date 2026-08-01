[English](README.md) | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md) |
[日本語](README.ja.md) | [Español](README.es.md) | [Français](README.fr.md) |
**Deutsch**

# MissionWeaveProtocol Rust SDK

Offizielles Rust-Protokoll-SDK für
[MissionWeaveProtocol](https://github.com/missionweaveprotocol/missionweaveprotocol).
Es bietet striktes JSON-Parsing, das exakt gepinnte Protokoll-Bundle, Offline-Validierung nach
Draft 2020-12, den vollständigen Schema-Konformitätsprüfer, kanonisches JSON nach RFC 8785,
SHA-256-Inhalts-IDs, Ed25519-Helfer, `SignedDocumentCodec` für die neun expliziten Profile,
`AdmissionService` und einen schema-validierenden FrameCodec.

> Die aktuelle Version weist **Schema-, Kryptografie- und Admission-Vektorkonformität**
> nach. Sie beansprucht
> noch nicht, den autoritativen Core, die Worker-Laufzeit, den Planer, den Speicher oder den
> WebSocket-Client der Python-Referenzimplementierung umzusetzen.

- Website: <https://missionweaveprotocol.github.io/>
- Protokoll: <https://github.com/missionweaveprotocol/missionweaveprotocol>
- Repository: <https://github.com/missionweaveprotocol/rust-sdk>
- Lizenz: Apache-2.0

## Kompatibilität

| Rust SDK | MissionWeaveProtocol |
| --- | --- |
| `0.1.x` | `0.1` |

[`PROTOCOL_PIN.json`](PROTOCOL_PIN.json) bindet das SDK an Commit
[`f7e70a72c76bbeb5014c186cd820aac2112f0dde`](https://github.com/missionweaveprotocol/missionweaveprotocol/commit/f7e70a72c76bbeb5014c186cd820aac2112f0dde),
22 Schemas, 58 Konformitätsvektoren, den [mitgelieferten Kryptografie-Vertrag](cryptography/README.md)
mit 62 Auswertungen und den [mitgelieferten Admission-Vertrag](admission/README.md) mit 30
Auswertungen (12 vollständig, 18 abgelehnt). Der Admission-Digest ist
`sha256:39971bfafb68ef6c18f9026220cccc4f023fd4d5c8074f8ff0276cb1129cd0a0`.

## Verwendung

Vor einer Veröffentlichung auf crates.io kann das Repository direkt verwendet werden:

```toml
[dependencies]
missionweaveprotocol = { git = "https://github.com/missionweaveprotocol/rust-sdk", branch = "main" }
```

Einen WebSocket-Frame validieren und kanonisch kodieren:

```rust
use missionweaveprotocol::FrameCodec;

let codec = FrameCodec::new()?;
let frame = codec.decode(input.as_bytes())?;
let canonical = codec.encode(&frame)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Ein weiteres dauerhaftes Dokument validieren:

```rust
use missionweaveprotocol::{SchemaCatalog, parse_strict_json};

let catalog = SchemaCatalog::new()?;
let mission = parse_strict_json(mission_bytes)?;
catalog.validate("mission.schema.json", &mission)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Eine Ed25519-Protokollsignatur erstellen und prüfen:

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

Ein signaturpflichtiges dauerhaftes Dokument über das normative sechsstufige Profil signieren und
prüfen:

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
        send_to_peer(error.wire_code()); // verrät nicht, welche Prüfung fehlgeschlagen ist
        audit_locally(error.diagnostic()); // geschützte Stufe und Begründung
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

Der Dokumenttyp wird immer explizit angegeben; der Codec leitet keines der neun Profile ab.
`SigningKey` und `KeyResolver` sind die kryptografischen Anwendungsadapter. Der Resolver muss einen
ausdrücklich als `OrganizationWide` deklarierten Snapshot liefern; partielle Belege oder Belege
ohne Vollständigkeitsangabe schlagen bei der Schlüsselauflösung geschlossen fehl. Das verifizierte
Ergebnis hält unveränderlich das geparste Dokument und die empfangenen Bytes, JCS-Bytes/Hashes der
Signiereingabe und des vollständigen Dokuments, den exakten und geparsten geschützten Zeitpunkt,
Signaturmaterial und aufgelöste Agent-Registry-Belege fest. Admission bleibt eine getrennte Ebene
über diesem unveränderten Prüfer. Siehe das ausführbare Beispiel
[`sign_document`](examples/sign_document.rs).

## Erstzulassung und historisches Vertrauen

`AdmissionService::admit_first` führt alle sechs Prüfphasen des Signed Document mit aktuellen
Registry-Nachweisen erneut aus, bevor ein authentifiziertes, nur anhängbares Admission Log
abgefragt wird. `verify_historical_admission` verwendet die aufbewahrte Registry-Historie,
verlangt einen vorhandenen validierten Datensatz und hängt niemals an.
`AdmissionCurrentKeyResolver::resolve_current` ist die ausdrückliche Vertrauensgrenze für neue
Admissions; historische Wiederholungen verwenden weiterhin `KeyResolver`.

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

Jede Admission-Ablehnung verwendet `AUTH_INVALID_SIGNATURE`, die geschützte Stufe `admission` und
einen stabilen `AdmissionReason`. `AdmissionOperationError` trennt sechsstufige Prüffehler von
Admission-Fehlern.

## Schemakonformität ausführen

```bash
cargo run --locked --bin missionweaveprotocol-conformance
```

Erwartetes Ergebnis:

```text
58/58 conformance vectors passed
```

Die 58 Vektoren belegen nur das strukturelle Schemaverhalten. Vollständige Protokollkonformität
erfordert außerdem die normativen Zustandsautomaten, Autoritätsprüfungen, Fencing durch Epochs,
Budgets, Reihenfolge, Replay-Schutz, Wiederherstellung der Zustellung und Regeln für menschliche
Freigaben.

## Öffentliche API

- `ProtocolBundle`: eingebetteter Pin, Schema-/Vektor-/Kryptografie-/Admission-Ressourcen und
  bytegenaue Digest-Prüfung.
- `parse_strict_json`: UTF-8-Parsing, das doppelte Member und nachgestellte Daten ablehnt.
- `SchemaCatalog`: Offline-Draft-2020-12-`$id`-Registry mit Formatprüfungen.
- `ConformanceRunner`: alle 27 gültigen und 31 ungültigen kanonischen Vektoren.
- `canonical_bytes` / `canonical_sha256`: RFC 8785 und `sha256:`-Inhalts-IDs.
- `Ed25519Signer`: Rohsignaturen und Regeln zum Auslassen des obersten `signature`-Members.
- `SignedDocumentCodec`: explizite Signatur für neun Profile und sechsstufige Prüfung mit
  vollständigen unveränderlichen Belegen und Wire-Fehlern ohne Offenlegung des Fehlerpunkts.
- `AdmissionService`: Erstzulassung, historische Wiederholung, strikte Datensatzprüfung und alle
  30 Admission-Auswertungen über typisierte Registry-, Kontext- und Log-Adapter.
- `SigningKey` / `KeyResolver`: kryptografische Anwendungsadapter; die Schlüsselauflösung verlangt
  einen organisationsweit vollständigen `KeyRegistrySnapshot`.
- `FrameCodec`: striktes Dekodieren und kanonisches Kodieren anhand des normativen Frame-Schemas.

## Entwickeln und prüfen

Rust 1.85 oder neuer ist erforderlich.

```bash
node scripts/check-repository-policy.mjs
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo run --locked --quiet --bin missionweaveprotocol-conformance
cargo package --locked
```

Das Crate enthält die festgelegten Schemas, Konformitätsvektoren sowie Kryptografie- und
Admission-Bundles, sodass Validierung, Admission und CLI ohne Netzwerkzugriff funktionieren.

## Sicherheit

Melde Schwachstellen vertraulich über GitHub Security Advisories für dieses Repository.
Veröffentliche keine Produktionszugangsdaten, privaten Schlüssel oder sensiblen Mission-Daten in
öffentlichen Issues.
