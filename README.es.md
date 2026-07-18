[English](README.md) | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md) |
[日本語](README.ja.md) | **Español** | [Français](README.fr.md) |
[Deutsch](README.de.md)

# MissionWeaveProtocol Rust SDK

SDK oficial de protocolo en Rust para
[MissionWeaveProtocol](https://github.com/missionweaveprotocol/missionweaveprotocol).
Incluye análisis JSON estricto, el paquete de protocolo fijado exactamente, validación Draft
2020-12 sin red, el ejecutor completo de conformidad de esquemas, JSON canónico RFC 8785,
identificadores SHA-256, utilidades Ed25519, `SignedDocumentCodec` para los nueve perfiles
explícitos y un FrameCodec con validación de esquemas.

> La versión actual demuestra **conformidad con esquemas y vectores criptográficos de documentos
> firmados**. Todavía no afirma
> implementar el Core autoritativo, el entorno de ejecución de Worker, el planificador, el almacenamiento ni el
> cliente WebSocket de la implementación de referencia en Python.

- Sitio web: <https://missionweaveprotocol.github.io/>
- Protocolo: <https://github.com/missionweaveprotocol/missionweaveprotocol>
- Repositorio: <https://github.com/missionweaveprotocol/rust-sdk>
- Licencia: Apache-2.0

## Compatibilidad

| Rust SDK | MissionWeaveProtocol |
| --- | --- |
| `0.1.x` | `0.1` |

[`PROTOCOL_PIN.json`](PROTOCOL_PIN.json) fija el SDK al commit
`6f10987627d62fb296e3490ceceb5539b1e94b70`, 21 esquemas y 52 vectores de conformidad. Las
versiones del SDK y del protocolo son independientes.

## Uso

Antes de una publicación en crates.io, usa el repositorio directamente:

```toml
[dependencies]
missionweaveprotocol = { git = "https://github.com/missionweaveprotocol/rust-sdk", branch = "main" }
```

Valida una trama WebSocket y codifícala canónicamente:

```rust
use missionweaveprotocol::FrameCodec;

let codec = FrameCodec::new()?;
let frame = codec.decode(input.as_bytes())?;
let canonical = codec.encode(&frame)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Valida otro documento duradero:

```rust
use missionweaveprotocol::{SchemaCatalog, parse_strict_json};

let catalog = SchemaCatalog::new()?;
let mission = parse_strict_json(mission_bytes)?;
catalog.validate("mission.schema.json", &mission)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Crea y verifica una firma de protocolo Ed25519:

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

Firma y verifica un documento duradero que requiere firma mediante el perfil normativo de seis
etapas:

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
        send_to_peer(error.wire_code()); // no revela qué comprobación falló
        audit_locally(error.diagnostic()); // etapa y motivo protegidos
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

El tipo de documento siempre se indica explícitamente; el codec no infiere ninguno de los nueve
perfiles. `SigningKey` y `KeyResolver` son los únicos adaptadores de aplicación. El resolver debe
devolver un snapshot declarado explícitamente como `OrganizationWide`; la evidencia parcial o sin
completitud declarada falla de forma cerrada en la resolución de claves. El resultado verificado
conserva de forma inmutable el documento analizado y los bytes recibidos, los bytes/hash JCS de la
entrada firmada y del documento completo, el tiempo protegido exacto y analizado, la firma y la
evidencia del Agent Registry resuelto. First-Admission Record, vigencia y autorización son comprobaciones
separadas. Consulta el ejemplo ejecutable [`sign_document`](examples/sign_document.rs).

## Ejecutar la conformidad de esquemas

```bash
cargo run --locked --bin missionweaveprotocol-conformance
```

Resultado esperado:

```text
52/52 conformance vectors passed
```

Los 52 vectores solo demuestran el comportamiento estructural de los esquemas. La conformidad
completa con el protocolo también requiere las máquinas de estado normativas, controles de
autoridad, fencing que invalida las autoridades obsoletas, presupuestos, orden, prevención de
repeticiones, recuperación de entregas y reglas de aprobación humana.

## Superficie pública

- `ProtocolBundle`: pin integrado, recursos de esquemas y vectores, y verificación exacta de los
  resúmenes, byte a byte.
- `parse_strict_json`: análisis UTF-8 que rechaza miembros duplicados y datos sobrantes.
- `SchemaCatalog`: registro `$id` offline de Draft 2020-12 con aserciones de formato.
- `ConformanceRunner`: los 25 vectores válidos y 27 inválidos canónicos.
- `canonical_bytes` / `canonical_sha256`: RFC 8785 e identificadores de contenido `sha256:`.
- `Ed25519Signer`: firmas sin procesar y reglas de omisión de `signature` en el nivel superior.
- `SignedDocumentCodec`: firma explícita de nueve perfiles y verificación en seis etapas con
  evidencia completa e inmutable y errores wire que no revelan el punto de fallo.
- `SigningKey` / `KeyResolver`: los únicos adaptadores de aplicación; la resolución exige un
  `KeyRegistrySnapshot` completo para toda la organización.
- `FrameCodec`: decodificación estricta y codificación canónica sobre el esquema normativo de tramas.

## Desarrollo y verificación

Se requiere Rust 1.85 o posterior.

```bash
node scripts/check-repository-policy.mjs
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo run --locked --quiet --bin missionweaveprotocol-conformance
cargo package --locked
```

El crate incluye los esquemas y vectores de conformidad fijados, por lo que la validación y la CLI
funcionan sin acceso a la red durante la ejecución.

## Seguridad

Informa de las vulnerabilidades de forma privada mediante GitHub Security Advisories para este
repositorio. No incluyas credenciales de producción, claves privadas ni datos sensibles de Mission
en incidencias públicas.
