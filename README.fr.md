[English](README.md) | [简体中文](README.zh-CN.md) | [繁體中文](README.zh-TW.md) |
[日本語](README.ja.md) | [Español](README.es.md) | **Français** |
[Deutsch](README.de.md)

# MissionWeaveProtocol Rust SDK

SDK de protocole Rust officiel pour
[MissionWeaveProtocol](https://github.com/missionweaveprotocol/missionweaveprotocol).
Il fournit une analyse JSON stricte, le paquet de protocole épinglé exactement, la validation
Draft 2020-12 hors ligne, l’outil complet d’exécution des tests de conformité des schémas, le JSON
canonique RFC 8785, les identifiants SHA-256, les outils Ed25519 et un FrameCodec validant les schémas.

> La version actuelle démontre une **conformité limitée aux schémas et aux vecteurs**. Elle ne
> prétend pas encore implémenter le Core faisant autorité, l’environnement d’exécution Worker,
> l’ordonnanceur, le stockage ou le client WebSocket de l’implémentation de référence Python.

- Site officiel : <https://missionweaveprotocol.github.io/>
- Protocole : <https://github.com/missionweaveprotocol/missionweaveprotocol>
- Dépôt : <https://github.com/missionweaveprotocol/rust-sdk>
- Licence : Apache-2.0

## Compatibilité

| Rust SDK | MissionWeaveProtocol |
| --- | --- |
| `0.1.x` | `0.1` |

[`PROTOCOL_PIN.json`](PROTOCOL_PIN.json) lie le SDK au commit
`6f10987627d62fb296e3490ceceb5539b1e94b70`, aux 21 schémas et aux 52 vecteurs de conformité. Les
versions du SDK et du protocole sont indépendantes.

## Utilisation

Avant une publication sur crates.io, référencez directement le dépôt :

```toml
[dependencies]
missionweaveprotocol = { git = "https://github.com/missionweaveprotocol/rust-sdk", branch = "main" }
```

Validez et encodez canoniquement une trame WebSocket :

```rust
use missionweaveprotocol::FrameCodec;

let codec = FrameCodec::new()?;
let frame = codec.decode(input.as_bytes())?;
let canonical = codec.encode(&frame)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Validez un autre document durable :

```rust
use missionweaveprotocol::{SchemaCatalog, parse_strict_json};

let catalog = SchemaCatalog::new()?;
let mission = parse_strict_json(mission_bytes)?;
catalog.validate("mission.schema.json", &mission)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Créez et vérifiez une signature de protocole Ed25519 :

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

## Exécuter la conformité des schémas

```bash
cargo run --locked --bin missionweaveprotocol-conformance
```

Résultat attendu :

```text
52/52 conformance vectors passed
```

Les 52 vecteurs prouvent uniquement le comportement structurel des schémas. La conformité complète
au protocole exige aussi les machines d’état normatives, les contrôles d’autorité, le fencing qui
invalide les autorisations obsolètes, les budgets, l’ordre, la prévention des rejeux, la reprise des
livraisons et les règles d’approbation humaine.

## Interface publique

- `ProtocolBundle` : pin intégré, ressources de schémas et de vecteurs, et vérification exacte des
  empreintes, octet par octet.
- `parse_strict_json` : analyse UTF-8 qui rejette les membres dupliqués et les données
  supplémentaires en fin d’entrée.
- `SchemaCatalog` : registre `$id` Draft 2020-12 hors ligne avec assertions de format.
- `ConformanceRunner` : les 25 vecteurs valides et 27 invalides canoniques.
- `canonical_bytes` / `canonical_sha256` : RFC 8785 et identifiants de contenu `sha256:`.
- `Ed25519Signer` : signatures brutes et règles d’omission de `signature` au premier niveau.
- `FrameCodec` : décodage strict et encodage canonique autour du schéma normatif des trames.

## Développer et vérifier

Rust 1.85 ou ultérieur est requis.

```bash
node scripts/check-repository-policy.mjs
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo run --locked --quiet --bin missionweaveprotocol-conformance
cargo package --locked
```

Le crate contient les schémas et vecteurs de conformité épinglés ; la validation et la CLI
fonctionnent donc sans accès réseau pendant l’exécution.

## Sécurité

Signalez les vulnérabilités en privé au moyen des GitHub Security Advisories de ce dépôt. N’incluez
pas d’identifiants de production, de clés privées ni de données Mission sensibles dans les tickets
publics.
