# First-admission and historical-trust vectors

`manifest.json` defines the protocol-owned MissionWeaveProtocol 0.1 Admission bundle. Its
`profileId` is `missionweaveprotocol.first-admission-historical-trust.v0.1` and its
`manifestVersion` is `1`.

The bundle contains 19 digest-protected artifacts, five cases, and 30 evaluations. Twelve
evaluations complete and eighteen are rejected at the protected `admission` stage with wire code
`AUTH_INVALID_SIGNATURE`. Every evaluation first reruns the unchanged six-stage Signed Document
verification function and then exercises either first admission or historical replay.

The Admission manifest pins the cryptography bundle digest:

```text
sha256:5eade516e4bc5dcf04477727ebcccd11f33348b2d9135fb6fe0365c6e6cc2ea3
```

This pin keeps Admission evidence layered above the existing 22-case, 62-evaluation cryptography
contract. Admission does not change signing bytes, signing hashes, resolved-key evidence, or the
meaning of cryptographic `complete`.

## Fixture and adapter model

The bundle's `trustedContext`, `lookup`, and `append` members are deterministic test-harness
metadata. They model authoritative absence, authenticated records, and typed adapter failures so
all implementations execute the same orchestration paths. They are not a deployed log proof
format, portable append receipt, trust boolean, authentication proof, or integrity proof.

Successful deployment adapters assert authenticated service identity, authorized writes, and
append-only integrity by returning a successful typed result. Implementations must still strictly
parse and validate the returned First-Admission Record, compare all required bindings, and check
the trusted acceptance instant against the resolved key interval.

The 30 evaluations cover nine first-admission profile successes, idempotent retry, retained-history
replay after later expiry and revocation, record-binding failures, exclusive validity boundaries,
typed lookup and append failures, and Event self-anchoring.

## Digest calculation

To calculate `artifactDigest`, remove exactly the top-level `artifactDigest` member from the parsed
manifest, serialize the remaining value with RFC 8785 JCS, hash those canonical bytes with
SHA-256, and encode the result as `sha256:` followed by 64 lower-case hexadecimal digits. Each
entry in `artifacts` separately binds the exact bytes at its declared repository path. The
manifest also requires equality with the pinned cryptography `artifactDigest` above.

## Regeneration and validation

Use the hash-locked Python environment outside the repository worktree:

```bash
MW_CRYPTO_PYTHON=/Users/lionelmbp/.config/superpowers/venvs/missionweaveprotocol-first-admission-historical-trust/bin/python
"$MW_CRYPTO_PYTHON" scripts/generate_admission_vectors.py
git diff --exit-code -- admission
"$MW_CRYPTO_PYTHON" scripts/validate_admission_vectors.py
```

Generation is deterministic. A successful run must preserve the committed Admission tree and
report 19 artifacts, five cases, 30 evaluations, twelve complete, and eighteen rejected.

## Scope boundary

This bundle demonstrates only the declared First-Admission Record and historical-trust behavior
on top of six-stage cryptographic verification. It does not demonstrate Command freshness or
clock-skew enforcement, signer authorization, state-machine transitions, Event creation, a
portable Admission Log proof format, or deployment-specific authorization and retention policy.
