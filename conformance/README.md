# Conformance vectors

`manifest.json` maps 58 structural test cases to one schema, one instance document, and each
case's expected validity. The vectors are implementation-neutral protocol artifacts.

The protocol repository owns the canonical vectors. Implementations should pin a protocol release
or commit, run the complete manifest, and record the pinned source and content digest in their own
repository.

Passing these vectors demonstrates structural schema conformance only. Behavioral conformance also
requires the state-machine, ordering, authorization, lease, budget, and replay rules in
[`spec/PROTOCOL.md`](../spec/PROTOCOL.md). Signed-document cryptographic interoperability is covered
separately by the [cryptography bundle](../cryptography/README.md); passing that bundle likewise
does not prove First-Admission Record validation, Command freshness, or signer authorization under
applicable role and policy.

Behavioral First-Admission and historical-replay evidence is defined separately by the
[Admission bundle](../admission/README.md).
