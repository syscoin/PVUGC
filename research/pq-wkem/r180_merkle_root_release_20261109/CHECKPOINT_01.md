# R180 — Fixed-root hash-path release as a native signature candidate

Status: hypothesis, before running a checker. NOT a release construction or QPT proof.

Observed `syscoin/PVUGC#1` head at start: `393685c7394a14533f08eb2018ad11161f239a8f`, branch `research/pq-wkem-validation-20260918`, draft/open. Read exact R179 research blob `19fc5ad47bd12a2d602c094b1e98835ce55f2aa5`, plus latest ordinary comments since `2026-11-09T20:00Z` (none). No general PR diff or literature search.

Research object: can a preauthorized Bitcoin-native hash-based signing root double as a commitment to source-valid challenge evidence, so that a challenger obtains a valid signature from a hash-authentication path, without WE, a new Bitcoin verifier, or an online authority? This directly tests the N-of-N native signature path instead of another public XOR pad.

Proposed `Build`: for each claim, commit an 8-depth toy Merkle tree whose semantic fork-slot leaf stores the asserted Syscoin child identity, and use its root as a frozen verification target; `Open` would attempt to use an authenticated alternate child to produce a path to this root and a native challenge authorization. The actual native signature compiler is **not supplied**; a Merkle membership path is only a candidate ingredient, not already a native SLH-DSA signature.

Exact questions: (i) Can a new *different* child at the SAME semantic slot open the same frozen root with valid hash paths? (ii) Does changing a parent-work certificate for the SAME child preserve the root, as it should? (iii) Does dynamically replacing an empty leaf by a future challenger leaf preserve the root? (iv) Can publicly specified wildcard openings enable future child insertion without opening a forgeable bypass? (v) Do the answers differ with distinct indexes or a source-verifier circuit as a leaf?

Proposed proof obligation: given two distinct accepted Merkle openings at the same index under one fixed root, straight-line output a collision in a domain-separated hash; do not claim impossibility for general hash-only witness encryption, obfuscation, or protocols with an authenticated evolving root.

Execution and any actual output will be recorded separately after tests; no claim of experiments, runtime or breakthrough is made here. A successful challenge must still be valid for ALL three original OR predicates, with same frozen claim-specific cancellation signatures, and adversaries' full public quantum view. This single candidate does not establish that.
