# Source-root binding of a nonspliceable future certificate (NONQUALIFYING WKEM)

## Provenance
Started at the actual open/draft/unmerged syscoin/PVUGC PR #1 branch \`research/pq-wkem-validation-20260918\`, head \`79793abd112c81187853f177cf676ab36eecdc1a\` (R352). Read R350 blob \`bd1de20269249d79bb48481446b5932591fcdd2b\`, R351 blob \`48fc1a17abf0e6455434168aff4be521730a48ba\`, and R352 file blob \`14960f91739ddfb741c67040193e19ee9a80fa71\`. This checks a different, hash-only way to prevent R289's **mixed-incompatible-witness label splicing** without R351's explicit exponential frontier state. It does not claim a source-dependent public release.

## Constructed local source-consistency interface
The future witness-holder, not the builder, computes a **single** Merkle root \`rho\` of a canonical, bounded Boolean source-verifier transcript \`w=(w_0,...,w_{N-1})\`. Use typed, length- and position-bound, domain-separated leaves \`leaf_i=H(0x00||protocol||N||i||encode(w_i))\` and internal nodes \`node=H(0x01||protocol||left||right)\`. All local SHA-gate, source-circuit and ancestry constraints receive exactly the required coordinate values and Merkle paths under the same root \`rho\`. Reject mismatched roots, variable indices, types, lengths, directions and malformed canonical encodings, and perform the actual local Boolean constraints. If an original challenge uses multiple independently qualifying certificates, each certificate has its own root, with explicit common-claim relation checks.

**Straight-line QPT collision reduction for submitted records.** Given two *accepted* classical openings for different values at the same coordinate under one root, compare their leaf and upward hash inputs. At the first level where unequal inputs produce equal digests, output those inputs as a collision in H. This requires neither quantum rewinding nor a volunteered algorithm state or query log: the actual accepted proofs contain the collision. Thus, under QPT collision resistance, every repeated coordinate used by verified local gates has one consistent value. The union of verified records yields one assignment to every covered coordinate (arbitrarily fill unconstrained coordinates) satisfying every checked local constraint. This proof is solely about accepted input records; it does not extract a certificate from arbitrary cancellation-key recovery.

This removes the precise *syntax* of R289/R351's incompatible-variable splice for a submitted proof using polynomial-size local checks and Merkle paths, even when the verifier's frontier would be exponential. No zero-knowledge or confidentiality is claimed. A Merkle root authenticates chosen bytes; it does not provide secret inputs, ensure Bitcoin best-chain membership, or itself enforce the original bridge relation.

## Joint-public release attempt, exact failing equation
Let \`rho=Merkle(w)\` be chosen **after** the frozen capsule is built. The public serialized source-conditioned transport would still need

\`Edge_C(rho,j,a_j,K_j) -> K_(j+1)(rho)\`

only for globally consistent, original-authenticated transitions, plus a terminal correction

\`D_C(rho) XOR H_out(x,rho,K_final(rho)) = sigma_cancel\`

for **every** qualified original \`w\`, producing the **same** frozen native cancellation capability.

A builder that does not know future witness roots cannot precompute an edge/terminal ciphertext row for each root in polynomial time. Public keys \`K(rho)=H(public||rho)\` yield no hidden secret; \`K(rho)=H(builder_secret||rho)\` cannot be evaluated by a public Open without revealing the builder secret, enumerating future roots, or an independently instantiated source-gated secret program. Replacing the latter by an honest-code \`VerifyOriginal\` after any publicly recoverable pad is not sound; the unrestricted pad remains recoverable even for FALSE instances. A public Merkle root or certificate verifier cannot instantiate \`Edge_C\` by itself.

Therefore the Merkle component **does not supply** any \`Build_inc/Open_inc\`, FALSE full-public native-key simulator, or hard-TRUE QPT recovery-to-ORIGINAL-certificate reduction. It is an optional source-consistency subcomponent only; all of the true source-dependent release gap remains. No general hash-only WE, ideal obfuscation or claim of concrete SHA quantum security follows.

## Actual bounded checker and exact limitations
A CPython standard-library checker constructed a domain-separated Merkle tree over Boolean wires, rejected a splice across separate roots that individually satisfy contradictory clauses \`z_0=0\` and \`z_0=1\`, tested a SHA-Ch local gate with a repeated wire, and exhaustively checked cross-root false membership in a 4-wire domain. There were **two successful byte-identical executions** of 585 assertions each. A preliminary run failed because the checker passed a hexadecimal root string where bytes were required; it was corrected and is **not** counted as passed.

Local-only executable checker SHA256: \`de2cd7e118a10a53928f432883a4e3a48dce485cd3c4a7685e5b7c0a8d436b6a\`. Both local JSON outputs SHA256: \`bfd5ba0482ccffc78f025b8183ace260543e45e7cd3cd172fca4948894a5ec7a\`. The paired local checker/results and derivation were archived in \`/mnt/data/pq_source_merkle_binding_20261118.tar.gz\` with SHA256 \`95c781c611b1d1648fc0e8b753a175f7a14db4d5f34234d6d1edf095572dcc52\`; this archive is **not** represented as a GitHub publication or guaranteed persistent artifact. These are synthetic wire transcripts, not full original source certificates, actual Core consensus tests, Bitcoin work anchors, native SLH signatures or quantum experiments.

The ORIGINAL relation still has three independent OR challenge grounds with strict post-PQ contextual AuxPoW, modern chain ID/exact tags, finite authenticated burn-fault evidence, claim-relevant actual-ancestor conflicts, independent carrier authentication for malformed tag evidence, BTC same-anchor greater-work proof, required LC depth, and all claim/UTXO/amount/recipient/VK/window/reset/deadline binding. R225 native signature portability and malicious N-of-N setup remain open. The unimplemented \`Edge_C\` and \`D_C\` are the next *cryptographic* equations; no narrower verifier-only scope is promoted as a missing-advance solution.

**NONQUALIFYING:** no user or PR progress comment, no production change, and no automation change warranted.