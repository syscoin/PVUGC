# R192 — SHA-OR: direct source-hash release candidate

**Status: source-dependent candidate falsified within a precisely defined direct-hash family; no working original-witness key release or PQ proof.**

## Provenance
Repo syscoin/PVUGC PR #1, branch research/pq-wkem-validation-20260918, initial head 4be2434d30898c42f1201b49cd7381d4ff52ca24. Read actual PR metadata, ordinary comments since 2026-11-09 20:00 UTC (none), exact prior R191 research note, and head commit. Earlier hypothesis checkpoint saved first as 9ed343474fc931b0ba5037b7d92a354b52baba36. No external internet/literature, other repository writes, independent agent, production deployment, genuine BTC/SYS chain mining, native signing or quantum experiment.

## The fixed original challenge
A future one-notary activation must be Bitcoin-witness-authenticated to its preauthorized vault transaction and a claim-specific cancellation message. Anyone with ORIGINAL qualifying evidence of (1) competing greater anchored Bitcoin work, (2) source-authenticated missing/invalid exact burn authorization, or (3) sufficiently qualified inconsistent Syscoin AuxPoW tags/history, opens the same frozen cancellation signature contribution from each N-of-N setup participant. The three challenges form one OR, and N participants' protected signatures form an AND. Relevant source authentication, actual intervals/anchors, full parent/coinbase/child commitment checks, other capsules, native VK and auxiliary data all participate in the adversarial public view. Pure parent PoW is NOT Bitcoin best-chain membership, and synthetic parent headers are not Syscoin source evidence.

## The actual attempted release family
For honest participant i, choose uniform 256-bit K_i independent of source generation, publish D_i = sigma_i XOR Hpad(x,K_i), and CK_i = Hcheck(x,K_i). Seek a public F(x,w) derived directly from a qualifying authentic work transcript or tag such that EVERY ORIGINAL valid witness w recovers the *same* precommitted K_i, while nobody can obtain K_i without real evidence. F must not be an arbitrary unrelated hash puzzle, hidden online issuer or source-signer-retained OTS labels.

### Attempt A: shared public Bitcoin predecessor
F(x,w)=H('source',context,anchor_parent_prev) is constant across work witnesses but the anchor and context are already public before any event. The masked native signature is then decrypted by any classical observer without challenge evidence.

### Attempt B: hash of actual parent header or coinbase
F(x,w)=H('source',context,header(w)) can depend on expensive future work, but different valid nonces, alternate parent headers and fork certificates have different digests. The frozen D_i cannot open from every valid witness. The bounded fixture produced 24 distinct qualifying parent hashes and 24 candidate keys (two synthetic child/ancestor commitments, same parent predecessor), and a mask set for one witness failed to open for the other 23. Different work certificates for the same Syscoin child must never automatically count as a fork. Varying hash outputs cannot be assumed to supply one precommitted key.

### Attempt C: common PoW digest prefix
Every nine-zero-bit-target solution has an eight-zero-bit public prefix. Hashing that prefix does produce a common key, but it is derivable from the public constant 0x00; a fabricated unattested digest opens the mask. Verification performed only by the honest Open procedure cannot protect a secret whose raw pad is already computable.

### Repair attempt D: selected work-certificate lookup
A public table of capsules for setup-mined parent header candidates cannot ensure actual Bitcoin best-chain/source inclusion. The builder may know the candidates before any relevant event, and an attacker can present an unanchored local-work certificate; legitimate other certificates and forks outside the selected set fail completeness. Enumerating every possible future SHA256d header, relevant source window and all possible claims is not a polynomial-time Build. This particular table repair fails; it is NOT an impossibility proof against compact nonblackbox SHA encodings.

## Simple direct-extractor lemma
Let W(x) be nonempty. Suppose F(x,w) is a deterministic, *capsule-independent* candidate key and K is sampled uniformly from {0,1}^lambda independently of F and the source. For fixed w0 in W(x), Pr_K[F(x,w0)=K] = 2^-lambda. Therefore an independently sampled fixed secret cannot be expected to match an arbitrary source-only hash extractor for all valid witnesses. Choosing K=F(x,w*) for a preselected witness instead requires the missing invariant F(x,w)=F(x,w*) for EVERY valid original w, and that this invariant remains unavailable to an attacker without valid original evidence. Publicly computable shared anchors/prefixes fail secrecy, while suffix/nonce-dependent keys fail common-output correctness. Hpad collisions add a separately quantified negligible exception. This lemma is intentionally limited to the direct F family, not capsule-dependent source-SHA-circuit encodings.

### Three-branch coverage
Even a working fresh-PoW-only extractor would not automatically open from challenge (2), whose witness can be an authenticated nonmembership/wrong-burn proof against an existing root without mining any new header. No independent hash puzzle can be appended as a fake ORIGINAL certificate. Multiple branch capsules exposing the same frozen signature need joint correlated-capsule QPT security, not three marginal proofs.

## Actual test
Published checker.py was executed locally twice with byte-identical output; 39 FUNCTIONAL assertions for 24 synthetic SHA256d parent-header PoW solutions, common anchor, distinct parent hashes, earlier opening from public prefix/ancestor and per-nonce key divergence. Toy nBits are NOT validated by Bitcoin DAA, synthetic coinbase roots are not consensus AuxPoW, and the tests do NOT establish a bound against QPT attacks or full source validity. Local source SHA256: 1a8ce3aad394f05bb3b60f1de5e729ba34f2c6d74fec9328b1756dea8ae07cc8; local captured JSON SHA256: 6d998802875688cc41fa070489bb138bf2f3e88a2c3e9e8fe637a913c2784fe1.

## Exact remaining constructive obligation
Find a polynomial classical Build_SHA(x,sigma; r) -> C and Open_SHA(C,ORIGINAL witness w) -> *same* sigma for every valid original work/burn/fork challenge. The C-dependent cryptographic release must actually bind full SHA/PoW/AuxPoW/source-state verification, not check it after a publicly accessible key. Prove arbitrary QPT unauthorized raw-key recovery or accepted native forgery from all correlated public inputs gives an actual ORIGINAL evidence witness or independent quantum hash/native signature break. Do not assume generic WE, iO, on-chain NP verification, a hidden online issuer, source-generated future secret preimages or any lattice/DLog foundation. Earlier public-both-label garbling and direct source-secret retention failures remain live regressions.

No constructive secret-release milestone or ordinary PR comment qualifies. Preserve this as a negative result to avoid repeating these superficially attractive direct-hash candidates.
