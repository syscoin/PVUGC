# R209 — Source-root-authenticated future labels are not a release primitive

**Status: bounded ORIGINAL-dependent negative candidate/repair experiment. No secure hash-only Build/Open, no practical bridge release, no quantum proof or qualifying progress report.**

## Exact continuity

On 2026-11-10, syscoin/PVUGC PR #1, open/draft, branch research/pq-wkem-validation-20260918. Start SHA 10fff30d4dd7becf9205b99ef224d01f8e699087. The relevant latest R208 hidden sparse mask research file was read, along with recent PR issue comments since 18:00 UTC (none). No external web/literature, other repository writes, independent agent, actual mining or native PQ signing. Genuine intermediate hypothesis CHECKPOINT_01.md was separately published before tests in commit 103464601922cdde16a96bab7cc9c43d80300624 (parent = start SHA).

Full local checker.py SHA256 b056d2b9d908225aaa87fadd799951bec03699c531ea35e28576c8aef1bd121a; local captured.json SHA256 5b60ab6b1efa4d9836312e831631d555ca8bfa4328749d5353d69968dd1ec43a. Ran twice, byte-identical, 786 synthetic assertions. Separate 16-bit deliberately weak toy Merkle collision extractor SHA256 fdd36444f58e16aaefa7c983bf93137f8b32c7b7c5a5f90effe45119cc116e9a, local output SHA256 32a2615d25fc60868095e76268967195a0daa503422035f0ab2775cbbe8fe4d1. Ran twice, byte-identical: 32 explicit collisions, 128 checks and 9364 trials. Full two scripts and outputs remain LOCAL ONLY. A separately run exact small Python SHA-256 reproduction, its captured output and this research note are published on the branch. Synthetic Merkle trees are NOT Bitcoin/Syscoin headers or a substitute for ORIGINAL source verification; no QPT attacker or source consensus validator was run.

## Target unchanged

One preauthorized withdrawal x_W binds source/claim/UTXO, burn ID, amount/recipient, BTC/SYS authenticated roots/anchors, observation interval/deadline, N-of-N setup, exact cancel message and VK and capsule ID. One notary initiates; anyone presenting genuine R1 greater-work contradictory BTC evidence, R2 missing/invalid bound PoB or R3 qualified Syscoin incompatible prefix/tag-fault evidence must recover the SAME frozen native cancellation authorization OFF CHAIN, with no online issuer. Full actual SHA/AuxPoW/coinbase/headers and source authenticity are mandatory, never replaced with a synthetic Merkle proof.

## Specific source-tied construction attempted

Let A be a fixed authenticated baseline source history, with semantic value a_i at the relevant first-incompatible slot i. Build chooses independent 256-bit secret K. Let L(v)=SHA256(domain-label || v), P(u,v)=SHA256(domain-pair || u || v), using unambiguous typed encodings. Try:

    E_i = K XOR P(L(a_i), L(b_i))
    Open_i(E_i, B) = E_i XOR P(L(a_i), L(b_i))

where b_i is from a future genuinely authenticated alternate source history B. The hope: existing source Merkle/sha chaining cryptographically enforces possession of the opposite label. However Build knows A and K but not any future B. All valid B must recover one precommitted K. These are exact candidate equations, not a WE assumption.

### Three repairs, tested

**Preselect B*.** Build can precompute E_i for a designated b*_i. This B* recovers K, but every distinct future B returns K XOR P(L(a_i),L(b*_i)) XOR P(L(a_i),L(b_i)), generally NOT K. Retaining B* permits early release independent of whether B* is valid source evidence. Synthetic checker: 24 designated openings succeed; 48 other-valid-branch attempts return another key.

**Public wildcard/normalization.** Set the second label to a fixed public U_i to force all valid futures to one output. Then any caller computes K=E_i XOR P(L(a_i),U_i) without authenticating the source. 24 early-open fixtures.

**Public table of B-dependent pads.** Publishing E_{i,B} for all possible B lets anyone choose any syntactically available row and calculate K before source qualification; a small 8-bit complete-table fixture demonstrated 256 early openings. This is a family-specific observation, not an asymptotic lower bound against all succinct hash-based encodings. A full 256-bit future-source table is not practical polynomial setup.

### Private table committed by Merkle root does not repair derivation

Hide each E_{i,B} and publish only its Merkle root R_E. The root can authenticate a row when disclosed. It does not compute the undisclosed row or Merkle siblings for a future challenger who merely possesses SHA/AuxPoW evidence B. An online issuer violates the user requirement. Publishing an evaluator for all rows without authenticated-source-dependent cryptographic protection reopens the early-recovery problem. Secretly seeded rows remain inaccessible to honest challenge witnesses. This is a missing algorithm, not an encoding overhead problem.

## Same-root dual opening is not an actual Syscoin fork certificate

For conventional ordered, domain-separated Merkle hashing, two different leaf values at the same index with complete paths both verifying under the SAME frozen root yield a straight-line hash collision: either the leaf hashes collide or at the first level of merging unequal intermediate states two distinct ordered node-hash inputs collide. The extractor also works on classical openings output by a QPT adversary, but QPT collision resistance of the deployed hash is a separate assumption, not proved here.

An actual Syscoin fork has two potentially DIFFERENT descendant-root commitments joined through a common pre-fork ancestor; two opposite leaf openings under a single fixed post-fork source root are not valid alternate histories. In 24 synthetic seeds, 72 independently generated alternative paths authenticate under their own roots but not cross-root or same-root baseline paths. The separate deliberately weak 16-bit SHA-truncated Merkle test found 32 explicit same-root leaf collision witnesses and extracted the hash collisions; this is NOT a SHA-256 break.

This isolates why source Merkle authentication alone cannot be recycled into the secret opposite input labels for arbitrary future authenticated forks. It does not rule out a genuinely nonblackbox hash/constraint release, iO or other novel source-bound primitives. No original-source-only Build/Open, full-public simulator, hard-TRUE/false-instance or malicious setup/multi-capsule QPT reduction follows.

## Exact missing equation and handoff

Construct in classical PPT, BEFORE the alternate history exists:

    Build_inc(R_original,x_W,sigma_cancel) -> (C,CK)

and public

    Open_inc(C,w)=the SAME frozen sigma_cancel
    for EVERY valid original R1/R2/R3 witness w.

The public capsule must cryptographically entangle real SHA/AuxPoW authentication with hidden output, not merely call an honest verifier before a public gate, give a root-only commitment, invent secret source signatures, or use an independent puzzle. Arbitrary full-public QPT unauthorized recovery/native forgery must yield actual ORIGINAL evidence or an independently justified PQ break without a volunteered internal representation; cover source-controlled coins, sibling capsules, aux data, VK/CK and honest-erasure malicious setup. Do not restart Merkle same-root hidden table or static opposite-label carrier absent a new release algorithm. No user-level positive finding or PR comment this run; keep existing automation enabled.
