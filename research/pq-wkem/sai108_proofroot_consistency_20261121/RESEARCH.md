# SAI108 — proof-root-bound SHA gate as a replacement for explicit state labels (nonqualifying triage)

## Provenance and decision
Research-only bounded continuation of SAI107, which was read at the then-current open/draft syscoin/PVUGC PR #1 head `d021bfdaa41bb290a53ad7107d0f5ee2a089c9dd`, branch `research/pq-wkem-validation-20260918`, note `research/pq-wkem/sai107_confluent_sha_transducer_20261121/RESEARCH.md` blob `e42b249e59d770a257793a5ff79a3c9d7e020946`. Scoped issue comments since 2026-11-20 were empty. No Bitcoin/Core source/tests, network validation, external literature, or FE execution was performed this iteration.

SAI107's exact missing operation was compact, publicly usable transition of a hidden semantic-state label without revealing the global terminal key or enumerating exponentially many semantic states. Rather than changing hash placement, degree or randomization, this attempt replaces the hidden semantic-state labels with an authenticated **whole-evidence proof commitment**; it tests whether binding ALL SHA/AuxPoW trace positions to ONE Merkle root removes cross-witness label splicing without state enumeration.

## Candidate and constructive interface

Let `R_x(w)` be the approved fully bound ORIGINAL three-branch relation: greater exact Bitcoin work on the qualified same anchor; finite authenticated specific burn fault; or relevant Syscoin history inconsistency / independently authenticated applicable tag fault at required LC depth. A qualifying `w` contains original evidence, not merely a claimed acceptance bit.

A classical transparent proof system `Prove(x,w;rho)->pi`, `Verify(x,pi)` might commit to a consistent trace by `r=MerkleRoot(pi)`. An honest receiver can bind all opened local constraints to the SAME `r` and check the proof off-chain. This is only an **authentication and consistency improvement** over SAI106's independently reusable local gate labels; it does not, by itself, deliver a secret.

Try an explicit source-conditioned encrypted signature with root-dependent pad:

```
k_r = H(domain || r)               [public-root alternative]
Delta_r = sigma_cancel XOR k_r
Open(C,pi) = Delta_r XOR H(domain || r), after proof verification.
```

For a fixed `r`, this is correct if `Delta_r` is provided. A legitimate DIFFERENT original certificate may have a different proof `pi'`, `r' != r`, and must nevertheless open the **same** frozen sigma. The public `Compile(x,sigma)` runs before ANY such future root exists.

If every supported root has a separately published `Delta_r`, completeness requires entries for every possible qualifying root. Any finite explicit set `I` missing a valid root violates the ORIGINAL every-witness condition. A polynomial bound on verifier randomness or on local PCP test *types* does NOT bound the number of distinct global proof roots. Conditional on a language with superpolynomial distinct accepted proof roots, explicit root-keyed tables are not classical-PPT Build.

Alternative A: `Delta(r)=sigma XOR H(domain||r)` as a public formula. Reading or evaluating its public constant sigma (or evaluating at an attacker-selected r) immediately releases it. Checking `Verify(x,pi)` in an external wrapper cannot repair an arbitrary direct invocation of the public formula.

Alternative B: `k_r=PRF_s(r)` for erased private setup seed s and publish compact `Delta(r)=sigma XOR PRF_s(r)`. To evaluate this only on verified roots without exposing s or sigma, one needs an independently instantiated protected public evaluation of the whole verification function (FE/WE/iO-like). Rebranding `Delta` as a Merkle token, a proof commitment or a hash oracle does not instantiate it.

Alternative C: enforce one canonical proof root `r_x`. If `r_x` is public and its pad is public, it releases early; if it is secret, there is no classical public derivation from arbitrary ORIGINAL witnesses. Requiring all witnesses to generate the exact same proof root is an unjustified extra condition and can silently reject legitimate competing histories/burn refutations.

The relevant accept-and-release equation remains

```
C <- Build(x, sigma_cancel; rho)
Open(C, w) = sigma_cancel                 for EVERY original R_x(w)=1
```

with security of the **entire serialized public C**. A public root verifies proof consistency, not the hidden conditional-release computation. No independent FALSE/hard-TRUE classical or QPT simulator, source-extracting recovery reduction, malicious setup / sibling composition, or valid native output was produced by this root substitution.

## Joint-public security assessment

The joint view includes all hashed proof roots and their Merkle branches, the relation/verifier versions, native VK and message, the capsule/graph commitments, sibling capsules and corrupted source-generation coins. A simulator can generate proof commitments and check consistency, but cannot simulate a *hidden* `Delta(r)` for all accepted roots without either the secret sigma, an explicit enumeration, or a new cryptographic gate. A simulator that receives the actual target capsule or a release oracle is circular. Consequently this is not a conditional theorem with independently instantiated premises.

This conclusion is about the **root-indexed token family**, not a generic impossibility of hash-only witness encryption. We made no synthetic/test-pass claim and did not claim network-fork reachability statistics. Only a new protected root-independent gate that is actually encoded in polynomial-size classical public bytes, with original-source extraction security, would merit continuing this candidate. Do not repeat this as a new hash-placement, lookup, canonical-proof or PCP-local-check experiment.

**NONQUALIFYING.** No breakthrough comment/user notification, source release, production edit, PR review, network deployment or automation change.
