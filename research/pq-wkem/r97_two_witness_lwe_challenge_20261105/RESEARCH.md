# R97 — Two-ORIGINAL-witness honest-LWE challenge embedding: restricted exact obstruction

**Run:** R97-TWO-WITNESS-LWE-CHALLENGE-20261105. **Result: NO POSITIVE CONSTRUCTION ADVANCE.** This is an exact attempted continuation of R96's genuinely honestly sampled LWE leaf and R89's broken 3CNF bounded-error source; it does NOT establish a secure general WKEM or a new hardness assumption.

**Continuity/provenance.** syscoin/PVUGC#1 was open, draft, unmerged at starting commit `77a0bafc3564f030ffd64a38774ab3cb13915501` on `research/pq-wkem-validation-20260918`. Read exact R96 `research/pq-wkem/r96_mandatory_honest_lwe_source_20261105/RESEARCH.md` blob `4c2196f0646b0a2a59509314885a37d297b1917c`, exact R89 source compiler note blob `4e42a958ccd6a9ae0c26886d5a73ba69856065f5`, and ordinary latest relevant PR comment `6670584741`. No external literature or web research.

## Targeted candidate and exact distribution

Attempt to replace R89's publicly distinguishable, publicly decryptable BDD source (A,b) with an **actual honest ordinary-LWE source public key**, while preserving two predetermined distinct ORIGINAL witness-derived decryption states. Let q be prime, m,d≥1, 0≤β, 2β+1<q and E={−β,…,β} embedded modulo q. Fix distinct s0,s1∈Zq^d independent of fresh A. Even generously give the proposed compiler the secret s0. It samples A uniform from Zq^(m×d), e0∼χ^m with χ supported in E, and B=A·s0+e0 mod q. This is a real standard LWE public-key distribution, with no supplied SourceOpen oracle.

For s1 also to be a valid bounded-error source secret under this SAME public (A,B), every row must satisfy B_i−A_i s1∈E. But B_i−A_i s1=e0_i+A_i(s0−s1). Since s0−s1≠0, A_i(s0−s1) is exactly uniform in Zq, independently across i, even after conditioning on all e0. Thus

`Pr[||B−A s1||∞≤β | fixed distinct s0,s1] = ((2β+1)/q)^m`.

This is an unconditional exact probability statement for **fixed predetermined distinct secret vectors independent of A**, not an impossible-ALL-WKEM theorem. For t−1 additional fixed predetermined distinct candidates, union bound gives (t−1)·((2β+1)/q)^m. Identical secrets s0=s1 are exceptional (probability 1), and A-dependent witness-to-secret maps invalidate this fixed-vector calculation. This does NOT prohibit different ORIGINAL witnesses retaining different states in another construction.

Illustrative, uncalibrated q=65521, β=3, m=1649 gives log2 collision probability ≈ −21754.127 for a prescribed second state. This is NOT a concrete 128-bit QPT hardness or distributional NP security estimate.

## Why this does not complete the source/challenge simulator

R96's honest LWE PKE INDCPA simulator can inject a challenge for its LWE-key ORIGINAL predicate. For arbitrary ORIGINAL NP x, R89's extracted source key s(w) is determined by the satisfying assignment and its slack variables. Merely supplying a genuine LWE challenge A,B for an arbitrarily different s0 does not give the compiler an equal-distribution statement-dependent source where EVERY ORIGINAL s(w) satisfies bounded error. A preselected pair already fails with the probability above. Conversely retaining R89's structured (A,b) and placing a scalar LWE pad around C does not simulate honest ordinary-LWE public-key setup and leaves its original public v-only release attack. The precise unsimulated correlation is **(x, source public B, actual openings s(w), ciphertext C, checking CK, context, auxiliary, related capsules)**, not marginal pad INDCPA.

The separately checked affine-public-shift negative control uses b′=b+A t and ciphertext (u,v′). If t is public, v′−tᵀu=bᵀr+ΔT, retaining R89's public rounded bit. Private t without witness access prevents straightforward original-only opening. This negative control is already known from R89 and is NOT counted as a repair or advance.

## Executed offline exact checker

The published **actual V8 checker** `checker.js` (its function `runR97` was executed before and during publication) passed **3,566** assertions. For each q∈{7,11,13}, with d=1,m=2,β=1,s0=1,s1=2 it exhaustively iterated q²·3² honest key random tapes, obtaining 81 qualifying second keys out of 441/1089/1521 respectively: exactly 9/49, 9/121 and 9/169. It also checked public affine-shift leakage. Captured exact output is in `captured-output.json`. A separate **LOCAL-ONLY** Python checker independently passed 3,573 analogous assertions (includes identical-secret exception). Neither is quantum security experimentation, and no successful source compiler was constructed.

## Security and exact next obligation

Honest setup/evaluation in the desired final construction must be classical PPT; the attacker is arbitrary QPT with nonuniform independent advice, joint coherent processing, checking-key/aux/other-capsule correlations and allowed classical selective openings. This lemma is information-theoretic for fixed secret candidates and assumes none of that quantum machinery; it proves no full-public false-x hiding and no unauthorized hard-TRUE extraction.

The next constructive candidate must avoid demanding that two distinct ORIGINAL witness-derived **fixed** secrets simultaneously decrypt a single independently sampled honest LWE challenge key. Instead find a concrete classical-PPT `Comp(R_original,x)` and genuine QPT-LWE challenge simulator that jointly produce **all public outputs** without knowing a witness or challenge secret; every valid original w must independently recover the same precommitted capability T, and an arbitrary QPT T-recovery/native forgery must imply an actual ORIGINAL witness or an independently justified QPT break, without an adversary-supplied representation. Do not assume a common short preimage, canonical witness, iO/WE, SourceOpen oracle, or online committee to fill this gap.

The N-of-N no-bypass graph, one honest preauthorizer and private audit/erasure baseline from R95, pre-funding availability and safe aborts, claim/path binding, source SYS/BTC fork/ancestor/interval-tag rules, unrelated-capsule separation, and conditional hypothetical Bitcoin native PQ signature/P2MR-like endpoint remain requirements, NOT proved by R97. Bitcoin does not verify original NP/proofs/VM/PCP. The stopping criteria are unmet; leave the existing research automation enabled.
