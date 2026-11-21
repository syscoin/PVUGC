# Run 628 — Quantitative noisy local-gauge reconciliation falsifier

2026-10-19. Research only; syscoin/PVUGC PR #1; branch research/pq-wkem-validation-20260918; starting SHA 77b0723b3d69b6c66c340cf58bcd1aa0851896c4. No production modification or completed PQ witness-KEM. This is a toy local-mixing carrier counterexample, NOT an attack on CCMR/RIO, genuine Gaussian SOURCE, or a complete relation-gated WE construction.

## Model and exact finite law

Let t>=3 be separately published capsule groups, with one edge per group on a directed t-cycle. Underlying edge bits u_i satisfy XOR_i u_i=b, where b is a secret bit. Honest classical PPT setup samples uniform independent vertex frames f_i in F_2 and independent Bernoulli(p) edge errors eta_i, 0<=p<=1/2. Publish z_i=f_i XOR u_i XOR f_(i+1 mod t) XOR eta_i. Group names, relation/context labels, and optional auxiliary advice in the positive subset theorem are b-independent; the full attack remains valid with extra published checking keys. An arbitrary QPT attacker sees all published classical bytes and may coherently compute public functions; common b-independent quantum advice is permitted.

Every *proper* subset of capsule groups forms a forest. Its exact joint edge distribution is independent uniform in either bit world: fix errors and output edges, choose one frame at each tree root, then all remaining frames are forced.

For the whole cycle, XOR_i z_i=b XOR XOR_i eta_i. Put delta=(1-2p)^t. Therefore

Pr[Z=z | b]=2^(-t)[1+(-1)^(XOR_i z_i XOR b) delta].

Consequently TV(Law(Z|b=0),Law(Z|b=1))=|delta|, and the public parity test is optimal with success (1+|delta|)/2. This exact quantitative calculation extends the noiseless shared-frame counterexamples in Runs 626–627, but only in their specified transparent XOR masking model.

## Independent noise amplification and secret recovery

Generate r independent cycles, each with fresh masks/errors but the same bit b. Every proper subset of the t groups is still statistically independent of b. With every group public, majority of the r public parities recovers b with error at most exp(-r delta^2/2) (Hoeffding, delta>=0). Repeating independently for each of lambda secret bits K yields total failure at most lambda exp(-r delta^2/2), by union bound.

For t=3, p=1/4, delta=1/8, lambda=128 and r=16384, the upper failure bound is 3.29242799698229096e-54, below 2^-128, with 6,291,456 raw public edge bits (786,432 packed bytes) and O(lambda r t) classical XOR work. Attacker receives NO ORIGINAL witness or source-gated oracle. The public toy representation itself exposes the bearer K; it is NOT a cryptanalytic attack on a realized witness-KEM, because no such admission gate was constructed here. Public native checking keys cannot undo key recovery; incomplete-view hiding excludes b-correlated checking-key auxiliary data.

## Exactly canceling noise is gauge noise

For any connected graph, every cycle has XOR eta_e=0 iff eta_e=a_src XOR a_dst for vertex potentials a_v. Fix a spanning tree root and propagate a_v along tree paths; every non-tree edge obeys the desired equality precisely when its fundamental cycle parity vanishes. Thus eta can be absorbed by f'_v=f_v XOR a_v and does not change any public cycle invariant. When original frames are independent uniform and independent of eta, f' remains uniform. Conversely p=1/2 makes the whole transcript information-theoretically independent of b; a b-independent witness label without extra secret-correlated inputs cannot decode b. This is not a no-go theorem for nonlinear/nontransparent cryptographic reconciliation.

## Security scope and nine attack classes

(1) Local seams telescope; (2) global gauge synchronization leaves cycle parity; (3) full-cycle distribution carries a statistical fingerprint; (4) all t distinct capsule groups reveal what every strict subset hides; (5) chosen-input/adaptive evaluator access is unnecessary; (6) the attack uses honest setup and no retained randomness, malicious seeds remain an unproved additional hazard; (7) per-UTXO labels do not stop public joins within a shared cycle, but truly independent keyed contexts are outside this exact attack; (8) checking-key correlations are not needed for the break and are not covered by positive restricted-view hiding; (9) for common independent quantum advice, classical transcript trace distance equals TV, and a classical PPT key-recovery attack already defeats QPT hiding of this toy carrier. No quantum-only attack or QPT guarantee for a distinct realization is claimed.

Run 259 requires an accepted COMPLETE original source representation; a cycle-bit leak supplies none. The Run 625 ideal coherent release oracle does not model unrestricted white-box analysis of public edge tables. No common short preimage, canonical witness, new WE-equivalent hardness assumption, or Bitcoin on-chain NP evaluation is introduced.

## Exact executed checker and handoff

The standard-library Python checker run628_noisy_cycle_check.py passes 3427 counted assertions, over 12 fully enumerated t/p worlds, proper subset marginals, 504 zero-cycle/coboundary assignments, exact majority/TV identities and the 128-bit bound. Two executions were byte-identical, and syntax compilation passed. The captured JSON is exact stdout. Finite identities provide no cryptographic security evidence.

Canetti–Chamon–Mucciolo–Ruckenstein's TCC 2024 local-mixing framework and a September 2026 quantum extension are only architectural context; their full proof/errata were not newly audited, and they do not instantiate this simple XOR model by assertion.

Next constructive work: a *genuinely source-authenticated* small public release frontier with all valid ORIGINAL witnesses obtaining the SAME branch-bound protected native capability while complete-public-output false-instance and hard-true QPT security, arbitrary recovery/forgery-to-ORIGINAL extraction, one-honest N-of-N erasure, multiple-capsule and checking-key correlations, unlimited SOURCE history support, and 128-bit practical parameters are actually proved. Those properties are UNPROVED. Conditional P2MR/SLH only supplies a hypothetical native endpoint; Bitcoin must not evaluate NP proofs. PR remains draft/unmerged; do not disable research automation.