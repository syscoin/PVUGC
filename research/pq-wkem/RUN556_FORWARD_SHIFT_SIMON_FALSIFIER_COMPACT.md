# Run 556 — forward-only local frames fail a coherent Simon test

Verified starting PR head: `3e7af956f0bb9de47681bf08642e7b42cce91c72`, branch `research/pq-wkem-validation-20260918`, open/draft/unmerged. This is a focused **ideal-oracle falsifier**, not a WE construction or a claim against Canetti–Luo–Zhang.

## Exact family

Choose a hidden nonzero `Delta` uniformly from `{0,1}^n` and an independent uniform permutation `P` on `{0,1}^n`. Publish *two forward-only opaque* maps:

`F0(z)=P(z)` and `F1(z)=P(z xor Delta)`.

Each **individual** map has a perfectly uniform random-permutation distribution, independent of Delta. A classical observer with only forward oracle access needs birthday-scale cross-collision queries: `F0(a)=F1(b)` iff `Delta=a xor b`. With q0 and q1 queried inputs, at most q0*q1 candidate shifts are tested, and the no-collision transcript contains no extra shift information for uniform P. Constant-success classical oracle discovery requires `Omega(2^(n/2))` queries; this is **not** a concrete security claim for readable public code.

## Quantum theorem

Combine the maps into `G(b,z)=F_b(z)=P(z xor b*Delta)`. By injectivity of P,

`G(u)=G(v)` iff `u=v` or `v=u xor sigma`, where `sigma=(1,Delta)`.

G has the **exact** Simon two-to-one promise. With coherent public evaluation, Hadamard sampling yields uniformly random vectors `y` satisfying `y dot sigma=0` in GF(2). For domain dimension n+1, n+c independent samples span the n-dimensional hyperplane with probability at least `1-2^(-c)`. Solve this system to recover Delta using `O(n+c)` quantum queries and polynomial processing. No inverse oracle or classical collision is required. At n=256 this is polynomial quantum work even though the ideal classical black-box collision scale is 2^128.

If a proposed protected capability is `K_x=KDF(full_context(x),Delta)`, the attacker derives K_x and checks it against the complete public verification object without any ORIGINAL witness. For a false statement this defeats hiding; for true-instance unauthorized recovery no Run-259 representation is supplied. If K_x is independent of Delta, this attack by itself **does not recover K_x**. This premise must be audited, not presumed.

## Model, scope, and non-circularity

Honest generation of an ideal uniformly random permutation is **not classical PPT**; the model deliberately gives an opaque *black box* to the defender to falsify a particular joint structure. It proposes no implementable mixer and assumes no WE/WPRF/RIO security. A public deterministic classical PPT evaluator that provides F0 and F1 can in principle be implemented coherently by a QPT attacker; an interactive classical-only oracle or randomized fresh encodings may not satisfy the Simon promise. Independently randomized branch maps or non-XOR linkage likewise need separate analysis.

The relevant attack families are joint local-seam synchronization, two-view correlation, adaptive coherent-input evaluation, and public checking-key correlations; malicious setup, retained randomness, replay and multiple capsules are **not needed**. No claim is made for those other families against unrelated designs. If Delta is reused between branches/UTXOs, related outputs worsen its exposure. Simon's algorithm is preexisting literature; the **application to this precise two-forward-map release encoding** is the bounded result here. Compare quantum/classical oracle distinctions in Alagic–Bai–Katz–Majenz, arXiv:2112.07530. This does not refute CLZ's actual construction or its quantum CCA claims.

## Executed checks and handoff

Exact V8 checker `run556_forward_shift_check.js` is provided with its captured JSON: **19535 assertions**, **31 parameter/shift configurations**, **155 exact Fourier-distribution recovery trials**. An independent Python checker was also executed twice locally (158,489 assertions, 68 configurations, 408 trials, SHA-256-captured output). These computations do not execute a quantum computer or certify QPT security.

Any local witness-dependent release frontier using shared opaque forward masks must test the **joint coherent evaluator** for hidden periods, not infer PQ hiding from single-view randomness or classical birthday estimates. The missing practical WE-like mechanism, all-valid-ORIGINAL-witness SAME capability, false-instance QPT hiding, arbitrary signature-to-ORIGINAL extraction, malicious honest-erasure N-of-N setup, multi-capsule composition and concrete 128-bit resources remain **UNPROVED**. The endpoint is still conditionally P2MR-like with native SLH-DSA-like signature verification; Bitcoin does not evaluate source evidence or a VM. Production unchanged; stop criterion unmet.
