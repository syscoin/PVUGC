# Run 571 — cyclic-shift local mixing embeds a dihedral hidden-subgroup problem

Date: 2026-10-16. Research only. Exact starting live PR head `7e1ccb3912959f1449125b2f8f754155ab01894c`, branch `research/pq-wkem-validation-20260918`, draft/unmerged. Before this research, GitHub reads confirmed the PR, latest 265 comments (latest substantive comment 6067040320), exact Run 570 blob `fd35828a0c397c4e98cc7d9eca15eb0be9277aff`, CLZ assessment blob `c19d9d9cd515140e3ce62eac960cd548c0add622`, and Run 259 blob `c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2`.

## Narrow subproblem

Runs 568–570 eliminated symmetric and directed public **XOR** seams using coherent Simon/hidden-shift attacks. Could replacing XOR-coordinate translation with *addition with carry mod 2^n* avoid that? A generic modular shift no longer satisfies the specific XOR-period promise, but the complete three-view oracle reduces *exactly* to a dihedral hidden-subgroup instance. The known quantum algorithm is **subexponential, not QPT/polynomial**; this checkpoint does not demonstrate a QPT break or 128-bit parameters.

## Exact oracle and reduction

Let N=2^n, `A,B:Z_N -> {0,1}^m` be public and `delta in Z_N` secret. Expose separately coherent public A, B, and

`F_delta(s)=A(s) XOR B(s+delta mod N)`.

Adversary cancels `A` to evaluate `G_delta(s)=F_delta(s) XOR A(s)=B(s+delta)`. Define the dihedral group `D_N=Z_N semidirect Z_2`, with multiplication

`(x,b)*(y,c)=(x+(-1)^b*y mod N,b XOR c)`.

Build an oracle on the dihedral group:

`O(x,0)=B(x); O(x,1)=G_delta(x)=B(x+delta)`.

Let `h=(-delta,1)`. It satisfies `h*h=e`. The right coset `(x,0){e,h}={(x,0),(x-delta,1)}` has one identical O-value B(x). Likewise `(x,1){e,h}={(x,1),(x+delta,0)}`, both yielding B(x+delta). **If B is injective, these are exactly the oracle fibers.** Therefore the public coherent interface is a valid dihedral HSP oracle for the hidden reflection, revealing delta to an algorithm solving this HSP. No assumption that A itself is random is needed for this algebraic reduction.

A Fourier transform over the cyclic coordinate of a coset state `|x,0>+|x-delta,1>` gives relative phase `exp(-2*pi*i*k*delta/N)` at Fourier frequency k (positive-exponent QFT convention). This matches the standard dihedral coset state.

If B is ideal uniform random with m output bits, the collision union bound gives
`Pr[B noninjective] <= N(N-1)/2^(m+1) < 2^(2*n-1-m)`.
For `m>=2*n+kappa`, exact HSP promise holds except with probability below `2^(-kappa-1)`. The ideal oracle is **not** a claimed classical-PPT instantiation or concrete QPT random-oracle proof.

Greg Kuperberg's published DHSP algorithms have complexity `2^O(sqrt(log N))=2^O(sqrt(n))` in quantum time, with space tradeoffs. Crucially this is **subexponential but not polynomial**: this run DOES NOT prove failure against asymptotic arbitrary QPT. Actual coherent implementation resources and algorithm constants are not calibrated. A simpler Grover inversion from `G_delta(0)=B(delta)` costs `O(2^(n/2))` coherent queries if B injective. Thus n=128 gives at most about 64 bits generic Grover search cost; n>=256 is necessary **but not sufficient** for a 128-bit work-factor goal, given the dihedral algorithm. Do not assign a concrete Kuperberg bit-cost from big-O.

If B has an efficient public inverse, delta is classically recovered as `B^-1(G_delta(0))`; this preserves the previously known transparent-reversible-circuit failure, not a new attack. For short-output noninjective B, the strict DHSP promise and random-function bound above do not apply automatically; do not transfer Run 570's XOR-Sidon bound to cyclic offsets without proof.

## Exact attack-surface boundaries

(1) Seam cancellation: public A cancels. (2) Gauge: delta becomes the dihedral reflection. (3) Single-view random-looking outputs do not establish security for the joint triple. (4) One triple suffices; related statements and reused shifts compound exposure. (5) Coherent chosen input to all public algorithms is necessary; classical API-only access is not equivalent. (6) Honest construction suffices for the ideal attack; retained delta independently defeats a keyless builder. (7) Context-separated KDFs cannot hide a recovered delta. (8) Native public checking keys can be included as auxiliary information and are not needed for the reduction. (9) The genuine quantum attack is DHSP/Kuperberg, **not** Simon polynomial time or Grover alone.

If `K_x=KDF(ctx_x,delta)` and delta is its only hidden ingredient, its recovery releases K without an ORIGINAL witness. If K depends on independently protected material, this implication is not established.

No relation-dependent late-witness Join or WE-like release has been built; no all-witness SAME capability, false-instance QPT hiding, true-instance arbitrary unauthorized recovery-to-ORIGINAL extraction, N-of-N erasure/abort, multi-capsule security or 128-bit parameters are proved. Run 259 still applies **only after** a complete accepted source representation is produced, not to delta or a native signature. The conditional P2MR/native-SLH Bitcoin endpoint remains unimplemented; no Bitcoin proof verification is proposed.

## Primary literature and reproducibility

Primary statements inspected October 16, 2026: G. Kuperberg, *A Subexponential-Time Quantum Algorithm for the Dihedral Hidden Subgroup Problem*, SIAM J. Computing, DOI https://doi.org/10.1137/S0097539703436345 ; G. Kuperberg, *Another Subexponential-time Quantum Algorithm for the Dihedral Hidden Subgroup Problem*, TQC 2013, https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.TQC.2013.20 ; O. Regev, *A Subexponential Time Algorithm for the Dihedral Hidden Subgroup Problem with Polynomial Space*, https://arxiv.org/abs/quant-ph/0406151. Full PDFs and concrete constant factors were **not audited**; the group-law proof and finite checker are independent. No claim is made against CCMR/CLZ's actual public programs.

The adjacent exact executed checker and output test all nonzero shifts at n=2..8 with three deterministic public A/B instances each, exact dihedral cosets, Fourier phase identities and public-inversion negative controls. No quantum hardware or Kuperberg algorithm was executed.

**Handoff:** Cyclic shift is a DHSP attack surface, not an established escape from Simon. Develop a source-authenticating local late-witness mixer with an independently justified QPT reduction; no practical PQ WKEM achieved.
