# Run 526 — sparse nonlinear hidden frames leak a public loader fingerprint

2026-10-15; research-only syscoin/PVUGC#1. Starting head b97e62d5435913290da03df15a7e25963af805e3. This is a black-box **distinguishing** theorem, NOT protected-key recovery or a complete witness-KEM.

## Exact construction and theorem

Let P be an n-bit reversible permutation consisting of arbitrary affine gates (NOT/CNOT/SWAP/invertible linear layers) and at most r Toffoli gates. The attacker does NOT receive the P gate list. Suppose a public globally acting encoded witness loader has the form

    L(y) = P(P^{-1}(y) XOR v)

for a fixed nonzero semantic translation v. Choose q=2r+1 <= n, with 4q <= 2^n. Query L on q disjoint affine squares {x_j,x_j XOR u,x_j XOR w,x_j XOR u XOR w}. Define D_j as the XOR of the four output words.

**Theorem.** For every specified sparse P, rank_F2(D_1,...,D_q) <= 2r, regardless of the affine mixing depth. For a uniformly random P, L is a uniform fixed-point-free involution. With N=2^n and m=4q, the probability its q difference vectors have full rank q is at least

    PROD(i=0..q-1)(1-2^(i-n))
    - m(m-1)/(2(N-1)) - m^2/N - m(m-1)/(2N).

Thus a deterministic classical 4q-query rank test distinguishes sparse nonlinear frames from ideal uniformly mixed loaders. A QPT adversary can run this test, but no coherent-query speedup is claimed.

**Proof.** Any affine-plus-s-Toffoli circuit F can be expanded as F(x)=Ax XOR b XOR SUM_j v_j*h_j(x), where the v_j are fixed output vectors obtained by propagating each Toffoli target through subsequent affine layers, and h_j are arbitrary Boolean scalars evaluated on intermediate states. The second XOR derivative eliminates Ax+b and lies in span(v_j), of dimension <=s. The loader is composed of P^{-1}, an affine XOR-v, and P; the inverse uses r Toffolis, so s<=2r. For random P, conjugating a translation yields a uniform perfect matching. For m distinct query inputs, probability of an internal paired query is <=m(m-1)/(2(N-1)). Conditional on its absence the outputs are uniformly distinct outside the query set. Couple these with iid uniform words, paying at most m^2/N for a hit on an input and m(m-1)/(2N) for an output collision. The XOR of four independent uniform words is uniform, independent across disjoint squares, and q such words span dimension q with the product probability above. This proves the bound.

## Exact limits

The attack requires a public globally acting translation conjugate callable on arbitrary encoded states. Source-authenticated, claim-sector-guarded, or only atomic guarded terminals do NOT automatically expose this action. The result distinguishes the public loader from its ideal-frame model; it does not recover K_x, refute independent per-claim release, or prove the source predicate false. Replacing each Toffoli by a k-local nonlinear reversible gate gives a conservative k-dimensional nonlinear contribution per gate.

Attack taxonomy: no gate seam, no known reference and no native checking key; low-dimensional gauge and deterministic second-derivative fingerprint; chosen-input public evaluation; honest erased setup is insufficient to protect this particular public-loader distribution; relation/branch replay is not invoked; classical distinguisher also available to QPT. All-witness common-capability correctness, false-instance full-view QPT key hiding, arbitrary signature-to-ORIGINAL extraction, malicious N-of-N setup, multi-capsule composition, practical parameters, and native PQ Bitcoin graph remain unproved.

The exact executed JS checker supplies seeded n=12 and 16 finite trials: 320 sparse frames, 320 ideal uniform conjugates, q=2r+1, 4q chosen evaluations per case; repeated output was byte-identical. Tests are functional checks, not cryptographic proof.

Literature: Dujmovic–Haferkamp–Poremba, arXiv:2610.02100v1 (2026-10-01), Theorem 1.3 and Section 4.1 exhibit quantum **unitary** local walks with fixed-t adaptive design mixing yet O_t(log^2 n) coherent distinguishers. That is NOT a classical reversible RIO theorem. CCMR (ePrint 2024/006) still conditions iO on RIO/SCP assumptions; no concrete classical-PPT QPT-secure local release follows. This run's distinguishing theorem is separately proved above.

Production unchanged; PR draft/unmerged; practical stopping condition unmet.
