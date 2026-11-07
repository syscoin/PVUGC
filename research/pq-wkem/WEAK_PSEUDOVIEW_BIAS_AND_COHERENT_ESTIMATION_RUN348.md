# Run 348: fresh local masks do not imply safe multi-view release

Status: **focused conditional falsifier, not a construction, a break of a specific LWE scheme, or a post-quantum security proof.**

Live connected GitHub state read before research: syscoin/PVUGC#1 open/draft/unmerged, branch research/pq-wkem-validation-20260918, starting SHA 28038e42207d31ca3ac669d63bfdd1b78d9a6ca4, latest substantive ordinary comment 5945825660. Exact current-head dependencies read: Run347 note a651b129680d3d71d4b3006dc7294944041b058b, Run115 cf2ec9575948e16b58acbd870208686759f14e44, Run259 c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2.

## The new conditional attack

For a fixed public statement/capsule P_x with one hidden kappa-bit capability K, suppose a **public, witness-free** PPT sampler D_j(P_x;r) and public evaluator produce a bit B_j(r). Suppose, **conditioned on this fixed P_x**, every bit has the correctly oriented bias

Pr_r[B_j(r)=K_j | P_x] >= 1/2 + epsilon.

This is an explicit testable premise, **not** a claim that a public sampler with such bias actually exists in the proposed LWE local mixer. It must be established or falsified for each concrete construction.

**Theorem A — classical aggregation.** With M independent public evaluations per bit, majority decoding and Hoeffding give

Pr[K_guess != K | P_x] <= kappa exp(-2 M epsilon^2).

Hence M >= ln(kappa/delta)/(2 epsilon^2) yields full-key recovery with probability >= 1-delta, **without any ORIGINAL witness or accepted source representation**. If epsilon is inverse polynomial and the public procedures are PPT, this is a PPT attack. At epsilon=0.05, kappa=128, delta=0.01, M=1892 per bit suffices according to this conservative bound.

**Theorem B — independence of projectors is not the same as independence of outputs.** As an exact ideal-channel stress test, sample K uniformly and, for every view i and bit j, independent E_ij with Pr[E_ij=0]=1/2+epsilon. Let B_ij=K_j XOR E_ij. Each single B_ij is exactly uniform unconditionally, although independent E_ij and independent per-view randomness are used. Nevertheless

Pr[B_ij=B_lj] = 1/2 + 2 epsilon^2,

and the joint two-view distribution is at total-variation distance exactly 2 epsilon^2 from independent uniform bits. Multiple fresh views can therefore reveal the shared K through statistical correlation, with **no reused affine projector and no exact kernel cancellation**. This differs from Run347's attack. The uniform one-view claim is *not* conditional on native PK(K): such an auxiliary input can correlate with B, and remains part of the mandatory full-view game.

For independently corrupted kappa-bit candidate views, one whole candidate equals K with probability (1/2+epsilon)^kappa. For epsilon=.05, kappa=128, that is approximately 2^(-110.4), yet majority of polynomially many views recovers K. More starkly, let every view have exactly h incorrect bit positions chosen uniformly, 1<=h<kappa/2. **Every individual full-key view is guaranteed wrong**, while each bit is correct with probability 1-h/kappa >1/2 and majority still reconstructs K. This is a channel counterexample to a single-view full-key-success argument, not an implementation of a source-witness sampler.

**Theorem C — coherent quantum version.** If the public sampler and evaluator can be implemented coherently and reversibly using polynomial-size quantum circuits, a QPT adversary can use quantum amplitude estimation to estimate Pr[B_j=1] to additive error less than epsilon and recover K_j using O(epsilon^(-1) log(kappa/delta)) controlled public evaluations per bit; classical majority uses O(epsilon^(-2) log(kappa/delta)). This invokes the **actual** quantum phase-estimation/amplitude-estimation algorithm of Brassard–Hoyer–Mosca–Tapp, arXiv:quant-ph/0005055, section 4/Theorem 12. It does not assume QRAM for a static list, free quantum access to an external classical sampling appliance, or automatic superposition access to any unspecified oracle. If epsilon is negligible rather than inverse polynomial, this alone is not a QPT break. Quantum-query bounds are not fault-tolerant gate counts.

## Attack taxonomy and exact limits

The attack is weak-bias leakage at a local non-source evaluation seam, a pairwise statistical fingerprint, related-view/multi-capsule aggregation, adaptive chosen-input evaluation, and (under the explicit coherent-public-interface premise) a genuinely quantum amplitude-estimation attack. It does not require global gauge synchronization, shared projectors, cross-UTXO key reuse, malicious setup, or PK(K) correlations; those remain important independent obligations. Context/branch/claim binding does not remove correlations among multiple views of the **same intended branch key**. Independently keyed UTXOs need separate analysis.

Run259 establishes only accepted source-bound z -> ORIGINAL witness (information theoretically or under its stated SIS reduction). This attack outputs K directly; it does not produce an accepted z. The missing K recovery -> accepted z / independently justified QPT break remains missing. The full-public-output false-instance QPT hiding, true-instance early-recovery and accepted-forgery extraction, malicious N-of-N setup/keyless builder game, graph and native endpoint composition, and practical parameters all remain **UNPROVED**.

## Reproducibility and handoff

Exact new deterministic Python checker weak_view_bias_run348_check.py passed py_compile and two byte-identical executions: **53,694 assertions**, including independent-noise marginal uniformity and pairwise TV; exhaustive Hamming-sphere wrong-full-key controls through kappa=8; exact binomial majority error; ideal coherent phase-estimation probability calculations for M=32,64,128,256; and multi-view joint TV. These are algebra/probability checks, not actual LWE/SIS security or physical quantum experiments.

Next, for any concrete *fresh-projector* candidate, directly estimate or prove an upper bound on per-fixed-instance oriented bias of **efficiently public-samplable invalid-certificate distributions**, including all public auxiliary/checking keys and related capsules. A bitwise-noisy witness-free output can be fatal even when a complete wrong representation almost never outputs the full credential. This is a **falsification requirement**, not a new release assumption and not a completed practical PQ WKEM.

Primary reference inspected at theorem level: https://arxiv.org/html/quant-ph/0005055v1 (Theorem 12).
