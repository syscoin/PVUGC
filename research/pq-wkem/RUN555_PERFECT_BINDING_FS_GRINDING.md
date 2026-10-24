# Run 555 — perfectly binding Fiat–Shamir admission still lacks all-input release soundness

**Starting verified GitHub PR head:** `f3f819a96f73c048e1f3249a5a7942f50f180cc7`. Branch `research/pq-wkem-validation-20260918`, syscoin/PVUGC#1, 2026-10-16. Research only.

## Scoped new result
Runs 552–554 showed that a computationally inaccessible accepting proof, adaptive-CRS selection and Merkle equivocation each disrupt a proposed universal FE-style release proof. This pass removes all three special conditions: hold one ORIGINAL-false statement x fixed; generate setup honestly; and use a **perfectly binding** commitment C=(a,nonce), with a t-bit a. There are no alternate openings for the same C.

In a public-coin interactive source-admission experiment the prover publishes C *before* the independent uniformly random t-bit challenge c. Acceptance is [a=c]. Even an unbounded dishonest prover has exact success probability 2^(-t) for each precommitted C.

Fiat–Shamir instead defines c=H("FS"||x||C) using an ideal t-bit random oracle. Fix a=0^t and vary N distinct public nonces. The hash inputs are independent. Hence

`Pr_H[exists accepting false-statement C among N choices] = 1-(1-2^(-t))^N.`

With N=2^t this approaches 1-e^(-1); with N=16*2^t it approaches 1-e^(-16). These are exponential-search existence statements, not PPT or QPT breaks at cryptographic t. A classical public evaluator finds a winner in approximately 2^t trials. Domain-separating x/UTXO/branch prevents replay, but does not prevent chosen-nonce grinding *within* one bound context.

**Coherent quantum attack.** With quantum-accessible H, B(nonce)=[H(x,(a,nonce))=a] is a reversible predicate. Given M winners among N candidates and theta=arcsin sqrt(M/N), q Grover iterations succeed with exactly sin^2((2q+1)*theta). Choosing N=16*2^t gives M≈16 and q=Theta(2^(t/2)) queries for constant success. This is an ideal-oracle query complexity, not SHA-256 gate/memory cost or an asymptotic polynomial-time quantum attack. For this particular attack, 128-bit QROM *query* resistance necessitates approximately >=256 bits of effective challenge entropy; this is not a sufficient security bound for realistic FRI/STARK/WKEM systems.

## FE / original-source interface
For the attempted protected gate F_{x,H}(K,pi)=K when pi=(a,nonce) passes this public FS verifier, and bottom otherwise, a winning false-statement pi causes F(K0,pi) != F(K1,pi) for distinct protected capabilities. Thus **pointwise all-proof equality**, as required by a straightforward ordinary FE indistinguishability argument, is false even with perfectly binding commitments. Importantly, query-bounded QROM FS soundness can still hold when finding a winning pi is exponential. An FE security notion tolerating computationally inaccessible accepting inputs would require its own proof jointly with public keys and capsule correlations; we do not assume it.

No accepted full ORIGINAL representation is obtained. Run 259 (`GLOBAL_FINGERPRINT_SOURCE_BINDING_RUN259.md`, blob `c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2`) gives downstream extraction only for complete representations satisfying its residual hypotheses, not short FS transcripts or bare native signatures.

## Attack coverage / model
Honest compiler/verification is classical PPT; public outputs include the whole commitment, hash, relation x and any checking key; attacker may be arbitrary QPT with coherent oracle and related capsules. Direct chosen-input/hash grinding and coherent search are exhibited. Local seam/gauge attacks do not apply to this toy; malicious setup, witness privacy failures, cross-UTXO replay and multi-capsule masks are unnecessary. No secret credential is placed in this toy checker: the example targets the admission predicate that a future release gadget would call. Other attack families remain unproved for any actual candidate.

The exact committed JavaScript checker `run555_perfect_binding_fs_grinding_check.js` enumerates interactive challenges for t=2..10, tests exact binding of (a,nonce), searches deterministic finite pseudo-oracle fixtures and checks the analytic Grover-amplification identity. The larger independent Python/SHA-256 finite checker, proof and output were also executed and preserved locally. Deterministic fixtures are NOT random-oracle security experiments.

## Literature and handoff
Don–Fehr–Majenz–Schaffner (2019, arXiv:1902.07556) establish QROM security of Fiat–Shamir under precise conditions; Don–Fehr–Majenz (2020, arXiv:2003.05207) state that Grover witnesses a tight quadratic loss. Attema–Fehr–Klooß, Journal of Cryptology 36:36 (2023), DOI 10.1007/s00145-023-09478-y, full HTML introduction/Main Theorem inspected: multi-round FS reduction loss depends on structure and query count. The present toy is not claimed to satisfy their special soundness hypotheses or to break a deployed proof system.

**What is proved:** the exact interactive 2^(-t) bound, exact ideal-oracle existence probability, conditional amplitude formula, and failure of an all-input equality premise. **What is not proved:** concrete QPT false-instance hiding, any WE-like construction, unauthorized final-native-signature-to-ORIGINAL extraction, malicious honest-erasure N-of-N setup, related-capsule security or 128-bit practicality. Canetti–Luo–Zhang/RIO remain architectural references, not concrete QPT assumptions. The conditional P2MR/SLH endpoint is not activated or used. Bitcoin would still only check an ordinary signature if a release primitive were ever built. No production changes. Stop condition unmet.
