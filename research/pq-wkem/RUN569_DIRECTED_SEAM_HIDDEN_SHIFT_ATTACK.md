# Run 569 — directed public seam hidden-shift reconstruction

Research-only bounded falsifier, 2026-10-16. Draft syscoin/PVUGC#1, branch research/pq-wkem-validation-20260918, starting head 8c8600aeb47aa44f910877915c615dd8e85150ff. Exact Run 568 note blob b0e7ddc93d047efd70059c5e9a581baf43d3d1db; CLZ applicability blob c19d9d9cd515140e3ce62eac960cd548c0add622. No actual witness-KEM, Bitcoin change, or new quantum algorithm is claimed.

## Directed local seam and full public attack model

Classical-PPT honest setup samples independent ideal public random functions A,B:{0,1}^n -> {0,1}^m and an independent uniform secret nonzero n-bit displacement Delta. A hypothetical opaque deterministic seam evaluator exposes F_Delta(s)=A(s) XOR B(s XOR Delta). All public code/function oracles, auxiliary information, capsules and native checking keys are in the arbitrary QPT adversary view, and coherent access to deterministic public A,B,F is explicitly granted. This is a deliberate ideal-oracle toy model, not a concrete circuit-hiding construction or a release function authenticating ORIGINAL source witnesses.

## Theorem 1: no single-view shift information, no isolated period

Conditional on B and Delta, uniform independent A(s) make the F(s) values independent uniform. Thus (B,F) has the same distribution for all Delta. Symmetrically, conditional on A and Delta, B(s XOR Delta) is a permutation of independent uniform B values; (A,F) has the same distribution for all Delta. (A,B) itself is independent of Delta. Nonetheless the joint (A,B,F) is not.

Indeed, F alone is a uniform random function even conditional on B. For any fixed d != 0, the probability it has global XOR period d is 2^(-m*2^(n-1)). The probability of any nonzero period is at most (2^n-1)*2^(-m*2^(n-1)). A directed seam generally has NO Run 568 single-oracle Simon period.

## Theorem 2: combined oracle has a strict Simon period

Compute the public left-cancelled function G(s)=F(s) XOR A(s)=B(s XOR Delta). Form J(s,b)=B(s) when b=0 and J(s,b)=G(s) when b=1. Then J(s,b)=J(s XOR Delta,b XOR 1).

If B is injective, these are exactly all equal-output pairs. J is a strict two-to-one Simon oracle on n+1 bits, with hidden period p=(Delta,1). For uniform B, Pr[B not injective] <= binom(2^n,2)2^-m < 2^(2n-1-m). Thus m>=2n+kappa gives probability of injectivity at least 1-2^(-kappa-1).

Simon samples are uniform y orthogonal to p. After t=n+kappa' coherent queries, the failure probability to span the n-dimensional orthogonal subspace is below 2^(-kappa'). Solving the linear system and taking the nonzero null vector recovers Delta in O(n+kappa') quantum oracle calls and polynomial classical work. This is a standard injective hidden-shift-to-Simon reduction, not a novel quantum algorithm.

The two failures together are less than 2^(-kappa-1)+2^(-kappa'). If the sole hidden input to the protected KDF is Delta, K_x=KDF(x,Delta) becomes publicly computable; otherwise recovering Delta alone does not imply capability recovery. A native signature is not an ORIGINAL-witness proof, and Run 259's complete-accepted-representation extraction cannot be invoked on Delta or a naked signature.

## Focused attack taxonomy

(1) Seam: A cancels algebraically. (2) Global frame synchronization: recover Delta. (3) Fingerprint: single F is uniform/nonperiodic despite joint failure. (4) Multi-view: (A,F), (B,F) separately reveal no Delta, but (A,B,F) permits attack; reusing Delta compounds harm. (5) Chosen-input: construct coherent controlled J; measurement-only access does not imply this bound. (6) No malicious setup needed; retained randomness separately unsafe. (7) Domain separation alone cannot save a KDF whose only secret is recovered Delta. (8) Checking keys are part of the view but are unused in shift recovery. (9) This is genuinely coherent hidden-period recovery rather than Grover.

This does NOT establish an attack on CCMR or CLZ, where one frame may be unavailable as a separate coherent oracle. It does NOT solve false-instance QPT hiding, true-instance unauthorized recovery/native-signature forgery -> ORIGINAL, all-witness SAME capability, N-of-N setup/erasure, cross-UTXO security, resource estimates or native P2MR/SLH endpoint. In particular, this is not a new narrow local-mixing assumption and is not a practical WKEM.

## Reproduction and literature

Standard-library Node checker run569_directed_seam_hidden_shift_check.js deterministically evaluates 42 configurations (n=3..8); checks 42 nonperiodic directed F instances, 3,528 two-element fibers, 1,223,040 Fourier cancellation identities and 42 recovered shifts from simulated Simon samples. Output in run569_directed_seam_hidden_shift_validation.json. Toy arrays use a PRNG and reject collisions in B: no random-oracle sampling claim, cryptographic implementation, or physical quantum query.

Daniel Simon, On the Power of Quantum Computation, SIAM J Comput 26(5), 1997, https://doi.org/10.1137/S0097539796298637. Mirmojtaba Gharibi, The non-injective hidden shift problem, Waterloo 2012, Theorem 3.5, https://uwspace.uwaterloo.ca/items/d713cdc4-2448-44cb-a76b-f4d37b4d6be4. CCMR TCC 2024 https://doi.org/10.1007/978-3-031-78023-3_2; CLZ CRYPTO 2026 https://doi.org/10.1007/978-3-032-35367-2_18.

Handoff: test the complete public view for a separable pair of shifted functions, not just single-seam Simon periods. Preserve source authentication and exact ORIGINAL extraction scope. All practical WKEM requirements remain UNPROVED.