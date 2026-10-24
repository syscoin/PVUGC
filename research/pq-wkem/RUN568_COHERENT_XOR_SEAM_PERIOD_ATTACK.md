# Run 568 — coherent hidden-period failure of a symmetric XOR local seam

Date: 2026-10-16. Research-only, draft syscoin/PVUGC#1, starting head 9c3899e4858af9f01afc8a23bf29d73aa2ba5a03, branch research/pq-wkem-validation-20260918. Verified latest ordinary substantive PR comment 6067040320. Exact dependencies at start: Run 567 note blob 6b48c45ae7e719a0cafc716af0ad7d33cf08f390, Run 566 note blob 7e21c5fbb9d7a872b91a9415da52d15e60f2efa7, Run 259 source binding blob c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2, CLZ applicability blob c19d9d9cd515140e3ce62eac960cd548c0add622.

## One narrowly scoped local-mixing candidate

Assume a proposed mixer uses an unknown XOR displacement Delta between neighboring frames and exposes a *swap-invariant* public seam fingerprint. Model the candidate by a uniformly random public function H:{0,1}^n -> {0,1}^m and an independent uniform nonzero Delta. The publicly evaluable deterministic seam is

F_Delta(s) = H(s) XOR H(s XOR Delta).

An independently domain-separated key may be K_x = H_key("branch" || x || Delta), with a native checking key also public. The attacker has the entire public view, chosen inputs, arbitrary auxiliary advice independent of fresh Delta, and QPT coherent query access to the deterministic seam. Honest setup is classical PPT relative to the public ideal random oracle, sampling Delta/context/optional key. Giving the defender a black-box rather than a transparent code representation only strengthens the falsification.

This is NOT a witness-KEM construction and supplies no ORIGINAL witness admission. It does not claim CLZ or CCMR exposes this function. The result removes one natural *symmetric XOR-frame seam* from consideration.

## Theorem 1: strict period with high probability

For every s, F_Delta(s)=F_Delta(s XOR Delta), because the two H calls swap. The N=2^n inputs form M=2^(n-1) disjoint pairs. The M outputs on pair representatives are independent uniform m-bit strings because their H-inputs are disjoint. Thus

Pr[all pair outputs distinct] = (2^m)_M / (2^m)^M,

and Pr[extra cross-pair collision] <= binom(M,2)*2^(-m) < 2^(2n-3-m). For m>=2n+kappa, with probability >1-2^(-kappa-3) this is an exact two-to-one Simon-function with hidden period Delta. Output marginal randomness does NOT preclude the joint relation.

## Theorem 2: coherent QPT period recovery

Simon Fourier sampling queries the deterministic public evaluator as a reversible oracle |s,z> -> |s,z XOR F_Delta(s)>. Measuring the output leaves a coset superposition (|a>+|a XOR Delta>)/sqrt(2). After Hadamards, the Fourier coefficient at y is proportional to

(-1)^(a dot y) * (1 + (-1)^(Delta dot y)).

Therefore every sample is uniform in Delta-perp, the (n-1)-dimensional linear subspace y dot Delta=0. After t=n-1+kappa' independent samples, the chance that some nonzero d outside span(Delta) remains orthogonal to them all is <2^(-kappa') by a union bound over the 2^(n-1)-1 distinct extra orthogonality constraints. Linear algebra then recovers Delta in O(n+kappa') coherent queries and polynomial postprocessing.

The two failure terms are <2^(-kappa-3)+2^(-kappa'). Any K_x depending only on a public KDF of secret Delta and bound context is now publicly reconstructible, regardless of a public verification key. This is genuine quantum hidden-period exploitation, NOT classical brute force with a Grover speedup. No concrete hash, native signer, oracle implementability cost or physical quantum-resource security level is established.

## Attack surface and necessary scope limitations

(1) Seam: commutative XOR pairing exposes periodicity. (2) Gauge: recovering Delta aligns frames; unlike earlier classical gauge checks this uses a coherent chosen-input period-finder. (3) Statistical fingerprints: even independent uniform pair outputs have the period. (4) Multi-capsule: one vulnerable capsule suffices; Delta reuse worsens correlation. (5) Public evaluation: exact deterministic/coherently reversible F is necessary; no claim against randomized interfaces without this oracle. (6) Retained setup secrets bypass protection separately; honest fresh Delta is assumed here. (7) Distinct context, UTXO, branch identifiers are necessary but cannot conceal Delta once F is exposed. (8) Public signing checking keys are included in the adversary view and irrelevant to Simon's period recovery. (9) Coherent QPT access is essential to the stated polynomial-query attack. If H is instantiated by a public concrete hash, no black-box classical lower bound is asserted.

Even an ideal black-box for this function leaks Delta to a QPT adversary; an obfuscated circuit preserving identical deterministic behavior cannot remove the exposed period. A *directed*, non-swap-invariant seam may avoid this specific attack, but needs independent analysis.

## Reproduction and original-source obligations

The exact standard-library Node.js checker in this commit exhaustively verifies 42 finite seeded-SHA256 examples (n=3..9, m=2n+20): 3,048 period orbits; 36,576 Fourier cancellation identities; 42 reconstructions from analytically sampled Delta-perp vectors; and a low-output-width counterexample. It reports 47,710 assertions. SHA256 finite fixtures are not a random oracle or a security proof, and no quantum hardware was executed.

Run 259 proves only supplied-complete-representation -> ORIGINAL witness under its information-theoretic or SIS hypotheses; it does not convert a recovered key or native signature into a representation. Run 567's false-language existential gap remains. This pass does not instantiate the locally mixed release, all-valid-witness common-key correctness, QPT false-instance full-public-output hiding, true-instance unauthorized recovery/accepted-forgery extraction, malicious N-of-N setup/erasure, adaptive multi-capsule composition, 128-bit resources, or conditional P2MR/SLH-native Bitcoin execution. Stopping condition NOT met.

Next: test small *asymmetric* authenticated single-source release seams, looking for Simon/hidden-subgroup structure before any claimed QPT security theorem. Do not infer any attack on published CCMR/CLZ from this scoped XOR model.

Primary literature: Daniel Simon, On the Power of Quantum Computation, SIAM J. Comput. 26(5) (1997), https://doi.org/10.1137/S0097539796298637 ; Canetti–Chamon–Mucciolo–Ruckenstein, Towards General-Purpose Program Obfuscation via Local Mixing, TCC 2024, https://doi.org/10.1007/978-3-031-78023-3_2 ; Canetti–Luo–Zhang, How to Encrypt with Random Reversible Circuits, CRYPTO 2026, https://doi.org/10.1007/978-3-032-35367-2_18 .
