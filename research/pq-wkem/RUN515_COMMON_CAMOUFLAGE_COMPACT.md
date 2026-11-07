# Run 515 — common-camouflage cancellation and independent-pad no-decoding control
Research-only, October 14 2026 UTC; `syscoin/PVUGC#1`, draft branch `research/pq-wkem-validation-20260918`, starting commit `bdcdbb01693ea63f0321761c5ee214d1f4f36978`. This is a scoped falsification, NOT a practical or proven PQ witness-KEM.

## Exact lemma
Run 514's gated reversible terminal is (B_i(u,z,t)=(u,z,t XOR ((u_i XOR delta_i) AND f_x(z)))), with h seed-coordinate bits, n source bits, and one marker. Set (N=2^{h+n+1}) and (m=|\{z:f_x(z)=1\}|).

For an arbitrary hidden frame P and independently uniform (ideal, exponential-size) permutation C, publish a baseline (D=P C P^{-1}) and terminal (E_i=P C B_i P^{-1}). Both are **individually exactly uniformly distributed** as permutations conditioned on P and B. Nevertheless the complete public pair is correlated: (D^{-1}E_i=P B_iP^{-1}). Any white-box inverse of D strips the common pad, recovering Run 514's involution/fixed-point fingerprints. This is exact for **every** invertible C, not only random C.

Even without inverse access, two forward queries on a uniform y reveal a distinguishing correlation:
[
Pr[D(y)=E_i(y)]=1-m/2^{n+1}\ge 1/2,
]
versus (1/N) for independent uniform random permutations. On a false statement, D and E are **identical functions**, giving distinguishing advantage (1-1/N) against the unjustified independent-PRP model. **This is NOT seed recovery and does not violate false-instance WE hiding.**

For any invertible L,R, (D=LR,E=LAR) also implies (D^{-1}E=R^{-1}AR), and (E D^{-1}=LAL^{-1}). Shared reversible input/output masking cannot erase the quotient's conjugacy invariants.

## Independent-padding control
If independent uniform C0,Ci replace C, (D=P C0 P^{-1}), (E=P Ci B_i P^{-1}), the full public function pair is a product of independent uniform permutations **even conditioned on** P, K, delta, and the ORIGINAL predicate, provided pads are independent of every such variable and auxiliary input. The pair conveys *no new* key or witness information beyond previously public loader/anchor/native-key data. With ideal seed-hiding loader symmetry and omitting correlated native VK, no all-witness decoder can recover K from these pairs better than prior guessing. Thus: common camouflage preserves equality-based release but leaks its joint structure; completely independent camouflage removes that structure but also removes the release signal. This is NOT a general impossibility theorem for other alignment mechanisms.

## Bounded executed checks
The exact committed JS checker was executed before publication and checks 576 S4 quotient equations, 1,152 honest seed-bit recoveries, 24 full uniform marginal checks, disjoint common-pad seed-view supports, equality of two full independent-pad distributions across 27,648 seed-labeled S4 cases with 2,304 support points, and 241,920 quotient/fixed-point checks over 40,320 S8 pads. Exact n4 collision rates: 288/576 versus 144/576. A longer Python independent checker and detailed proof are preserved in the local checkpoint archive. Tests are not a security proof.

## Threat scope and handoff
(1) Common seam cancels; (2) hidden gauge not needed; (3) joint statistical fingerprint despite uniform marginals; (4) paired views already defeat the PRP-pair surrogate; (5) two forward chosen-input calls suffice; (6) any invertible C; (7) binding context changes f only; (8) native checking key unused; (9) attack is classical PPT (thus available to QPT), no new coherent attack. Ideal independent-pad distribution equality survives coherent postprocessing of its specified public view.

No classical-PPT protected terminal, complete-output QPT hiding, arbitrary native-authorization-to-ORIGINAL extraction, malicious setup, multi-capsule composability, resources or Bitcoin native-PQ endpoint is proved. Run 509 oracle extraction and Run 259 complete-source binding keep their exact limited scope. The next direction requires a genuinely protected decoder whose correlations are justified **jointly**, rather than marginally random guarded actions. Production unchanged; PR draft and unmerged. No paper proof was fully audited this iteration.
