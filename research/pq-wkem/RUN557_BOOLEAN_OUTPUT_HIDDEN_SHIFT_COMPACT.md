# Run 557 — one-bit compressed forward-only frames retain a coherent hidden shift

**Source branch:** syscoin/PVUGC#1, `research/pq-wkem-validation-20260918`, start `5b8c39387b39cbfe10b57f81525104b110eca7fd`. Research-only falsifier; no production changes, no completed WKEM.

## Candidate
Run 556 broke a two-branch *injective* Simon oracle. This iteration tests a tempting narrower countermeasure: compress both forward-only branches to **one output bit**. Let `Delta` be a hidden n-bit XOR translation and `h:{0,1}^n->{0,1}` be a uniformly random Boolean function. Expose `F0(z)=h(z)` and `F1(z)=h(z xor Delta)`. Each individual marginal is uniform random Boolean and independent of Delta. Neither exposes an inverse or a public permutation table. The combined public coherent oracle is `G(b,z)=F_b(z)`. The joint function is massively noninjective; the **exact two-preimage Simon promise does not hold**.

This is an application of **known Boolean hidden-shift cryptanalysis**, not a new quantum algorithm. Gavinsky, Roetteler and Roland, *Quantum algorithm for the Boolean hidden shift problem* (2011), arXiv:1103.3017, Sections 3–4, prove the random Boolean average-case O(n)-quantum vs Omega(2^(n/2))-classical separation. The new checkpoint here is its precisely scoped one-bit release-frontier falsifier, an elementary explicit bound, and independently executed finite checks. Primary proof audited: https://ar5iv.labs.arxiv.org/html/1103.3017 .

## Exact one-bit coherent sampling law
Write `N=2^n`, `s(z)=(-1)^h(z)`, `W(t)=sum_z s(z)(-1)^(t dot z)`. Start from a uniform (b,z) superposition, coherently write G(b,z) to one output qubit, apply Hadamards to the n+1 input qubits, and measure them. The measurement (a,t) always obeys `a=t dot Delta mod 2`, since G is invariant under (b,z)->(b xor 1,z xor Delta). The **exact** t-marginal is

`Pr[t] = [N^2 * 1(t=0) + W(t)^2]/(2*N^2)`.

This follows by summing output-register amplitudes; the checker also derives it by a direct full-state amplitude census at small n. The measured t=0 has probability at least 1/2, unlike ordinary perfect Simon sampling. For any nonzero trial delta, set `C_delta=Pr_z[h(z)=h(z xor delta)]`. By Walsh autocorrelation,

`E_t[(-1)^(t dot delta)]=C_delta`, hence `Pr[t dot delta=0]=(1+C_delta)/2`.

If Delta is the sole period, n independent equations recover it over GF(2).

## Explicit random-Boolean failure bound
For fixed delta != 0 the N/2 disjoint pairs {z,z xor delta} have independent fair equality bits under uniformly random h. Hoeffding plus union bound gives

`Pr_h[max_{delta != 0} C_delta >= 3/4] <= (N-1)*exp(-N/16)`.

Conditioned on the complementary event, T independent coherent samples fail to span n dimensions with probability at most `(N-1)*(7/8)^T`, since any nonzero incorrect delta satisfies the parity constraint with probability at most 7/8. Thus the joint failure bound is

`(N-1)*exp(-N/16) + (N-1)*(7/8)^T`.

Choosing `T>=ceil(ln((N-1)/eps)/ln(8/7))` makes the second term <=eps; this is O(n+ln(1/eps)) coherent oracle evaluations and polynomial GF(2) postprocessing. The 2011 paper gives a closely related general influence-based theorem and a classical birthday lower bound for uniformly random Boolean oracles. Here the elementary explicit constants apply only to this uniform random h model.

## Salt, checking keys and security scope
If public randomness r merely chooses h_r reused across both shifted branches, a QPT attacker fixes r and makes coherent queries: public randomness/one-bit postprocessing does not fix this **specific** shared-shift structure. Independently secret branch randomness or genuinely incoherent classical-only oracles change the model and remain unanalyzed. Public classical PPT code is normally coherently evaluable by QPT, but a truly uniform random Boolean h is **not a compact classical PPT instantiation**.

If a proposed capsule sets its branch signing capability to `K_x=KDF(full_context(x),Delta)`, recovering Delta permits unauthorized key recovery without an ORIGINAL witness; a public verification key may check the result. If K_x is independent of Delta, this attack **does not** imply key recovery. There is no claimed Syscoin ORIGINAL relation implementation.

Attack audit: joint seam/synchronization and fingerprint (one-bit marginals hide Delta), one-capsule chosen/coherent inputs, honest setup sufficient, public checker correlations harmless to the attacker; multi-capsule combination, malicious setup, replay, and independent-branch designs are not proved secure here. This is a **genuine quantum** polynomial-query separation in an ideal oracle, not a merely faster classical attack.

Run 259's downstream source binding only covers *accepted complete representations*. A derived key/ordinary signature is not such a representation. Still **UNPROVED**: practical source-authenticated release, all-valid-ORIGINAL-witness common K, false-instance full-view QPT hiding, unauthorized true-instance final-key/signature-to-ORIGINAL extraction or independent QPT break, malicious one-honest-party N-of-N erasure/abort, multi-capsule security and concrete 128-bit costs. The conditional P2MR/native-SLH endpoint is not changed. The stopping criterion remains unmet.

## Executed validation
The exact committed JS checker uses deterministic xorshift fixture bits (not a cryptographic PRF), checks Walsh and translation identities, enumerates full state amplitudes for n=2..5, and validates full-rank recovery in eight n=7..10 fixtures across 24 shifts. It was executed in V8 with the exact source used for the commit. An independent local Python 3.13 standard-library checker also passed **14,423** assertions over ten n=7..11 deterministic hash-bit fixtures, 40 shifts and direct state amplitudes; its source, output and extended derivation are preserved locally, not represented as committed files. Neither checker is a QPT security proof or a quantum hardware run.
