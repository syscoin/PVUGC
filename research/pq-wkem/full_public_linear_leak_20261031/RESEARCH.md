# Exact full-public polynomial-mask factorization and linear-leakage security

2026-10-31. Research-only result, starting from open/draft/unmerged syscoin/PVUGC#1 at 0ab4f17947dc8a3ca0f49beadfdedbd20a898006, branch research/pq-wkem-validation-20260918. Inherited the exact degree-4 polynomial-mask RESEARCH.md blob cede7a438ecea7d0705e264679ab8ba24796425f and checker.js blob ddfb2e39c53fe88fbdd607b108cf856c06d1ddd0; latest substantive PR comment 6541390949. Offline mathematical research only; no external literature or browsing.

## Genuine new restricted claim

The predecessor already had every-ORIGINAL-witness same-capability correctness and perfect master-independent ciphertexts for a certified FALSE subclass. This result **strengthens and exactly characterizes** that subclass's full-public joint leakage behavior: any number of related certified-FALSE capsules can share public B, R, u, selected LWE encryption coins, and the same native verification key while keeping all non-native transcript components statistically independent of the hidden native master, **if and only if** a concrete linear certificate exists for every selected SOURCE-mask leakage map. The iff is for the fully encryption-coin-exposed view. This is a rigorous conditional composition lemma, **not** generic NP witness encryption, a proof of ordinary-LWE security, or a hard-TRUE witness extractor.

## Complete construction, source data, and exact factorization

Over prime field F_q with nonzero g, let D in F_q^(m x T) be the deterministic degree-d polynomial-constraint matrix for ORIGINAL 3CNF relation F, and e the constant-monomial coordinate. Set public B = u e^T + R D for u in F_q^ell and R in F_q^(ell x m). For each protected bit k_j of a 512-bit native master K, independently draw a fresh uniform **secret** mask S_j in F_q^m and publish:

    P_j = k_j e + D^T S_j                  (hidden intermediate)
    c_j = B^T s_j + g P_j + eta_j           mod q
    t_j = u^T s_j + eta*_j                  mod q

The joint public view contains (F, relation identity, claim, UTXO, branch, anchors, observation window, intended challenge path, vk, D, u, B, all (c,t), authenticated context, auxiliary information, and related capsules). The native vk is generated from the actual K. The auxiliary view may additionally reveal R, all s_j, eta_j, eta*_j, and designated linear leaks l_j=L_j S_j. These revealed coins may be shared across related capsules. Requirement: S_j is sampled independently uniformly **after** R, u, L_j and all other mask-dependent choices are fixed. No hidden-source-correlated auxiliary leakage except the specified L_j S_j; auxiliary K-dependence other than native vk and oracle-signature responses must be independently simulatable. This is a classical PPT distribution for any fixed degree d, although the degree-d monomial basis grows as sum_{i<=d} C(n,i).

Define H_j = R^T s_j + g S_j. Then, as an **identity of the full real public distribution**,

    c_j - t_j e = g k_j e + D^T H_j + eta_j - eta*_j e  mod q.

Since g is invertible and each S_j is fresh uniform, H_j is independent uniform conditional on the public B, R, u, the permitted encryption coins, and every other S-independent related-capsule field. This gives a **straight-line exact sampler** for the real full view, not a marginal pad hybrid, for arbitrary fixed (F,D), including TRUE instances. However the key-bearing g k_j e remains for general F: no generic key-free simulator follows.

## Necessary-and-sufficient leakage theorem and proof

For each j, write L=L_j. If a publicly checkable delta in F_q^m satisfies

    D^T delta = e,           L delta = 0,                       (1)

then for ANY two values k,k' the mask change S' = S+(k-k')delta is a bijection on F_q^m. It preserves simultaneously

    k'e+D^T S' = k e+D^T S,          L S'=L S.

Thus the **actual** P,c,t,B and all exposure of encryption coins and specified leaks remain pointwise identical under a K-change coupling. Apply independent translations for all related capsules, even when all k_j are correlated, native K and B shared, s/eta coins shared or all encryption coins disclosed. This proves perfect K-independence of the entire **non-native transcript**. The genuine native vk of course remains correlated with K; it is not claimed statistically independent.

This condition is also **necessary** to hide K in the fully coin-exposed (P,L S) distribution. Consider linear image M:S -> (D^T S,L S). For uniform S, the K=0 and K=1 distributions are uniform on affine cosets of im(M), separated by (e,0). They are identical precisely when (e,0) lies in im(M), equivalent to (1). Otherwise the cosets are disjoint, and public modular linear algebra supplies a dual linear key extractor. When s and eta are opened, P=g^{-1}(c-B^T s-eta) becomes public, hence the iff applies directly. Without opened coins, failure of (1) is **not** automatically a ciphertext attack.

For L=0, condition (1) is the previous FALSE certificate e in rowspan(D). Every satisfying ORIGINAL witness has D v(W)=0 and e^T v(W)=1, so such a certificate is impossible for TRUE F. For certified FALSE F, the exact full-public simulator can take a genuine native verification-key challenge and simulate **all non-native fields without knowing K**. With classical native signing queries and auxiliary inputs efficiently simulatable from vk, arbitrary usable native signing-key recovery or a fresh signature on the unqueried intended challenge path yields a straight-line reduction to independently assumed nonuniform-QPT native EUF-CMA. The native primitive itself was not run or proved secure here. A native quantum-superposition signing oracle, source-secret-correlated quantum advice, and all non-simulatable hidden-K auxiliary data remain outside this restricted statement. Exact equality of classical distributions holds against coherent joint QPT processing with independent/vk-simulatable quantum advice, without quantum rewinding.

## Independently instantiated F10 leakage pattern

For the predecessor's unsatisfiable F10 formula on five Boolean variables at degree 4 over F_65537, the public D has 60 rows, 31 columns, rank 28 and a computed e-rowspan certificate supported on **13 mask positions** (zero-index rows 0,1,7,12,15,18,24,30,33,36,42,48,54). The other **47 whole mask coordinates** can be disclosed, along with all encryption coins, while preserving exact hiding; a separate fixed set of 10 dense linear leaks also admitted (1). In contrast exposing only positions 0,1,2,3 destroys (1); a public dual functional extracted 128/128 toy bits in the **fully coin-exposed** view. The complete deterministic standard-library Python calculation, 2,513 passed checks twice byte-identically, including those certificates, 432 related-source couplings, 256 releases across four distinct valid ORIGINAL witnesses of a TRUE companion, and a q=5 exhaustive two-capsule check, is in the local companion archive. The exact published JavaScript checker is separately supplied and executed; it tests the same distributional coupling and reused-mask boundary with a minimal certified-FALSE matrix.

Reusing S_j across capsules is forbidden: with other encryption coins shared, ciphertext differences expose g(k_1-k_2)e. Independent S_j permits sharing B, R, u and s. Revealing a valid TRUE capsule's same master trivially destroys that master's secrecy in any FALSE companion; claim/path-scoped key separation and graph safety are separate.

## Exact remaining gaps and limitations

This theorem does **not** solve the user's primary missing recovery-to-ORIGINAL-witness reduction. For arbitrary FALSE F, a fixed-polynomial-degree D need not satisfy (1); the predecessor contains direct low-degree FALSE attacks. For hard TRUE F, (1) is impossible, and there is no justified QPT reduction from arbitrary key recovery or native forgery to an ORIGINAL witness or an independent QPT break. The public B is structured and ordinary uniform-matrix LWE does not justify its security. No malicious N-1 setup/abort/Funding-DA proof, full related TRUE selective opening, SYS/BTC qualification, or deployed PQ-native Bitcoin endpoint is established. This is not a QPT-128 WKEM claim or a reason to merge/deploy.

The next essential equations are a classical-PPT witness-free ORIGINAL-dependent Comp and every-witness Lift with SAME precommitted K, plus a complete-public true/false source-generation simulator and, for arbitrary unauthorized native recovery, a straight-line ORIGINAL witness extractor or reduction to an independently justified QPT assumption. An adversary must not be required to submit a representation or SOURCE opening.

## Executed checker and provenance

The companion checker.js is the exact executed deterministic function, source-emitted and independently executable with Node. Its output.json was captured from that execution. It checks 3 shared correlated packets in 128 repetitions, exact simulator coupling, coin disclosure and safe mask exposure, and q=5 two-capsule distributions. Local extended checker and full formulas are preserved independently; neither codebase tests QPT hardness or real signatures. Only authorized research/pq-wkem/ paths and an optional ordinary top-level PR comment are in scope.
