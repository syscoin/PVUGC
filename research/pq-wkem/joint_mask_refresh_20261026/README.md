# Joint SOURCE-mask leakage and last-seal refresh (2026-10-26)

**Research-only, incomplete PQ witness-KEM.** This builds on the local SOURCE-syndrome and polynomial-size one-hot SOURCE checkpoints, and on the published `coupled_joint_support_20261025` checkpoint. The pivot-Schur carrier remains insecure. The old signed pseudowitness still breaks the generic linear source-syndrome release. No general arbitrary-key-recovery-to-ORIGINAL-witness reduction, standard-QPT-LWE embedding, secure malicious N-of-N ceremony or practical Bitcoin graph was obtained. Work was performed offline without external literature/web search.

## Exact new full-joint-output theorem

Let `M=C_x^T` be the public SOURCE matrix, `S` uniform in `F_q^r`, the public linear setup transcript `T=A S`, and the entire capsule `Y=M S+E+D K`. Here `D` has the public key-shift directions; noise `E` may depend on the PUBLIC `T`, but its conditional distribution must be independent of the remaining private mask coins and of `K`. Context and native checking object `vk(K)` are public. No residual mask secrets or quantum setup state may leak through auxiliary information outside the modeled transcript.

Given `T`, compute a public solution `S0` with `A S0=T` and a basis `N` for `ker A`. Uniform `S|T` has the law `S0+N U`, with uniform `U`. Put `R=M N` and compute public `P` such that `ker P=im R`. Then

```
Z = P(Y-M S0) = P E + P D K.
```

**Exact fiber simulator:** Conditional on `(T,Z)`, the complete `Y` is uniform over the fiber `{y:P(y-M S0)=Z}`. A straight-line classical simulator picks any preimage and adds uniform `im R`, without `S`, `E` or `K`. This is exact equality of the whole classical distribution, so any QPT postprocessing of that classical release preserves equality (provided its quantum side information does not separately reveal residual `U`).

**Public joint masking certificate:**

```
im(D) subset im(M ker A)
equivalently rank(M N) = rank([M N | D]).
```

When this holds, the entire `(T,Y)` distribution is independent of `K`, conditional on source/context and the assumed K-independent error law. For one capability with `D=Delta e0`, it means there exists `u` with BOTH `C_x^T u=e0` and `A u=0`. The first equation alone (an old linear false-refutation) is insufficient after transcript leakage. The proof translates the uniform residual `U` by a vector mapping to any key-shift difference. This exact K-independence extends alongside a public `vk(K)`: the capsule contributes no information about K beyond checking material; security of the checking material itself is separately required. This is a restricted *public-refutable false-instance* theorem, not generic false-instance hiding.

## Explicit constructive repair to earlier setup-mask leakage

If old setup coins `S` have been fully or partially exposed, add an independent uniform **hidden** final mask `U_new` *privately at seal time*:

```
Y_seal = C_x^T (S + U_new) + E + Delta e0 K.
```

Publish only the final aggregate `Y_seal`, NEVER the separate refresh term `C_x^T U_new`. If `e0 in im(C_x^T)`, the new mask restores the public joint certificate even when the entire old `S` is revealed. Every ORIGINAL witness `v_w` still has `C_x v_w=0` and `v_w[0]=1`, hence `v_w^T Y_seal=Delta K+v_w^T E`: distinct valid witnesses recover the SAME precommitted K. Refresh uses a fresh `r*ell`-element secret matrix and one sparse multiplication with no additional public coefficient matrix.

**This is not an implemented secure ceremony.** It requires a protected final aggregation step, no leaking of the separate refreshed term, prevention of adaptive corrupt cancellation, and verified erasure before irreversible funding. Publicly broadcasting individual shares or merely adding publicly known mask terms defeats the repair.

## Complete related-capsule rule

For stacked related capsules `Y_all=M_all S_all+E_all+D_all K_all` with jointly leaked setup transcript `T_all=A_all S_all`, use ONE global certificate `im(D_all) subset im(M_all ker A_all)`. Independent per-capsule certificates do not imply joint security when secret masks are reused. Explicit failure: with one mask `S`, `Y1=S+K1` and `Y2=S+K2` reveal `K1-K2`, even if each marginal is uniform. Fresh independent masks restore both independent key directions. Shared-key cases must encode their actual correlation in the global key-direction matrix. This is a full-public, classical-linear simulation theorem; it does not assume product-of-marginals security.

## Executed controls and exact scope

A deterministic standard-library Python checker completed twice with byte-identical output (**553 counted assertions**), using finite fields q=7 and q=257. It checks exact joint public transcript histograms for safe and unsafe leaks, explicit leaked-key equations, restoration after **full** old-mask disclosure, affine-fiber simulation, safe and leaking shared-mask related capsules, and two distinct honest one-hot SOURCE witnesses still recovering the same K after refresh. It also directly reuses the previous three-variable, eight-clause unsatisfiable factor SOURCE: the signed norm-B+2 pseudowitness recovers K in eight refreshed samples, proving **refresh does not cure the underlying source-release flaw**.

The full executed checker, verbatim previous local SOURCE helper, exact validation, provenance, and the longer proof are preserved in the local artifact `PQ_WKEM_JOINT_MASK_REFRESH_20261026.tar.xz`; SHA-256 `f32743dffd17c7c1051998b941fa053ca459d7dd311c8fd4b2965db1e4784c59`. This README publication alone is **partial publication**, not a claim that those local executable bytes are committed. No test of QPT secrecy, independent standard-LWE reduction, wallet signature, native verifier, malicious setup or production-sized deployment was executed.

**Precise remaining target:** repair the complete SOURCE-dependent nonlinear release so that the known signed false pseudowitness cannot recover K, and prove for arbitrary QPT bare-key recovery/native forgery either extraction of an ORIGINAL witness or a standard independently justified PQ break. The source-syndrome hard-false `P_x E + Delta(P_x e0)K` distribution still lacks generic QPT hiding and is sometimes directly insecure. Keep PR open/draft/unmerged, production and workflows unchanged, and research ongoing.
