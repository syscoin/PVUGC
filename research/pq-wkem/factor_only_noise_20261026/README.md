# Factor-only SOURCE channel: exact full-public rate improvement (2026-10-26)

**Restricted positive efficiency result. Not a generic-NP witness-KEM.** Parent is `research/pq-wkem/compact_polar_source_20261026/README.md` at SHA `78416840a3500bc2a1c762e2d71fecbcae7f4646`, blob `7d0c77cbe82ab73a30184598a3ae925caafaeea2`. An independent full-detail Python mathematical checker with **952 assertions**, exact rational gap certificate and provenance is preserved locally, not represented here as GitHub-published.

## Concrete release, not a SourceOpen oracle

For the existing homogeneous Boolean one-hot factor SOURCE `C_x`, compute a public row basis `R` of `ker(C_x)` and `b=R e0`. Every valid ORIGINAL witness `w` has a distinct binary lift `v_w` in that kernel, constant coordinate 1, and exactly one active assignment coordinate per factor. Write `g` for the public number of factors.

Choose independent uniform bits `X_j`; **only** the factor-assignment error coordinates `E_{j,i}` are independent Bernoulli(`p`), and constant and variable-label errors are zero. Publish `Q_j=R E_j + b X_j` over `F_2` (not the uncompressed full masked Y). Separately publish a public polar frozen helper `W=(X G_L)_F` for a BSC channel, an independent public Toeplitz hash seed `H`, `T=Encode(K) xor H X`, the precommitted native checking key `vk(K)`, full relation identity, claim/UTXO, branch, anchors/window, context and auxiliary data.

**Open any valid ORIGINAL witness off chain**: check the ORIGINAL relation, form `v_w`, solve the *public* representation `alpha_w R=v_w^T`, and compute `Z_{w,j}=alpha_w Q_j=X_j+v_w^T E_j`. As every valid witness selects exactly `g` independent error coordinates, each has the *same* marginal BSC bias `rho^g`, `rho=1-2p`, and capacity `C_h=J(rho^g)`, `J(z)=1-h2((1+z)/2)`. Distinct witness states and correlated projections are allowed. With successful polar decoding all obtain the SAME precommitted K. Classical Build/Open run in polynomial time in explicit capsule length, but finite crypto-size polar frozen sets were NOT constructed in this run. The earlier bounded-integer extraction theorem over odd q must NOT be reused for this GF(2) carrier.

If the predecessor's full `Y=C_x^T S+E+e0 X` is formed with a fresh uniformly hidden S, Q=RY and the complete Y conditional on Q is uniform on the public affine fiber, for any error distribution. The actual release emits Q directly, with **no S** and no SourceOpen oracle. This quotient is the *entire capsule* for information computations.

## Exact full-public false distribution

Fixture retained exactly from predecessor: false x has two bits and four factors forbidding 00,01,10,11 respectively; true control has four factors each forbidding 00, hence ORIGINAL witnesses 01,10,11. Both are 17-coordinate SOURCEs with rank 14 and quotient dimension 3. For the false source, the complete kernel has one zero vector, four odd-constant vectors with **six factor coordinates each**, and three even-constant vectors with **eight factor coordinates each**.

For a quotient basis R with h rows, the **complete conditional public distribution** is

`Pr[Q=q | X=x] = 2^(-h) sum_{a in F_2^h} (-1)^(a.q+x(aR)_0) rho^(wt_factor(aR))`.

Its full information is `I_f=(D/4) J(t)`, `D=1+3 rho^8`, `t=4 rho^6/D`. On the true control `C_h=J(rho^4)`. No selected attack projection or omitted public Q coordinate is used. For rational `p=1/6`, `rho=2/3`, `D=2443/2187`, `t=768/2443`:

```text
C_h                      0.02833180908451680492891349 bits/column
I_false                  0.02024993341478424196679021 bits/column
C_h - I_false            0.00808187566973256296212329 bits/column
prior isotropic gap      0.00060614611640738021418907 bits/column
improvement factor       13.3332136443168688x
theoretical 256-bit Shannon floors: 31,676 vs 422,341 columns
```

This is not a claimed concrete 128-bit-size design: the floor ignores polar finite-length losses, leakage/decoding margins, the frozen helper and Toeplitz seed, native signatures, and malicious setup.

**Exact sign certificate:** `J(z) ln(2) = sum_{j>=1} z^(2j)/[(2j)(2j-1)]` for |z|<1. Sum through j=12; bound the remaining tail by `z^26/[26*25*(1-z^2)]`. The exact rational *lower* endpoint of `(C_h-I_f)ln2` is positive, using J(rho^4)'s lower and J(t)'s upper endpoints. The independent local checker records both rational numerators/denominators, canonical-endpoints SHA-256 `a1b3623ab31b156303ee4b7bca7afb514b84662d312fa2086098844f5576b5c1`. A GitHub-published JS checker executes 617 deterministic assertions, enumerating all **4096** factor-error patterns with exact BigInt weights and comparing all **16 rational full-quotient conditional probabilities** with the Fourier formula, plus all three true ORIGINAL lifts and 128 seeded honest recovery identities. JS floating-point rates are cross-checked by the independent local decimal/rational implementation. The GitHub JS check itself does NOT prove the rational sign.

## Whole-view statistical theorem, exactly scoped

For independent columns the finite-alphabet AEP yields asymptotically `H_min^eps(X^L|Q^L) >= L(1-I_f-delta)`. Polar frozen helper length `|F| <= L(1-C_h+delta)` leaves `L(C_h-I_f-2delta)` bits; a fresh public independent two-universal Toeplitz H extracts k bits for `k<L(gap-3delta)`. Then `(Q,W,H,HX)` is statistically close to the same tuple with independent uniform k-bit HX. Therefore `T=Encode(K) xor HX` adds negligible information about K *beyond* its already public native checking key, relation/context and auxiliary advice **conditional on independence from hidden X,E**. QPT postprocessing cannot increase trace distance for that classical distribution with conditionally independent quantum side information. Independent fresh related capsules compose by a hybrid; malicious N-of-N setup, builder coin retention, selectively opened correlated capsules/hidden coins, or advice entangled with those coins remain unproved. This is an asymptotic PPT claim only for the ONE fixed false source and an easy true control, not general-source secrecy.

## ORIGINAL-extraction obligation still unsolved

Need for arbitrary hard-true x and arbitrary QPT key-only/native-forgery adversary A: `Pr[A(full public x,Q,W,H,T,vk,ctx,aux,related capsules) recovers K or forges] <= Pr[straight-line Extract^A outputs ORIGINAL w with R_x(w)=1] + Adv_independent_QPT_break + negl`. This statement is **NOT PROVED**. The source-specific R is not a uniform standard LWE challenge and no joint simulator embeds its correlated checking key, frozen helper and all auxiliary capsules. The code does not demand or obtain a representation from A. The fixed false SOURCE is easy to refute; the matching true control is easy to solve. No security claim for hard false circuits, no generic-NP gap theorem, no practical polar parameter set, no native SLH/P2MR deployment, no fully secure Bitcoin graph or ceremony.

Published files are research-only under the authorized existing PR branch, not production, workflows or an approval. Leave PR draft/open/unmerged and continue research.