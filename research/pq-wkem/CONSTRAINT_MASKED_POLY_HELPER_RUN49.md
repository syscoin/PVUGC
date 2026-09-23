# Run 49 — Constraint-masked polynomial right delegation and the truncated-ideal pseudo-transfer attack

## Status

Starting point: verified PR #1 head `f5c3bc839dc98aa546cb17bd353f5a15202879c4` (Run 48).

This run does **not** claim a completed witness KEM, a generic impossibility theorem, or a post-quantum security proof. It makes a concrete constructive attempt at the exact escape hatch left open by Run 48: hide a setup-time right/column transform `D`, erase it, but publish a **nonlinear polynomial helper** which agrees with `D Phi(w)` on every genuine source witness while being masked by source constraints away from the witness set.

The attempt is more selective than the ordinary public linear helper rejected in Run 48. Nevertheless, if the helper is masked inside a truncated source ideal, every public truncated-ideal pseudofunctional evaluates through the mask and recovers the transformed pseudorepresentation **without recovering `D`**.

A degree-2 false Boolean fixture makes the complete-output failure explicit. A separate growing-degree statement connects the attack to Run 45's Laurent dual family.

No external literature or web search was used. Production code is unchanged.

## 1. Constructive attempt: nonlinear constraint-masked right helper

Let the source variables be `w`, let

    Phi(w) = (phi_1(w),...,phi_N(w))

be a public polynomial feature map, and let source constraints be

    g_1(w)=...=g_m(w)=0.

Setup samples a secret invertible matrix `D` and would like future genuine witnesses to obtain

    Y(w) = D Phi(w)

after `D` has been erased.

Instead of publishing `D`, publish each helper coordinate as a polynomial

    P_i(w)
      = <D_i, Phi(w)>
        + sum_j h_{i,j}(w) g_j(w),                       (1)

with public random masking polynomials `h_{i,j}`. On every genuine source witness all constraints vanish, so

    P(w) = D Phi(w).                                     (2)

This is a real nonlinear public/offline helper. It is not the ordinary linear map `X -> D X` rejected in Run 48. The intended hope is that the constraint multiples hide `D` everywhere except on genuine source witnesses.

## 2. Truncated-ideal pseudo-transfer theorem

Fix a finite-dimensional polynomial coefficient space `E_T` (for example all monomials through degree `T`) and the truncated source-ideal mask space

    V_T = span {
      m(w) g_j(w) :
      deg(m g_j) <= T
    } subset E_T.                                       (3)

Let

    Lambda : E_T -> F_q

be any public linear functional satisfying

    Lambda(V_T)=0.                                      (4)

Write the pseudo feature vector

    X*_r = Lambda(phi_r).                               (5)

Assume every helper coordinate (1) lies in `E_T`.

### Theorem 2.1 — exact pseudo-transfer through nonlinear ideal masking

For every helper row,

    Lambda(P_i)
      = sum_r D_{i,r} Lambda(phi_r)
      = (D X*)_i.                                       (6)

Therefore the attacker obtains the complete transformed pseudorepresentation

    Y* = D X*                                            (7)

using only the **public helper coefficients and `Lambda`**. It does not recover `D`.

#### Proof

The difference `P_i - <D_i,Phi>` is in `V_T`. Applying `Lambda` kills the difference by (4), leaving exactly (6). QED.

### Corollary 2.2 — uniform masks expose exactly the quotient class

If the masking term in each helper row is uniform in `V_T`, then `P_i` is uniform in the affine coset

    <D_i,Phi> + V_T.

Thus the public output intentionally hides only directions inside `V_T`; every dual quotient functional in `V_T^perp` survives exactly. The attack above is not recovering the mask randomness. It is evaluating the quotient invariant that the mask cannot change.

### Corollary 2.3 — transformed native preimage survives

Suppose `X*` is an exact preimage for a native relation

    A X* = u,

and setup uses the secret right transform

    A_D = A D^{-1}.

Then the public helper gives the attacker `Y*=D X*`, and

    A_D Y* = A X* = u.                                  (8)

So a standard dual/preimage capsule is again cancellable by the false pseudorepresentation whenever `Y*` remains inside the decryption noise radius.

This is a stronger boundary than Run 48's public **linear** helper attack: the helper here is a genuinely nonlinear polynomial in the source variables.

## 3. Degree-2 false fixture over F_257

Use monomial coordinates

    Phi(x,y) = (1, x, y, x^2, xy, y^2).

Consider the false Boolean statement

    x^2-x = 0,
    y^2-y = 0,
    x+y+2 = 0.                                          (9)

No Boolean pair satisfies (9).

Work in the complete degree-2 truncated ideal. A convenient basis is

    v1 = x^2-x,
    v2 = y^2-y,
    v3 = x+y+2,
    v4 = x(x+y+2),
    v5 = y(x+y+2).                                      (10)

In coefficient order `(1,x,y,x^2,xy,y^2)`, define

    X* = (1,-1,-1,-1,3,-1).                             (11)

Direct substitution gives

    <X*,v_i> = 0   for i=1,...,5.                       (12)

The checker also confirms that the five masks have rank 5. Since the degree-2 coefficient space has dimension 6, their annihilator is exactly one-dimensional and is spanned by `X*`.

Thus, if each public helper row is

    P_i = <D_i,Phi> + random element of span(v1,...,v5), (13)

then the full public degree-2 polynomial row has `q^5` possible masks but still reveals the single quotient scalar

    <X*,P_i> = (D X*)_i.                                (14)

This is exactly the transformed false pseudorepresentation needed by the attacker, not the secret row `D_i`.

## 4. Complete native capsule break for norm-preserving secret geometry

To test the most correctness-friendly erased transform, setup chooses `D` as a secret signed permutation. This preserves every centered `L1` and `L2` norm, so genuine witness preimages remain exactly as short as before.

Let the native false relation contain normalization and the three base constraints in (9), so `A X*=u`. Publish

    A_D = A D^{-1}

and use the standard dual/preimage capsule

    a = A_D^T s + e,
    b = <u,s> + e_0 + 64 K                mod 257,       (15)

with coordinate errors in `{-1,0,1}`.

The attacker does not know `D`. From the public nonlinear helper it computes

    Y*_i = <X*,P_i>,

which equals `D X*` exactly by (14). Therefore

    b - <Y*,a>
      = 64 K + e_0 - <Y*,e>.                            (16)

A signed permutation preserves

    ||Y*||_1 = ||X*||_1 = 8,

so the centered noise magnitude is deterministically at most 9. The key centers are 64 apart, hence nearest-center decoding recovers `K` for **every** allowed bounded error vector.

This is a complete false-instance break of the attempted helper family. It does not use the erased `D`, helper mask randomness, or a source witness.

The point is not that signed permutations are the only possible secret geometry. They are the cleanest norm-preserving right transform one would use to retain honest correctness. More aggressive `D` may enlarge `D X*`; this run does not prove that every polynomial helper/geometry pair remains decryptable.

## 5. Honest correctness control

For the true Boolean relation

    x^2-x = 0,
    y^2-y = 0,
    x+y-1 = 0,                                          (17)

construct the analogous degree-2 helper using

    x+y-1,
    x(x+y-1),
    y(x+y-1)

as mask generators.

For both genuine witnesses `(1,0)` and `(0,1)`, direct evaluation of the public polynomials gives exactly

    P(w)=D Phi(w)

for every sampled mask. The transformed vector is an exact preimage of the transformed native relation and decapsulates the same key.

This verifies the constructive side of the attempted interface: it really is a public nonlinear witness evaluator after `D` is erased.

## 6. Growing-degree generalization from the Run-45 Laurent dual

Run 45 used the false chain

    g0 = x0,
    gi = xi - yi x_{i-1}       (1 <= i <= n),
    g_{n+1} = x_n - 1.                                  (18)

For degree `T <= n`, define the Laurent substitution

    psi(y_i)=y_i,
    psi(x_i)= product_{k=i+1}^n y_k^{-1},

and let `Lambda_T` be the constant coefficient of `psi(f)`.

This dual can be checked directly. Under `psi`, every recurrence generator `g_i` for `1<=i<=n` maps identically to zero because

    psi(x_i) = product_{k=i+1}^n y_k^{-1}
             = psi(y_i x_{i-1}),

and `g_{n+1}=x_n-1` also maps to zero because `psi(x_n)=1`. The only nonzero image is

    psi(g0) = product_{k=1}^n y_k^{-1}.

If `deg(m g0)<=T<=n`, then `deg(m)<=n-1`. Every `x_i` occurring in `m` contributes only additional nonpositive Laurent exponents; cancelling all `n` negative exponents of `psi(g0)` therefore requires at least one positive `y_i` factor for each `i`, hence multiplier degree at least `n`, impossible. So the constant coefficient remains zero. Consequently

    Lambda_T(1)=1,
    Lambda_T(m g_j)=0

for every allowed generator multiple of total degree at most `T`.

Therefore Theorem 2.1 applies verbatim: **any degree-`T` helper masked by those truncated ideal multiples leaks the `Lambda_T`-image of the erased transform.** The checker independently enumerates the allowed generator multiples for small `n` and verifies this annihilation exactly.

This does not say that every polynomial agreeing with `D Phi` on the witness set must admit a low-degree representation (1). It rejects the natural and efficient construction in which witness-selectivity is obtained by adding explicit low-degree constraint multiples.

## 7. What this does and does not close

### Proved here

* A nonlinear public helper of the form `D Phi + truncated-ideal mask` transfers every dual pseudofunctional exactly.
* Uniform mask coefficients do not help: the pseudofunctional is precisely a quotient invariant of the public helper.
* The degree-2 false fixture has a one-dimensional quotient generated by an explicit pseudomoment `X*`.
* A secret signed-permutation right transform plus that nonlinear helper is broken on the complete noisy capsule with deterministic bounded-error recovery.
* The Run-45 Laurent dual extends the pseudo-transfer theorem to an explicit growing-degree false family for every `T<=n`.

### Not proved

* This is **not** an impossibility theorem for arbitrary public polynomial helpers. A helper whose correctness is not represented by a low-degree source-ideal mask is outside the theorem.
* It does not rule out a high-degree succinct computational helper, an encrypted/obfuscated helper, or a non-polynomial source-aware mechanism.
* It does not prove that every secret right transform keeps the transformed pseudo short.
* It does not supply the arbitrary-QPT early-key-recovery to source-witness / independent-PQ-break reduction required by the target WKEM.

The remaining constructive target is narrower:

> a post-erasure witness evaluator must escape the public truncated-ideal quotient, not merely hide a secret transform by adding polynomial constraints that vanish on witnesses.

If it escapes by using a computational encoding, the complete public output still needs a reduction to an independently justified PQ assumption rather than a new assumption whose statement is already witness-restricted release.

## 8. Validation

The accompanying standard-library checker uses fixed seed `490049`.

It checks:

1. exact rank-5 / one-dimensional-annihilator structure of the degree-2 mask space;
2. 2,000 random nonlinear false-helper fixtures, all satisfying `Lambda(P)=D X*`;
3. 1,000 true-helper fixtures across both genuine witnesses, all satisfying `P(w)=D Phi(w)`;
4. 2,000 full false noisy capsules under secret signed-permutation transforms;
5. 2,000 full true noisy capsules;
6. exhaustive bounded-error false decapsulation for one fixed transformed fixture;
7. the Run-45 Laurent annihilation identities on all enumerated allowed generator multiples for `n=1,...,5`;
8. random sparse ideal-masked helper controls against those Laurent pseudofunctionals.

Tests validate the finite identities and the stated deterministic capsule attack. They are not evidence of PQ security.

## 9. Handoff

The stopping condition is not met.

The most useful next branch is no longer "make the right helper nonlinear" in the obvious algebraic way. A viable helper must either:

1. use correctness information not captured by any efficiently exploitable truncated-ideal pseudofunctional while staying polynomial-size, or
2. use a computational source-aware encoding whose **complete** helper/capsule security is reduced to an independently justified PQ primitive.

The Run-42/43 SIS supplied-short-preimage binding theorem remains useful if such a helper is obtained. Ceremony composition and end-to-end parameters remain downstream of that missing inner primitive.
