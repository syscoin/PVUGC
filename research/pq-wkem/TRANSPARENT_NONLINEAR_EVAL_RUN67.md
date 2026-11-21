# Run 67 — transparent nonlinear evaluators are polynomially interpolable on local feature supports

**Status: constructive nonlinear-binder attempt plus complete-output interpolation theorem and exact attacks; not a completed WKEM.**

## Scope and starting checkpoint

This run starts from PR #1 head `55ebb031d6767407d0a77a41fbf5fa4855aab3f0`, after reading the Run-66 checkpoint/result and current draft PR state.

Run 66 left one specific constructive direction open: a genuinely nonlinear hidden checksum can semantically reject malformed source coefficients, provided the key-bearing public operation is forced to evaluate the *actual nonlinear function* of one raw witness rather than accepting freely chosen lifted monomial coordinates.

This run tests the most direct implementation of that idea:

- setup samples and later erases random coefficients for a nonlinear consistency polynomial;
- the public key-bearing object exposes a transparent evaluator `F(w)` on raw Boolean witness candidates;
- the decoder supplies the actual witness bits `w`, so there are no caller-supplied monomial coordinates.

The result is negative for a broad, explicit class. If the completed public object lets anyone evaluate a multilinear polynomial whose monomial support is known and downward closed, then the supposedly hidden coefficients are recoverable by Möbius interpolation. For constant degree this takes `O(n^d)` public evaluations. More importantly for the surviving Run-65 route, if the support is the union of local scopes of width `R=O(log n)`, the number of required evaluations is at most `T 2^R`, hence polynomial when `T=poly(n)`.

After reconstruction, the candidate collapses exactly to the public coefficient-subspace mask studied in Runs 63–64. On every true instance a public annihilating key functional exists and can be synthesized by linear algebra without a source witness. In the noiseless case it recovers the key exactly. With fixed coefficient noise it returns the exact residual `K + lambda(e)`; the earlier Run-64 covariance theorem then applies whenever the noise model is a public positive-definite Gaussian/covariance model.

This does **not** prove that every nonlinear public operation is interpolable, and it does not rule out a compact high-degree evaluator whose internal coefficients remain cryptographically hidden by a nontransparent mechanism. Implementing such an evaluator without assuming an obfuscation/FE/WE-equivalent release primitive remains open.

No external literature or web search was used. Production code is unchanged.

---

## 1. Constructive candidate: erased hidden nonlinear checker as a transparent public evaluator

Let the public NP relation be described by known multilinear constraint polynomials

```text
h_1(w), ..., h_t(w)
```

over a field `F_q`, with

```text
h_j(w) = 0
```

for every valid Boolean witness `w`.

Setup samples hidden random coefficients `rho_j`, a key `K`, and optionally a coefficient-noise polynomial `E`. It forms

```text
F(w) = K + sum_j rho_j h_j(w) + E(w).                    (1)
```

The `rho_j` are intended to be temporary ceremony secrets and erased.

A genuine witness sees

```text
F(w) = K + E(w).                                         (2)
```

The attraction compared with the failed additive lift in Run 66 is that the caller supplies only raw witness bits. It never supplies free values for `w_i w_j`, higher monomials, or a separate feature vector.

The critical complete-output question is whether the public evaluator itself hides the polynomial coefficients.

For the transparent low-/local-degree realization below, it does not.

---

## 2. Exact interpolation theorem on Boolean inputs

Write a multilinear polynomial as

```text
F(x) = sum_{S in M} a_S prod_{i in S} x_i,              (3)
```

where `M` is a known family of subsets of `[n]`.

Assume `M` is **downward closed**:

```text
S in M and U subset S  =>  U in M.                       (4)
```

For `T subset [n]`, let `1_T` be its Boolean indicator vector.

Then

```text
F(1_T) = sum_{S subset T} a_S.                           (5)
```

because a monomial indexed by `S` evaluates to one exactly when `S subset T`.

### Theorem 2.1 — Boolean Möbius reconstruction

For every `T in M`,

```text
a_T = sum_{U subset T} (-1)^(|T|-|U|) F(1_U).           (6)
```

Thus the complete coefficient vector is recoverable from exactly `|M|` public evaluations, all on Boolean inputs.

### Proof

Equation (5) is the zeta transform on the Boolean subset lattice. Equation (6) is its Möbius inverse. Downward closure guarantees every queried `U subset T` is itself in `M`, so all required values belong to the stated query set. QED.

This is an exact algebraic statement over every field. In characteristic two, the signs in (6) coincide, as expected.

---

## 3. Complexity consequences

### 3.1 Dense degree-`d` evaluator

If `M` contains all monomials of degree at most `d`, then

```text
|M| = sum_{i=0}^d C(n,i).                                (7)
```

For constant `d`, this is polynomial in `n`.

Therefore erasing the coefficients of a public transparent quadratic, cubic, or other constant-degree key-bearing polynomial does not keep them hidden.

### 3.2 Known local scopes, including the Run-65 width

Suppose the hidden checker is a sum of local functions on known scopes

```text
Q_1, ..., Q_T,
|Q_j| <= R.
```

Its monomial support lies in

```text
M = union_j P(Q_j),                                      (8)
```

which is downward closed and satisfies

```text
|M| <= sum_j 2^|Q_j| <= T 2^R.                          (9)
```

Hence if

```text
T = poly(n),   R = O(log n),
```

then the entire hidden local high-order polynomial is recoverable with polynomially many public evaluations.

This directly covers the obvious transparent-evaluator implementation of the Run-65 high-order local feature: taking local degree all the way to `R=Theta(log n)` does not by itself defeat interpolation because each local truth table has only `2^R=poly(n)` entries.

### Important scope

The theorem is about a transparent evaluator whose multilinear support is publicly known (or at least bounded by such a known downward-closed family). It does not cover an opaque compact circuit whose effective polynomial has exponentially many unknown monomials and whose hidden constants cannot be inspected or queried through the algebraic core.

A software branch such as

```text
if Verify(w): return EvalHiddenPolynomial(w)
else: reject
```

does not by itself provide that opacity in the public-offline model: the public data and code can be copied and the algebraic evaluator run on arbitrary candidate bits unless a separate cryptographic access-control/obfuscation mechanism is supplied. This run does not assume such a mechanism.

---

## 4. After interpolation: exact reduction to the public subspace mask

Let `P_M` be the coefficient vector space indexed by `M`. Let

```text
u = coefficient vector of the constant polynomial 1,
V = span{ coefficient(h_1), ..., coefficient(h_t) }.
```

After interpolation, the public learns the complete vector

```text
f = K u + v + e,     v in V,                            (10)
```

where `e` is the recovered coefficient-noise vector (possibly zero).

That is exactly the public-subspace form from Run 63.

### Theorem 4.1 — true instance gives a public key functional

If the statement has a valid Boolean witness `w`, then there exists a public linear functional `lambda` satisfying

```text
lambda(u) = 1,
lambda(V) = 0.                                           (11)
```

Moreover such a `lambda` can be synthesized from the public constraint coefficient matrix by Gaussian elimination; the witness is not needed by that algorithm.

### Proof

Evaluation at a valid witness,

```text
ell_w(p) = p(w),
```

satisfies

```text
ell_w(u) = 1,
ell_w(h_j) = 0
```

for every constraint. Hence system (11) is consistent.

All coefficients defining (11) are public after the support is fixed, so ordinary linear algebra finds some solution `lambda`. QED.

Consequently,

```text
lambda(f) = K + lambda(e).                               (12)
```

In the noiseless case `e=0`, this gives exact public recovery of `K`.

The synthesized `lambda` need not itself be evaluation at any Boolean witness. Therefore the native recovery object produced by this attack is not automatically a source witness.

---

## 5. Noise interpretation

Equation (12) is exact for any fixed coefficient noise.

If the coefficient noise is modeled by a public positive-definite real Gaussian covariance `Sigma`, Run 64 already proved that the public minimum-variance feasible dual

```text
lambda_* =
Sigma^-1 C^T (C Sigma^-1 C^T)^-1 b
```

has variance no larger than any valid witness-evaluation functional, because every witness functional is feasible for the same public constraints.

Therefore the transparent nonlinear wrapper does not evade that theorem: interpolation first exposes the noisy coefficient vector, then the Run-64 public covariance dual applies unchanged.

This run does **not** extend that minimum-variance theorem to arbitrary modular/discrete noise distributions. The surviving modular short-dual issue remains distinct.

---

## 6. False-instance control

If

```text
u in V,
```

then there is a constraint-span vector equal to the constant polynomial one. In the noiseless candidate

```text
K u + V = V
```

for every `K`, so the coefficient-vector distribution is identical across keys when the hidden span coefficient is sampled uniformly.

The checker includes the simplest explicit control `h_1=1` over `F_q`: exhaustive enumeration of the hidden coefficient gives identical reconstructed-output histograms for every key.

This is only a control. A generic false NP instance need not have `1` in the span of the *bare* constraints at a low degree. Obtaining false-instance hiding may require ideal multiples or another compiler, and the degree/size consequences remain part of the unresolved problem.

---

## 7. Why this is not merely “the coefficients are public”

The constructive attempt was deliberately allowed to expose only an evaluation algorithm, not a coefficient list.

The attack uses the stronger public-offline property:

1. the evaluator can be copied and run locally;
2. it accepts raw candidate bits;
3. its relevant function lies in a polynomial-size known multilinear support.

Under those conditions the adversary manufactures its own coefficient list using (6). Erasing the setup coefficients after constructing the evaluator therefore provides no protection.

The local-support version is important: even `R=Theta(log n)` full local degree is not enough if the evaluator is a sum of known local functions, because its total support remains polynomial.

---

## 8. What would survive this theorem

A candidate is not ruled out merely because its semantic checker is nonlinear.

To avoid this run's attack, at least one of the following must fail:

- the key-bearing algebraic core is publicly evaluable on arbitrary candidate bits;
- its effective multilinear support is polynomial-size and known/downward-closed;
- its recovered coefficient vector has the public subspace form `K u + V + e`;
- or the public dual has decoding-quality noise.

A compact **high global degree** function can have exponentially many monomials while still having a small arithmetic circuit. But if the coefficients/constants of that circuit are transparent, erasure again buys nothing; if they remain cryptographically hidden while arbitrary valid witnesses can still drive the circuit to the common key, then that hidden evaluator is itself the missing primitive and needs an independent standard-assumption construction and full-output reduction.

This run does not name such an evaluator as an assumption.

---

## 9. Executed validation

`transparent_nonlinear_eval_run67_check.py` is deterministic, standard-library-only.

The finalized checker validates:

1. exact Möbius reconstruction for dense degree-bounded random polynomials over several prime fields;
2. exact reconstruction for unions of known local scopes, including width-10 scopes;
3. hundreds of fresh satisfiable hidden-checker instances in which:
   - the attack receives only the public constraints and black-box evaluator;
   - interpolation recovers the exact coefficient vector;
   - public Gaussian elimination synthesizes `lambda`;
   - `lambda(f)=K` exactly without using the planted witness;
4. whether the synthesized dual itself coincides with any Boolean evaluation functional (recorded as a diagnostic, not required for the attack);
5. exact noisy residual identities `lambda(f)=K+lambda(e)`;
6. an exhaustive false-instance control with `1 in V`, showing identical reconstructed-output histograms for every key.

Tests validate the implementation and finite algebra only. Security conclusions come from the proofs above.

---

## 10. Current conclusion and handoff

### Proved this run

- transparent public evaluation of a known downward-closed multilinear support leaks all coefficients by exact Boolean Möbius interpolation;
- constant-degree support costs `sum_{i<=d} C(n,i)` queries;
- known local scopes cost at most `T 2^R` queries, so the Run-65 `R=O(log n)` full-local-degree direction is still polynomially interpolable if implemented transparently;
- on every true instance the reconstructed coefficient vector admits a publicly synthesized key functional;
- noiseless unauthorized key recovery is exact;
- fixed coefficient noise obeys the exact residual identity (12), and the prior Run-64 public-Gaussian theorem composes after interpolation.

### Not proved

- no general impossibility for arbitrary nonlinear/nontransparent public operations;
- no generic modular short-dual lower bound;
- no arbitrary-QPT-to-source-witness reduction for a surviving construction;
- no malicious-secure erased-setup theorem for a surviving nonlinear binder;
- no complete practical WKEM.

### Next constructive target

The remaining direction is no longer “hide a quadratic checksum and erase it.” A surviving binder must prevent polynomial-time reconstruction of its effective key-bearing function while still letting **every** valid witness invoke that function offline and obtain the same key.

A compact globally high-degree evaluator is the next algebraic possibility, but making its hidden constants available for valid-witness evaluation without exposing either its coefficient function or a free lifted representation is exactly the unresolved cryptographic step. Any proposal for that step must be built from an independently justified PQ assumption rather than being named as a WE-equivalent release primitive.
