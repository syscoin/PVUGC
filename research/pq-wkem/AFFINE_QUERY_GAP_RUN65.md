# Run 65 — high-order exclusion block, affine-query three-preimage barrier, and the nonlinear-feature handoff

## Scope and starting checkpoint

This run starts from PR head `c17ef2c2ee95b7b166dc05d7bb8fdfb83f5b3f3a` after reading the latest Run-64 result and current PR discussion. Run 64 left one narrow route open: a genuinely modular short-dual construction in which source witnesses induce decoding-quality centered representatives, while every unauthorized public dual is outside the useful decoding radius or finding one reduces to an independently justified PQ problem.

This run makes a constructive attempt to create a **superconstant local metric gap** before any LWE/SIS assumption is invoked. The proposed semantic gadget is a padded high-order exclusion block. It has a strong exact gap if its high-order query features are trusted. The complete public-output audit then finds the obstruction: any purely affine/public-linear query interface has an exact three-accepting-preimage representation of the rejected query, and leaving the nonlinear features as free linear auxiliaries restores a weight-three forgery.

The result is therefore a conditional positive interface plus a new exact no-go for its naive linearization. It is **not** a completed WKEM, not an LWE/SIS reduction, and not a claim that all nonlinear/computational binders fail.

No external literature or web search was used. Production code is unchanged.

---

## 1. Candidate: padded high-order exclusion block

Work first over `F_2`. Let a local predicate have a single rejected query `q*`. If the original predicate has several rejected rows, split it into a constant number of single-reject tests, one for each rejected local row. This costs only a constant factor for constant local arity.

Pad the local query to `R >= 2` bits. The extra bits are intended to be fixed to zero. Let

```text
Omega = {0,1}^R \ {q*}.
```

For every allowed row `x in Omega`, introduce a block coordinate `z_x`.

For every proper subset `S subsetneq [R]`, including `S=empty`, define the Boolean monomial

```text
m_S(x) = product_{i in S} x_i.
```

The **ideal trusted-feature block** asks for

```text
sum_{x in Omega} m_S(x) z_x = m_S(q)      for every S subsetneq [R],
```

where `q` is the actual queried local Boolean row and the right-hand feature vector is assumed to be the real degree-`<=R-1` Boolean moment vector of that same `q`.

There are exactly `2^R-1` block coordinates and `2^R-1` equations.

### Theorem 1.1 — exact ideal block gap

For every accepted query `q != q*`, the unique block solution is the one-hot vector `delta_q`, of Hamming weight one.

For the rejected query `q=q*`, the unique block solution is the all-ones vector on `Omega`, of Hamming weight

```text
M = 2^R - 1.
```

### Proof

The full Boolean monomials `{m_S : S subseteq [R]}` form a basis of all functions `{0,1}^R -> F_2`. Hence the proper monomials, with the degree-`R` monomial omitted, are linearly independent and span a `(2^R-1)`-dimensional subspace.

Restrict their evaluation matrix to the `2^R-1` points in `Omega`. If a proper-degree polynomial vanished on all of `Omega`, as a Boolean function it would be supported on at most the single point `q*`. The nonzero point indicator at `q*` has algebraic degree exactly `R`, so no nonzero degree-`<=R-1` function can have that support. Therefore the restricted square evaluation matrix is invertible.

For an accepted `q`, `delta_q` visibly has the required moments, hence it is the unique solution.

For the rejected `q*`, let `1_Omega` be one on every allowed row. On the full cube, the all-ones coefficient vector has zero inner product with every proper monomial because

```text
sum_x m_S(x) = 2^(R-|S|) = 0 mod 2
```

for every `S subsetneq [R]`, including the empty set. Removing the `q*` coefficient therefore leaves exactly the moment vector of `delta_{q*}`. Thus `1_Omega` satisfies the rejected moment equations. Invertibility makes it unique. QED.

This is the desired local geometry: one honest coordinate versus `2^R-1` rejected coordinates.

---

## 2. Conditional global consequence if those features were really bound

Suppose, only for this subsection, that every local block receives the **true** high-order feature vector of one common Boolean proof assignment.

Let

- `W` be the number of Boolean proof-variable blocks;
- `T` be the number of single-reject local tests;
- `B=W+T` be the Hamming weight of every honest global representation, since every proof-bit block and every accepted local block contributes one;
- `M=2^R-1` be the rejected-block weight.

Every Boolean proof assignment then determines exactly one global projective representation. If it violates `nu` local single-reject tests, that representation has exact weight

```text
w = B + (M-1) nu.
```

For a false statement, `nu>=1` for every proof assignment, so every projective mode has weight at least

```text
B + M - 1.
```

The important point is that this is a **superconstant** gap when `R` grows logarithmically.

### Binary additive capsule diagnostic

Consider the same binary native capsule studied in the earlier native/projective runs:

```text
c = A^T s + e,
d = b^T s + e0 + K,
```

with independent Bernoulli bit errors of rate `p` and

```text
rho = 1 - 2p.
```

For transcript Fourier label `(z,t)`, exact character averaging gives key-sensitive support only at

```text
t=1,  A z = b,
```

with coefficient magnitude

```text
rho^(wt(z)+1).
```

Let

```text
S = sum_{Az=b} rho^(2 wt(z)).
```

Parseval plus Cauchy-Schwarz gives the complete key-conditioned transcript bound

```text
TV(P_0,P_1) <= rho sqrt(S) <= sqrt(S).
```

Under the ideal trusted-feature compiler, projective solutions are in bijection with Boolean proof assignments. Therefore for a false statement

```text
S <= 2^W rho^(2(B+M-1)).
```

This is a bound on the **complete public distribution**, not just on a direct decoder.

If honest direct decoding is set to success `h>1/2`, define

```text
beta = 2h-1,
rho^(B+1) = beta.
```

Then choosing

```text
M >= ((W+2kappa) ln 2)/(-2 ln rho) - B + 1
```

makes the crude bound satisfy

```text
S <= 2^(-2kappa),
TV(P_0,P_1) <= 2^(-kappa).
```

Because `-ln rho = Theta(1/B)` at fixed honest success, this needs

```text
M = Theta(B(W+kappa)),
R = Theta(log(B(W+kappa))).
```

So **if** the nonlinear feature vector could be bound to the real query, the local block gives a polynomial-size information-theoretic false-instance hiding route for this binary diagnostic while keeping constant honest direct success.

The checker evaluates several finite parameter examples. They are an ideal-interface diagnostic only; they are not a deployable parameter claim because the feature-binding problem below is unresolved.

---

## 3. Complete-output audit: affine query maps have a three-preimage barrier

The ideal block needs the public relation to know a nonlinear feature vector of the queried witness bits. Before trying to implement that, consider any local public linear capsule whose right-hand syndrome depends **affinely** on the queried Boolean row.

Let `Rng` be any commutative ring and

```text
sigma(q) = c + sum_i q_i l_i
```

be an affine syndrome map from `{0,1}^r` to an `Rng`-module, with `r>=2`.

Fix a uniquely rejected row `q*`. Choose two distinct bit positions `i,j` and define the three accepted rows

```text
a = q* with bit i flipped,
b = q* with bit j flipped,
c = q* with bits i and j flipped.
```

Coordinatewise over the integers,

```text
q* = a + b - c.
```

Because an affine map preserves affine combinations whose coefficients sum to one,

```text
sigma(q*) = sigma(a) + sigma(b) - sigma(c).
```

### Theorem 3.1 — affine-query three-preimage barrier

Let `H` be any public linear map. Suppose the three accepted rows have source-local preimages

```text
H z_a = sigma(a),
H z_b = sigma(b),
H z_c = sigma(c).
```

Then

```text
z_* = z_a + z_b - z_c
```

is an exact preimage for the uniquely rejected query:

```text
H z_* = sigma(q*).
```

For every norm obeying the triangle inequality,

```text
||z_*|| <= ||z_a|| + ||z_b|| + ||z_c||.
```

In particular, if all accepted local source encodings have norm at most `L`, the rejected query has a public algebraic preimage of norm at most `3L`. For support/Hamming weight, its support is contained in the union of the three accepted supports, so its support is at most the sum of their supports.

This holds over `F_2`, odd or even modular rings, and the integers. Random row scrambling, public basis changes, or a larger linear ambient space do not change the identity.

### Consequence

A superconstant local short-dual gap cannot come from an affine syndrome of the raw query bits. The ideal high-order block escapes Theorem 3.1 only because its feature map contains nonlinear monomials.

This is a quantitative strengthening of the earlier affine-hull/extended-formulation warnings: for the single-reject local gadget it does not merely say that the rejected point lies in an affine relaxation; it gives an explicit **three accepted source-preimage combination** and a factor-three norm upper bound.

---

## 4. Natural linearization of the high-order features fails with weight three

One might now keep the ideal high-order block but expose its degree-`>=2` moments as auxiliary public variables, while tying only the raw/degree-one features to the real query bits through linear equations.

That does not work.

Take, after an affine relabeling, the rejected padded query

```text
q* = 0^R,
```

with `R>=3`, and the three accepted points

```text
a = e_1,
b = e_2,
c = e_1 + e_2.
```

Let `phi(x)` be the proper-monomial feature vector from Section 1. Define the forged feature vector

```text
m_forge = phi(a) + phi(b) + phi(c)   over F_2.
```

Then:

1. its constant and every degree-one coordinate agree exactly with `phi(q*)`; but
2. its quadratic `x_1 x_2` coordinate equals one, whereas the real rejected feature has zero there.

The weight-three allowed-row vector

```text
z = delta_a + delta_b + delta_c
```

satisfies the entire high-order block with right-hand side `m_forge`.

So if the nonlinear feature coordinates are merely free or linearly unconstrained auxiliaries, the ideal rejected weight `2^R-1` collapses immediately back to **three** while all raw queried bits still look exactly like the rejected query.

The checker verifies this for every `R=3..10`: the ideal rejected weights `7,15,...,1023` all become a three-row exact representation under this forged higher-feature vector.

### Why more linear auxiliaries do not solve the exact feature graph

The graph of a genuinely nonlinear Boolean feature such as

```text
m = q_1 q_2
```

is not affine. Projection of the solution set of any system of public linear equations, even after adding arbitrary auxiliary variables, is affine. Therefore no exact purely linear extended formulation can force those nonlinear feature values from the raw query bits.

This is the same algebraic fact behind the earlier Run-62 affine-projection barrier, applied here to the specific feature coordinates that the high-order gap requires.

A surviving implementation therefore needs a **nonlinear/computational feature binder**. Calling that binder hard, or assuming it releases the feature vector only for a source witness, would simply restate the missing WE primitive and is not accepted as a construction.

---

## 5. Relation to the modular short-dual direction

Run 64 left open the possibility that source witnesses yield short centered representatives in a modular affine dual coset while every unauthorized decoder is a hard SIS/ISIS problem.

Run 65 narrows what such a compiler must do:

- If the local syndrome depends only affinely on raw queried bits, every unique rejection inherits an exact three-accepting-preimage decoder. No superconstant local norm amplification is possible.
- High-order nonlinear features **can** create an exponential ideal local gap with only `R=O(log n)` padded bits and `2^R=poly(n)` local dimension.
- But a public linear relation cannot exactly bind those nonlinear features to the same raw witness bits. The naive auxiliary-variable linearization admits the explicit three-row forgery above.

Thus the remaining missing object is more precise than “find a short dual”: it is a public offline PQ mechanism that binds a high-distance nonlinear feature vector to one source witness, while keeping every legitimate witness complete and without making the complete public transcript expose an equivalent no-witness decoder.

The ideal block demonstrates that **if** such a binder existed, a polynomial metric amplification sufficient for complete false-instance Fourier hiding is available. This run does not supply the binder.

---

## 6. Implemented checks actually executed

`affine_query_gap_run65_check.py` is deterministic, standard-library-only, seed `650065`. The finalized checker was executed twice and the two JSON outputs were byte-identical.

It checked:

- **1,200/1,200** affine-square identities over moduli `2`, `17`, and `257`, arities `2..6`;
- **1,000/1,000** exact three-preimage linear combinations with random integer matrices, plus all Euclidean triangle and support-union bounds;
- the ideal high-order block for every `R=2..8`: each restricted moment matrix had full rank `2^R-1`, every one of **501** accepted targets had its unique one-hot solution, and every rejected target had the unique all-ones solution of weight `2^R-1`;
- the free-feature forgery for every `R=3..10`, always giving weight three while the ideal rejected weights ranged from `7` to `1023`;
- an explicit affine-closure counterexample for the Boolean multiplication graph `(q1,q2,q1 q2)`, confirming that the nonlinear feature graph is not the projection of a purely linear `F_2` system;
- finite ideal trusted-feature BSC arithmetic for four `(B,W,kappa)` cases. These are formula checks only and are explicitly marked non-deployable because the nonlinear feature binder is missing.

Checker SHA-256:

```text
07efd27b9484ddca5850d1d2536ee1961629e93553cfe59aadd39ada7117fbb5
```

Captured validation SHA-256:

```text
e0cb07535039759364df8c98de478865e9e2867b09bf5f12a96af6fbdb5525c2
```

Tests validate the finite algebra and implementation. They are not cryptographic evidence beyond the proved identities.

---

## 7. What is proved, what is not

### Proved here

1. The ideal proper-moment exclusion block has exact accepted weight `1` and rejected weight `2^R-1` over `F_2`.
2. If those nonlinear features were globally bound to one proof assignment, the binary additive capsule has the stated complete Fourier/TV false-hiding bound and needs only polynomial `2^R` for fixed honest success and target statistical security.
3. Any affine local query syndrome admits the exact three-accepting-preimage representation of a unique rejection, with norm at most the sum of the three accepted norms.
4. Free/linearly unconstrained higher-order features let the explicit weight-three forgery bypass the ideal high-order block while preserving the real constant/degree-one query features.
5. Pure linear auxiliary-variable extensions cannot exactly enforce a nonlinear Boolean feature graph.

### Not proved / still missing

- A public offline PQ binder that enforces the high-order feature vector from a source witness.
- A standard-LWE/SIS reduction for any such nonlinear binder's **complete public output**.
- Arbitrary-QPT early key recovery `=>` source-witness extraction or an independently justified PQ break on true instances.
- Malicious-secure setup with abort, erased trapdoors, auxiliary-input composition, and the allowed t-of-X / N-of-N operator structure.
- Practical end-to-end resource estimates for a complete construction. The ideal block is polynomial but the finite diagnostic dimensions are already large.

The stopping condition is therefore not met.
