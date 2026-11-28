# Run 66 — erased-secret linear tags, exact affine-hull bypass, and the nonlinear checksum boundary

## Scope and starting checkpoint

This run starts from PR #1 head `839ed4460948e5c550c115aaf762fa75482addd9` after reading the latest Run-65 checkpoint/result and the current draft PR state.

Run 65 established a useful conditional positive result and a precise missing step:

- a high-order exclusion block can give a polynomially large metric gap **if** the true nonlinear feature vector is bound to one source representation;
- every affine/public-linear query interface has an exact three-accepting-preimage bypass;
- leaving higher-order features as free linear auxiliaries collapses the ideal gap back to a weight-three forged representation.

This run tests a natural use of the setup ceremony that Run 65 left open: hide random nonlinear-consistency checks in the key-bearing capsule, erase their coefficients, and hope that a malformed signed representation cannot adapt to them.

The constructive attempt is stronger than an optional public verifier. The hidden tag is inserted directly into the same additive capsule coordinate that carries the native secret pad, so an attacker cannot repair the candidate merely by saying “ignore the checker.” The complete-output audit nevertheless shows an exact obstruction for **linear** erased tags: the Run-53 signed pseudorepresentations cancel the hidden tag algebraically before any LWE/SIS assumption is relevant.

A genuinely nonlinear hidden checksum is a positive semantic control: it detects every fixed malformed normalized block with exact probability `1-1/q` per independent random check. But every additive/public linearization of that checksum again admits an affine forged lift. This identifies the remaining primitive more sharply: the nonlinear check has to be entangled in the **key-bearing public operation itself**, not merely represented by more additive coordinates.

No external literature or web search was used. Production code is unchanged. This is not a completed WKEM and not an LWE/SIS security proof.

---

## 1. Candidate: erased-secret consistency tags inside the native capsule

Start from a public integral/modular representation relation

```text
B y = d.
```

A source witness gives a representation `y_w`. The ordinary native additive capsule has the shape

```text
a = B^T s + e,
c = d^T s + e0 + mu K,
```

so every exact preimage cancels the secret pad:

```text
c - y^T a = mu K + e0 - y^T e.
```

That is precisely why the Run-53 signed pseudorepresentations are dangerous.

### 1.1 Entangled hidden tag

Let setup additionally choose an erased random tag vector `tau`, constructed from the public verifier topology but not from a source witness, such that

```text
<tau, y_w> = 0
```

for every genuine source representation.

Publish instead

```text
a = B^T s + e + Delta tau,
c = d^T s + e0 + mu K.
```

Then

```text
c - y^T a
  = mu K + e0 - y^T e - Delta <tau,y>.
```

A genuine witness still gets the key because its hidden tag phase is exactly zero. A malformed exact preimage would be destroyed if `<tau,y>` were unpredictable and nonzero.

This is not an optional checker: the tag is in the same public coordinates used to cancel `B^T s`.

The natural ceremony implementation is to build `tau` from random **consistency labels** on shared variable occurrences.

---

## 2. Concrete hidden-incidence tag construction

For a local-view/CNF representation, block `b` has row coefficients `z_{b,a}` over locally valid rows `a`. For each global Boolean variable `v`, let the setup choose random field labels

```text
theta[v,0], theta[v,1].
```

For every incidence `(b,v)`, choose a public-or-secret coefficient `gamma[b,v]` satisfying

```text
sum_{b containing v} gamma[b,v] = 0.
```

Assign block-row `(b,a)` the hidden tag

```text
tau[b,a] = sum_{v in V_b} gamma[b,v] theta[v,a_v].
```

A genuine globally consistent witness chooses one row in every block. If its bit for variable `v` is `w_v`, the total tag is

```text
sum_b tau[b,w|V_b]
 = sum_v theta[v,w_v] * sum_{b containing v} gamma[b,v]
 = 0.
```

Thus setup needs no witness. The random `theta` values can be generated during the ceremony and erased after the public capsule is formed.

At first sight this looks materially stronger than the earlier public marginal relation because the actual tag coefficients can be perfectly hidden.

It is not stronger against the signed local-view pseudorepresentations.

---

## 3. Proved attack: exact shared marginals cancel every such secret tag

For an arbitrary signed representation define its block marginal for bit value `1` by

```text
p_{b,v} = sum_a a_v z_{b,a}
```

and use block normalization `sum_a z_{b,a}=1`.

Its contraction with the secret incidence tag is

```text
sum_{b,a} z_{b,a} tau[b,a]
 =
sum_v sum_{b containing v} gamma[b,v]
      [ theta[v,1] p_{b,v} + theta[v,0] (1-p_{b,v}) ].
```

If the representation has **shared marginals**

```text
p_{b,v} = p_v
```

for all incident blocks, then the bracket is independent of `b`, so

```text
<tau,y>
 =
sum_v [theta[v,1] p_v + theta[v,0](1-p_v)]
      * sum_{b containing v} gamma[b,v]
 = 0.
```

This identity holds for **every** choice of hidden labels `theta`. There is no probability statement and no cryptographic assumption.

### Consequence

The exact Run-53 signed lifts already satisfy block normalization and shared marginals. Therefore they cancel the erased-secret incidence tag identically.

Adding the tag to an LWE-style native capsule does not require the attacker to learn the tag or the LWE secret. The same public signed preimage cancels both:

```text
B y = d,
<tau,y> = 0.
```

The resulting residual is the same key-bearing residual, up to the ordinary noise, as before the tag was added.

So **hiding a linear consistency tag is not enough**. Semantic pseudorepresentations that satisfy the tag identity algebraically remain valid no matter how well the tag coefficients themselves are hidden.

---

## 4. More general theorem: secret linear checks cannot bind an affine hull

The incidence attack is one concrete realization of a broader fact.

Let

```text
U_1,...,U_m in V
```

be any publicly usable source decoder/lift vectors for a local one-hot choice. The vectors may contain arbitrary polynomial features, setup-randomized coordinates, or other auxiliary data.

Let a secret linear checker `L:V -> F_q^t` be correct with the same required value `c` on every source lift:

```text
L(U_i) = c   for all i.
```

For any coefficients `lambda_i` satisfying

```text
sum_i lambda_i = 1,
```

define the affine forged lift

```text
U_lambda = sum_i lambda_i U_i.
```

Then, without knowing `L`,

```text
L(U_lambda)
 = sum_i lambda_i L(U_i)
 = c.
```

### Three-source forge

For any three source lifts,

```text
U_* = U_a + U_b - U_c
```

passes **every** such secret linear checker exactly, because the coefficients sum to one.

If the public/raw projection maps the source lifts to one-hot vectors,

```text
pi(U_i) = (1,e_i),
```

then

```text
pi(U_*) = (1, e_a + e_b - e_c),
```

which is a normalized signed non-one-hot vector of support three.

This theorem is independent of:

- whether the checker coefficients are public or perfectly hidden;
- how many linear checks are used;
- the feature dimension;
- whether the feature coordinates include arbitrarily high-degree polynomial values;
- whether setup later erases the checker trapdoor.

The only requirement is that the key-bearing/check operation is additive-linear in a publicly usable source lift and has the same correct value on those source lifts.

This does **not** prove that every cross-block row-dependent secret-tag scheme is useless. A surviving scheme may assign different local tag values that cancel only globally. Section 3 shows, however, that the natural hidden-incidence realization is still exactly canceled by the existing shared-marginal pseudorepresentations.

---

## 5. Positive control: a genuine nonlinear one-hot checksum works semantically

The failure above is about linearized/additive checks. A truly nonlinear hidden checksum does distinguish malformed normalized coefficients.

Let

```text
z = (z_1,...,z_m) in F_q^m,
sum_i z_i = 1.
```

Define the quadratic one-hot violation vector

```text
G(z) =
(
  z_i(z_i-1)                 for every i,
  z_i z_j                    for every i<j
).
```

### Lemma 5.1

`G(z)=0` if and only if `z` is one-hot.

### Proof

`z_i(z_i-1)=0` makes every coordinate Boolean. The pair products make at most one coordinate equal to one. Normalization forces exactly one. Conversely a one-hot vector makes every component zero. QED.

Now choose a uniformly random hidden vector `r` of the same dimension and define

```text
chi_r(z) = <r,G(z)>.
```

For every fixed malformed normalized `z`, `G(z)` is nonzero, hence

```text
Pr_r[chi_r(z)=0] = 1/q.
```

With `kappa` independent hidden checks the fixed-representation survival probability is exactly `q^{-kappa}`.

This is a real constructive semantic improvement over a linear tag. Setup can sample `r` without knowing a source witness because the one-hot equations are public.

### Critical scope

This is only useful if the public offline KEM can force the key-bearing operation to evaluate **the actual nonlinear `G(z)`** of the representation being used.

That implementation is the missing step.

The probability statement is for a fixed malformed `z` independent of the hidden `r`. An implementation must separately prove that its complete public transcript does not leak enough about `r` to let a QPT attacker adapt `z`.

---

## 6. Why the obvious additive quadratic lift loses the check exactly

The direct additive implementation introduces public/lifted coordinates

```text
Y_ii  intended as z_i^2,
Y_ij  intended as z_i z_j.
```

and replaces the nonlinear equations by linearized ones such as

```text
Y_ii - z_i = 0,
Y_ij = 0   for i != j
```

on one-hot source points.

Take the support-three normalized vector

```text
z_* = e_1 + e_2 - e_3.
```

Set

```text
Y_* = diag(z_*).
```

Then every linearized one-hot identity above holds exactly:

```text
Y_ii = z_i,
Y_ij = 0.
```

But the true nonlinear violation does not vanish:

```text
G(z_*) != 0.
```

Indeed `(z_3)(z_3-1)=2` and several pair products are nonzero over every sufficiently large odd field.

The lifted forged point is exactly

```text
Phi(e_1) + Phi(e_2) - Phi(e_3),
```

where `Phi(e_i)` is the genuine quadratic source lift.

Therefore every secret **linear** checksum that is correct on all genuine quadratic source lifts is also correct on the forged `(z_*,Y_*)`.

This is not a weakness of quadratic degree specifically.

---

## 7. Degree-independent lifted-feature barrier

Let `Phi(e_i)` contain **any finite or infinite list of features** of the one-hot source point `e_i`: monomials of any degree, random setup features, table lookups, or other values.

As long as the public key-bearing layer treats the resulting lift additively-linearly, the same affine forged lift

```text
Phi_* = Phi(e_1) + Phi(e_2) - Phi(e_3)
```

inherits every linear identity and every secret linear checker value that all three source lifts share.

For ordinary polynomial features this has a particularly simple form:

- every mixed monomial is zero on a one-hot point;
- every positive pure power of coordinate `i` equals that coordinate;
- the affine forge therefore sets every lifted pure-power coordinate to the signed coefficient `z_i` and every mixed coordinate to zero.

No polynomial degree repairs the fact that the lifted coordinates are no longer required to be the **true nonlinear features of the raw signed vector**.

This is the exact implementation gap Run 65 exposed at high degree, now stated independently of the chosen degree and independently of whether the linear checks are public or erased-secret.

---

## 8. Proper-degree hierarchy of the Run-53 signed falsifying lift

There is a second exact identity that clarifies why low-degree hidden tags are especially weak on the existing local-view pseudorepresentations.

For a width-`k` unique-reject row `f`, Run 53 used

```text
q_f(a) = (-1)^(d_H(a,f)+1),    a != f.
```

Let `P(a)` be any multilinear polynomial in the row bits of total degree `< k`.

Then

```text
sum_{a != f} q_f(a) P(a) = P(f).                 (1)
```

### Proof

Translate `a` by `f`. Each bit flip is an affine substitution, so degree `<k` is preserved. It is enough to take `f=0`.

For a monomial `m_S(a)=prod_{i in S} a_i` with `|S|<k`,

```text
sum_{a != 0} (-1)^(|a|+1) m_S(a)
```

equals `1` for `S=empty` and `0` for every nonempty proper `S`, exactly the value `m_S(0)`. Linearity gives (1). QED.

Thus the falsifying signed lift is **indistinguishable from the rejected point to every degree-<k polynomial moment**.

A degree-`k` point indicator separates them:

```text
delta_f(f)=1,
delta_f(a)=0 for every allowed a != f,
sum_{a != f} q_f(a) delta_f(a)=0.
```

This matches the Run-65 high-order exclusion result from another direction: full local degree can separate the signed lift, but making that nonlinear target value available to an offline additive capsule is exactly the feature-binding problem.

---

## 9. Complete-output interpretation

The candidate hidden tag was deliberately inserted into the same additive coordinate as the key-bearing native pad. Therefore this run does not fail merely because an adversary can omit an optional checker.

It fails because the existing pseudorepresentation lies in the **exact kernel of the hidden tag for every ceremony randomness** in the natural incidence construction.

Likewise, for a general local one-hot lift, any secret linear checker that must take one common correct value on every publicly usable source lift necessarily takes that same value on their affine hull.

Consequently:

> Erasure and computational hiding can protect the coefficients of a linear tag, but they cannot change an algebraic identity that already makes the malformed representation's tag exactly correct.

A surviving binder must make malformed source coefficients feed a **nonlinear key-bearing operation** before the attacker is free to replace nonlinear feature values by an independent affine lift.

Examples of what this statement does *not* rule out include a genuinely nonadditive post-quantum public operation, or a standard-assumption mechanism that cryptographically binds a nonlinear evaluation without exposing a freely choosable lifted vector. No such mechanism is constructed here.

---

## 10. Executed validation

`erased_linear_tag_run66_check.py` is deterministic, standard-library-only, seed `660066`, modulus `q=257`.

The finalized checker was executed twice and the two JSON outputs were byte-identical.

It checked:

- **320** arbitrary random source-lift systems and **1,920** secret linear tag functionals sampled from the full constant-on-source nullspace; every support-three affine forge inherited the exact honest tag value;
- **2,131** normalized small centered non-one-hot vectors; every one had a nonzero genuine quadratic violation vector;
- **100** exhaustive single-coefficient sweeps of the hidden quadratic checksum, each with exactly **1 zero among 257 choices**, matching the exact `1/q` theorem;
- dimensions `m=3..10` for the quadratic linearized lift; all **8/8** support-three forgeries satisfied the linearized lift while violating the true quadratic relation;
- **348** random secret polynomial-feature linear checks, all inherited exactly by the affine forged lift;
- the eight-block width-3 all-exclusions false formula under **200** random erased incidence-tag setups: all **1,600/1,600** false signed pseudolifts had exact total hidden tag zero;
- every falsifying row for `k=2..8` against every proper multilinear monomial: **86,868** exact proper-moment equalities;
- **508** full-degree point-indicator separations.

Checker SHA-256:

```text
f06c262ed947133dcd6c98bae80070ddece9f429d149986d7ea22cfdbeaaa252
```

Captured validation SHA-256:

```text
4be3db48fe467b3074f7482c603ab8a0be03251508c9b795165d940f08e69dfb
```

These tests validate the finite algebra and the implementation. They are not evidence of LWE/SIS security or of a complete WKEM.

---

## 11. What is proved and what remains open

### Proved here

1. The natural erased-secret **linear incidence tag**, even when entangled directly into the native key-bearing capsule, is canceled exactly by the Run-53 signed shared-marginal pseudorepresentations.
2. Any secret linear checker taking one common correct value on all publicly usable local source lifts takes that same value on their entire affine hull; a three-source signed forge therefore survives independently of feature dimension and checker secrecy.
3. A genuine quadratic hidden one-hot checksum detects every fixed malformed normalized block with exact probability `1-1/q` per independent check.
4. Replacing that nonlinear checksum by an additive quadratic/polynomial lift restores an exact support-three affine forgery.
5. The Run-53 signed falsifying lift matches the rejected point on **every polynomial moment of degree `<k`** and is separated by a degree-`k` point indicator.

### Not proved / still missing

- A public offline post-quantum mechanism that evaluates a genuinely nonlinear hidden checksum **inside the key-bearing operation** without exposing an independently forgeable lifted feature vector.
- A non-circular reduction of that mechanism's complete public transcript to LWE/SIS or another independently justified PQ assumption.
- Arbitrary-QPT early key recovery on true instances `=>` source-witness extraction or an independently justified PQ break.
- Generic-NP false-instance hiding for such a nonlinear mechanism.
- Malicious-secure erased-setup composition, auxiliary-input composition, and practical end-to-end parameters.

The stopping condition is therefore not met.
