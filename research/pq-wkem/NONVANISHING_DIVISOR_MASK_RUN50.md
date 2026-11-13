# Run 50 — Nonvanishing-divisor ideal mask: exact witness division, complete-view dichotomy, and the quotient-unit boundary

## Status

Starting point: verified PR #1 head `e655d10bfa73bdee22e101538a5afe823c79120e` (Run 49).

This run does **not** claim a completed WKEM, generic false-instance hiding, or a PQ security proof. It makes a concrete attempt to escape the Run-45/49 constant-shift ideal-mask barrier by changing the key-bearing direction from the constant polynomial `1` to a public polynomial `r(w)` that is guaranteed nonzero on every Boolean witness. A witness divides by `r(w)` at decapsulation, so setup still needs no source witness and every valid witness obtains exactly the same key.

The attempt has an exact complete-public-output audit. For the full uniform truncated-ideal coefficient distribution, false hiding is equivalent to `r` belonging to the truncated source ideal. Otherwise Gaussian elimination gives a public exact key extractor. Because `r` is a **unit modulo the Boolean equations**, unbounded membership of `r` is equivalent to unbounded membership of `1`; only the bounded-degree / representation complexity can differ.

The run therefore identifies a real but narrower possible escape hatch: a nonvanishing divisor could only help if it has a substantially cheaper **bounded representation/certificate** on every false instance than the constant polynomial does. The executed small unsatisfiable Boolean controls did not exhibit such a gain.

No external literature or web search was used. Production code is unchanged.

---

## 1. Constructive candidate

Let the source witness be a Boolean vector

\[
w=(w_0,\ldots,w_{n-1})\in\{0,1\}^n
\]

and let the public source constraints be polynomials

\[
g_1(w)=\cdots=g_m(w)=0
\]

over a prime field `F_q`. Include the Boolean equations

\[
b_i(w)=w_i^2-w_i=0
\]

among the source constraints.

For degree cutoff `D`, let

\[
V_D=\operatorname{span}\{m(w)g_j(w),\;m(w)b_i(w):\deg(mg_j),\deg(mb_i)\le D\}
\]

inside the complete coefficient space of polynomials of total degree at most `D`.

Choose a public polynomial `r(w)` such that

\[
r(a)\ne0\qquad\text{for every }a\in\{0,1\}^n.
\tag{1}
\]

To encapsulate a field key `K`, sample `R` uniformly from `V_D` and publish the complete coefficient vector of

\[
\boxed{C_K(w)=K\,r(w)+R(w).}
\tag{2}
\]

A source witness decapsulates by

\[
\boxed{\operatorname{Dec}(w,C_K)=C_K(w)/r(w).}
\tag{3}
\]

### Theorem 1 — exact common-key correctness

For every valid Boolean witness, every source constraint and every Boolean equation vanishes, hence `R(w)=0`. By (1), `r(w)` is invertible in the field, so

\[
C_K(w)/r(w)=K.
\]

Thus setup knows only the statement, no source witness is needed, no participant is online after setup, and **every** valid witness obtains exactly the same key.

This is a genuine nonlinear decoding change relative to Run 45: the witness is allowed to divide by a source-dependent public value rather than merely evaluate a constant-shift ideal mask.

---

## 2. Exact complete-public-output dichotomy

The public coefficient distribution is still an affine coset of the public subspace `V_D`.

### Theorem 2 — hiding or public extraction, with shift direction `r`

Exactly one of the following holds.

1. **`r in V_D`.** Then every key shift `K r` lies in `V_D`, so for uniform `R in V_D` all key-conditioned coefficient distributions are identical.

2. **`r notin V_D`.** Public Gaussian elimination gives a linear functional

   \[
   L:P_{\le D}\to F_q
   \]

   satisfying

   \[
   L(V_D)=0,\qquad L(r)=1.
   \]

   Applying it to the complete capsule gives

   \[
   \boxed{L(C_K)=K}
   \]

   for every setup random choice.

The proof is the same finite-dimensional affine-coset argument as Run 45, but the distinguished direction is now `r` rather than `1`.

### Consequence for multiplicative/factorized repairs

Suppose one additionally publishes key-independent public factors and has the witness multiply them with (2) before decoding. That does not repair Case 2: the separator above acts on the key-bearing coefficient vector `C_K` alone and recovers `K` before any witness-side multiplication is considered.

Therefore a multiplicative-consistency wrapper can only help this architecture if the key-bearing direction `r` is already hidden inside the mask span. Nonlinear witness post-processing does not convert an exposed affine coset into a computationally hidden one.

---

## 3. Explicit globally nonvanishing divisor

For the executed controls use

\[
\boxed{r_n(w)=1+\sum_{i=0}^{n-1}2^i w_i.}
\tag{4}
\]

If the prime satisfies `q > 2^n`, then for every Boolean vector, interpreting the sum as an integer gives

\[
1\le r_n(w)\le 2^n<q.
\]

Hence `r_n(w)` is never zero modulo `q`.

The field modulus therefore needs only `O(n)` bits even though its numeric value is larger than `2^n`. The witness evaluates one sparse linear polynomial and one field inversion; no polynomial representation of `1/r_n` is needed by the decapsulation algorithm.

The checker uses the prime `q=65537` and verifies nonzero/inverse correctness through `n=10`.

---

## 4. Quotient-unit theorem: `r` does not change the full ideal, only proof complexity

Because `r` is nonzero at every Boolean point, its reciprocal is a well-defined function on the Boolean cube. Every function on the cube has a unique multilinear polynomial representation, so there exists a multilinear polynomial `s(w)` of degree at most `n` such that

\[
s(a)=1/r(a)\qquad\forall a\in\{0,1\}^n.
\tag{5}
\]

Thus

\[
r(w)s(w)-1
\]

vanishes on the entire Boolean cube.

### Lemma 3 — Boolean reduction certificate

Any polynomial `f` which vanishes on the Boolean cube satisfies

\[
f\in\langle w_i^2-w_i\rangle_i.
\]

Moreover the standard monomial-by-monomial multilinear reduction gives such a certificate without increasing total degree.

For one variable,

\[
w^k-w=(w^2-w)(1+w+\cdots+w^{k-2}),\qquad k\ge2.
\]

Applying this reduction coordinate by coordinate replaces every monomial by its multilinear form, preserving the total-degree bound. If the resulting multilinear polynomial vanishes at all `2^n` Boolean points, it is zero. Hence the original polynomial lies in the Boolean ideal with certificate degree at most `deg(f)`.

Applying the lemma to (5) gives

\[
rs-1\in I_B:=\langle w_i^2-w_i\rangle_i
\]

with certificate degree at most

\[
\deg(rs)\le n+\deg(r).
\tag{6}
\]

### Theorem 4 — unit membership equivalence

Let `I` be any source ideal containing the Boolean ideal. Then

\[
\boxed{r\in I\iff 1\in I.}
\tag{7}
\]

Proof:

- `1 in I` trivially implies `r in I`.
- If `r in I`, then `sr in I`; since `rs-1 in I_B subset I`, subtracting gives `1 in I`.

So replacing the constant shift by a globally nonvanishing divisor does **not** change full ideal soundness. It only changes the degree/representation at which the relevant membership becomes visible.

---

## 5. Degree comparison

Define

\[
\delta(f)=\min\{D:f\in V_D\},
\]

when the membership exists.

For the linear divisor (4), `deg(r)=1` and the reciprocal polynomial has degree at most `n`.

### Proposition 5 — bounded-degree sandwich

Whenever the relevant memberships exist,

\[
\boxed{\delta(r)\le\delta(1)+1.}
\tag{8}
\]

Indeed multiply any degree-`delta(1)` certificate of `1` by `r`.

Conversely, from a degree-`delta(r)` certificate of `r`, multiply by the degree-at-most-`n` polynomial `s` and subtract the Boolean certificate for `rs-1`. This gives

\[
\boxed{\delta(1)\le\max\{\delta(r)+n,\;n+1\}.}
\tag{9}
\]

In particular, when `delta(1)>n+1`,

\[
\delta(r)\ge\delta(1)-n.
\]

This is deliberately only a degree relation. It does **not** prove that the divisor never helps: its pointwise reciprocal can be computed cheaply by a witness even when the multilinear polynomial `s` is dense.

The remaining hope of this route is exactly such a representation-complexity separation.

---

## 6. The reciprocal is cheap to evaluate but dense as an explicit polynomial in the executed family

For `r_n` in (4), the checker constructs the unique multilinear polynomial for `1/r_n` by Möbius inversion of the `2^n` cube values.

For every `n=1,...,10` under `F_65537`, **all `2^n` multilinear coefficients are nonzero**, and the maximum degree is exactly `n`.

This is an executed finite observation, not a theorem for every prime or every `n`. It illustrates the relevant distinction:

- witness-side inversion of the field element `r_n(w)` is cheap;
- explicitly expanding the polynomial inverse can be exponential.

That distinction is why the divisor idea is not dismissed merely by Theorem 4. A useful construction would need to turn it into false-instance hiding without requiring an explicit dense inverse or an exponential mask space.

---

## 7. Exact finite false-instance audit

The checker uses a completely unsatisfiable 3-variable Boolean CNF containing the unique width-3 clause that excludes each of the eight assignments. It includes the Boolean equations and converts every clause to its standard polynomial `product(false literals)=0`.

For this fixture:

\[
\delta(1)=3,\qquad \delta(r_3)=3.
\]

At cutoff `D=2`, `r_3 notin V_2`. The checker constructs the public dual separator and verifies exact key recovery on **300/300** independently masked capsules.

At cutoff `D=3`, `r_3 in V_3`. The checker verifies on **300/300** random mask/key samples that adding `K r_3` stays inside the same mask subspace, which is the finite linear-algebra identity behind identical key-conditioned distributions.

So on this explicit false statement the divisor does not lower the hiding threshold relative to the constant shift.

---

## 8. Additional small unsatisfiable Boolean controls

With fixed seed `500050`, the checker generated the first 50 unsatisfiable 4-variable, 14-clause 3CNFs encountered by its deterministic generator. For each one it independently computed the minimum dense truncated-ideal degree for `1` and for `r_4`.

Observed pairs:

- `delta(1)=4`, `delta(r)=4`: 32 cases;
- `delta(1)=3`, `delta(r)=4`: 17 cases;
- `delta(1)=3`, `delta(r)=3`: 1 case;
- `delta(r)<delta(1)`: **0 cases**.

These are finite controls, not a proof that no better divisor exists or that the chosen divisor never helps. They are useful negative evidence against the simplest deterministic divisor on small CNFs: in this sample it was equal or one degree worse, never better.

---

## 9. True-instance correctness controls

For the true Boolean source relation

\[
x+y-1=0,
\]

with both Boolean equations included, the valid witnesses are `(1,0)` and `(0,1)`.

The checker sampled 400 independent ideal masks and field keys at cutoff `D=2`. Both witnesses decapsulated every capsule exactly:

- 400 capsules;
- 2 witnesses each;
- **800/800** exact common-key decapsulations.

The correctness proof is Theorem 1; these executions only validate the implementation.

---

## 10. Complexity consequence for an explicit low-degree full-subspace realization

The divisor direction does not by itself evade the explicit coefficient-space barrier.

If, for an NP-complete Boolean source language, there were a polynomial-time rule producing a globally nonvanishing `r_x` and a cutoff `D=O(1)` such that

- every false statement satisfies `r_x in V_D`, and
- every true statement has a valid witness and therefore `r_x notin I`,

then statement truth could be decided by constructing the polynomial-size degree-`D` coefficient matrix and testing `r_x in V_D` with Gaussian elimination.

That would put the source language in deterministic polynomial time. This is a conditional complexity consequence of the proposed guarantee, **not** a claim here that `P != NP`.

Therefore any generic success of the divisor route must eventually rely on one of the same genuinely nontrivial mechanisms exposed by Runs 45–49:

1. a degree/feature representation whose explicit membership problem is not polynomial-size dense linear algebra, or
2. a computationally hidden compressed representation with complete-output security reduced to an independently justified PQ assumption.

A newly named assumption saying only that the divisor capsule hides `K` on false statements would simply restate the target WE/WKEM privacy property and is not accepted as an intermediate result.

---

## 11. What is proved and what remains open

### Proved here

1. Exact witness-free setup and same-key correctness of the nonvanishing-divisor mask candidate.
2. Exact complete-output affine-coset dichotomy: `r in V_D` gives identical key laws; otherwise public Gaussian elimination recovers the field key exactly.
3. For Boolean source relations, any globally nonvanishing divisor is a unit modulo the Boolean equations, so `r in I iff 1 in I` in the full ideal.
4. A concrete degree sandwich relating certificates for `r` and `1` through the multilinear reciprocal.
5. The simple explicit divisor `1+sum 2^i w_i` is globally nonzero over a prime larger than `2^n`, with only `O(n)`-bit modulus size.

### Executed, not promoted to proofs of security

- 800/800 exact genuine-witness decapsulations;
- 300/300 public false-key extractions below the divisor-membership threshold;
- 300/300 mask-space shift controls at the hiding threshold;
- 50 deterministic small unsatisfiable 4-variable CNFs with exact minimum-degree comparisons;
- 2,046 Boolean-cube reciprocal evaluations through `n=10`;
- full-support explicit multilinear reciprocal coefficients (`2^n` nonzero coefficients) for every executed `n=1,...,10`.

### Still unresolved

- No generic method is known here for choosing a divisor whose truncated membership is cheap on **every** false instance while remaining efficiently invertible on every valid witness.
- No polynomial-size complete-output PQ hiding construction has been obtained.
- No arbitrary-QPT early-key-recovery -> source-witness / independently justified PQ-break reduction has been obtained for a surviving construction.
- Ceremony and auxiliary-input composition remain downstream of the missing inner primitive.
- No practical end-to-end parameters or completed generic-NP WKEM are claimed.

## 12. Handoff

The multiplicative-consistency idea becomes cleanest when expressed as a **quotient unit / denominator** rather than another moment lift. That yields a real new design axis: let a witness perform cheap field inversion, while a false complete transcript would need the key-bearing divisor to disappear into the source ideal.

The next useful question is now sharply testable:

> Is there a polynomial-size, statement-derived family of public nonvanishing denominators for which at least one key-bearing combination has a low-complexity ideal certificate on every false instance, without making falsehood itself efficiently decidable and without assuming a WE-equivalent hiding compiler?

A positive answer still needs the full complete-output PQ reduction. A negative answer would need a genuine lower bound on this denominator/certificate model; neither is established here.
