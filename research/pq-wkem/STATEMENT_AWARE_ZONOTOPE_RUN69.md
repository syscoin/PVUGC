# Run 69 — Statement-aware vanishing noise and the public zonotope-dual barrier

## Scope

This run starts from PR head

`ad7e9f460884ac2b0b25db704349f2c4eff57a72`

and the Run-68 conclusion: changing only the iid modular error law does not
repair the normalized short-kernel compiler.  The remaining additive direction
named there was **globally correlated / statement-aware noise**.

The constructive attempt below is intentionally favorable to witness
correctness.  It gives the setup a public polynomial feature space, random
multipliers of the verifier constraints, and a correlated noise family taken
from the Boolean vanishing ideal.  Consequently every Boolean candidate
cancels the correlated noise exactly; valid witnesses return the same key, and
each fixed invalid Boolean candidate sees a uniform random constraint phase.

That attractive pointwise behavior is still insufficient.  The complete public
coefficient vector exposes an exact no-witness dual by ordinary linear algebra.
The same phenomenon extends from exact vanishing noise to any **public bounded
zonotope** for which correctness is proved by a deterministic residual radius:
a public linear program finds a decoding functional whose worst-case radius is
no larger than that of the best legitimate witness functional.

These are complete-output barriers for explicit public linear-generator /
public-convex additive noise geometry.  They are **not** impossibility results
for hidden nonlinear noise families, arbitrary modular wraparound
constructions, LWE/SIS in general, or witness encryption.

No external literature or web search was used.

---

## 1. Constructive candidate: verifier masks plus Boolean-vanishing noise

Work over a prime field `F_q`.  Fix a public polynomial feature basis

\[
\Psi=(\psi_1,\ldots,\psi_M),\qquad \psi_1=1,
\]

large enough to hold the verifier-constraint polynomials and a chosen family of
Boolean-vanishing polynomials.

For a Boolean vector `x`, let

\[
\ell_x=(\psi_1(x),\ldots,\psi_M(x))\in F_q^M
\]

be its public evaluation functional.  Let

\[
u=(1,0,\ldots,0)
\]

be the constant/key direction.

For a 3CNF statement, represent clause `j` by its falsity indicator polynomial
`g_j(x)`.  On Boolean inputs,

\[
g_j(x)=
\begin{cases}
1,&\text{clause }j\text{ is false},\\
0,&\text{clause }j\text{ is true}.
\end{cases}
\]

Write the coefficient vectors as columns of a public matrix

\[
G=[G_1|\cdots|G_m]\in F_q^{M\times m}.
\]

Now add public Boolean-vanishing generators.  A concrete family is

\[
h(x)(x_i^2-x_i)
\]

for public monomials `h` that fit in the chosen feature basis.  Put their
coefficient vectors in

\[
N\in F_q^{M\times s}.
\]

For every Boolean `x`,

\[
\ell_x^T N=0.                                      \tag{1}
\]

Setup chooses

\[
K\leftarrow F_q,\qquad
r\leftarrow F_q^m,\qquad
\eta\leftarrow F_q^s
\]

and publishes the single coefficient-space capsule

\[
\boxed{
Y=K u+G r+N\eta.
}                                                       \tag{2}
\]

The setup uses the statement but no source witness.

### 1.1 Honest completeness is exact

If `w` is a valid Boolean witness, every clause is true, so

\[
\ell_w^T G=0.
\]

Equation (1) also gives `ell_w^T N=0`, while
`ell_w^T u=1`.  Therefore

\[
\boxed{\ell_w^T Y=K.}                                  \tag{3}
\]

Every valid witness obtains exactly the same key.

### 1.2 Every fixed invalid Boolean candidate has perfect marginal hiding

Take a Boolean `x` that violates at least one clause.  Then the vector

\[
g(x):=\ell_x^T G\in F_q^m
\]

is nonzero.  Because `r` is uniform,

\[
g(x)r
\]

is exactly uniform in `F_q`.  The vanishing noise still cancels by (1), hence

\[
\ell_x^T Y=K+g(x)r
\]

is exactly uniform and independent of `K`.

So the intended public evaluator has unusually strong local semantics:

* valid Boolean witness: exact common key;
* each fixed invalid Boolean candidate: perfect marginal key hiding.

The failure below is therefore genuinely a **complete-public-output** failure,
not a bad local decoder.

---

## 2. Exact complete-output attack on every true statement

Let

\[
W=\operatorname{colspan}[G\;N]\subseteq F_q^M.
\]

If the statement is true, choose any valid witness `w`.  From (3),

\[
\ell_w^T W=0,\qquad \ell_w^T u=1.
\]

Therefore

\[
u\notin W.                                             \tag{4}
\]

Everything in (4) is now a public linear-algebra fact, even though the witness
used to prove it need not be known by the attacker.

The attacker solves the public affine system

\[
\boxed{
\lambda^T W=0,\qquad \lambda^T u=1.
}                                                       \tag{5}
\]

Because of (4), a solution exists and Gaussian elimination finds one in
polynomial time.  Applying it to the complete capsule gives

\[
\boxed{
\lambda^T Y
=
K+\lambda^T G r+\lambda^T N\eta
=
K.
}                                                       \tag{6}
\]

Thus (2) is publicly decryptable on every true statement.

This attack does not learn the erased setup randomness `r,eta`; it cancels the
*entire possible mask space*.  It does not solve LWE/SIS or exploit any failed
parameter choice.

### 2.1 The public dual need not encode any source witness

Let

\[
d=M-\operatorname{rank}(W)-1.
\]

Under (4), the solution set of (5) is an affine `d`-space over `F_q`, so it has
`q^d` members.

There are at most `2^n` Boolean evaluation vectors `ell_x`.  Moreover, any
Boolean evaluation vector satisfying (5) is necessarily a valid source
witness: `ell_x^T G=0` says all clause-falsity indicators vanish.

Therefore a uniformly sampled public dual from (5) is a Boolean evaluation
with probability at most

\[
\boxed{
\frac{2^n}{q^d}.
}                                                       \tag{7}
\]

The attacker can test whether a sampled dual is a Boolean evaluation without
solving the source instance: read its degree-one coordinates as candidate bits
and check all published feature coordinates against direct monomial
evaluation.  If it is an evaluation vector, reject and resample.

So whenever `d` is even moderately large, ordinary public linear algebra gives
an explicit **non-evaluation** decoder satisfying (6).

For the degree-4 feature spaces used by the checker, `M=Theta(n^4)` while the
displayed Boolean-vanishing family has `Theta(n^3)` columns.  In the tested
`n=4,m=8,q=257` fixtures the dual affine dimension was between 13 and 17.
All 120 sampled public duals were immediately non-evaluation functionals and
all 120 recovered the exact key.

This is the native-encryption/source-witness distinction again: a public key
functional can exist even when it is not a source representation at all.

---

## 3. False statements: perfect pointwise hiding still does not imply transcript hiding

For a false 3CNF, every Boolean assignment violates at least one clause, so
Section 1.2 says every fixed Boolean candidate has a perfectly uniform
key-conditioned scalar output.

Nevertheless the *joint coefficient vector* is key-hiding only if the key
direction is absorbed by the complete public mask space.  If

\[
u\notin W,
\]

the same public dual (5) exists and (6) recovers `K` exactly even though there
is no source witness.

The checker contains the following explicit unsatisfiable four-variable,
nine-clause formula (variables are `x0,...,x3`):

\[
\begin{aligned}
 &(x_1\vee\neg x_2\vee\neg x_3),\\
 &(x_0\vee\neg x_1\vee\neg x_2),\\
 &(x_0\vee\neg x_1\vee x_3),\\
 &(\neg x_1\vee x_2\vee\neg x_3),\\
 &(x_1\vee x_2\vee x_3),\\
 &(\neg x_0\vee\neg x_1\vee x_3),\\
 &(x_1\vee\neg x_2\vee x_3),\\
 &(\neg x_0\vee\neg x_1\vee\neg x_2),\\
 &(x_1\vee x_2\vee\neg x_3).
\end{aligned}
\]

With the degree-4 exponent-at-most-two feature basis over `F_257`:

* feature dimension: `M=50`;
* clause-mask columns: `9`;
* Boolean-vanishing columns: `28`;
* `rank(W)=37`;
* `rank([W,u])=38`.

Hence `u notin W`; the public dual affine space has dimension 12 and recovers
the exact key.

The checker exhaustively verifies that all 16 Boolean assignments violate at
least one clause, then performs 200 fresh setup samples.  The public dual
recovers `K` in 200/200.

This is a useful warning for future candidates:

> Perfect hiding for every fixed invalid witness candidate is weaker than
> hiding of the complete public transcript.

Adding more constraint multiples can make `u in W` on particular false
instances (an algebraic refutation), but it cannot repair the true-instance
attack of Section 2: on a true statement, an actual witness always separates
`u` from every mask family that it cancels exactly.

---

## 4. Bounded correlated noise: public zonotope optimization

The exact vanishing construction might be judged too strong: perhaps valid
witnesses should cancel only *most* of a correlated error, while non-source
public duals receive a large residual.

Run 64 closed the public Gaussian/covariance version.  The same complete-output
logic extends to a broad non-Gaussian class used by deterministic
correctness arguments.

Work in a lifted real coefficient space, or in an integer no-wrap regime.
Let `W` be the public exact-mask subspace, `u notin W`, and publish

\[
Y=\Delta K\,u+w+H\xi,\qquad
w\in W,\qquad
\|\xi\|_\infty\le B,                                  \tag{8}
\]

where the public matrix `H` describes a correlated zonotope.

For any feasible decoding functional

\[
\Lambda=\{\lambda:\lambda^T W=0,\ \lambda^T u=1\},
\]

the worst-case residual over the advertised noise support is exactly

\[
\rho(\lambda)
=
\sup_{\|\xi\|_\infty\le B}|\lambda^T H\xi|
=
B\|H^T\lambda\|_1.                                    \tag{9}
\]

A public attacker solves

\[
\boxed{
\lambda_*=
\arg\min_{\lambda\in\Lambda}\|H^T\lambda\|_1.
}                                                       \tag{10}
\]

This is a rational linear program: introduce `t_j>=0` and constrain

\[
-t_j\le h_j^T\lambda\le t_j,
\]

then minimize `sum_j t_j`.

Every legitimate witness evaluation `ell_w` is feasible.  Therefore

\[
\boxed{
\rho(\lambda_*)\le \rho(\ell_w)
\quad\text{for every valid witness }w.
}                                                       \tag{11}
\]

Also

\[
\lambda_*^T Y=\Delta K+\lambda_*^T H\xi.               \tag{12}
\]

Consequently, if honest correctness is established by a deterministic
support-radius condition such as

\[
\rho(\ell_w)<\Delta/2
\quad\text{for every valid }w,
\]

then the public no-witness functional `lambda_*` satisfies the same condition
and rounds to `K` for **every allowed noise vector**.

This theorem covers, for example:

* coefficientwise bounded noise (`H=I`);
* arbitrary public linear mixing of bounded independent coordinates;
* public correlated zonotopes;
* exact Boolean-vanishing generator noise as the zero-radius special case.

It does **not** say that the `l1` minimizer dominates a witness for every
high-probability distributional decoding metric.  It transfers deterministic
support-radius correctness.  It also does not claim a modular theorem when
large centered coefficients/wraparound invalidate the lifted norm model.

### 4.1 Exact finite validation of the LP identity

The checker uses the Run-64 two-variable OR coefficient basis

\[
(1,x_1,x_2,x_1x_2),
\]

with mask vector

\[
g=(1,-1,-1,1)
\]

and legitimate evaluations

\[
(1,1,0,0),\quad
(1,0,1,0),\quad
(1,1,1,1).
\]

For 160 deterministic random integer `4 x 3` zonotope generators `H`, a
standard-library exact-rational vertex enumerator solves the small LP (10).

Results:

* public LP radius <= best witness radius: 160/160;
* strictly smaller radius: 150/160;
* LP minimizer is not one of the three witness evaluations: 153/160;
* largest public/best-witness radius ratio observed: 1.0.

The brute-force vertex enumerator is only a small-instance validator.  The
general public algorithm asserted by (10) is ordinary rational linear
programming.

---

## 5. Validation actually executed

`statement_aware_zonotope_run69_check.py` is deterministic and
standard-library-only.

The finalized checker was executed twice; the resulting JSON files were
byte-identical.

It checks:

1. **120 satisfiable 3CNF statement-aware capsules**
   * exact valid-witness recovery: 120/120;
   * explicit sampled non-evaluation public duals: 120/120;
   * exact no-witness public-dual key recovery: 120/120;
   * dual affine dimensions: 13 through 17;
   * zero Boolean-evaluation samples had to be rejected.

2. **Exact invalid-candidate marginal**
   * over `F_5`, a falsifying assignment to one 3OR clause;
   * exhaustive multiplier histogram `[1,1,1,1,1]`.

3. **Explicit false-statement complete-output counterexample**
   * all 16 assignments checked and rejected;
   * `rank(W)=37`, `rank([W,u])=38`;
   * exact public key recovery: 200/200 fresh capsules.

4. **Public zonotope LP**
   * 160 exact-rational small LPs;
   * public optimum never worse than the best legitimate witness radius;
   * 150 strict improvements;
   * 153 non-witness minimizers.

The tests validate the finite algebra and the implementation of the displayed
identities.  Passing tests is not a cryptographic security argument.

---

## 6. What this run closes and what it does not

### Closed in this run

The Run-68 suggestion “use globally correlated / statement-aware error
geometry” does **not** survive when the geometry is realized as either:

1. an explicit public linear-generator family that every valid witness cancels
   exactly; or
2. a public bounded zonotope whose correctness is proved by a deterministic
   support-radius bound.

In the exact case, the attacker cancels the full public mask span by Gaussian
elimination.  In the bounded-zonotope case, the attacker publicly optimizes
over the same feasible dual space and obtains a residual radius no larger than
any source witness.

The construction also supplies a concrete false statement where every Boolean
candidate has perfect marginal hiding yet the complete public transcript
reveals the key exactly.

### Not closed

This run does **not** rule out:

* a hidden noise geometry that is not reconstructible as a public linear span
  or public convex body;
* a genuinely nonlinear/nonadditive key-bearing operation;
* a computationally pseudorandom error family whose useful witness action
  cannot be reproduced by public convex optimization;
* a modular short-dual construction outside the lifted/no-wrap support model;
* LWE/SIS or another independently justified PQ assumption used in a
  non-circular way.

No such surviving primitive is constructed here.

The next constructive target should therefore require the source witness to
invoke a **nonlinear or computationally hidden cancellation rule** that is not
equivalent to belonging to a public annihilator affine space and is not
recoverable by transparent interpolation.  It must still support every valid
witness offline from the completed public transcript, and its arbitrary-QPT
early-key recovery must reduce to source-witness extraction or an independent
PQ break.

The malicious-secure erased setup, auxiliary-input composition, concrete
parameters, and final generic-NP WKEM remain unresolved.
