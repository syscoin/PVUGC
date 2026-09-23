# Run 51 — Threshold denominator atlases do not evade the public ideal-membership barrier

## Status and scope

This note continues from Run 50.  It does **not** construct the requested generic-NP
PQ witness KEM.  It analyzes a strictly broader repair of Run 50's one-denominator
ideal mask: use many public witness-evaluable denominators, secret-share the payload
across them, and require only an authorized subset to be evaluable at any one valid
witness.

The result is an exact complete-output theorem for the following candidate class.
It covers additive `N-of-N` sharing and ordinary linear threshold sharing (for example,
Shamir sharing), and more generally any perfect monotone secret-sharing scheme whose
scalar shares are placed into the components below.  It does **not** rule out encrypted
or computationally hidden helpers, correlated mask distributions outside this affine
coset model, or a witness-selective evaluator whose security is reduced to an
independently justified PQ primitive.

No external literature is used here.

## 1. Candidate: denominator atlas + secret sharing

Fix a statement `x` and a field `F_q`.  Let a perfect secret-sharing scheme share a
field key `K` into scalar shares

```
(s_1,...,s_m) <- Share_x(K)
```

with public monotone access structure `Gamma_x subseteq 2^[m]`.  Thus an authorized
set reconstructs `K`, while the joint shares of every unauthorized set have a law
independent of `K`.

For component `j`, setup has:

* a public finite-dimensional polynomial/function coefficient space `P_j`;
* a public mask subspace `V_j(x) <= P_j` whose elements vanish at every valid source
  witness;
* a public denominator/key direction `r_j in P_j`.

It samples independent uniform `R_j <- V_j(x)` and publishes

```
C_j = s_j r_j + R_j.                      (1)
```

A source witness `w` can evaluate component `j` whenever `r_j(w) != 0`:

```
C_j(w) / r_j(w) = s_j,                    (2)
```

because every mask in `V_j` vanishes at `w`.  Write

```
A_x(w) = { j : r_j(w) != 0 }              (3)
```

for its accessible share set.  The construction is complete at `w` if
`A_x(w) in Gamma_x`.

This is a real strengthening of Run 50's single globally nonvanishing divisor: false
hiding no longer needs every component to hide.  In principle it would suffice for
the publicly exposed shares to form an unauthorized set.

## 2. Exact per-component complete-output dichotomy

Define the public exposure set

```
E_x = { j : r_j notin V_j(x) }.           (4)
```

### Lemma 1 — hidden component

If `r_j in V_j`, then for every share value `s`, `C_j` is uniform on `V_j`.

**Proof.**  Translation by `s r_j` is a bijection of `V_j`, so
`V_j + s r_j = V_j`.  QED.

### Lemma 2 — exposed component

If `r_j notin V_j`, public Gaussian elimination finds a linear functional `lambda_j`
with

```
lambda_j(V_j)=0,   lambda_j(r_j)=1.        (5)
```

Consequently

```
lambda_j(C_j)=s_j                         (6)
```

for every mask sample.

This is a complete-public-output statement, not merely a failure of the intended
witness decoder.

## 3. Complete transcript is exactly the exposed share view

### Theorem 1 — threshold-atlas quotient theorem

Assume the masks `R_j` in (1) are independent uniform samples of the public
subspaces `V_j`.  Conditioned on a share vector `(s_1,...,s_m)`, the complete public
transcript `(C_1,...,C_m)` is efficiently simulatable from `s_{E_x}` and public data.
Conversely, the public transcript deterministically reveals every share in `E_x`.
Therefore, for a perfect secret-sharing scheme and any two distinct keys `K_0,K_1`,

```
TV( Transcript(K_0), Transcript(K_1) ) =
    1,  if E_x in Gamma_x,
    0,  if E_x notin Gamma_x.              (7)
```

**Proof.**  For `j notin E_x`, Lemma 1 says `C_j` is independent of `s_j`.  For
`j in E_x`, Lemma 2 recovers `s_j` exactly; conditioned on that share, `C_j` is simply
uniform on its public affine coset `s_j r_j + V_j`, so it can also be simulated from
the share.  Independence of the masks gives the product simulation.

If `E_x` is unauthorized, perfect secret-sharing privacy makes `s_{E_x}` independent
of the key, hence so is the transcript.  If it is authorized, its exposed shares
reconstruct the key exactly; transcripts belonging to two distinct keys therefore
have disjoint supports.  QED.

For `N-of-N`, (7) says **all** components must be exposed before the public learns the
key.  For `t-of-m`, it says any `t` exposed shares suffice.  Thus threshold sharing
can change which membership pattern leaks, but does not make that pattern hidden.

## 4. Witness accessibility is contained in public exposure

### Lemma 3 — `A_x(w) subseteq E_x`

For every valid source witness `w`,

```
A_x(w) subseteq E_x.                       (8)
```

**Proof.**  If `r_j in V_j`, then by definition of the source-mask space every member
of `V_j` vanishes at `w`, so `r_j(w)=0`.  Contrapositively,
`r_j(w) != 0 => r_j notin V_j`.  QED.

### Corollary 1 — exact true-instance public authorization

If a valid witness `w` can reconstruct under this atlas, so
`A_x(w) in Gamma_x`, then monotonicity and (8) imply

```
E_x in Gamma_x.                            (9)
```

By Theorem 1 the complete public transcript then reveals `K` exactly **without** the
witness.

This is the central obstruction.  Secret sharing avoids requiring *every* denominator
to be public-key-exposing, but every share that a genuine witness can obtain by public
vanishing-mask evaluation is necessarily already in the publicly exposed set.  An
authorized witness set therefore implies an authorized public set.

## 5. Generic-NP complexity consequence for this candidate class

The predicate

```
B_x := [ E_x in Gamma_x ]                  (10)
```

is publicly computable in polynomial time whenever each `V_j` is supplied in an
explicit polynomial-dimensional representation: Gaussian elimination decides each
membership `r_j in V_j`, followed by the public access-structure test.

For deterministic setup, exact completeness of this candidate on a true statement
forces `B_x=1`, while perfect false-instance hiding forces `B_x=0`.  Thus such a
candidate with both guarantees would itself give a public decision algorithm for the
source language.

For randomized public setup `sigma`, the statement is quantitative.  Include `sigma`
in the complete transcript, as an attacker sees it.  For each fixed `sigma`, Theorem 1
gives TV either zero or one, so

```
TV( (sigma,Transcript_0), (sigma,Transcript_1) )
    = Pr_sigma[ E_{x,sigma} in Gamma_{x,sigma} ].       (11)
```

If valid-witness correctness succeeds only when its accessible set is authorized,
average completeness at least `1-epsilon` implies

```
Pr_sigma[B_x=1 | x true] >= 1-epsilon.     (12)
```

If false-statement pairwise key TV is at most `eta`, (11) gives

```
Pr_sigma[B_x=1 | x false] <= eta.          (13)
```

Thus sampling public setup and evaluating `B_x` is a randomized public true/false
distinguisher with gap at least `1-epsilon-eta` for this candidate class.

This is a **candidate-class complexity consequence**, not a claim here that
`NP != BPP` or that generic witness encryption is impossible.

## 6. Relation to the allowed N-of-N setup ceremony

The requested research allows `N-of-N` roots across operators and redundant threshold
shares within an operator.  The theorem above does **not** invalidate the earlier
conditional ceremony composition around a genuinely secure inner primitive.

It says something narrower: using `N-of-N` or `t-of-m` secret sharing **as the repair
for public ideal-mask denominator components (1)** does not create source-witness
restriction.  On a true statement, any shares usable by the witness are contained in
the public exposed-share set; once that public set is authorized, the public can
reconstruct too.  Operator erasure or abort semantics do not change this post-setup
complete-output fact.

## 7. Concrete toy control

Over `F_7`, represent degree-at-most-2 univariate polynomials by coefficient vectors.
For the true source equation `w=0`, let

```
V_true = span{w,w^2}.
```

Use denominators

```
r_1=1+w, r_2=2+w, r_3=3+w.
```

At the valid witness `w=0`, all three are nonzero, and all three lie outside
`V_true`; hence `A(w)=E={1,2,3}`.

For the contradictory false equations `w=0` and `w-1=0`, the degree-2 truncated mask
span is the full coefficient space, so `E=empty`.  An `N-of-N` sharing therefore
works in this toy only because the **public membership pattern itself** distinguishes
the true and false statements.  It is an illustration of the theorem, not a generic
construction.

## 8. Validation actually executed

The accompanying standard-library checker was executed twice with deterministic seed
`510051001`; the captured JSON was byte-identical.  It independently checks:

* all 8 exposure patterns for additive `3-of-3` sharing and all 8 for Shamir `2-of-3`,
  with exact complete transcript distributions over `F_5`;
* **60,000** enumerated transcript samples with multiplicity; exact TV is `1` iff the
  exposed set is authorized and `0` otherwise;
* **600** random quotient fixtures over `F_7^5`, with 4,179 exact separator/share
  recoveries on exposed components and 21 exact shift-invariance support checks on
  hidden components;
* the true/false toy above and **1,000** random vanishing-subspace containment checks
  validating `r(w)!=0 => r notin V`;
* a randomized public-setup mixture whose exact complete TV is `9/10`, equal to the
  exact authorized-setup probability `9/10`;
* **1,000** independent Shamir `2-of-3` reconstruction controls.

These tests validate finite algebra and the implementation only.  The theorem is the
analytic argument above; passing tests is not a security claim.

## 9. What remains open

This closes the natural **denominator atlas + perfect secret sharing + independent
public ideal masks** escape hatch from Run 50.  It does not close:

* a computational/encrypted nonlinear public helper whose complete output reduces to
  LWE/SIS or another independently justified PQ assumption;
* a correlated global mask distribution that is not equivalent to the componentwise
  affine-coset view analyzed here;
* a post-erasure source-witness-selective evaluator constructed non-circularly from an
  independent PQ primitive;
* the central arbitrary-QPT key-recovery -> source-witness / independent-PQ-break
  theorem for a surviving construction.

The positive Run-42/43 SIS lemma still applies only when a sufficiently short native
preimage is **supplied**.  Malicious-secure ceremony/auxiliary-input composition and
concrete practical parameters remain downstream of a surviving inner release
primitive.

**Stopping condition: not met.**
