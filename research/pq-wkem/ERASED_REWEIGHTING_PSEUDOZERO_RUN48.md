# Run 48 — Erased reweighting, nonlinear metric gap, and the universal-pseudozero barrier

## Status

This run continues from the verified Run-47 head
`7eaddcfac437d377d9476e2b49a3387914abc185`.

It does **not** claim a complete witness KEM, a post-quantum security proof, or a
generic impossibility theorem.  The constructive attempt was to repair the
Run-42/43 short-preimage geometry by moving the metric amplification into a
nonlinear source-residual map and then hiding setup-time reweighting/mixing
coefficients that are erased after setup.

There is a real positive result: on **actual integer source traces**, a
polynomial-size nonlinear residual map gives an arbitrarily large multiplicative
norm gap between valid Boolean witnesses and invalid traces.

The attempted transfer into a native linear preimage capsule fails for a more
basic reason.  A false truncated-moment representation can be an **exact
zero of every residual row**.  Once such a universal pseudozero exists, no
secret diagonal row weighting, arbitrary left row mixing, repetition, or
N-of-N composition of those same rows changes it.  A standard dual/preimage
capsule is then decapsulated by the false pseudopreimage even if the row-mixing
secrets and even the mixed relation itself are erased after setup.

The run also isolates the boundary for secret **column/right** reweighting:
if the public offline helper is an ordinary public linear map on the
representation, it transforms the pseudopreimage too; if the helper is instead
selective for genuine source witnesses, that is exactly the missing
witness-restricted public encoding and is not obtained here.

No external literature or web search was used.  Production code is unchanged.

## 1. Positive construction: a polynomial nonlinear metric gap on actual traces

Let a Boolean source witness be `z in {0,1}^n`.  Assume the verifier is
represented by integer-valued polynomial residuals

    g_1(z),...,g_m(z)

such that a Boolean vector is valid iff every `g_j(z)=0`.

For an integer scale `L >= 1`, define the explicit feature map

    Psi_L(z) =
      ( 1,
        z_1,...,z_n,
        L z_1(z_1-1),...,L z_n(z_n-1),
        L g_1(z),...,L g_m(z) ).

This has only `1+n+n+m` coordinates, so evaluating it is polynomial whenever
the source residuals are polynomial-time computable.

### Theorem 1.1 — exact integer metric gap

For every valid Boolean witness,

    ||Psi_L(z)||_2^2 = 1 + ||z||_2^2 <= n+1.

For every integer vector `z in Z^n` that is **not** a valid Boolean witness,

    ||Psi_L(z)||_2^2 >= L^2.

Moreover, if `z` is non-Boolean, then

    ||Psi_L(z)||_2^2 >= 4 L^2.

#### Proof

If `z` is valid and Boolean, every Boolean residual `z_i(z_i-1)` and every
verifier residual `g_j(z)` is zero.  This gives the first identity.

Now suppose `z` is invalid.

* If some coordinate is not in `{0,1}`, then for an integer `a`,
  `a(a-1)` is a nonzero even integer, hence has absolute value at least `2`.
  The corresponding feature coordinate therefore has magnitude at least `2L`.
* Otherwise `z` is Boolean.  Invalidity means some integer-valued verifier
  residual is nonzero, hence has absolute value at least `1`.  The
  corresponding feature coordinate has magnitude at least `L`.

Squaring proves the bounds.  QED.

Thus choosing, for example,

    L^2 >= c (n+1)

gives a multiplicative invalid/valid squared-norm gap at least `c` on actual
integer traces.  This is a genuine improvement over the additive `+4`
Run-43 diagnostic gap.

It is **not yet an encryption construction**.  The remaining question is how
to transfer this nonlinear graph into a public offline native decryption
relation without admitting low-degree pseudorepresentations.

## 2. Attempted native transfer: secret reweighted linearization

A natural transfer is to linearize the polynomial residuals into moment
coordinates, enforce them as linear rows, and use the resulting preimage as the
secret direction in a dual/preimage lattice-style capsule.

Abstractly, let

    A X = u

be the linearized native relation.  Setup may try to hide its geometry by
choosing a secret left transformation `L_setup` and replacing it with

    A' = L_setup A,
    u' = L_setup u.

This covers:

* secret diagonal row weights;
* arbitrary invertible row mixing;
* rectangular repetition/compression maps;
* sequential row mixing by several setup operators.

The setup coefficients may be erased and `A'` itself need not be published for
the attack below.

A standard linear preimage capsule has the form

    a = A'^T s + e,
    b = <u',s> + e_0 + mu K.

Any exact preimage `X` obtains

    b - <X,a>
      = mu K + e_0 - <X,e>.                         (1)

The hoped-for security argument is that genuine witness preimages remain short
while invalid traces become long after the secret reweighting.

That argument is irrelevant if the linearized relation already contains a
short **exact pseudopreimage**.

## 3. Universal-pseudozero theorem

### Theorem 3.1 — erased left reweighting cannot remove an exact pseudopreimage

Suppose a vector `X*` satisfies

    A X* = u.                                          (2)

Then for **every** setup matrix `L_setup`, of any compatible row dimension,

    (L_setup A) X* = L_setup u.                        (3)

Consequently, in the capsule above,

    b - <X*,a>
      = mu K + e_0 - <X*,e>,                           (4)

independently of `L_setup` and independently of the secret `s`.

The attacker does not need to recover the erased setup transformation, and does
not even need `A'` after encapsulation.  It needs only the public capsule
`(a,b)` and the fixed pseudopreimage `X*`.

#### Proof

Equation (3) follows by left-multiplying (2) by `L_setup`.

Then

    <X*, A'^T s>
      = <A' X*, s>
      = <u', s>,

so the pad cancels from the complete public capsule exactly, giving (4).  QED.

### Corollary 3.2 — N-of-N setup mixing does not help this failure

If several operators sequentially apply secret left transformations

    L_N ... L_2 L_1,

the same `X*` remains an exact preimage.  At least one honest operator, erasure,
abort semantics, or secret redundant shares do not alter this algebraic fact.

This is **not** a statement that ceremony composition is generally useless.
It says that a ceremony cannot repair an already-existing exact pseudozero by
merely reweighting or mixing the same residual rows.

## 4. Explicit false instance over F_101

Use moment coordinates

    X = (m_0, m_x, m_y, m_xx, m_xy, m_yy)

and the Boolean statement

    x,y in {0,1},
    x + y + 2 = 0  mod 101.                            (5)

No Boolean pair satisfies (5), since `x+y` is one of `0,1,2`.

The degree-2 linearized rows are

    m_0 = 1,
    m_xx - m_x = 0,
    m_yy - m_y = 0,
    m_x + m_y + 2 m_0 = 0.                             (6)

Now take the centered vector

    X* = (1,-1,-1,-1,0,-1).                            (7)

It satisfies all four equations (6) exactly modulo 101:

    -1 - (-1) = 0,
    -1 - (-1) = 0,
    -1 + (-1) + 2 = 0.

Thus it is a public exact preimage even though the source statement has no
witness.

This is precisely where the positive nonlinear metric map and the linearized
native relation separate:

* the actual integer point `(-1,-1)` has Boolean residuals
  `x(x-1)=2` and `y(y-1)=2`, so the nonlinear feature map penalizes it by
  `2L` in each Boolean-residual coordinate;
* the pseudomoment sets `m_xx=m_x=-1` and `m_yy=m_y=-1`, so both **linearized**
  Boolean residuals are zero.

No choice of residual magnitude can amplify a value that is already exactly
zero in the relaxation.

## 5. Concrete complete-output capsule break

For the checker, use modulus

    q = 101

and binary key phase

    mu = 25.

Errors `e_i,e_0` are in `{-1,0,1}`.

The false pseudopreimage (7) has centered `L1` norm `5`, so from (4)

    |e_0 - <X*,e>| <= 6.                               (8)

The two key centers `0` and `25` are separated by `25`; radius-6
neighborhoods are disjoint.  Nearest-center decoding therefore recovers the
key **deterministically for every bounded error vector**.

The checker exhaustively tested all

    2 * 3^7 = 4,374

key/error combinations for the false pseudopreimage and recovered the key in
all 4,374.

As a correctness control, replace (5) by the true statement

    x + y - 1 = 0.

Its two Boolean witnesses have moment vectors

    (1,1,0,1,0,0)
    (1,0,1,0,0,1).

Across both witnesses, both key bits, and all bounded errors, the checker
recovered the key in all

    2 * 2 * 3^7 = 8,748

cases.

These finite tests are not the security argument.  The false-instance break is
the exact cancellation identity (4) plus the deterministic bound (8).

## 6. Secret diagonal weights, arbitrary row mixing, and repetition

The explicit false pseudopreimage is stronger than a failure for one hand-picked
matrix.

Let setup multiply the three residual equations in (6) by arbitrary nonzero
weights `rho_x,rho_y,rho_g`.  Equation (7) remains an exact solution for every
choice because each unweighted residual is already zero.

The checker tested 2,000 independently sampled nonzero weight triples.

It then tested:

* 1,000 secret random invertible `4 x 4` left mixes;
* 500 arbitrary rectangular left maps with between 1 and 8 output rows;
* 300 five-operator sequential N-of-N-style left-mixing fixtures.

The false pseudopreimage remained exact in every fixture.  Fresh bounded-noise
capsules recovered the false key in every corresponding attack fixture.

The maximum realized centered residual noise in those attacks was `6`, exactly
matching (8).

## 7. Residual tensoring does not repair an exact zero

Let

    r(X*) = (m_xx-m_x, m_yy-m_y, m_x+m_y+2m_0) = (0,0,0).

Any residual-only polynomial or tensor feature `T(r)` with

    T(0)=0

also vanishes at `X*`.

Therefore:

* repeating residual coordinates;
* multiplying them by secret weights;
* taking products/tensor monomials of them;
* applying any polynomial magnitude amplifier with zero constant term

does not distinguish this pseudomoment.

The checker explicitly evaluated all 83 nonconstant monomials in the three
residual variables through total degree 6; all are zero.

This is a **zero-set** problem, not a concentration or parameter-sizing problem.

## 8. Right/column reweighting: exact boundary, not an impossibility claim

A different idea is to choose a secret invertible column transform `D` and use

    A_D = A D^{-1}.                                     (9)

A native preimage transforms as

    X_D = D X.

This can change geometry in a way left row mixing cannot.

However, an offline valid witness must somehow compute its transformed
preimage after the temporary setup secret `D` has been erased.

There are two sharply different cases.

### 8.1 Public ordinary linear helper

If setup publishes `D` itself, or a public ordinary linear evaluator that maps
an arbitrary representation `X` to `D X`, then the false pseudopreimage gets
the same interface:

    X*_D = D X*,
    A_D X*_D = u.

The checker generated 300 random invertible `6 x 6` transforms and verified
300/300 exact noiseless false-key recoveries through the exposed linear helper.

This is a complete-output attack on that helper class.

### 8.2 Source-witness-selective helper

A helper that lets a **genuine source witness** compute the necessary
transformed object but does not give the same operation on arbitrary
pseudorepresentations is not ruled out by the theorem above.

But that is exactly the missing construction: a public offline
**witness-restricted encoder/evaluator**.  This run does not assume such a
helper and does not rename it as a hardness assumption.

Thus right reweighting identifies a boundary rather than completing the WKEM:

> secret geometry can matter only if honest witnesses retain a selective
> post-erasure evaluation capability that pseudorepresentations do not inherit.

Proving and implementing that capability under an independently justified PQ
assumption remains the central missing step.

## 9. Relation to the earlier ideal/proof-degree result

Run 45 showed a sparse unsatisfiable family whose truncated source ideal does
not contain `1` below a growing degree.  The present result gives that fact a
direct preimage interpretation:

* a low-degree dual pseudofunctional annihilates the whole available
  constraint span;
* secret row scaling or arbitrary secret linear mixing stays inside the same
  span;
* therefore such setup randomness cannot create zero-set soundness that the
  underlying representation did not already have.

The current explicit `F_101` fixture is deliberately much smaller and is used
to make the complete capsule attack fully concrete.  It does not replace the
Run-45 growing proof-degree family.

## 10. Fresh validation actually executed

`check_erased_reweighting_run48.py` is deterministic, standard-library only,
with seed `480048`.

It was executed twice after the final edits.  The JSON stdout was byte-identical
across both runs.

The executed checks were:

1. Exact nonlinear metric-gap controls at `L in {2,3,4,8,16}`.
2. 21,600 integer-trace checks over 100 random small verifier systems.
3. 2,000 secret residual-weight pseudopreimage checks.
4. 83 residual-only polynomial/tensor monomials through degree 6, all zero at
   the pseudomoment.
5. 1,000 secret invertible left-mixing identities and 1,000 fresh false
   bounded-noise capsule recoveries.
6. 500 arbitrary rectangular left-transform identities and 500 false capsule
   recoveries.
7. 300 five-operator sequential left-mixing identities and 300 false capsule
   recoveries.
8. Exhaustive bounded-error decapsulation:
   * false pseudopreimage: 4,374 / 4,374 successful false recoveries;
   * two true witnesses: 8,748 / 8,748 successful honest recoveries.
9. 300 random secret right/column transforms with a public ordinary linear
   helper: 300 / 300 noiseless false recoveries.

Final local hashes:

* checker SHA-256:
  `f46a685c04088e5573b15e62eaeef2438cd7f35a5fb8562f5794c469649dfe74`
* captured JSON SHA-256:
  `a2324389c8c8c871a327be48f9dfa3075dd3873e6f5c98fe9236ee6b0778e119`

The tests validate the stated finite identities and exhaustive bounded-error
claims only.  They are not evidence of PQ security and do not establish a
generic impossibility theorem for nonlinear or computational
source-witness-selective encodings.

## 11. Result and handoff

### Proved in this run

* A polynomial-size nonlinear residual map gives an arbitrarily large
  multiplicative metric gap between actual valid Boolean witnesses and invalid
  integer traces.
* An exact linearized pseudopreimage survives **every** left row
  reweighting/mixing transformation, even if setup keeps that transformation
  secret and erases it.
* The standard dual/preimage capsule then cancels the erased pad on that false
  pseudopreimage.
* Residual-only tensor/polynomial magnitude amplification cannot change an
  exact residual zero.
* Public ordinary linear right/column helpers transform the pseudopreimage
  along with genuine representations.

### Implemented/tested, not promoted to a security theorem

* Finite `F_101` false and true capsule fixtures.
* Arbitrary secret left mixing, rectangular transforms, sequential
  five-operator composition, and public linear column-helper controls.
* Exhaustive bounded-error decoding for the explicit false and true fixtures.

### Still unresolved

* A polynomial-size **zero-sound** source representation whose native
  decryption geometry has no short false pseudorepresentations.
* Or, equivalently for the right-transform route, a public offline
  source-witness-selective evaluator obtained from an independently justified
  PQ assumption rather than assumed as WE-equivalent functionality.
* Arbitrary-QPT early key recovery -> source witness or independent PQ break.
* Complete false-instance hiding with all auxiliary public data.
* Malicious-secure ceremony composition for a surviving inner primitive.
* Concrete practical end-to-end parameters.

The stopping condition for a complete generic-NP offline PQ witness KEM is
therefore **not met**.
