# Run 52 — nonlinear correlated support masks and the secret-scramble interpolation barrier

## Status and scope

This run starts from verified PR head
`98dfda35a4e1a00860cad41fd6ec5331e0f3dedd` (Run 51).

It does **not** construct the requested generic-NP PQ witness KEM.  It tests the
next natural repair of the Run-50/51 denominator/ideal-mask family:

1. replace independent uniform masks by masks driven by a shared hidden seed
   through arbitrary nonlinear coefficient maps, with arbitrary cross-component
   correlations and nonuniformity; and
2. optionally hide the coefficient geometry behind a setup-time random
   invertible linear scramble that is erased after setup.

The result is a distribution-free quotient theorem for the first repair and a
polynomial interpolation attack on the second repair whenever the public offline
helper is an ordinary linear evaluator on a polynomial-dimensional function
space.

The result does **not** rule out a genuinely witness-selective public evaluator,
a non-additively-separable capsule, a hidden support that is never made
linearly evaluable, or a different construction reduced to LWE/SIS.  It also
does not turn a newly named property into an assumption.

No external literature or web search is used here.

## 1. Candidate: arbitrary nonlinear/correlated masks inside vanishing supports

Fix a field `F_q`, statement `x`, and components `j=1,...,m`.

For component `j` let:

- `P_j` be a public finite-dimensional coefficient space;
- `V_j <= P_j` be a public linear subspace whose every element vanishes at every
  valid source witness;
- `r_j in P_j` be the public payload/denominator direction;
- `s_j in F_q` be a share of the common payload key.

Now make **no** linearity, independence, or uniformity assumption on the masks.
Let a global hidden seed `tau` and any additional setup randomness produce a
joint random vector

    (R_1,...,R_m) = F_x(tau, randomness)

subject only to the support condition

    R_j in V_j              for every realized sample.          (1)

The map `F_x` can be nonlinear, correlated across all components, highly
nonuniform, deterministic given `tau`, or computationally complicated.  Publish

    C_j = s_j r_j + R_j.                                  (2)

A valid witness `w` obtains the intended share whenever `r_j(w) != 0`, because
`R_j(w)=0`.

This strictly contains Run 51's independent uniform affine masks and its joint
uniform linear-mask addendum.

## 2. Distribution-free quotient extraction

Define the public exposure set

    E_x = { j : r_j notin V_j }.                         (3)

### Theorem 1 — support-only quotient theorem

For every `j in E_x`, public Gaussian elimination computes a linear functional
`lambda_j : P_j -> F_q` such that

    lambda_j(V_j)=0,
    lambda_j(r_j)=1.                                    (4)

Therefore, **for every realization and every mask distribution satisfying (1)**,

    lambda_j(C_j)=s_j.                                  (5)

No property of the seed distribution appears in the proof.

**Proof.**  Because `r_j notin V_j`, extend a basis of `V_j` by `r_j` and define
a linear functional that is zero on the basis of `V_j` and one on `r_j`.
Equation (5) follows immediately from (1)-(2).  QED.

Consequences:

- replacing a uniform mask by a PRF-looking coefficient sequence does not help
  if the realized coefficient vector still lies in the same public `V_j`;
- quadratic/cubic/shared-seed correlations do not help;
- arbitrary dependence between `R_j` and `R_k` does not help;
- computational hardness of recovering `tau` is irrelevant to (5).

This is stronger than Run 51's affine-coset distribution theorem: share
extraction on exposed components is deterministic and distribution-free.

## 3. Every witness-accessible share is publicly exposed

For a valid witness `w`, define

    A_x(w) = { j : r_j(w) != 0 }.                        (6)

### Lemma 2 — accessibility containment

    A_x(w) subseteq E_x.                                (7)

**Proof.**  If `r_j in V_j`, then `r_j(w)=0` because every vector in `V_j`
vanishes at every valid witness.  Take the contrapositive.  QED.

### Corollary 3 — nonlinear correlated masks still do not source-restrict shares

Suppose the shares use a public monotone access structure `Gamma_x`, and
decapsulation from witness `w` reconstructs the key because
`A_x(w) in Gamma_x`.  Then (7) and monotonicity imply

    E_x in Gamma_x.                                     (8)

The public computes every `s_j` for `j in E_x` using (5), so it reconstructs the
same key without the witness.

This conclusion does not require perfect privacy of the share scheme and does
not require any assumption about the mask law.  It uses only the additive form
(2), the public vanishing supports, and monotone reconstruction.

Thus a “nonlinear correlated mask” is not a new cryptographic layer merely
because its **seed-to-mask map** is nonlinear.  To escape this theorem, the
complete output must leave the public support quotient itself, hide that support
in a way that remains hidden after all public evaluation material is included,
or abandon the additively separable share direction.

## 4. Secret coefficient scrambling

The obvious support-hiding repair is to choose a secret setup-time

    S in GL(P)

and publish the scrambled coefficient vector

    C' = S C.                                           (9)

If `S` is erased, the public no longer sees `V` or `r` in the clear.  A valid
witness still needs some offline public mechanism for evaluating the original
function represented by `C`.

Let `phi(z)` be the ordinary evaluation vector, so

    Eval(C,z) = phi(z)^T C.                             (10)

A natural public linear adapter is

    psi(z) = S^{-T} phi(z),                             (11)

because

    psi(z)^T C' = phi(z)^T C.                           (12)

The next theorem shows that, in a polynomial-dimensional function space,
ordinary public evaluation is enough to undo the hiding.

## 5. Public unisolvent evaluation interpolates the unscrumbled capsule

Let `P` have dimension `M=poly(lambda)` and suppose there is a public
polynomial-time constructible unisolvent set

    U = {z_1,...,z_M}

whose evaluation matrix

    Phi_U =
      [ phi(z_1)^T
        ...
        phi(z_M)^T ]                                    (13)

is invertible.

### Theorem 4 — capsule interpolation

If the public offline helper permits ordinary evaluation of the **actual
scrambled capsule** at every `z_i in U`, returning

    y_i = phi(z_i)^T C,                                 (14)

then the public recovers the complete unscrumbled coefficient vector by

    C = Phi_U^{-1} y.                                   (15)

This does not require recovery of `S`.

Once `C` is recovered, Theorem 1 applies exactly as before.

### Theorem 5 — adapter-key recovery

If the helper instead publishes the linear evaluation keys

    psi(z_i)=S^{-T}phi(z_i),                            (16)

for the same unisolvent set, then writing the vectors as columns gives

    Psi = S^{-T} Phi

and therefore

    S^{-T} = Psi Phi^{-1}.                              (17)

Hence the scramble itself is publicly reconstructed.

These are deterministic linear-algebra statements.  They do not assume that an
attacker knows a source witness.

## 6. Explicit unisolvent set for low-degree Boolean multilinear functions

For `n` Boolean variables and degree bound `D`, use the monomial basis

    { x_T = product_{i in T} x_i : |T| <= D }.

Its dimension is

    M = sum_{k=0}^D binom(n,k).                         (18)

For every subset `S` with `|S|<=D`, let `1_S` be the Boolean indicator point.
Then

    x_T(1_S) = 1[T subseteq S].                         (19)

Index rows and columns by subsets of size at most `D` in any linear extension of
set inclusion.  The matrix in (19) is triangular with diagonal one (equivalently
the finite subset zeta transform), so it is invertible over every field.

Therefore, whenever (18) is polynomial-sized, the entire unisolvent query set is
also polynomial-sized and constructible without searching for witnesses.

This matters for the setup ceremony proposal: erasing `S` after setup does not
help if the surviving public helper is merely an ordinary evaluator that works
on arbitrary public inputs.  If the helper releases (12) **only for a valid
source witness** and refuses the unisolvent nonwitness points, then it has become
the missing witness-restricted evaluator.  This note does not assume or
construct that primitive.

## 7. Complete-public-output boundary

The two theorems separate three cases.

1. **Public vanishing supports.** Arbitrary nonlinear/nonuniform/correlated mask
   samplers are defeated by the deterministic quotient (5).

2. **Secretly scrambled support + ordinary public evaluation.** Polynomial
   interpolation (15), or adapter recovery (17), reveals the unscrumbled view.

3. **Secretly scrambled support + witness-selective evaluation.** Not broken by
   the arguments above, but this is exactly the unresolved cryptographic object:
   after setup erases `S`, a future valid witness must obtain the needed
   evaluation while arbitrary nonwitness public inputs cannot.  A software
   wrapper that simply contains `S`, an online service, or an assumed
   obfuscation/WE-equivalent release compiler does not satisfy the stated goal.

Accordingly this run closes a materially broader “just make the correlations
nonlinear / hide the basis” repair, but it does not close nonlinear
non-additively-separable LWE/SIS constructions in general.

## 8. Validation actually executed

`nonlinear_support_scramble_run52_check.py` is standard-library only and uses
deterministic seed `5200520052` over `F_101`.

It was executed twice from the saved bytes; stdout was byte-identical.  The
captured run checked:

- 5 explicit Boolean multilinear unisolvent systems with total dimension 95;
- 1,200 shared-seed nonlinear support fixtures, with 1,200/1,200 exact quotient
  share recoveries;
- 600 key-sharing trials alternating additive 3-of-3 and Shamir 2-of-3, with
  600/600 public key reconstructions from quotient-exposed shares;
- 180 random secret scrambles in the degree-2, 5-variable multilinear space
  (`M=16`), with 180/180 exact recoveries of `S` from public adapter keys;
- the same 180 fixtures with 180/180 exact interpolation recoveries of the
  complete unscrumbled capsule from ordinary public evaluations on the
  unisolvent set;
- 180/180 subsequent exact capsule unmaskings and share recoveries.

The nonlinear mask coefficients deliberately include quadratic and cubic
functions of a shared global seed.  The tests validate the finite algebra and
implementation only.  The general claims above are proved algebraically; test
success is not treated as a security proof.

Captured stdout SHA-256:

    4348221a2d77c03a7538423185d9315cbafd0b9af9d0794ecb4193856c8fbb76

Checker SHA-256:

    da9d8a0eb24677ead4fadb48fcb44a40809a6cfddfa5deaf3bb9aef1290a095b

## 9. Remaining obligations

The stopping condition is not met.

The next surviving construction must do at least one of the following without
circularity:

- make the complete output non-additively-separable so there is no public
  vanishing-support quotient that deterministically extracts witness-accessible
  shares;
- keep the relevant support hidden **and** provide a genuinely
  witness-selective post-erasure evaluator whose full public output is reduced
  to LWE/SIS or another independently justified PQ assumption;
- return to the Run-42/43 short-preimage interface with a compiler whose complete
  public representation has no short exact false pseudorepresentations.

Still unproved are arbitrary-QPT early-key recovery -> source witness /
independent-PQ-break for a surviving primitive, complete false-instance hiding,
malicious-secure ceremony plus auxiliary-input composition for that primitive,
and concrete practical parameters.

**Stopping condition: not met.**
