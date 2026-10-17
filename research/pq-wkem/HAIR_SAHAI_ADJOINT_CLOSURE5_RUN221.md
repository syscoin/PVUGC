# Run 221 — scalar-core proof closes the adjoint GF(16)-closure-five case

**Status:** bounded joint shared-factor / growing-effective-codimension checkpoint.
This is an exact finite theorem for the literal current `N=3,R=1` Hair–Sahai
false-source fixture.  It does **not** complete false-instance hiding, arbitrary-QPT
ORIGINAL-witness extraction, malicious distributed setup, or the practical WKEM.

## 1. Verified live starting point

Connected GitHub reads before research verified `syscoin/PVUGC#1` at:

- branch `research/pq-wkem-validation-20260918`;
- exact head `aa8f5b0dc257942b40930364a5f18408aca2ea50`;
- PR open, draft, unmerged;
- latest ordinary substantive top-level PR comment `5913974235` (Run 196).

The newest branch-published source checkpoint relevant to this derivation is Run
214.  Exact files read at the live head:

- `research/pq-wkem/HAIR_SAHAI_GENERALIZED_SUPPORT_RUN214.md`, blob
  `6a67013fda501295e631d5bb17bb7d50c4bd8be5`;
- `research/pq-wkem/hair_sahai_generalized_support_run214_check.py`, blob
  `b38c7eea6c6a2cb387b5dcb1b97ac018c0b03f32`;
- `research/pq-wkem/hair-sahai-generalized-support-run214-validation.json`, blob
  `21a7354f085615d8067073a5de8800616f01fd7c`;
- `research/pq-wkem/HAIR_SAHAI_GENERALIZED_SUPPORT_RUN214_PROVENANCE.json`, blob
  `f0433cce9a6ee62be899ce59498660a795ae1b55`.

Conversation-local later runs were used only to choose the present closure-five
question.  This checker independently reconstructs the exact compiler source and
does not import their unpublished artifacts.

## 2. Exact field adjoint

Use the same false fixture as Run 214:

- `N=3`, `R=1`;
- `GF(16)=F_2[x]/(x^4+x+1)`;
- compiler generator `gamma=2`, order `15`;
- impossible Boolean relation `w_0 + 2 w_1 + 4 w_2 = 8`.

The weighted-table source is four-dimensional over `GF(16)`.  Before binary
scalar descent its source words are `56 x 4` matrices over `GF(16)`.  The joint
field span of their columns has dimension exactly six.  Compress that column
ambient to

`A = GF(16)^6`

and write the source coefficient space as

`V = GF(16)^4`.

For `y in A^* ~= GF(16)^6`, define the field adjoint matrix

`E(y) in Mat_(4 x 4)(GF(16))`

by the identity

`<E(y)_j, z> = <y, column_j(M(z))>`

for every source coefficient `z in V` and column index `j=1,...,4`.

The checker constructs `E` directly from the exact field source and proves its
six field generators are independent.  Thus

`E : GF(16)^6 -> Mat_(4 x 4)(GF(16))`

is injective.

For a field or binary domain subspace `X`, write

`Gamma(X) = sum_(j=1)^4 E_j(X)`

for the span of all adjoint rows.  Over binary scalar restriction this is exactly
the row-support object whose dimension controls the primal source capacity.

## 3. Exact preimage censuses

Two complete finite censuses are decisive.

### Field row hyperplanes

There are

`[4 choose 3]_16 = 4,369`

three-dimensional row subspaces.  Equivalently enumerate their unique projective
normal vector.  For each row hyperplane `P`, compute

`dim_GF16 { y in GF(16)^6 : Row(E(y)) <= P }`.

The complete histogram is

| preimage field dimension | number of row hyperplanes |
|---:|---:|
| 2 | 4,352 |
| 3 | 17 |

In particular every such preimage has field dimension at most three.

Consequently **every five-dimensional field-domain hyperplane**
`H <= GF(16)^6` has full field row support `GF(16)^4`: if its row support had
field dimension at most three, `H` would lie in one of the preimages above,
contradicting `5 > 3`.

### Field row planes — new decisive census

There are

`[4 choose 2]_16 = 70,161`

two-dimensional field row subspaces.  The checker enumerates every one in unique
RREF form (via its two-dimensional annihilator) and again computes the full
field-domain preimage dimension.

The exact histogram is

| preimage field dimension | number of row planes |
|---:|---:|
| 0 | 69,632 |
| 1 | 529 |

Therefore

`boxed(max_P dim_GF16 E^{-1}(Rows <= P) = 1)`

for every field row plane `P`.

This is substantially stronger than merely failing to find a low-support
subspace: **no two-dimensional field-domain subspace can have its complete row
support inside any two-dimensional field row plane.**

## 4. Scalar-core lemma

Fix any five-dimensional field-domain hyperplane

`H <= GF(16)^6`.

View `H` as a 20-dimensional binary space.  For any binary subspace `X <= H`,
define

`delta(X) = dim_F2 X - dim_F2 Gamma(X)`.

The following facts are elementary and exact.

1. `Gamma(X+Y)=Gamma(X)+Gamma(Y)` and
   `Gamma(X cap Y) <= Gamma(X) cap Gamma(Y)`.  Hence `dim Gamma(.)` is
   submodular and `delta(.)` is **supermodular**:

   `delta(X)+delta(Y) <= delta(X+Y)+delta(X cap Y)`.

2. Each adjoint row map is `GF(16)`-linear.  Therefore for every nonzero field
   scalar `lambda`,

   `delta(lambda X)=delta(X)`.

3. By the row-hyperplane census above, `Gamma(H)=GF(16)^4`.  Therefore

   `delta(H)=20-16=4`.

Let `Delta=max_(X<=H) delta(X)` and choose a maximizer `X`.  Every scalar
translate `lambda X` is also a maximizer.  Supermodularity implies the sum and
intersection of two maximizers are again maximizers: the two right-hand terms
cannot exceed `Delta`, while their sum must be at least `2 Delta`.

Intersect all nonzero scalar translates:

`C = cap_(lambda in GF(16)^*) lambda X`.

Repeated use of the preceding equality shows `C` is still a maximizer.  It is
stable under every field scalar, hence is a `GF(16)`-linear subspace.  Since
`Delta >= delta(H)=4>0`, `C` is nonzero.

For a field-linear `C`, `Gamma(C)` is field-linear too and

`delta(C)=4( dim_GF16 C - dim_GF16 Gamma(C) )`.

Now use the exact preimage censuses to classify positive field deficiency inside
`H`:

- field dimension 1 cannot have row support 0 because `E` is injective;
- field dimension 2 with positive deficiency would need row support at most 1,
  hence would lie in the preimage of a row plane, but every row-plane preimage
  has dimension at most 1;
- field dimension 3 with positive deficiency would need row support at most 2,
  contradicted by the same row-plane census;
- field dimension 4 with positive deficiency would need row support at most 3,
  but every row-hyperplane preimage has dimension at most 3;
- the only field dimension-5 subspace of `H` is `H` itself, and it has row
  support dimension 4, hence field deficiency exactly 1.

Therefore **`H` is the only field-linear subspace of `H` with positive
field deficiency**.  The scalar core `C` must consequently equal `H`.  Since
`C <= X <= H`, the maximizing binary subspace is also `X=H`.

So `H` is the **unique binary maximizer** of `delta`, with maximum value 4.
Every proper binary `X < H` obeys

`boxed(delta(X) <= 3)`.

Equivalently,

`boxed(dim_F2 Gamma(X) >= dim_F2 X - 3)`

for every proper binary subspace of a field-domain hyperplane.

## 5. Closure-five consequence

Let `L` be any 15-dimensional binary adjoint-domain subspace whose `GF(16)`
closure has field dimension five.  Put

`H = span_GF16(L)`.

Then `L` is a proper binary subspace of the 20-dimensional field hyperplane `H`,
so the scalar-core theorem gives

`dim_F2 Gamma(L) >= 15-3 = 12`.

Thus

`boxed(`
`  every binary 15D L with GF(16)-closure dimension 5`
`  has adjoint row support at least 12.`
`)`

In the generalized-support notation of the current research, an
`e_15(D) <= 11` witness therefore **cannot** lie in the field-closure-five
class.

The separate prior closure-four analysis had already isolated closure four; this
run does not republish or rely on its denied artifacts.  Algebraically, the new
result means that after treating closure four and closure five separately, the
only remaining possible location for an `e_15<=11` counterexample is **full
`GF(16)` closure dimension six**.

## 6. Why this is a growing-codimension result, not fixed-codimension recounting

The proof does not enumerate another collection of primal support-7/8/9
subcodes.  It moves to the joint four-row adjoint channel and proves a structural
dimension-expansion statement for **all** 15-dimensional binary subspaces in an
entire closure class.  The key new mechanism is the scalar-core of a
supermodular deficiency maximizer, tied to complete field preimage censuses.

This directly addresses the shared-factor / effective-codimension handoff: the
four adjoint row maps are treated jointly, and the theorem rules out a whole
class of joint low-image subspaces.

## 7. Reproducibility

Artifacts:

- `HAIR_SAHAI_ADJOINT_CLOSURE5_RUN221.md`;
- `hair_sahai_adjoint_closure5_run221_check.py`;
- `hair-sahai-adjoint-closure5-run221-validation.json`;
- `HAIR_SAHAI_ADJOINT_CLOSURE5_RUN221_PROVENANCE.json`.

The checker is standalone Python standard library.  It reconstructs the exact
weighted-table compiler fixture, compresses the field column ambient, constructs
the field adjoint directly, and exhausts all 4,369 field row hyperplanes and all
70,161 field row planes.

Final validation on this environment:

- Python `3.13.5`;
- syntax check passed;
- 26 explicit assertions in each execution;
- two complete executions;
- byte-identical captured output;
- execution times approximately `3.75 s` and `3.87 s`;
- captured-output SHA-256
  `117428dc13fac986dce57b2d595a1142fa4bf8a05753e3512da0d1668c3713b7`;
- no network used by the checker.

The finite checker validates the exact fixture and the finite census hypotheses.
The scalar-core argument above is the mathematical proof; the absence of a
counterexample in a search is not being promoted into a security theorem.

## 8. QPT/security scope

### Unconditional in this run

- exact field adjoint construction for the literal current false-source fixture;
- exact row-hyperplane preimage census;
- exact complete row-plane preimage census;
- scalar-core/supermodularity theorem;
- closure-five lower bound `rowSupport(L)>=12` for every binary 15D `L` in that
  closure class.

### Still unproved

- the full closure-six case;
- global `e_15(D)=12` and therefore global `d_5(C)=10`;
- the complete generalized-support tail required for full false-instance
  statistical hiding;
- any asymptotic theorem for arbitrary generic-NP Hair–Sahai false sources;
- arbitrary-QPT premature final-capability recovery -> ORIGINAL witness or an
  independently justified PQ hardness break;
- malicious one-honest N-of-N setup/abort/erasure composition;
- a complete practical witness-KEM satisfying the user's stopping condition.

Nothing here upgrades Hair–Sahai's classical generic-group theorem to concrete
post-quantum security.  This run is finite algebra about one exact source
fixture.

## 9. Handoff

The next bounded source-side target is now the **full scalar-closure-six case**.
A useful formulation is:

> classify or exclude 15-dimensional binary `L <= GF(16)^6` with full field
> closure and `dim_F2 Gamma(L) <= 11`.

The closure-five proof suggests looking at the supermodular deficiency lattice
and scalar orbit of a hypothetical `delta(L)>=4`, but the full domain has
`delta(GF(16)^6)=24-16=8`, so the unique-maximizer argument used here does not
apply directly.  The next pass should exploit the intermediate field-hyperplane
maximizers or derive a quotient/second-core invariant, rather than return to flat
support enumeration.

The practical PQ witness-KEM stopping condition remains unmet.
