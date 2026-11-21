# Run 214 — exact first generalized column-support spectrum of the actual N=3 Hair–Sahai false source

**Status:** bounded source-spectrum checkpoint. This extends the conversation-local
Run-213 generalized-support handoff by computing the complete one- and
two-dimensional support enumerators, and the exact first three generalized
column-support weights, for a literal current-compiler Hair–Sahai false source.
It is not a completed generic-NP false-hiding proof and not a practical PQ WKEM.

## 1. Verified live starting point

Connected GitHub reads before research verified `syscoin/PVUGC#1`:

- branch `research/pq-wkem-validation-20260918`;
- exact head `45185f59e519753d611d2bcf45af88348ff7f16d`;
- PR open, draft, unmerged;
- latest ordinary substantive top-level PR comment `5913974235` (Run 196).

Exact-version files used:

- `research/pq-wkem/CMV_MINRANK_LACONIC_QPT_SOURCE_BRIDGE_RUN152.md`,
  blob `398b93af491d0b11cc486e86c89295a05b714804`;
- `research/pq-wkem/literature-20260924/rank_field_extensions.py`,
  blob `e3c51bff4a8f3817f70b1368190b8b35893cafa2`;
- `research/pq-wkem/HAIR_SAHAI_PUBLIC_ANCHOR_QUOTIENT_BARRIER_RUN129.md`,
  blob `cb74329d418b365abd325270185673b29fb10560`.

The current branch does **not** contain Run 213. Its generalized-support theorem
was conversation-local, so this run independently rebuilds the literal source
fixture from the exact current compiler rather than treating unpublished Run-213
artifacts as repository evidence.

## 2. Source fixture

Use the exact scalar-descent fixture already present in
`rank_field_extensions.py`:

- `N=3`, `R=1`;
- `GF(16)=F_2[x]/(x^4+x+1)`;
- compiler generator `gamma=2` of order `15`;
- impossible Boolean label relation
  `w_0 + 2 w_1 + 4 w_2 = 8`.

There is no Boolean witness because the three binary weights span only labels
`0,...,7`.

The current weighted-table compiler gives a `4`-dimensional `GF(16)` source.
Restricting scalars exactly as the current checker does produces a
`16`-dimensional binary matrix code

`S <= F_2^(224 x 4)`.

Exhausting all `2^16-1=65,535` nonzero matrices gives:

- `225` matrices of rank `3`;
- `65,310` matrices of rank `4`;
- all `65,535` have **distinct binary column spaces**;
- the joint column support of the complete source has dimension `24`.

The `225` rank-three matrices form exactly `15` one-dimensional
`GF(16)` projective source lines, each containing `15` nonzero binary words.

## 3. Generalized column-support profile

For a binary subcode `W <= S`, define

`c(W) = dim_F2 sum_(M in W) Col(M)`.

Define the support enumerator

`A_(j,c) = #{ W <= S : dim W=j and c(W)=c }`

and generalized support weights

`d_j = min_(dim W=j) c(W)`.

These are the column-oriented matrix-code support parameters naturally adjacent
to the generalized/Delsarte matrix-weight and rank-support-profile literature.
No coding-theory security theorem is imported here.

### Dimension one — complete

The ordinary rank census is exactly

`A_(1,3)=225`,
`A_(1,4)=65,310`.

Therefore

`boxed(d_1=3)`.

### Dimension two — complete

There are

`[16 choose 2]_2 = 715,795,115`

binary two-dimensional source subcodes. Instead of looping over all 2.1 billion
unordered bases, the checker counts intersections of the already-enumerated
column spaces.

Exact incidence facts:

1. rank-3/rank-3 pairs:
   - support `5`: `1,260` unordered pairs;
   - support `6`: `23,940`.

2. rank-3/rank-4 pairs:
   - intersection dimension at least `2`: **zero**;
   - intersection dimension exactly `1`: `62,370`.

3. rank-4/rank-4 pairs:
   - intersection dimension `3`: **zero**;
   - intersection dimension `2`: `8,820`;
   - intersection dimension `1`: `7,616,385`.

Because every two-dimensional binary coefficient subspace has exactly three
unordered nonzero bases, division by three yields the complete enumerator:

`boxed(A_(2,5)=420)`

`boxed(A_(2,6)=31,710)`

`boxed(A_(2,7)=7,416,255)`

`boxed(A_(2,8)=708,346,730)`.

These sum exactly to `715,795,115`.

Therefore

`boxed(d_2=5)`.

This is substantially more information than minimum rank alone: almost every
two-dimensional subcode has full possible eight-dimensional column support, but
there are exactly 420 exceptionally compressed two-dimensional subcodes.

## 4. Exact third generalized support weight

Every one of the `420` support-five two-dimensional subcodes has the following
strong property:

> the complete source subcode whose matrices have all columns inside that same
> five-dimensional ambient support has dimension **exactly two**.

So no three-dimensional source subcode can have support five. Otherwise one of
its two-dimensional subspaces would have support at most five; since `d_2=5`,
that two-dimensional subspace would be one of the 420 above and its fixed support
would contain a three-dimensional source subcode, contradicting the exhaustive
dimension check.

The checker also gives an explicit three-dimensional coefficient subspace with
support six, with basis coefficients

`(39235, 1002, 6)`

in the exact 16-bit scalar-descent basis.

Hence

`boxed(d_3=6)`.

The first three generalized column-support weights of this actual false source
are therefore

`boxed((d_1,d_2,d_3)=(3,5,6)).`

This is the first exact growth information beyond the global `c(S)=24` result.

## 5. Consequence for the Run-212 repaired row

The conversation-local Run-213 conditional-image accounting gives, for a
`j`-dimensional source subspace of support `c`, the exact contribution

`A_(j,c) * sigma(t,j) * 2^(-r c)`

to

`E[ |ker L_V^*| - 1 ]`,

where

`sigma(t,j)=product_(i=0)^(j-1) (2^t-2^i)`.

The complete `j=1` and `j=2` contribution can now be evaluated exactly for this
source.

At the Run-212 cube-repair row

`r=74`, `t=86`,

the known contribution is

`log2(sum_(j<=2,c) A_(j,c) sigma(t,j) 2^(-rc))
 = -128.18621880878297`.

It is overwhelmingly dominated by the 225 rank-three one-dimensional source
directions:

`log2(225 * (2^86-1) * 2^(-222))
 = -128.1862188...`.

That has an important interpretation:

> the `r=74,t=86` cube-specific proof cannot simply be transplanted to this
> actual `N=3` source and advertised as a `2^-136` per-bit support-sum
> certificate.

This is a **failure of that sufficient certificate**, not a proof that the true
statistical distance is `2^-128.18` and not an efficient distinguisher.

Keeping the same `t=r+12` correctness margin, the first value for which the now
fully known `j<=2` contribution falls below `2^-136` is

`r=78`, `t=90`,

where it is

`2^-136.18621880878297`.

But `j>=3` remains unenumerated, so `r=78,t=90` is only a **necessary next
candidate**, not a proven hiding row.

The newly proved `d_3=6` shows that higher-dimensional compression continues:
the source does not jump immediately to private support after dimension two.

## 6. Structural observations

The exact incidence census supplies several useful constraints on any attempted
closed form.

- All nonzero source words have distinct column spaces.
- The 225 rank-three words form 15 `GF(16)` projective lines.
- Exactly 210 of those rank-three binary words participate in a support-five
  pair; each participates in 12 such unordered pairs.
- The remaining 15 rank-three words participate in none.
- No rank-three column space is contained in a rank-four column space.
- No two rank-four source words have a three-dimensional column-space
  intersection.

These facts make the support spectrum much more rigid than an arbitrary
16-dimensional binary matrix code, but they do not yet give a general formula
for all `A_(j,c)`.

## 7. Relation to generalized matrix weights

Ravagnani's Delsarte generalized weights and later relative generalized matrix
weights formalize subcode-support parameters for matrix codes via optimal
anticodes/support spaces. The quantity used here is the direct column-support
profile needed by the conditional-image theorem; transposing matrices converts
between row- and column-oriented conventions.

The literature is useful terminology and structural context only. It does not
turn the Hair--Sahai classical generic-group theorem into a concrete QPT theorem,
and it does not prove this source's higher support enumerator.

## 8. Exact checker

`hair_sahai_generalized_support_run214_check.py` is standard-library Python.

Final validation:

- Python `3.13.5`;
- `455` assertions;
- syntax validation passed;
- two executions produced byte-identical JSON;
- execution times about 25 seconds each on this environment.

It independently rebuilds the exact current compiler fixture and checks:

- the complete `65,535`-word rank census;
- uniqueness of every nonzero column space;
- global support dimension `24`;
- the 15 rank-three `GF(16)` projective lines;
- all `25,200` rank-three/rank-three pairs;
- exact one-, two-, and three-dimensional incidence structures needed for the
  full `A_(2,c)` census;
- every support-five two-dimensional subcode's fixed-support source dimension;
- an explicit support-six three-dimensional subcode;
- the exact known support-sum terms at `r=74,t=86` and `r=78,t=90`.

The host emitted an unrelated spreadsheet-runtime warmup warning before Python
startup. The checker subprocesses themselves completed normally and produced
identical captured output.

## 9. Security scope

### Unconditional in this run

- exact finite source construction for the specified false fixture;
- exact `A_(1,c)` and `A_(2,c)` enumerators;
- exact `(d_1,d_2,d_3)=(3,5,6)`;
- exact arithmetic for their conditional-image support-sum contributions.

### Not proved

- complete `A_(j,c)` for `j>=3`;
- full false-instance statistical hiding for this fixture at any proposed
  practical row;
- asymptotic generalized-support bounds for arbitrary Hair--Sahai false sources;
- arbitrary-QPT premature final-key recovery -> ORIGINAL witness for the complete
  wrapper;
- malicious one-honest N-of-N setup/abort/erasure composition;
- practical source dimensions for the intended Syscoin relation.

The practical PQ witness-KEM stopping condition remains unmet.

## 10. Handoff

The next source-side pass should **not** return to ordinary minimum-rank counting.

The concrete target is now one of:

1. derive the higher generalized column-support weights/enumerator of this
   `4`-dimensional-`GF(16)` / `16`-dimensional-binary source using its field-linear
   structure, ideally enough to bound the full
   `sum_(j,c) A_(j,c) sigma(t,j) 2^(-rc)`; or
2. obtain a general polynomial lower bound on `c(W)` as a function of
   `dim W` for the statement-derived weighted-table family.

If neither works, an explicit higher-dimensional compressed subcode is itself a
useful falsification checkpoint.

Do not call `r=78,t=90` secure until the `j>=3` mass is bounded.
