# Run 219 — adjoint dualization of the actual Hair–Sahai support problem

**Status:** bounded joint-channel / growing-codimension checkpoint.  This run does
not complete the generic witness-KEM.  It replaces the unresolved primal
support-8/9 search by an exact adjoint generalized-row-support problem, and
computes the entire rank spectrum plus every transported-GF(16) projective-line
row-support class of the literal current `N=3,R=1` false-source fixture.

## 1. Verified live starting point

Connected GitHub reads before research verified `syscoin/PVUGC#1`:

- branch `research/pq-wkem-validation-20260918`;
- exact head `aa8f5b0dc257942b40930364a5f18408aca2ea50`;
- PR open, draft, unmerged;
- latest ordinary substantive top-level PR comment `5913974235`.

The exact current-head scientific input used was:

- `research/pq-wkem/HAIR_SAHAI_GENERALIZED_SUPPORT_RUN214.md`,
  blob `6a67013fda501295e631d5bb17bb7d50c4bd8be5`;
- `research/pq-wkem/hair_sahai_generalized_support_run214_check.py`,
  blob `b38c7eea6c6a2cb387b5dcb1b97ac018c0b03f32`;
- captured output blob `21a7354f085615d8067073a5de8800616f01fd7c`;
- provenance blob `f0433cce9a6ee62be899ce59498660a795ae1b55`.

Conversation-local Runs 215–218 were used only to choose the next question.  Their
unpublished files are not treated as branch evidence.

The exact compiler fixture is again

- `N=3`, `R=1`;
- `GF(16)=F_2[x]/(x^4+x+1)`;
- impossible Boolean label `w_0+2w_1+4w_2=8`;
- binary descended source
  `C <= Mat_(224 x 4)(F_2)` of dimension `16`;
- global column support dimension `24`.

Run 214 proved on-branch

`d_1(C)=3`, `d_2(C)=5`, `d_3(C)=6`.

## 2. Adjoint operator code

Compress the 224-dimensional physical row ambient to the exact 24-dimensional
global column support

`A = ColSupp(C) ~= F_2^24`.

Let the 16-dimensional source coefficient space be `V`, and write the source as
the bilinear map

`B : V x F_2^4 -> A`,
`B(w,x)=M(w)x`.

For a linear functional `y in A^*`, define the adjoint operator

`D(y) : V -> (F_2^4)^*`

by

`<D(y)w,x> = <y,B(w,x)>`.

In bases, `D(y)` is a binary `4 x 16` matrix.  The checker proves the map

`A^* -> Mat_(4 x 16)(F_2)`

is injective, so its image `D` is an exact 24-dimensional binary operator code.

This is not the 80-dimensional Frobenius orthogonal code `C^perp`.  It is the
adjoint of the source tensor after the exact 24-dimensional ambient compression.

## 3. Exact primal-capacity / adjoint-row-support identity

For any ambient support `U <= A`, define the primal capacity

`m_C(U) = dim { w in V : Col(M(w)) <= U }`.

Let `L=U^perp <= A^*`, and let

`RowSupp(D(L))`

denote the span in `V^*` of every row of every `D(y)`, `y in L`.

Then

`w in C(U)`
iff
`<y,M(w)x>=0` for every `y in U^perp` and every `x in F_2^4`
iff
every row of every `D(y)`, `y in U^perp`, annihilates `w`.

Therefore, exactly,

`boxed( m_C(U) = 16 - dim RowSupp(D(U^perp)) ).`

No probability, hardness assumption, generic-group model, or random oracle is
used.

Define the adjoint generalized row-support profile

`e_s(D) = min_(L <= A^*, dim L=s) dim RowSupp(D(L)).`

The primal generalized column-support weights satisfy the exact dual formula

`boxed( d_j(C) = 24 - max { s : e_s(D) <= 16-j } ).`

This converts the difficult support search into a high-dimensional row-support
question in the much smaller `4 x 16` adjoint representation.

### Exact `d_5` target

For `j=5` the threshold is `16-j=11`.

Hence

`boxed( d_5(C) <= 9  iff  e_15(D) <= 11. )`

The checker independently exhibits the 4-dimensional source subcode

`span_F2(39234,1002,6,1)`

with column support dimension `9` and exact capacity `4`.  Its orthogonal
15-dimensional adjoint subcode has row support exactly `12`.

Thus

`boxed( e_15(D) <= 12 ).`

The unresolved support-9 question is now a **single-unit drop**:

> does any 15-dimensional adjoint subcode have row support `11`, or is the
> minimum exactly `12`?

If `e_15(D)=12`, then no five-dimensional primal source subcode can fit in nine
ambient dimensions.  Combined with an independently verified support-10 `W_5`,
that would give `d_5=10`.

This run does not use the conversation-local support-10 witness as branch proof,
so it records the exact target without promoting the final equality.

## 4. Complete adjoint rank spectrum

The companion C++ engine exhausts all

`2^24 - 1 = 16,777,215`

nonzero adjoint words.

The exact binary matrix-rank spectrum is

| rank of `D(y)` | number of nonzero `y` |
|---:|---:|
| 1 | 0 |
| 2 | 525 |
| 3 | 59,850 |
| 4 | 16,716,840 |

Therefore

`boxed(d_min(D)=2).`

The absence of rank-one adjoint words is exact for this fixture.

This spectrum is not itself enough to determine `e_15`; generalized support of a
large subcode depends on the joint span of many row spaces, not only on
individual ranks.

## 5. Transported `GF(16)` module symmetry

The 24-dimensional compressed ambient inherits multiplication by `GF(16)` from
the original scalar-descent construction.  Transposing those linear maps gives a
verified `GF(16)` module action on `A^*`.

The checker verifies, on every coordinate basis vector and every pair of field
scalars, both module laws:

`(a+b)y = ay + by`,
`a(by) = (ab)y`.

Thus `A^*` is a 6-dimensional transported `GF(16)` module.

There are exactly

`(16^6-1)/(16-1) = 1,118,481`

one-dimensional `GF(16)` projective lines.

The engine exhausts every one of them and measures:

1. the binary rank of a representative adjoint matrix; and
2. the binary row support of the complete 4-dimensional binary scalar orbit.

The exact joint spectrum is

| representative rank | whole field-line row support | number of field lines |
|---:|---:|---:|
| 2 | 8 | 35 |
| 3 | 8 | 406 |
| 3 | 12 | 3,584 |
| 4 | 8 | 88 |
| 4 | 12 | 66,048 |
| 4 | 16 | 1,048,320 |

Aggregating only by field-line row support gives

`529` lines of support `8`,
`69,632` lines of support `12`,
`1,048,320` lines of support `16`.

Multiplying each line count by its 15 nonzero scalars exactly reconstructs the
complete word-rank census:

- `35*15 = 525` rank-two words;
- `(406+3584)*15 = 59,850` rank-three words;
- `(88+66048+1048320)*15 = 16,716,840` rank-four words.

This is a useful structural constraint on any candidate low-`e_15` subcode.
The low-rank words are highly organized, but a 15-dimensional binary subcode
need not contain a whole transported field line, so this does **not** yet prove
`e_15>=12`.

## 6. Exact high-dimensional adjoint tail implied by Run 214

Because Run 214 already proved on-branch

`d_1=3`, `d_2=5`, `d_3=6`,

the exact dual formula gives several adjoint generalized weights without further
enumeration.

From `d_1=3`:

`max{s:e_s<=15}=21`,

so

`e_22=e_23=e_24=16`
and `e_21<=15`.

From `d_2=5`:

`max{s:e_s<=14}=19`,

so `e_20>=15` and `e_19<=14`.

From `d_3=6`:

`max{s:e_s<=13}=18`,

so `e_19>=14`.

Combining monotonicity:

`boxed(e_19=14)`,
`boxed(e_20=e_21=15)`,
`boxed(e_22=e_23=e_24=16)`,

with `e_18<=13`.

So the unresolved fifth-weight problem lives much lower, at `e_15`, rather than
near the already-rigid high-dimensional tail.

## 7. Reproducibility

Artifacts:

- `HAIR_SAHAI_ADJOINT_DUAL_RUN219.md`;
- `hair_sahai_adjoint_run219_check.py`;
- `hair_sahai_adjoint_run219_engine.cpp`;
- `hair-sahai-adjoint-run219-validation.json`;
- `HAIR_SAHAI_ADJOINT_DUAL_RUN219_PROVENANCE.json`.

The Python checker reconstructs the compiler fixture from first principles,
derives the 24-dimensional compression and adjoint generators, verifies the
capacity identity on deterministic source-derived and coordinate fixtures,
derives the transported field action, and feeds only those derived generators to
the generic C++ exhaustive engine.

Final validation:

- Python `3.13.5`;
- Python syntax check passed;
- C++17 syntax check passed;
- `13,156` Python assertions;
- two complete executions;
- outputs byte-identical;
- execution times approximately `6.56 s` and `6.57 s`;
- no network used by either checker;
- validation SHA-256
  `1d56bf27865c14d7c765306e54354e07143602ed1cab33472843a1ee20f58574`.

The host emitted an unrelated spreadsheet-runtime warmup error before Python
startup.  It did not affect either checker subprocess, both of which completed
normally and identically.

## 8. Security/QPT scope

### Unconditional in this run

- exact adjoint construction for the literal current false-source fixture;
- exact capacity/row-support dual identity;
- exact complete `2^24-1` adjoint rank spectrum;
- exact complete transported-`GF(16)` field-line row-support spectrum;
- exact reduction of the support-nine `W_5` question to `e_15(D)<=11`;
- explicit `e_15(D)<=12` witness via a support-nine capacity-four primal
  ambient.

### Still unproved

- whether `e_15(D)=11` or `12`;
- the complete primal generalized-support tail;
- full false-instance statistical hiding for the actual generic source family;
- an asymptotic theorem for arbitrary Hair–Sahai false statements;
- arbitrary-QPT premature final-capability recovery -> ORIGINAL witness;
- malicious one-honest N-of-N setup/abort/erasure composition;
- a practical end-to-end WKEM satisfying the user's stopping condition.

This run does not infer PQ security from the words "rank metric", "GF(16)", or
the absence of a finite attack.

## 9. Handoff

The next bounded source-side target is now sharper than another flat
support-eight/nine primal enumeration:

> determine `e_15(D)` for this exact 24-dimensional adjoint code.

The decisive outcomes are binary:

- find `L <= A^*`, `dim L=15`, with row support `<=11`; this immediately yields
  a primal ambient `U=L^perp`, `dim U=9`, of source capacity at least five and
  therefore a concrete support-nine `W_5`; or
- prove every 15-dimensional `L` has row support at least 12; together with a
  verified support-ten primal witness this closes `d_5=10`.

The transported field-line spectrum supplies a much smaller structural object
for that attack/proof than the original `224 x 4` matrices.

The practical PQ witness-KEM stopping condition remains unmet.
