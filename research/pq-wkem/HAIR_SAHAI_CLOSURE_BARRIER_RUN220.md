# Run 220 — field-closure barriers for the actual Hair–Sahai `d_5` / adjoint `e_15` problem

**Status:** bounded joint-support / growing-effective-codimension checkpoint. This run does not complete the generic witness-KEM. It narrows the exact unresolved support-nine problem for the literal current `N=3,R=1` false-source fixture to source `GF(16)`-span at least three, equivalently on the adjoint side to binary 15-spaces whose `GF(16)` closure has dimension five or six.

## 1. Verified live starting point

Connected GitHub reads before research verified `syscoin/PVUGC#1` at:

- branch `research/pq-wkem-validation-20260918`;
- exact head `aa8f5b0dc257942b40930364a5f18408aca2ea50`;
- PR open, draft, unmerged;
- latest ordinary substantive top-level PR comment `5913974235` (Run 196).

The exact current-head scientific input was Run 214:

- `HAIR_SAHAI_GENERALIZED_SUPPORT_RUN214.md`, blob `6a67013fda501295e631d5bb17bb7d50c4bd8be5`;
- checker blob `b38c7eea6c6a2cb387b5dcb1b97ac018c0b03f32`;
- captured-output blob `21a7354f085615d8067073a5de8800616f01fd7c`;
- provenance blob `f0433cce9a6ee62be899ce59498660a795ae1b55`.

Conversation-local Run 219 supplied the *question* `e_15(D)=11 or 12`; its unpublished artifacts are not treated as branch evidence. The exact source and adjoint structures used here are independently rebuilt by the Run-220 checker from the current compiler fixture.

## 2. Literal source fixture

As in Run 214:

- `N=3`, `R=1`;
- `GF(16)=F_2[x]/(x^4+x+1)`;
- impossible Boolean label `w_0+2w_1+4w_2=8`;
- binary descended source `C <= Mat_(224 x 4)(F_2)` of dimension `16`;
- exact global binary column support dimension `24`;
- nonzero rank census: `225` rank-three and `65,310` rank-four matrices.

The checker compresses the 224-row physical ambient to the exact 24-dimensional global column support and retains the natural `GF(16)` scalar action inherited from the current compiler.

## 3. New result A: every binary `W_5` with `GF(16)` span two has support at least 12

The 16-dimensional binary source is four-dimensional over `GF(16)`. There are exactly

`[4 choose 2]_16 = 70,161`

`GF(16)`-planes in the source. Their complete binary column-support histogram is

- `529` planes of support `20`;
- `69,632` planes of support `24`.

A binary five-dimensional subspace cannot have `GF(16)`-span one because a field line has only four binary dimensions. Thus every `W_5` of field-span exactly two is a five-dimensional binary subspace of one unique eight-dimensional binary field plane.

### Support-24 field planes

If `K <= H` has binary dimensions `5 <= 8`, extend a basis of `K` by three source matrices to span `H`. Each added `224 x 4` binary matrix contributes at most four new column-support dimensions. Therefore

`c(K) >= c(H) - 4(8-5)`.

For `c(H)=24`,

`boxed(c(K) >= 12).`

### Support-20 field planes — exact exhaustive census

The C++ engine enumerates every binary five-space in every one of the 529 support-20 field planes. Each field plane contains

`[8 choose 5]_2 = 97,155`

binary five-spaces, for an exact total of

`529 * 97,155 = 51,394,995`

subspaces.

Their complete support histogram is:

| support | count |
|---:|---:|
| 13 | 8,820 |
| 14 | 168,315 |
| 15 | 785,445 |
| 16 | 1,652,610 |
| 17 | 3,159,180 |
| 18 | 13,674,885 |
| 19 | 23,815,680 |
| 20 | 8,130,060 |

There are **zero** examples of support at most 11; in fact the exact minimum in this class is 13.

An explicit support-13 example is contained in the field plane with binary coefficient basis

`(61185, 61456)`

and has binary five-space basis

`(36928, 2340, 54294, 37128, 61185)`.

Combining the support-24 codimension bound and the support-20 exhaustive census gives

`boxed(any binary W_5 with GF(16)-span exactly 2 has c(W_5) >= 12).`

In particular, a hypothetical support-eight or support-nine `W_5` cannot live in a field plane. It must have source `GF(16)`-span at least three.

## 4. Independent global upper witness remains support 10

The checker independently verifies, directly from the current source reconstruction, the five-dimensional binary source subcode

`W_5 = span_F2(39234, 970, 32, 6, 1)`

has:

- binary dimension `5`;
- exact column support `10`;
- exact source capacity of that support ambient `5`;
- `GF(16)` source-span dimension `4`.

Thus this local calculation re-establishes

`d_5(C) <= 10`

without importing the unpublished Run-216 checker as evidence.

It does **not** prove `d_5=10`, because field-span-three/four/five-space configurations of support eight or nine remain logically possible.

## 5. New result B: an adjoint `e_15 <= 11` witness cannot have `GF(16)` closure four

The same checker independently reconstructs the adjoint operator code after the 24-dimensional ambient compression. Under the transported trace-dual coordinates, it is a six-dimensional `GF(16)` code

`E <= Mat_(4 x 4)(GF(16))`.

For a binary adjoint subspace `L`, let `cl_16(L)` be its `GF(16)` span.

Suppose `dim_F2 L=15` and `dim_GF16 cl_16(L)=4`. Then the field closure `H=cl_16(L)` has binary dimension 16, so `L` is a binary hyperplane in `H`.

The checker exhausts all

`[4 choose 3]_16 = 4,369`

field hyperplanes `P <= GF(16)^4` in the **row ambient**, and for each computes the field dimension of

`{ y in E-domain : Row_GF16(D(y)) <= P }`.

The exact preimage-dimension histogram is

- dimension `2`: `4,352` row hyperplanes;
- dimension `3`: `17` row hyperplanes;
- dimension `4`: **zero**.

Therefore no four-dimensional field-domain subspace can have field row support at most three. Every four-dimensional field-domain subspace has full `GF(16)` row support dimension four, hence binary row support 16.

Adding the one missing binary generator that extends `L` to its 16-dimensional closure `H` can enlarge binary row support by at most the binary matrix rank of one adjoint word, which is at most four. Consequently

`16 <= RowSupp(L) + 4`,

so

`boxed(dim RowSupp(L) >= 12).`

Thus:

`boxed(any hypothetical e_15(D) <= 11 witness must have adjoint GF(16)-span 5 or 6, not 4).`

## 6. Exact `e_15 <= 12` upper witness is independently reverified

The checker also rebuilds the four-dimensional primal source subcode

`W_4 = span_F2(39234, 1002, 6, 1)`.

Its column support `U` has:

- `dim U = 9`;
- source capacity `m_C(U)=4`.

Therefore `L=U^perp` has binary dimension 15 and, by the exact primal-capacity/adjoint-row-support identity,

`dim RowSupp(D(L)) = 16 - 4 = 12`.

The checker computes this directly as well. This `L` has full transported field closure dimension six.

Hence the exact local bracket is

`boxed(e_15(D) <= 12),`

while a value `<=11` is excluded for closure dimension four and remains open only in closure dimensions five or six.

## 7. Combined narrowing

The unresolved support-nine problem now has two equivalent closure restrictions:

### Primal side

A hypothetical `W_5` with support at most nine must have

`boxed(dim_GF16 span(W_5) >= 3).`

### Adjoint side

A hypothetical 15-dimensional `L` with row support at most eleven must have

`boxed(dim_GF16 span(L) >= 5).`

The already-known exact upper witness at row support 12 has field closure six.

This is a substantive search-space reduction, but not a proof that the remaining span-five/six classes are empty.

## 8. Exact checker and bounded execution

Artifacts:

- `HAIR_SAHAI_CLOSURE_BARRIER_RUN220.md`;
- `hair_sahai_closure_barrier_run220_check.py`;
- `hair_sahai_fieldspan2_run220_engine.cpp`;
- `hair-sahai-closure-barrier-run220-validation.json`;
- `HAIR_SAHAI_CLOSURE_BARRIER_RUN220_PROVENANCE.json`.

The checker uses no network. It reconstructs the current compiler source, its 24-dimensional compression, the transported field action, and the adjoint from first principles, then invokes the generic C++ enumerator for the 51,394,995-subspace field-span-two census.

Final validation:

- Python `3.13.5`;
- Python syntax check passed;
- C++17 syntax check passed;
- `65,996` Python assertions;
- two complete final executions;
- outputs byte-identical;
- execution times approximately `24.46 s` and `24.82 s`;
- validation SHA-256 `3c2581268c3f29262062d6c35bed2a691e3c49ac33bbfad4192a03d472fb68f8`.

Local development/validation failures, excluded from evidence:

1. an intermediate checker used the wrong helper name and failed with `NameError: name 'gf2_nullspace_basis' is not defined. Did you mean: 'gf2_nullspace_rows'?`;
2. a direct Python edit of the root-owned checker artifact failed with `PermissionError: [Errno 13] Permission denied`; the file was then edited through the container that owned it;
3. a compound two-execution validation wrapper completed the first `24.46 s` run, then ended with `Command failed because it timed out.` while the second redirected output was still empty. That zero-byte output was discarded; the second execution was rerun separately, completed in `24.82 s`, and matched byte-for-byte.

None of these were GitHub/service authorization or safety failures, and no request/correlation IDs were supplied.

## 9. Security/QPT scope

### Unconditional in this run

- exact field-plane support census for all 70,161 source `GF(16)` planes;
- exact 51,394,995 binary five-space census in all support-20 field planes;
- proof that source field-span-two `W_5` has support at least 12;
- independent support-10 `W_5` upper witness;
- exact field-row-hyperplane preimage census in the adjoint;
- proof that a binary 15-space of adjoint field closure four has row support at least 12;
- independent `e_15 <= 12` witness of field closure six.

### Still unproved

- whether `e_15(D)=11` or `12` globally;
- exclusion of adjoint field-closure five/six low-row-support subspaces;
- exclusion of primal source-span three/four support-eight/nine `W_5`;
- the complete generalized-support tail and full false-instance statistical hiding;
- an asymptotic theorem for arbitrary Hair–Sahai false statements;
- arbitrary-QPT premature final-capability recovery -> ORIGINAL witness;
- malicious one-honest N-of-N setup/abort/erasure composition;
- a practical end-to-end WKEM meeting the requested stopping condition.

No QPT hardness is inferred from these finite algebraic censuses.

## 10. Handoff

The next bounded source-side pass should attack the remaining **adjoint closure-five case** before closure six.

A useful formulation is: classify five-dimensional `GF(16)` domain subspaces `H <= GF(16)^6` by their field row-support dimension, and then ask whether any 15-dimensional binary `L <= H` can reduce the binary row support to at most 11. A field-closure-five lower bound would leave only full closure six.

Do not return to flat support-eight/nine primal enumeration unless it is used to falsify that closure reduction.

The practical PQ witness-KEM stopping condition remains unmet.
