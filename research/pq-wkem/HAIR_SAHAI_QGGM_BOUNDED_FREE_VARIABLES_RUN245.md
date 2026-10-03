# Run 245 — constant effective codimension makes the exponent-visible bounded image efficiently recognizable

## Status

Bounded cryptographic research checkpoint. This is a model-specific continuation of the branch-visible Run 242 exponent-channel analysis. It does **not** prove a concrete-group post-quantum attack, a practical witness-KEM, or arbitrary-QPT ORIGINAL-witness extraction.

The new result closes another part of the post-DLOG channel without introducing a new hardness assumption:

> If the effective bounded map has full row rank and only a constant number of more bounded input coordinates than output coordinates, exact bounded-image membership is polynomial-time by enumerating only those free bounded coordinates.

Together with Run 242's span test for rank-deficient maps, this gives one exact distinguisher for every matrix in the constant-effective-codimension branch.

## 1. Verified live starting point

Connected GitHub reads before research verified `syscoin/PVUGC#1`:

- branch `research/pq-wkem-validation-20260918`;
- starting head `b9b606cde04056e0b3766adcf4f6007951382d1e`;
- PR open, draft, unmerged;
- latest substantive ordinary top-level comment `5945825660`;
- branch-visible Run 242 note blob `589f113fd63e7a3f87f9ffd1b3473f3f9c2d9612`;
- branch-visible Run 242 checker blob `49274f56f9665a839224fefffe1c0b402360bb16`.

The exact compiler/source files consulted were the branch versions of Run 214 and the Run 242 effective-support checkpoint. No PR-wide diff was fetched.

## 2. Exponent-visible problem after QGGM DLOG

Run 242 reduces the structured exponent channel to

`y = A r  (mod p)`,

where

- `A in F_p^(k x n)` is public once the recovered exponent-side randomness is fixed;
- `n=N+1` is the effective, non-zero-padded bounded width;
- `r in B^n`, with `B={0,...,m-1}`;
- the random branch uses uniform `y <- F_p^k`.

Run 242 already handles `rank(A)<k` efficiently by testing whether `y` belongs to `im(A)`.

The remaining branch was `rank(A)=k<=n`, where ordinary span membership accepts every `y` when `A` is surjective.

## 3. Exact bounded-free-variable algorithm

Assume `rank(A)=k`. Choose any `k` linearly independent columns of `A`; call their index set `P`. Let `F` be the remaining indices, with

`d = |F| = n-k`.

Then `A_P` is invertible. For every candidate assignment

`r_F in B^d`,

compute

`r_P = A_P^(-1) ( y - A_F r_F ) mod p`.

Accept if and only if the canonical residues of all coordinates of `r_P` lie in `B`.

This is **exact**, not heuristic:

- if the algorithm accepts, the reconstructed `r=(r_P,r_F)` is a bounded preimage of `y`;
- if a bounded preimage exists, its `r_F` appears in the enumeration and the corresponding `r_P` is uniquely forced, so the algorithm accepts.

Thus exact membership in

`A B^n`

costs

`O(m^d * poly(n,k,log p))`.

No lattice assumption, oracle, rewinding, or witness-encryption primitive is used.

## 4. Combined distinguisher for every rank

Define one post-exponent-recovery distinguisher.

### Rank-deficient case

If `q=rank(A)<k`, accept `structured` iff

`y in im(A)`.

The structured branch accepts with probability one. A uniform `y` accepts with exact probability

`p^(q-k) <= 1/p`.

### Full-row-rank case

If `rank(A)=k`, run the exact bounded-free-variable membership algorithm above.

The structured branch again accepts with probability one. A uniform `y` accepts with exact probability

`|A B^n| / p^k <= m^n / p^k`.

Therefore for every fixed public matrix `A`,

`Pr_random[accept] <= max(1/p, m^n/p^k)`

when a rank deficiency loses at least one dimension, while full-row-rank cost is controlled by the effective codimension `d=n-k`.

## 5. Complexity consequence

Hair–Sahai's compiler parameter `m` is polynomial in the circuit/input-size parameter `N`. Therefore

`m^(n-k)`

is polynomial whenever the effective codimension

`d=n-k`

is bounded by a constant.

So **positive codimension is not enough** to create a plausible computational hiding branch. A candidate asymptotic family must at minimum have growing effective codimension, unless some stronger structural attack already applies.

This is the precise sense in which the remaining question is a **growing-effective-codimension** question rather than merely an underdetermined-vs-square question.

## 6. Exact checker

`hair_sahai_qggm_bounded_free_variables_run245_check.py` is deterministic and standard-library-only.

Final validation:

- Python `3.13.5`;
- `1,729` assertions;
- `py_compile` passed;
- two executions produced byte-identical JSON.

The checker exhaustively validates:

1. a full-row-rank toy map over `F_13` with `k=2,n=4,m=3`, hence codimension two;
2. exact agreement between the bounded-free-variable algorithm and brute-force image membership for every `y in F_13^2`;
3. recovery of a bounded preimage whenever one exists;
4. no more than `m^(n-k)=9` free-coordinate iterations;
5. a rank-deficient toy map where span membership has exact uniform false-accept probability `1/13`.

For the full-rank toy, the exact bounded image has `69` points out of `169`, below the universal `m^n/p^k=81/169` upper bound.

Finite tests validate the implementation and identities only; they are not a cryptographic security proof.

## 7. QPT / assumption ledger

### Honest model
Classical polynomial-time Hair–Sahai encryption as in the branch-visible Run 242 scope.

### Attacker model in this checkpoint
The theorem after exponent recovery is classical polynomial-time. Its relevance to QGGM uses only the same prior model step as Run 242: a quantum-generic adversary can first recover the relevant exponents, then run this classical algorithm.

### Assumptions
None for the bounded-free-variable algebra after the exponent transcript is available.

### Exact conclusion
A full-row-rank exponent map with constant effective codimension is efficiently and exactly recognizable. Rank-deficient maps are already efficiently recognizable by linear span membership. Hence a constant-codimension exponent-visible family does not supply QGGM hiding.

### Not proved

- concrete-group post-quantum insecurity;
- generic DLOG outside the QGGM model;
- efficient recognition when `n-k` grows superconstant;
- a reduction of the growing-codimension branch to standard SIS/LWE/ISIS;
- arbitrary-QPT premature final-capability recovery -> ORIGINAL witness;
- full-public-output QPT hiding;
- malicious one-honest N-of-N setup/abort/erasure composition;
- a practical public common-key witness-KEM.

## 8. Handoff

Do **not** treat a fixed positive `n-k` as a surviving hardness branch.

The next core question is now one of:

1. construct a valid false-statement compiler family in which `n-k` grows asymptotically while `A` remains full row rank with overwhelming probability; or
2. find a polynomial structural/lattice distinguisher that also covers growing effective codimension.

Any proposed hardness reduction must include the actual statement-derived matrix distribution and the enormous Hair–Sahai modulus; renaming the remaining recognition problem as ISIS is not a reduction.

The practical WE-like witness-KEM stopping condition remains unmet.
