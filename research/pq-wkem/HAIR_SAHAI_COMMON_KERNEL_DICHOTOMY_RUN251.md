# Run 251 — common-kernel successive-minimum dichotomy narrows the surviving QGGM branch

## Status

Bounded source/QGGM checkpoint. This run does **not** construct the required practical PQ witness-KEM and does **not** claim a concrete-group post-quantum break of Hair–Sahai. It sharpens Runs 246–250 by correcting an over-broad handoff: a common effective right kernel with a very large or `p`-scale orientation is not automatically an escape from the exponent-channel LLL distinguisher. If its shortest integer lift is larger than the embedding radius, it is actually harmless to the Run-246 short-vector argument.

The new result gives two attackable extremes and isolates only a mixed successive-minimum regime:

1. **high-minimum kernel:** `lambda_1(Lambda_K) > L` — direct Run-246 attack still works;
2. **fully short kernel:** `lambda_r(Lambda_K) <= L`, where `r=dim K` — polynomial-time LLL finds a short basis of the whole common kernel, Run 248 quotients it, and the reduced Run-246 attack works;
3. therefore a **one-dimensional** common kernel is never a surviving QGGM exponent-channel escape;
4. the only unresolved common-kernel geometry is `r>=2` with
   `lambda_1(Lambda_K) <= L < lambda_r(Lambda_K)`.

This is a model-side falsification result after exponent recovery. It does not replace the missing practical public witness-restricted encoding or its QPT reduction.

## 1. Verified live starting point

Connected GitHub reads before research verified `syscoin/PVUGC#1`:

- branch `research/pq-wkem-validation-20260918`;
- starting head `9e4b29592db7d3b52bfebc66ef08c1442bc8b7bb`;
- PR open, draft, unmerged;
- latest substantive ordinary top-level comment `5945825660`;
- the branch is one commit ahead of Run 245 and now contains Run 250;
- exact Run-250 note blob `fccb8a6a41c5f77a6467668637b96ef00b0ef39d`;
- exact Run-250 checker blob `e8b94dae1cde20da4678e460682bd8d534393229`;
- exact Run-250 validation blob `35d2bcf1aa90cd2e9fe4a9e1d78e68d44a3c10dd`;
- exact Run-250 provenance blob `0a6d989dead7fcdd357d26475b5200a38b656de2`;
- exact Run-214 note/checker blobs `6a67013fda501295e631d5bb17bb7d50c4bd8be5` and `b38c7eea6c6a2cb387b5dcb1b97ac018c0b03f32`.

No PR-wide diff was fetched.

## 2. External facts used

Hair–Sahai arXiv:2609.18275v1 is still the current version checked in this run. The paper proves witness encryption only in the **classical prime-order generic-group model**. Its compiler has `n=N+1` substantive columns before zero-padding, matrix order

`M=(N+1)(2NR+1) C(2R,R)`, `R=floor(log2 N)`,

and encryption samples the bounded right vector from `{0,...,M-1}^M` after padding. Section 4.6 gives a polynomial-time exact-span algorithm but does not itself give the post-quantum claim studied here.

For the lattice step we use the standard `delta=3/4` LLL successive-minimum guarantee: for an `n`-dimensional lattice with successive minima `lambda_i`, an LLL-reduced basis may be indexed so that

`||b_i|| <= gamma_n lambda_i`, `gamma_n = 2^((n-1)/2)`.

Only this worst-case polynomial-time approximation guarantee is used; no exact-SVP or BKZ assumption is introduced.

## 3. Common-kernel lattice

Let the effective public source basis be

`M_1,...,M_k in F_p^(a x n)`

and define its common effective right kernel

`K = intersection_j ker(M_j) <= F_p^n`, `r=dim K`.

Define the full-rank integer lattice of modular lifts

`Lambda_K = { z in Z^n : z mod p in K }`.

Let `lambda_i(Lambda_K)` be its Euclidean successive minima.

After the same QGGM exponent-recovery thought experiment as Runs 242–250, the structured branch is

`y=A_s x`,

where row `j` of `A_s` is `s^T M_j` and the honest bounded vector has coordinates in `{0,...,M-1}` before any quotient.

Take the safe embedding scale

`T=nM`,
`gamma_n=2^((n-1)/2)`,
`L=3 gamma_n T`.

The exact constants are inessential; what matters is

`log2 L = n/2 + O(log M) = O(N)`

while the Hair–Sahai prime obeys `log2 p >= M = Omega(N^3 log N)`.

## 4. High-minimum theorem: stack-injectivity is stronger than necessary

Run 246 assumed the stacked source had trivial common right kernel. That can be weakened substantially.

Fix a nonzero integer vector `z` with `||z||<=L`. If its reduction is **not** in `K`, then some `M_j z` is nonzero modulo `p`. Uniform `s` therefore satisfies

`A_s z = 0`

with probability at most `1/p`: at least one nonzero linear condition on `s` must hold.

Therefore, if

`boxed(lambda_1(Lambda_K) > L)`,

no nonzero integer vector in the entire embedding ball reduces into the common kernel. The Run-246 union bound applies verbatim:

`Pr_s[exists 0!=z, ||z||<=L, A_s z=0]
 <= ((2 floor(L)+1)^n - 1)/p.`

On the complement of this event the same LLL embedding recovers the bounded structured preimage. The common kernel can be nontrivial; it simply does not intersect the only integer region relevant to the attack.

**Consequence:** a genuinely `p`-scale or otherwise long common-kernel orientation is not a hiding mechanism here. Large shortest lift helps the attack rather than obstructing it.

## 5. Fully-short theorem: LLL finds a quotient basis

Now suppose instead that the common kernel has dimension `r>0` and

`boxed(lambda_r(Lambda_K) <= L)`.

Run ordinary polynomial-time LLL on `Lambda_K`. The first `r` reduced vectors satisfy

`||b_i|| <= gamma_n L`, `1<=i<=r`.

They are integer-independent. We also need their reductions modulo `p` to remain independent. Suppose not. Then every `r x r` coordinate minor of the integer matrix `U=[b_1 ... b_r]` would be divisible by `p`. Since the vectors are independent over the integers, some such minor is nonzero; Hadamard gives

`0 < |Delta| <= product_i ||b_i|| <= (gamma_n L)^r`.

Hence whenever

`(gamma_n L)^r < p`,

that nonzero minor cannot be divisible by `p`. Therefore the reductions of the LLL vectors are independent in `F_p^n`. Since there are `r=dim K` of them and every one lies in `Lambda_K`, they form a public integer lift basis of the **entire** common kernel.

For Hair–Sahai parameters the inequality is extremely loose in our favor. Here

`gamma_n L = 3 * 2^(n-1) * nM`,

so for every `r<=n-1`,

`log2((gamma_n L)^r) = O(N^2) << M <= log2 p`.

Thus LLL supplies exactly the kind of full short kernel basis Run 248 needs.

## 6. Quotient size remains far below the prime

Let `C=gamma_n L` bound the coordinates of those `r` integer kernel vectors. Run 248's adjugate quotient gives a reduced vector `q` of dimension `d=n-r` with symmetric coordinate bound

`B <= (M-1)(r+1) r! C^r`.

Since `log2 C=O(N+log M)`,

`log2 B = O(N^2)`.

The quotient source has trivial common right kernel. Applying the Run-246 embedding there gives a new radius

`L' = 3 * 2^((d-1)/2) * d * B`.

The two error-count exponents are therefore

`d log2(2L'+1)=O(N^3)`,
`d log2(2B+1)=O(N^3)`,

while `log2 p >= M = Omega(N^3 log N)`. Thus both the short-homogeneous-kernel union term and the relaxed-box support term are negligible at the paper scale.

The checker evaluates conservative finite margins for `N=4,5,8,16,32,64`. Even at `N=5` (`M=756`) the worst full-short quotient margins exceed 529 bits for the short-vector union and 541 bits for the relaxed box support.

## 7. One-dimensional common kernels are completely covered

If `r=1`, exactly one of the following holds:

- `lambda_1 > L`: the direct high-minimum theorem applies;
- `lambda_1 <= L`: this is also `lambda_r <= L`, so the full-short quotient theorem applies.

Therefore

`boxed(dim K = 1 is not a surviving QGGM exponent-channel escape.)`

This subsumes both kinds of one-dimensional examples discussed in the previous handoffs: tiny integral generators are quotientable, while long modular orientations are directly attackable.

## 8. The genuine remaining common-kernel geometry

For `r>=2`, the two theorems leave only a mixed successive-minimum spectrum:

`boxed(lambda_1(Lambda_K) <= L < lambda_r(Lambda_K).)`

That means some common-kernel directions enter the LLL embedding ball but the whole common kernel does not have a basis inside that ball. This is more precise than the Run-250 statement that “rational kernel height” is the remaining blocker.

A large rational/integer presentation by itself is not the issue. What matters is the **successive-minimum profile of the modular lift lattice relative to the embedding radius**.

The unresolved task is to handle that mixed spectrum in polynomial time without sequential quotient blow-up. A naive one-direction-at-a-time quotient can square the effective box bound repeatedly and is therefore not yet a valid universal reduction.

## 9. Exact deterministic checks

`hair_sahai_common_kernel_dichotomy_run251_check.py` is standard-library Python.

Final validation:

- syntax check passed;
- two executions produced byte-identical JSON;
- 48,881 assertions per finalized execution.

The checker contains two explicit kernel fixtures.

### High-minimum fixture

Over `F_1009`, take

`K=span((33,1,0))`

and source matrix rows

`(1,-33,0)`, `(0,0,1)`.

Its common right kernel is exactly `K`. Exhausting the integer cube `[-50,50]^3` finds the exact shortest modular-kernel lift squared norm

`lambda_1^2=1090`,

attained by `(-33,-1,0)` up to sign. For the toy embedding radius `L=18`, all 24,404 nonzero integer vectors in the Euclidean ball are verified outside `K` and exposed by the source.

### Fully-short non-coordinate fixture

Over `F_1009`, use the two-dimensional kernel generated by

`(1,1,0)`, `(0,1,1)`.

The checker constructs the exact integer adjugate quotient, verifies `QU=0` over `Z`, verifies the quotient kernel dimension modulo `p`, and exhaustively checks the Run-248 bounded-box inequality on `{0,1,2}^3`.

One exploratory development execution failed with

`AssertionError: unexpected short common-kernel vector`

because the first toy embedding scale was deliberately over-large (`L=36`) and crossed the fixture's actual shortest kernel vector. The finalized checker corrected the toy scale to `L=18`; both final executions pass identically. No external service/error/request ID is associated with that local development failure.

## 10. Security/QPT ledger

### Honest model

Classical Hair–Sahai compiler/encryption as published. The result concerns only the exponent-visible QGGM thought experiment used in the preceding runs.

### Attacker model

Polynomial-time classical lattice postprocessing after quantum-generic exponent recovery. This is **not** a concrete-group QPT attacker theorem.

### Assumptions

- standard deterministic LLL polynomial-time reduction and its worst-case successive-minimum approximation factor;
- elementary Hadamard determinant bound;
- the Hair–Sahai public parameter inequalities.

No SIS/LWE/ISIS assumption is invoked.

### Exact conclusion

A common right kernel is harmless to the Run-246 exponent-channel attack if it has no nonzero lift in the embedding ball. If the whole common kernel has a short successive-minimum basis in that ball, LLL finds a sufficiently short full lift basis and Run 248 removes it. One-dimensional common kernels are therefore completely covered.

### Still unproved

- the mixed regime `lambda_1<=L<lambda_r` for `r>=2`;
- a universal QGGM attack on every compiler output;
- concrete-group post-quantum insecurity or security of Hair–Sahai;
- a practical false-statement QPT-hiding replacement encoding;
- arbitrary-QPT early final-capability recovery -> ORIGINAL witness or an independent PQ break;
- malicious one-honest N-of-N setup/abort/erasure composition;
- practical all-witness-same-key public witness-restricted release;
- the requested end-to-end PQ witness-KEM.

The practical stopping condition remains unmet.

## 11. Handoff

The next bounded pass should target the **mixed successive-minimum regime**, not generic rational-height bookkeeping:

1. derive a polynomial-time simultaneous quotient that removes all common-kernel directions below a controlled threshold without repeated box-bound squaring; or
2. construct an actual Hair–Sahai false-source family whose common-kernel lift lattice provably has a mixed spectrum and show that this blocks both direct and full-short reductions.

Do not treat a `p`-scale kernel orientation by itself as an escape; this run shows the opposite.
