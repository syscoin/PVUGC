# Run 242 — effective-column collapse and a polynomial QGGM span distinguisher for Hair–Sahai

## Status

Bounded cryptographic research checkpoint. This is **not** a completed practical witness-KEM and it does not contradict Hair–Sahai's stated theorem: their theorem is explicitly for **classical** generic-group adversaries. The result below studies the natural quantum-generic lift, where generic discrete logarithms are available through Shor-type algorithms.

The checkpoint sharpens Run 241 in two ways:

1. the structured exponent transcript depends on only `N+1` bounded coordinates of `r`, not all `m` coordinates;
2. after quantum-generic discrete logarithms there is a simple polynomial-time linear-subspace distinguisher whenever the public matrix-space dimension `k` exceeds `N+1`, and more generally whenever the induced map is rank-deficient with noticeable probability.

This removes the need to invoke any bounded-preimage hardness assumption in those branches.

## 1. Exact paper facts used

Hair–Sahai, arXiv:2609.18275v1, Sections 3.1 and 4.4–4.7, define

- `R=floor(log_2 N)`;
- `m=(N+1)(2NR+1) binom(2R,R)`;
- a basis `M_1,...,M_k` of `S <= F_p^(m x m)` with `k<=m^2`;
- a prime `p in [2^m,2^(m+1))`;
- `s <- F_p^m`, `r <- {0,...,m-1}^m`, `eta <- F_p^k`;
- structured exponents `y_j=s^T M_j r` and random exponents `eta_j`.

Most importantly for this run, Section 4.4 states that the constructed matrices initially have `N+1` columns and are made square by appending exactly `m-(N+1)` **zero columns**. Thus every output-basis matrix has the block form

`M_j = [ Mtilde_j | 0 ]`,

where `Mtilde_j` has `N+1` columns.

The cited paper proves classical generic-group security only. Hhan–Yamakawa–Yun's quantum generic-group model contains Shor discrete logarithm with `O(log |G|)` generic group operations, so in that stronger model the transmitted handles can be converted to their exponents in QPT.

## 2. Effective bounded dimension is `N+1`, not `m`

Write

`r = (r_eff, r_tail)`

with `r_eff in {0,...,m-1}^{N+1}`. Because all appended columns are zero,

`M_j r = Mtilde_j r_eff`

for every `j`. Therefore, after recovering the exponents of the `X_i` and `Y_j`, the structured branch is exactly

`P0:  s <- F_p^m,   y = A_s r_eff`,

where `A_s in F_p^(k x (N+1))` has row `j`

`(A_s)_{j,*} = s^T Mtilde_j`,

while the random branch is

`P1:  s <- F_p^m,   y <- F_p^k`.

The last `m-(N+1)` coordinates of the encryption sampler `r` are cryptographically irrelevant to the public exponent transcript.

This corrects Run 241's coarse support count `m^m`: the exact universal bound is

`|supp(P0[y | s])| <= m^(N+1)`.

## 3. Stronger statistical separation after exponent recovery

For every fixed `s`, the structured conditional support has at most `m^(N+1)` points, whereas the random branch is uniform on `p^k` points. Therefore

`TV(P0[y|s], U(F_p^k)) >= 1 - m^(N+1)/p^k`.

Since the `s` marginal is identical and visible after discrete logarithms,

`boxed( TV(P0,P1) >= 1 - m^(N+1)/p^k ).`

Using `p>=2^m`,

`m^(N+1)/p^k <= 2^((N+1)log_2 m - km)`.

This is already exponentially small for the weakest nontrivial case `k=1`. From the paper's exact formula,

`m = Theta(N^4 log N)`

at `R=floor(log_2 N)`, while `(N+1)log m = O(N log N)`. Hence

`(N+1)log_2 m - m = -Omega(m)`.

Thus the exponent-visible structured and random branches are asymptotically almost disjoint in total variation even when `k=1`.

This is **information-theoretic separation after DLOG**, not yet an efficient distinguisher in every parameter branch. Efficiently recognizing the bounded image can remain nontrivial when the linear image is all of `F_p^k`.

## 4. Polynomial-time span-membership distinguisher

There is, however, an immediate efficient test that Run 241 did not isolate.

Given recovered `(s,y)`:

1. compute the public matrix `A_s`;
2. use Gaussian elimination to test whether `y in im(A_s)`;
3. output `structured` iff the test passes.

For every structured sample the test passes with probability one. For a random-branch sample, conditioned on `s`,

`Pr[y in im(A_s) | s] = p^(rank(A_s)-k)`.

Therefore its exact distinguishing advantage is

`boxed( Adv_span = 1 - E_s[p^(rank(A_s)-k)] ).`

This algorithm is polynomial in the public dimensions and `log p` once the generic DLOG values are available.

### Universal overdetermined corollary

Because `A_s` has only `N+1` columns,

`rank(A_s) <= N+1`.

Hence if

`k > N+1`,

then for **every** `s`,

`Pr_P1[accept | s] <= p^(-(k-N-1))`,

and

`boxed( Adv_span >= 1 - p^(-(k-N-1)) ).`

In particular `k=N+2` already gives advantage at least `1-1/p`, which is overwhelming at the paper's `p>=2^m` scale.

More generally, for any integer `c>=1`, if

`Pr_s[rank(A_s) <= k-c] >= eps`,

then

`Adv_span >= eps(1-p^(-c))`.

So a necessary condition for even *candidate* QGGM hiding is:

- `k <= N+1`; and
- `A_s` is full row rank `k` for all but negligible probability over `s`.

Only after those two conditions hold does the bounded-box recognition problem from Run 241 remain as the next obstruction.

## 5. Relation to ISIS/SIS terminology

When `A_s` is surjective, distinguishing the sparse structured support from uniform asks whether a random target lies in

`A_s {0,...,m-1}^{N+1}`.

This resembles an inhomogeneous short-integer-solution / bounded modular-preimage problem, but the present distribution is **not** a standard random ISIS instance:

- `A_s` is statement-derived and correlated with one random `s` through the public matrices `M_j`;
- the modulus is enormous, `p ~= 2^m`;
- the box bound is `m-1`;
- public matrix-space correlations are part of the instance;
- security requires the ORIGINAL-witness implication, not merely hardness of finding one short preimage.

No standard lattice theorem found in this bounded pass justifies replacing the missing QPT release theorem with “ISIS hardness.” Doing so would only rename the gap.

## 6. Exact validation

`hair_sahai_qggm_effective_support_run242_check.py` is deterministic and standard-library-only.

The finalized checker passed `py_compile` and two byte-identical executions. It performs 632 assertions and verifies on two exact finite fixtures:

- zero-padded tail coordinates never affect the structured exponent;
- every structured conditional support has size at most `m_total^n_eff`;
- joint exponent-space TV obeys `TV >= 1-m_total^n_eff/p^k`;
- the span-membership distinguisher has exact advantage `1-E[p^(rank-k)]`;
- the universal `k>n_eff` lower bound;
- the Hair–Sahai parameter formula has negative support exponent already for `k=1` for every `N=2,...,64` tested.

For the overdetermined fixture `(p,m_total,n_eff,k)=(7,4,2,3)`, the exact results are:

- rank histogram of `A_s`: `{0:1, 1:132, 2:2268}`;
- joint TV: `112374/117649`;
- support-only lower bound: `327/343`;
- span-test advantage: `711486/823543`.

For a square fixture `(7,4,2,2)`, the span test is weaker but the sparse-support separation persists:

- joint TV: `1776/2401`;
- support-only lower bound: `33/49`;
- span-test advantage: `552/2401`.

This second fixture is included specifically to prevent overclaiming: full-row-rank branches can evade the linear-span test even though the bounded image remains statistically sparse.

An initial development checker with a larger square fixture exceeded the local execution limit and failed with the exact message `Command failed because it timed out.` No service error code, request ID, or correlation ID was supplied. That incomplete run is not counted. The finalized checker was reduced without weakening the theorem and completed twice identically.

## 7. QPT / assumption ledger

### Honest model
Hair–Sahai encryption remains classical PPT in their stated classical generic-group model.

### Attacker model in this run
Quantum generic-group adversary with coherent generic group operations sufficient for Shor discrete logarithm, followed by classical polynomial-time linear algebra.

### Assumptions
The algebra after exponent recovery is unconditional. The only model step is the standard QGGM fact that generic DLOG is QPT.

### Exact conclusion
The direct Hair–Sahai ciphertext distribution is **not information-theoretically close** after exponent recovery; its structured exponent branch has effective bounded dimension `N+1`.

Moreover, whenever `k>N+1`, or whenever `A_s` is rank-deficient with noticeable probability, a polynomial-time post-DLOG span-membership distinguisher breaks message hiding with the exact advantage above.

### Not proved

- that every false Hair–Sahai instance produced by the compiler has `k>N+1`;
- that `A_s` is rank deficient with noticeable probability when `k<=N+1`;
- a polynomial-time bounded-image attack in the surviving full-row-rank branch;
- any standard-LWE/SIS reduction for that branch;
- arbitrary-QPT early final-capability recovery -> ORIGINAL witness for a complete public WKEM;
- full-public-output QPT hiding, malicious one-honest setup composition, or practical parameters.

## 8. Precise handoff

The post-Run-241 question is now split cleanly.

1. **Overdetermined/rank-deficient branch:** closed by the polynomial span test above. No bounded-preimage assumption is needed.
2. **Full-row-rank branch (`k<=N+1`, `rank(A_s)=k` overwhelmingly):** the linear test gives no information, while the structured box image is still exponentially sparse. This is the only branch in which bounded-image recognition remains a genuine computational question.

The highest-value next bounded pass is therefore source-specific: compute or prove the distribution of `rank(A_s)` for the actual Hair–Sahai compiler on a false-statement family. If rank deficiency is unavoidable, the natural QGGM lift is efficiently broken. If full row rank dominates, then and only then should the project investigate whether the resulting statement-derived bounded modular-preimage problem has an independently justified QPT hardness reduction.

This checkpoint does not complete the practical WE-like witness-KEM.
