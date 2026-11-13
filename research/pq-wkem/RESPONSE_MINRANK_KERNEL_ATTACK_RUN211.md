# Run 211 — the response-MinRank bad-image event has a standard kernel attack; the r=50 example is only ~2^25.5 quantum work

**Status:** bounded falsification / parameter-security checkpoint.  This corrects the
Run-210 handoff statement that the ciphertext-derived response-MinRank event had
"no demonstrated efficient solver."  A standard MinRank kernel-search attack
applies directly.  This is not a completed witness-KEM, not a full-capsule attack,
and not a proof that every parameter family is polynomial-time quantum breakable.

## 1. Live starting point and scope

Connected GitHub reads at the start of this run verified `syscoin/PVUGC#1`:

- branch `research/pq-wkem-validation-20260918`;
- exact head `10ef85d5e34186b5c7bb8bf144804925604021ea`;
- open, draft, unmerged;
- latest ordinary substantive PR comment: `5913974235` (Run 196).

Exact-version inputs read from that head:

- `CMV_MINRANK_LACONIC_QPT_SOURCE_BRIDGE_RUN152.md`,
  blob `398b93af491d0b11cc486e86c89295a05b714804`;
- `CONDITIONAL_IMAGE_MIXING_RUN196.md`,
  blob `99a0538f9823bfd562b34570d7aa68dd079fa446`;
- `QROM_ORIGINAL_WITNESS_BRIDGE_RUN204.md`,
  blob `552f0e4b890e434a3f5c0c45a86212cfab82d742`.

The immediately preceding Run-210 result was conversation-local and is not treated
as branch evidence.  The algebra needed below is restated self-contained.

This run asks one question only:

> Once the whole projected channel exposes the public predicate
> `exists n != 0: rank([C_1 n | ... | C_d n]) <= r`, is recovering such an
> `n` really an unexplained special MinRank problem?

The answer is no.

## 2. Response-space MinRank instance

For public matrices

`C_1,...,C_d in F_2^(t x t)`

define, for each right-coordinate basis vector `e_j`, the response generator

`F_j = [ C_1 e_j | C_2 e_j | ... | C_d e_j ] in F_2^(t x d)`,
`j=1,...,t`.

For any coefficient vector `n in F_2^t`,

`M(n) = sum_j n_j F_j
      = [ C_1 n | C_2 n | ... | C_d n ]`.

The Run-210 bad-image event is exactly

`exists n != 0 such that rank(M(n)) <= r`.

So this is a homogeneous MinRank instance with:

- `K=t` public generators;
- matrix dimensions `t x d`;
- target rank `r`.

Under the uniform ciphertext branch the `F_j` are independent uniform binary
`t x d` matrices, because this construction merely reindexes independent columns
of the uniform `C_a`.

On the principal structured bad branch, a planted `n` exists.

## 3. Direct kernel-search attack

Let `n_* != 0` satisfy

`E = M(n_*)`

with actual rank

`rho = rank(E) <= r`.

Sample a nonzero vector `x in F_2^d`.  Form the public `t x t` matrix

`B_x = [ F_1 x | F_2 x | ... | F_t x ]`.

If `x in ker(E)`, then

`B_x n_* = E x = 0`.

Therefore a right-kernel vector of the low-rank residual converts immediately
into a linear-algebra problem for the MinRank coefficient vector.

For nonzero `x`, the exact probability of landing in the nonzero right kernel is

`p_ker(rho)
 = (2^(d-rho)-1)/(2^d-1)`.

For the planted random-instance distribution, condition on such an `x`.
After choosing any pivot where `n_*` is one, the other `t-1` public response
columns `F_j x` are independent uniform vectors in `F_2^t`.  Hence they are
linearly independent with exact probability

`p_ind(t)
 = product_(i=0)^(t-2) (1 - 2^(i-t))`.

On that event `rank(B_x)=t-1`, its nullspace is one-dimensional, and the unique
nonzero null vector is exactly `n_*`.

Thus a purely classical attack is:

1. sample nonzero `x`;
2. build `B_x`;
3. if `rank(B_x)=t-1`, recover its unique nonzero null vector `n_x`;
4. verify `rank(M(n_x)) <= r`;
5. stop if verification succeeds.

A planted sample is clean-marked with probability at least

`p_clean = p_ker(rho) * p_ind(t)`,

so the expected number of trials is at most

`1/p_clean`.

No Gröbner basis, support-minors system, or nonlinear source-specific attack is
needed for this basic search.

### Relation to the standard Kernel Attack literature

This is the ordinary MinRank Kernel Attack in the present homogeneous notation.
For an affine MinRank instance, normalize one nonzero coefficient and regard the
remaining `t-1` coefficients as the unknown secret.  One guessed kernel vector
gives `t` linear equations in `t-1` unknowns.

Recent MinRank literature states the rectangular kernel-search complexity as

`O(q^(r ceil(k/m)) * poly)`

for `m` matrix rows and `k` unknown coefficients.  Here `q=2`, `m=t`, and after
normalization `k=t-1`, so `ceil(k/m)=1` and the exponential part is `2^r`.

Relevant records checked this run:

- Chatterjee--Mu--Vasudevan, *Public-Key Encryption from the MinRank
  Problem*, arXiv 2510.03752 / ePrint 2025/1833, Section 5.1.2 and Section
  5.2.1.  Their square-instance Kernel Attack has the same `2^(r ceil(k/n))`
  exponent, and they explicitly describe a Grover-based quantum square-root
  speedup.
- *Sneaking up the ranks: Partial key exposure attacks on rank-based schemes*,
  Designs, Codes and Cryptography (2026), which states the rectangular
  Kernel-Search bound `O(q^(r ceil(k/m)) k^w)`.
- Cabarcas--Gaggero--Gorla, *The complexity of the SupportMinors Modeling for
  the MinRank Problem* (2026), for the current generic MinRank modeling
  landscape.  Nothing in this run needs SupportMinors to obtain the attack.

## 4. Quantum square-root search is a direct QPT circuit transformation

The predicate on a candidate `x` is entirely public and polynomial-time:

- compute all `F_j x`;
- Gaussian-eliminate `B_x`;
- if its nullity is one, recover the unique `n_x`;
- compute and rank-test `M(n_x)`.

All operations are Boolean linear algebra and can be implemented reversibly with
polynomial overhead.  Quantum amplitude amplification over nonzero `x` therefore
finds a clean marked `x` in

`O(1/sqrt(p_clean))`

iterations.

For a parameter family this is a **polynomial-time QPT break only if the target
rank is small enough**, e.g. `r=O(log lambda)` (up to the other dimensions and
the exact rank `rho`).  If `r=Theta(lambda)` it remains exponential and is only a
concrete work-factor bound.

The important correction is therefore not "MinRank is polynomial-time quantum
solvable."  It is:

> the response-space event is not an unexplained hidden solver problem; it already
> inherits the standard Kernel Attack, including its Grover square-root speedup.

## 5. Concrete correction to the Run-210 example

For the representative parameters

`t=128`,
`r=50`,
`d=53`,
`s=3`,

and a principal planted residual of actual rank `rho=50`,

`p_ker
 = (2^3-1)/(2^53-1)`,

and

`p_ind(128)
 = product_(i=0)^126 (1-2^(i-128))
 ~= 0.5775761901732049`.

Therefore

`-log2(p_clean) ~= 50.984561902604426`.

So:

- classical expected clean trials: about `2^50.985`;
- quantum amplitude-amplification iterations: about `2^25.492`.

The previously computed uniform false-positive bound for the response-MinRank
event is

`u <= 2^-104.39231742277876`.

The principal structured bad-branch probability is approximately

`2^-22.000000171982656`.

Consequently a bounded quantum kernel search with constant conditional success
on the principal bad branch yields an **overall distinguishing advantage of order
`2^-22`** at roughly `2^25.5` quantum-search iterations, while the uniform branch
has a negligible response-MinRank false-positive probability at these concrete
numbers.

This is far below a 128-bit post-quantum work target.

It does **not** mean the attacker recovers a witness on every ciphertext.  Most
structured ciphertext samples are on the full-rank-`Y` branch and are exactly
uniform in this projected channel.  The attack detects the rare bad-image branch;
that rare branch is nevertheless too frequent for a `2^-128` hiding target.

## 6. Immediate parameter condition

The Kernel Attack alone gives the concrete quantum exponent approximately

`rho/2 <= r/2`

(up to constant and polynomial factors).

Therefore a parameter set that intends to rely on computational hardness of the
response-MinRank bad branch for `lambda` bits of Grover-style work must at least
have

`r >= 2 lambda`.

For `lambda=128`, this means

`r >= 256`

before considering faster algebraic attacks, hybrid attacks, memory costs, or
the rare-branch advantage.

Because honest decoding requires a visible rank gap below a uniform `t x t`
matrix, one also needs `t>r`.  The simple coarse uniform-rank-error heuristic
`2^(-(t-r)^2)` suggests that a gap of about 12 already exceeds 128 bits, giving
the purely illustrative pair

`r=256`, `t=268`.

This is **not** a recommended final parameter set.  It is only the minimum
constraint imposed by this one attack.

There is another legitimate route: make the bad-image probability itself
negligible at the target level by increasing the statistical margin
`rs-t`.  If that is already at least the desired security margin, the rare branch
does not need computational MinRank hardness at all.

## 7. Principal bad branch is also a standard planted-MinRank distribution

There is a useful distributional interpretation.

Write the hidden-factor channel as

`C_a = X_a Y^T + Z W_a^T`.

On the principal bad event

`rank(Y)=t-1`
and
`rank(Z)=r`,

let

`N=ker(Y^T)=span(n_*)`
and
`U=im(Z)`.

Conditioned on `N` and `U`, each `C_a` is independently uniform over

`S_(N,U) = { C : C n_* in U }`.

Equivalently, after reindexing to the response generators `F_j`, the tuple is
sampled by:

1. choose uniform nonzero `n_*`;
2. choose uniform `r`-subspace `U` of `F_2^t`;
3. choose a residual `E` whose `d` columns are independent uniform vectors of
   `U`;
4. choose `t-1` response generators uniformly;
5. set the remaining generator so that
   `sum_j (n_*)_j F_j = E`.

That is a natural planted **rectangular** MinRank distribution.

For `d<=t`, it is also statistically close to a simple public projection of the
square planted distribution used by Chatterjee--Mu--Vasudevan:

- symmetrize their `t-1` random generators plus target matrix by a uniform
  `GL(t,2)` basis change, which makes the homogeneous planted coefficient
  uniform over all nonzero vectors;
- keep only the first `d` columns.

Conditioned on the CMV residual having rank exactly `r`, its first `d` columns
are obtained from a uniform full-row-rank `r x t` factor restricted to `d`
columns.  Replacing that conditioned factor by an unrestricted uniform
`r x t` factor changes the full joint distribution by exactly the probability
that a uniform `r x t` matrix is not full row rank; taking a marginal cannot
increase total variation.

Thus the projection error is at most

`Pr[rank(G)<r for G <- F_2^(r x t)]`
plus
`Pr_CMV[rank(E)<r | rank(E)<=r]`.

For `t=128,r=50` these two terms are about

`2^-78`
and
`2^-157`

respectively.

This is useful evidence that the principal response-MinRank branch is not a
novel highly structured MinRank distribution.  But it **does not close QPT
security**: CMV's formal hardness conjecture is stated for non-uniform
probabilistic polynomial-time distinguishers, not arbitrary QPT distinguishers.
The paper says no quantum attack with a significant asymptotic speedup is known
beyond the analyzed Grover-style improvements; that is cryptanalytic evidence,
not a quantum hardness reduction.

## 8. Exact checker and finite validation

`response_minrank_kernel_attack_run211_check.py` is standard-library Python and
uses no network.

It checks:

- `4,096` exhaustive tiny planted free-generator choices;
- the exact independence probability `21/32` for two random vectors in
  `F_2^3`, obtaining exactly `2,688/4,096` clean instances;
- every clean instance recovers the planted homogeneous coefficient as the
  unique null vector;
- 32 deterministic planted MinRank fixtures at larger toy dimensions;
- exact binary matrix-rank counts through `4 x 4`;
- the exact nonzero-kernel sampling probability;
- the representative `t=128,r=50,d=53,s=3` work factors and false-positive
  exponent;
- finite CMV rank-stratum/projection controls.

Final execution:

- Python `3.13.5`;
- `2,978` assertions;
- syntax check passed;
- two executions produced byte-identical JSON.

The checker validates the finite algebra and probability accounting.  It does
not validate a physical fault-tolerant quantum implementation, estimate gate
counts, or prove any MinRank hardness theorem.

## 9. QPT / construction ledger

### Unconditional
- response event is a standard homogeneous MinRank instance;
- classical kernel-search reduction above;
- exact clean-sample probability;
- reversible predicate exists with polynomial overhead;
- amplitude amplification gives square-root query complexity;
- representative `r=50` exponent is about `2^25.5` quantum iterations.

### Literature theorem / known attack
- current MinRank literature already contains the Kernel Attack and a Grover
  square-root speedup;
- generic SupportMinors/Kipnis--Shamir attacks remain additional obligations.

### Still unproved
- full false-statement capsule hiding outside this response projection;
- arbitrary-QPT hardness of the CMV average-case MinRank distribution;
- true-instance arbitrary-QPT final-capability recovery -> ORIGINAL witness for
  the complete construction;
- malicious one-honest N-of-N setup/abort/erasure composition;
- retained-state keyless-builder security.

The practical WKEM stopping condition is **not met**.

## 10. Handoff

Do not spend another run merely asking whether the response-MinRank witness `n`
is algorithmically searchable.  It is, via the standard Kernel Attack.

The next useful choice is one of:

1. **parameter repair:** recompute the complete construction with `r` large
   enough that the classical/quantum Kernel Attack and the statistical
   bad-image margin both meet the intended security level, then check the
   resulting bandwidth and correctness costs; or
2. **construction-side extraction:** if false hiding is made statistical by
   parameters, return to the still-missing arbitrary-QPT ORIGINAL-witness
   extraction and malicious one-honest setup composition rather than relying
   on MinRank hardness.

A separate pass may also price SupportMinors / XL / hybrid attacks on any repaired
parameter row.  The Kernel Attack is only the first necessary filter.
