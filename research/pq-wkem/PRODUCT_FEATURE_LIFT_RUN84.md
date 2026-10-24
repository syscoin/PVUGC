# Run 84 — product-feature Vandermonde lift: inherited source extraction and a generic sparse-false gap

**Status:** constructive algebraic source transformation that escapes the scalar-weight recombination barrier of Run 83 and eliminates all false coefficient representations of support at most `m`. It preserves honest rank one and the existing Hair–Sahai supplied-low-rank ORIGINAL-source extractor. It does **not** prove complete-output PPT/QPT hiding, arbitrary-QPT key-recovery extraction, or practical parameters. The full PQ WKEM remains unresolved.

**Starting verified PR head:** `adcf3b578848c454c99191bc073f6ed430f4da42`.

No production path is changed.

## 1. Motivation after Runs 82–83

Run 82 constructed an exponentially large family of efficiently constructible false-source matrices using coefficient vectors supported on only `2^(R+1)` assignments. Run 83 showed that appending `L` scalar weight checks does not fundamentally cure the problem: linear recombination leaves low-rank survivors.

The next repair therefore has to **couple the added feature to the matrix factorization itself**, not merely append more scalar source equations.

This run gives such a coupled lift.

## 2. Base Hair–Sahai interface used

For a Boolean assignment `b`, let the base weighted-table assignment matrix be

    A(b) = u(b) v(b)^T,                                  (1)

where `v(b)=(1,b_1,...,b_N)` and `u(b)` stacks the listed weighted copies `h(b)v(b)`.

For source equations `f_e(b)=0`, the base source coefficients `lambda_b` obey

    sum_b lambda_b h(b) f_e(b) = 0                       (2)

for every listed base weight `h` and every equation `e`.

The properties imported from Hair–Sahai are purely algebraic:

* valid assignments give nonzero rank-one matrices;
* on a false statement, every nonzero base source matrix has rank `>R`;
* from a supplied nonzero base source matrix of rank `<=R`, the existing extractor returns an ORIGINAL satisfying assignment;
* the assignment span is computable without enumerating assignments because bit-setting acts by explicit linear maps, followed by Gaussian elimination and a homogeneous linear intersection with the source constraints.

The paper's **classical generic-group encryption security is not imported**.

Primary source inspected: Hair–Sahai, arXiv:2609.18275v1, especially Theorem 3.1 and Sections 4.3–4.6. The paper itself uses `p>2^N`; that same large-field regime is convenient here.

## 3. Injective assignment label and feature vector

Work over a prime field `F_p` with

    p > 2^N.                                              (3)

Define the binary-integer label

    theta(b) = sum_{i=1}^N 2^(i-1) b_i in F_p.           (4)

Since `0 <= theta(b) < 2^N < p`, this is injective on the Boolean cube.

For a public feature parameter `m`, define

    q(b) = (1, theta(b), theta(b)^2, ..., theta(b)^(m-1)). (5)

## 4. Product-feature assignment matrix

Replace the Boolean right factor by a coupled feature factor:

    A~_m(b)
      = u(b) ( q(b) tensor v(b) )^T.                     (6)

Equivalently, horizontally partition the matrix into `m` blocks:

    A~_m(b)
      = [ q_0(b) A(b) | q_1(b) A(b) | ... | q_{m-1}(b) A(b) ].  (7)

Every honest assignment remains **rank one**.

The first block is exactly the old assignment matrix because `q_0=1`.

## 5. Augmented source constraints

For every old weight `h`, source equation `f_e`, and feature index `j`, impose

    sum_b lambda_b h(b) q_j(b) f_e(b) = 0.              (8)

Let `S~_m` be the span of matrices (6) with coefficient vectors satisfying (8).

The key observation is blockwise:

    M_j(lambda) = sum_b lambda_b q_j(b) A(b).            (9)

Define

    mu_b^(j) = lambda_b q_j(b).                           (10)

Equation (8) says exactly that `mu^(j)` satisfies **all old Hair–Sahai source constraints**. Thus every block `M_j(lambda)` is itself a legitimate matrix in the original source space.

This is the mechanism that avoids the kernel/resurrection problem that would arise from simply appending arbitrary new columns.

## 6. Theorem 1 — low-rank ORIGINAL-source extraction is inherited exactly

Suppose

    0 != M~ = [M_0 | ... | M_{m-1}] in S~_m

has

    rank(M~) <= R.                                       (11)

Because `M~` is nonzero, some block `M_j` is nonzero. Any column submatrix has rank at most the rank of the whole matrix, so

    1 <= rank(M_j) <= R.                                 (12)

By Section 5, `M_j` is an ordinary base source matrix. Apply the existing Hair–Sahai supplied-low-rank extractor to `M_j`.

Therefore

    boxed{
      nonzero M~ in S~_m with rank <= R
      => ORIGINAL satisfying assignment.
    }                                                    (13)

This covers the case where the original `q_0=1` block happens to cancel to zero: the extractor simply uses any other nonzero feature block.

Consequently, on a false statement,

    every nonzero M~ in S~_m has rank > R.               (14)

This theorem is algebraic and model-independent. It is not a hiding theorem.

## 7. Theorem 2 — generic false coefficient-support distance > m

Assume the statement is false: for every Boolean assignment `b`, at least one source equation `f_e(b)` is nonzero.

Let `lambda` satisfy the augmented constraints (8), and suppose its support

    T = { b : lambda_b != 0 }

has size

    1 <= s <= m.                                         (15)

The base weight list contains the constant weight `h=1`. For every equation `e`, constraints (8) for `j=0,...,s-1` give

    sum_{b in T} lambda_b f_e(b) theta(b)^j = 0.         (16)

The `s x s` Vandermonde matrix on the distinct labels `theta(b)` is invertible. Hence

    lambda_b f_e(b) = 0

for every `b in T` and every equation `e`.

But for each false assignment `b`, some `f_e(b)` is nonzero, forcing `lambda_b=0`, contradiction.

Therefore

    boxed{
      false statement => every nonzero augmented source coefficient vector has Hamming support >= m+1.
    }                                                    (17)

This is a genuine source-code distance theorem and does **not** assume that one particular equation is nonzero on every assignment.

### Coding interpretation

For each equation `e`, the vector

    (lambda_b f_e(b))_b

is checked against the first `m` Vandermonde parity rows. On any support of size at most `m`, those checks are MDS: they force every coordinate to zero. The NP false condition then combines the equation-wise conclusions into (17).

## 8. Runs 82–83 sparse attacks are excluded at sufficient m

The Run-82 finite-difference codeword uses exactly

    s_FD = 2^(R+1)                                      (18)

assignments.

Therefore choosing

    m >= 2^(R+1)                                        (19)

makes that coefficient vector impossible in the augmented false source space.

The one-block Run-83 recombination combines two such family members, so its support is at most `2 s_FD`; it is excluded by `m >= 2 s_FD`.

More generally, the arbitrary-`L` Run-83 nullspace construction combines `L+1` family members and has support at most

    (L+1) 2^(R+1).                                      (20)

Choosing `m` at least that quantity excludes that **specific sparse recombination family**.

This does not rule out a different dense low-rank source combination.

## 9. Exact-span / polynomial-time compiler survives

When bit `i` changes from zero to one,

    theta' = theta + 2^(i-1).                            (21)

Therefore

    (theta')^j
      = sum_{k=0}^j C(j,k) 2^((i-1)(j-k)) theta^k.      (22)

Thus `q(b)` updates by a fixed public upper-triangular linear map.

Hair–Sahai already supplies fixed linear maps for the update of `u(b)` and `v(b)`. Hence the product factor

    q(b) tensor v(b)

also has a fixed linear bit-update map, and the whole rank-one assignment matrix updates linearly.

The exact-span algorithm therefore extends verbatim:

1. start from the all-zero assignment matrix;
2. at bit `i`, apply the two fixed update maps corresponding to bit values `0,1`;
3. retain a basis by Gaussian elimination;
4. intersect with the homogeneous constraints (8).

The number of matrix entries and constraints grows by a factor `m`, so the compiler remains polynomial for polynomial `m`.

## 10. Exact finite evidence

The deterministic checker uses the exact committed `rank_field_extensions.py` implementation.

### Generic false sparse-support control

It uses the contradictory two-equation system

    b_0 = 0,
    b_0 = 1,

so **no individual equation is nonzero on every assignment**. For `N=3,R=1,p=11,m=3`, it exhaustively checks all 92 assignment supports of size `1,2,3`; every restricted augmented constraint system has zero nullity.

This validates the equation-by-equation Vandermonde theorem rather than only the simpler single-equation case.

### Exact inherited extractor census

For the true relation

    b_0 + b_1 = 1

at `N=3,R=1,p=11,m=2`, the augmented source has dimension four. The checker exhaustively enumerates all its matrices. Exactly 40 nonzero matrices have rank at most `R=1`, and all 40 yield a verified original satisfying assignment by selecting a nonzero feature block and invoking the old extractor.

### Exact false MinRank census

For the explicit Run-82-style false equation

    sum_i b_i = N+1

at `N=4,R=1,p=17,m=3`, the augmented false source has dimension three. Exhausting all `17^3-1=4912` nonzero matrices gives

* 448 matrices of rank 9;
* 4464 matrices of rank 10;
* exact minimum rank 9.

The original compiler on the same false family has an explicit finite-difference codeword of rank at most `R+2=3`. Thus this tiny fixture demonstrates genuine rank amplification, but no asymptotic rank-amplification theorem is claimed.

### Explicit Run-82 rejection

For `N=4,R=1,p=17,m=4`, the exact old four-assignment finite-difference coefficient vector violates 43 augmented source constraints. This is a direct implementation-level check of Theorem 2.

### Honest / update checks

The checker also verifies:

* 40 distinct injective assignment labels;
* 37 exact partial-assignment transition identities;
* 24 honest augmented assignment matrices remain rank one and retain the old matrix as feature block zero.

The checker ran twice with byte-identical JSON. Passing finite tests are not used as a security proof.

## 11. The cost is currently fatal for the project's practical endpoint

For the original Hair–Sahai direct weighted-table compiler,

    rows = (N+1)(2NR+1) C(2R,R).                         (23)

Choosing

    R=floor(log_2 N),
    m=2^(R+1) ~= 2N                                    (24)

is enough to remove the Run-82 finite-difference support, but multiplies the right dimension by `m`.

The exact size ledger from the checker is already enormous:

* `N=32`: about `5.64e9` augmented field entries;
* `N=64`: about `3.84e11` entries;
* `N=128`: about `2.62e13` entries;
* `N=256`: about `1.78e15` entries.

So this is a useful **theoretical source transformation**, not a practical construction.

The large field needed for injective `theta` is not worse asymptotically than Hair–Sahai v1's own algebraic requirement `p>2^N`; nevertheless the earlier small-field extension is lost unless a different collision-resistant/full-spark feature mechanism is found.

## 12. QPT security classification

**Honest algorithms:** classical polynomial time in the explicit compiler dimensions and `log p`.

**Adversary model proved here:** none. Theorems 1–2 are information-theoretic algebraic statements.

**Hardness assumptions:** none for the new theorems.

**QPT false-statement hiding:** UNPROVED.

**Arbitrary-QPT early final-key recovery -> ORIGINAL source witness / independent PQ break:** UNPROVED.

A classical attack would still refute the target. Eliminating the known sparse classical attacks does not establish QPT security.

## 13. Relation to the new Jin result

Jin's ePrint 2026/2063 abstract states two relevant facts:

1. a Karp–Levin reduction from polylog-size circuit SAT to GapMDP with an `omega(log lambda)` Hamming gap;
2. unconditional **extractable witness encryption for polylog-size circuits** in the generic-group model.

That reinforces the usefulness of a source Hamming-distance interface, but does not close this project:

* the public theorem is still generic-group rather than a concrete standard-PQ encoding;
* the full manuscript was not retrievable in this run, so the exact extractor target and its path back to the ORIGINAL NP witness are not assumed;
* this Run-84 feature lift lives over an implicit exponential assignment-coordinate domain despite its polynomial matrix description.

A future useful comparison is whether Jin's explicit GapMDP reduction supplies a compact analogue of the support-distance property (17) that can be combined with a QPT-standard-assumption release mechanism.

## 14. Handoff

Run 84 gives a real escape from the **specific** Run-83 scalar-check barrier:

* new checks are coupled into the right rank-one factor rather than appended as scalar rows;
* every feature block remains an old source matrix, so supplied-low-rank ORIGINAL-source extraction is inherited exactly;
* every false coefficient representation has Hamming support at least `m+1`;
* all known Runs 82–83 sparse finite-difference/recombination families disappear once `m` exceeds their support;
* a complete small false fixture shows minimum rank jumping to 9.

But two central gaps remain:

1. dense source recombinations can still exist and no complete-output hiding theorem follows;
2. the direct representation is far too large for the practical stopping condition.

The next high-value question is whether this **MDS support-gap layer can be compressed without revealing an efficiently exploitable public quotient**, ideally into a distribution with a straight-line QPT reduction to ordinary LWE/SIS or another independently justified PQ assumption. If not, this path is only a structural diagnostic, not the holy grail.

The stopping condition is **not met**.
