# Run 198 — characteristic-two finite-difference family repairs the Run-197 field mismatch and preserves the generic-NP shared-factor attack

**Status:** correction plus a new exact false-source family in the actual characteristic-two / binary-scalar-descent source used by Run 152. This repairs a scope error in Run 197's application of Run 82. It does **not** prove the same family exists for an arbitrary fixed relation (including the concrete Syscoin bridge relation), does not prove full-transcript hiding/impossibility, and is not a completed PQ witness-KEM.

## 1. Verified starting point

Connected GitHub reads at the start of this bounded iteration verified `syscoin/PVUGC#1`:

- branch `research/pq-wkem-validation-20260918`;
- exact head `4e7cc5f9d3fc727a0b09981409bb05c776a803bc`;
- open, draft, unmerged;
- latest substantive ordinary PR comment remains `5913974235` (Run 196); Run 197's four research files are present at the live head, while its attempted ordinary comment was reported blocked and is not treated as published.

Exact-version inputs read:

- Run 197, `JOINT_LOWRANK_PROJECTION_RUN197.md`, blob `6dab6c3812ebbb7c35dbe8f541698a8389a59f7a`;
- Run 152, `CMV_MINRANK_LACONIC_QPT_SOURCE_BRIDGE_RUN152.md`, blob `398b93af491d0b11cc486e86c89295a05b714804`;
- Run 82, `FINITE_DIFFERENCE_LOWRANK_RUN82.md`, blob `6430557fd1596308db029d17b48549f9ed9490c8`;
- `literature-20260924/DEEP_DIVE_RANK_SCALAR_DESCENT.md`, blob `5d061495800bad32733298d25f1f1ac6e55779c2`.

No denied historical payload was retried. Production and workflows remain out of scope.

## 2. Correction to Run 197

Run 197's **binary projection theorems** are field-consistent on their own: for any public nonzero binary source direction `M`, the full shared-factor projection has the exact `A B^T` law with inner width `m=r rank(M)`, and the full-rank event gives the stated efficient distinguisher.

However, Run 197 Section 6 directly plugged in Run 82's family as though it were already a family in Run 152's binary source. That transfer was unsupported as written:

- Run 82 constructs its family over a prime field `F_p`, with coefficients `(-1)^|x|/q_x` and `p>N+1`;
- Run 152 instead uses the binary source obtained from the separately derived `GF(2^h)` compiler plus vertical scalar descent.

The vertical descent theorem transfers a matrix already living in the chosen characteristic-two source; it does **not** by itself transport an arbitrary prime-field Run-82 matrix into that source.

Therefore the Run-197 product law remains valid, but its claim that the specific prime-field Run-82 family directly supplies the binary directions must be replaced by a characteristic-two construction. The rest of this note supplies that construction for a legitimate generic-NP false source.

## 3. Characteristic-two false source

Use the field-flexible weighted-table compiler from the scalar-descent note over

`F = GF(2^h)`,

with `|F|>2NR`, a public `gamma` of multiplicative order greater than `N`, and at least `2NR+1` distinct sample values. Let the source rank threshold be `R` and put

`s=R+1`.

Consider the unsatisfiable Boolean polynomial system containing the single constant equation

`q(b)=1=0`.

This is a degree-zero false source. It is sufficient for a **generic-NP/source-language** security counterexample; it is not asserted to be the fixed Syscoin relation.

Choose `s` free Boolean coordinates `T subset [N]` and fix all remaining coordinates to any

`z in {0,1}^{N-s}`.

For each `x in {0,1}^s`, let `b(x,z)` be the complete assignment and define

`A_(T,z) = sum_x A(b(x,z))`

over `F`.

There are only `2^(R+1)` summands, so for `R=floor(log_2 N)` each member is polynomial-time constructible.

## 4. Theorem 1 — exact source membership in characteristic two

For every listed weight `h` of total Boolean degree at most `R`, the source constraint for `q=1` is

`sum_x h(b(x,z)) = 0`.

This follows from the characteristic-two cube-sum identity. After multilinearizing the restriction of `h` to the `s` free Boolean variables,

`sum_(x in {0,1}^s) f(x)`

equals the coefficient of the full monomial `x_1...x_s`: every monomial of degree `<s` is repeated `2^(s-d)` times and therefore sums to zero in characteristic two. Since `deg h<=R=s-1`, the full coefficient is absent.

Hence every weighted source equation vanishes and

`A_(T,z) in S_false`.

No prime-field reciprocal coefficients or alternating signs are used.

## 5. Theorem 2 — the matrix is nonzero although its public anchor is zero

The ordinary anchor is the constant-weight `(0,0)` entry. Here

`ell(A_(T,z)) = 2^s = 0`

in characteristic two.

That does **not** make the matrix zero. Pick one free coordinate `i_* in T`, let `T'=T\{i_*}` (so `|T'|=R`), and choose any nonzero compiler sample `tau`.

Take the listed weight

`h_tau(b)=prod_(j=1)^R ell_(j,tau)(b)`,

i.e. multi-index `(1,...,1)`. The coefficient matrix of the `R` linear forms on the variables in `T'` is

`[(gamma^(j-1) tau)^i]_(j,i in T')`.

Its determinant is a nonzero scalar times the Vandermonde determinant on the distinct values `gamma^i`: `tau!=0` and `ord(gamma)>N` make all factors nonzero. In characteristic two determinant and permanent have the same signs, so the squarefree monomial `prod_(i in T') b_i` occurs in `h_tau` with nonzero coefficient.

Now inspect, in that weighted block, row `i_*` and column `0`. Its value in `A_(T,z)` is

`sum_x h_tau(b(x,z)) b_(i_*)`.

The cube-sum identity extracts the coefficient of the full monomial on `T`, which is exactly the nonzero coefficient above. Therefore column `0` is nonzero and

`A_(T,z) != 0`.

This distinction matters: the family is **anchor-zero but ciphertext-distinguishing**. Run 152's structured-vs-uniform bit hiding must hide every public nonzero source projection; an anchor shift is not required for the Run-197 rank-event distinguisher.

## 6. Theorem 3 — near-gap rank survives binary scalar descent

All coordinates outside `T` are fixed across the cube:

- if `z_j=0`, column `j` is zero;
- if `z_j=1`, column `j` is identical to column `0`.

Thus over `F`, every column lies in the span of column `0` plus the `s` free columns, so

`rank_F(A_(T,z)) <= s+1 = R+2`.

Apply the published vertical coordinate descent `D`. It preserves zero/equal column relations and injectivity, hence

`D(A_(T,z)) != 0`,

`rank_F(A_(T,z)) <= rank_F2(D(A_(T,z))) <= R+2`.

Because this is a nonzero member of a false descended source, the published false-gap theorem gives

`rank_F2(D(A_(T,z))) > R`.

Therefore

`boxed(rank_F2(D(A_(T,z))) in {R+1,R+2}).`

This is the binary near-gap direction Run 197 actually needs.

## 7. Theorem 4 — exponentially many distinct binary near-gap directions

Fix `T` and vary `z`. There are

`2^(N-R-1)`

choices. If `z,z'` differ on outside coordinate `j`, one matrix has column `j=0` and the other has column `j=column0!=0`. Thus the field matrices are distinct. Injective descent preserves distinctness.

So the characteristic-two binary source contains at least

`boxed(2^(N-R-1))`

distinct public, efficiently constructible, nonzero directions of binary rank at most `R+2` for this generic false source.

Unlike Run 82's prime-field family, these directions have zero anchor. That is enough for false-bit distinguishing but not for an anchor-shift key-recovery claim.

## 8. Corrected application of Run 197

For any descended member with binary rank `rho in {R+1,R+2}`, Run 197 applies exactly:

`C(z) ==_dist A B^T`,

with independent uniform `A,B in F_2^(t x (r rho))`.

The polynomial-time full-rank event has advantage

`Delta_rank(t,r rho)=p_t(1-p_(t,r rho)).`

Consequently:

- if `r(R+2)<t`, every member of the family gives the Run-197 constant full-rank obstruction;
- for target advantage `2^-lambda`, if
  `r(R+2)-t <= lambda-3`, the coarse Run-197 bound still gives an explicit advantage greater than `2^-lambda` for every possible family rank `rho<=R+2`.

Thus Run 197's **generic-NP necessary parameter condition is repaired**, but with a different characteristic-two family and with anchor-zero scope made explicit.

What is *not* established:

1. that the prime-field Run-82 matrices themselves descend into Run 152;
2. that this constant-contradiction family is present in every fixed relation;
3. that the concrete Syscoin relation has an analogous efficiently constructible near-gap false family;
4. that satisfying this one-direction parameter condition proves full-transcript hiding.

Those remain separate obligations.

## 9. QPT / assumption ledger

- Honest compiler and family construction: classical polynomial time for `R=O(log N)`.
- Attack: classical polynomial-time Gaussian elimination on one public projection; therefore included in arbitrary QPT.
- New hardness assumptions: none.
- Quantum reduction: none; this is an unconditional false-source distinguisher/necessary condition.
- Witness privacy: irrelevant.
- False-instance QPT hiding: broken in the parameter region above for this legitimate generic false source.
- Arbitrary true-instance recovery -> ORIGINAL witness: unchanged and still conditional on Run 152's spectral conditions.
- Concrete fixed Syscoin relation: **not analyzed by this family**.
- Completed practical WKEM: **UNPROVED**.

## 10. Finite validation actually executed

`char2_finite_difference_run198_check.py` is standard-library-only. It independently implements the exact field-flexible weight syntax over small extension fields, constructs the constant-contradiction cube family, performs the vertical binary descent, and checks the Run-197 rank-event consequence.

The finalized checker passed syntax validation and two byte-identical executions.

Exact fixtures:

- `N=3,R=1,GF(8)`: 2 distinct matrices, all binary rank 3;
- `N=4,R=1,GF(16)`: 4 distinct matrices, all binary rank 3;
- `N=5,R=2,GF(32)`: 4 distinct matrices, all binary rank 4;
- `N=6,R=2,GF(32)`: 8 distinct matrices, all binary rank 4.

Every fixture checks all listed weighted source constraints, zero anchor, nonzero column 0, outside-column structure, field/binary rank inequalities, family distinctness, and the small exact Run-197 full-rank-event advantage. Representative demo advantages are `315/1024` for `t=4,r=1,rho=3` and `9765/32768` for `t=5,r=1,rho=4`.

These finite checks validate the implementation and small identities only. Sections 4-8 contain the general algebraic argument.

## 11. Handoff

The immediate multi-direction question from Run 197 should now be split cleanly:

1. **generic-NP CMV route:** the binary low-rank tail is real even without importing Run 82; analyze whether many characteristic-two cube directions sharing the same factors yield a stronger joint attack than the one-direction `AB^T` test;
2. **actual Syscoin relation:** separately search for relation-specific low-rank false directions. The generic constant contradiction cannot be silently treated as a Syscoin counterexample.

Do not reuse the prime-field Run-82 family as a binary Run-152 direction without an explicit characteristic-preserving transfer. The WE-like off-chain release and complete QPT/ORIGINAL-extraction stopping condition remain unchanged.
