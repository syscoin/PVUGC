# Run 82 — explicit finite-difference low-rank family in the actual Hair–Sahai false source space

**Status:** a new structural theorem and a concrete classical attack on part of the Run-81 parameter space. Because the attack is classical polynomial time, it also applies against the required QPT adversary class. This is **not** a completed PQ witness KEM.

**Starting verified PR head:** `c4a33a018607bda7d8e8b1d646d54df9c399e22e`.

The opening current-work GitHub checkpoint was blocked by the tool safety layer before reaching GitHub. It was not retried or rerouted in this run. No production path was changed.

## 1. Target of this run

Run 79 left open the possibility that the actual Hair–Sahai statement-derived source space might have very little low-rank spectral mass even though its minimum nonzero rank gap is only logarithmic. Run 81 increased the randomizer rank usable by the common-eigenvalue decoder, making that spectral question more important.

This run attacks that question directly on an explicit false NP family using the **actual weighted-table source construction**, not an abstract MinRank code.

## 2. Hair–Sahai source construction used

Let `R` be the source rank threshold and let the weighted-table construction use all weights `h(b)` of total degree at most `R`, together with the honest assignment matrices `A(b)`.

The only properties used here are:

1. every listed weight has Boolean polynomial degree at most `R`;
2. the source space is the span of whole assignment matrices subject to the weighted source equations;
3. on a false statement every nonzero admissible source matrix has rank strictly greater than `R`;
4. the constant-weight block contains the public honest anchor `ell(A(b))=1`.

No classical generic-group encryption theorem is imported.

## 3. Explicit false family

Work over a prime field `F_p` with

    p > N+1.

Consider the Boolean equation

    q_N(b) = sum_{i=1}^N b_i - (N+1) = 0.               (1)

For every Boolean assignment,

    0 <= sum_i b_i <= N,

so (1) is false over `F_p`.

Set

    s = R+1.                                             (2)

Choose a set `T subset [N]` of `s` free Boolean coordinates, and fix all other coordinates to an outside assignment

    z in {0,1}^{N-s}.                                    (3)

For each free assignment `x in {0,1}^s`, let `b(x,z)` denote the complete assignment.

Define

    mu_x = (-1)^|x|,
    q_x  = |x| + |z| - (N+1),
    lambda_x = mu_x / q_x.                              (4)

All `q_x` are nonzero because the equation is false.

Now form the whole weighted-table matrix

    A_{T,z}
       = sum_{x in {0,1}^s} lambda_x A(b(x,z)).          (5)

The support has only

    2^(R+1)                                              (6)

honest assignment matrices. With Hair–Sahai's usual `R=floor(log_2 N)`, this is at most `2N`, so an individual member of this family is polynomial-time constructible from the public compiler.

## 4. Theorem 1 — the matrices are in the actual false source space

### Claim

For every Hair–Sahai listed weight `h` of degree at most `R`,

    sum_x lambda_x h(b(x,z)) q_N(b(x,z)) = 0.           (7)

### Proof

By construction,

    lambda_x q_N(b(x,z)) = (-1)^|x|.

Hence the left side of (7) is

    sum_{x in {0,1}^s} (-1)^|x| h(b(x,z)).              (8)

As a polynomial in the `s=R+1` free Boolean variables, `h(b(x,z))` has total degree at most `R`.

Expression (8) is the full `(R+1)`-fold alternating finite difference of that degree-`<=R` polynomial, so it vanishes identically.

Therefore every weighted source constraint is satisfied, and

    A_{T,z} in S_false.                                  (9)

This is an exact source-space statement, not a relaxed or quotient representation.

## 5. Theorem 2 — public anchor is nonzero

Let

    a = N+1-|z|.                                         (10)

The anchor is

    ell(A_{T,z})
      = sum_x lambda_x
      = sum_{j=0}^s (-1)^j C(s,j)/(j-a).                (11)

The standard partial-fraction identity gives

    ell(A_{T,z})
      = (-1)^(s+1) s!
        / [a(a-1)...(a-s)].                              (12)

Because

    s <= a <= N+1 < p,

every denominator factor and `s!` is nonzero modulo `p`. Therefore

    boxed{ell(A_{T,z}) != 0}.                            (13)

So these are not harmless anchor-zero false codewords: they couple directly to the key shift used in Runs 79–81.

## 6. Theorem 3 — rank is at most R+2

Every support assignment in (5) fixes all coordinates outside `T`.

For an outside coordinate `j`:

* if `z_j=0`, source column `j` is the zero column in every support assignment and remains zero in `A_{T,z}`;
* if `z_j=1`, source column `j` equals the constant column `0` in every support assignment and therefore remains identical to column `0` in `A_{T,z}`.

Consequently every column lies in the span of

    column 0 plus the s free columns indexed by T.       (14)

Thus

    rank(A_{T,z}) <= s+1 = R+2.                         (15)

Hair–Sahai false-instance soundness gives

    rank(A_{T,z}) > R.                                  (16)

Therefore

    boxed{rank(A_{T,z}) in {R+1,R+2}}.                  (17)

The finite controls in this run observed rank exactly `R+2` in every tested instance, but the theorem only needs (15)–(17).

## 7. Theorem 4 — exponentially many distinct near-gap codewords

Fix `T` and vary only the outside assignment `z`.

There are

    M = 2^(N-s) = 2^(N-R-1)                             (18)

choices of `z`.

All resulting `A_{T,z}` are distinct.

### Proof

The anchor is nonzero, so column `0` is nonzero.

If `z` and `z'` differ on some outside coordinate `j`, then:

* one corresponding matrix has column `j=0`;
* the other has column `j=column 0 != 0`.

Hence the matrices differ.

Therefore the actual false source space contains at least

    boxed{2^(N-R-1)}

distinct anchor-sensitive source codewords of rank at most `R+2`.       (19)

This directly refutes the generic hope that the actual Hair–Sahai source code might have only a tiny number of near-minimum-rank directions.

## 8. Efficient public construction

When `R=floor(log_2 N)`, equation (6) uses at most `2N` honest assignment matrices.

Given `T,z`, an attacker can:

1. generate those assignment matrices using the public weighted-table compiler;
2. compute the coefficients (4);
3. form `A_{T,z}`;
4. express it in the published source basis by ordinary Gaussian elimination.

Thus individual low-rank anchor-sensitive source codewords are efficiently publicly constructible. No MinRank search oracle is needed.

The checker reconstructs public basis coordinates explicitly on the smaller validation fixtures.

## 9. Exact scalar key distinguisher

Consider the field-valued key-shift capsule of Run 81, or the analogous scalar additive statistic in Run 79.

Let `A` be a publicly constructed false codeword with

    rho = rank(A),
    ell(A) != 0.                                         (20)

Apply the corresponding public linear functional to one capsule. The result has the form

    W = K ell(A) + Z,                                    (21)

where `Z` is a sum of `r` independent bilinear forms over an `rho`-dimensional rank support.

For every nontrivial additive character `psi`,

    E[psi(Z)] = q^(-r rho).                              (22)

Therefore `Z` has the exact q-ary symmetric distribution

    Pr[Z=0]
       = 1/q + (1-1/q) q^(-r rho),                      (23)

    Pr[Z=z != 0]
       = 1/q - q^(-r rho)/q.                            (24)

For two different key shifts, the exact total-variation distance of this scalar statistic is

    boxed{TV = q^(-r rho)}.                              (25)

Since `rho<=R+2`,

    TV >= q^(-r(R+2)).                                  (26)

This is an explicit classical polynomial-time distinguisher. Therefore it also applies to the required QPT attacker class.

It is not automatically a non-negligible attack for every asymptotic parameter choice. Instead it gives a necessary parameter condition: to drive this one statistic below `2^-lambda`, one needs at least approximately

    r(R+2) log_2 q >= lambda.                           (27)

## 10. Spectral-mass lower bound

For a fixed free-coordinate set `T`, Theorem 4 supplies

    M = 2^(N-R-1)

distinct anchor-sensitive codewords with rank at most `R+2`.

Their corresponding normalized key-sensitive characters contribute at least

    M q^(-2r(R+2))                                      (28)

to the exact squared Fourier/rank-weight spectral sum considered in Run 79.

Thus merely pushing this explicit subfamily below `2^(-2lambda)` requires

    2r(R+2) log_2 q
       >= N-R-1 + 2lambda.                              (29)

Equation (29) is a **necessary condition for that spectral-rescue proof strategy**, not a lower bound on total variation by itself.

It shows that the actual rank enumerator contains an exponentially large low-rank tail, so the hoped-for rescue cannot come from an assumption that near-gap source directions are only rare.

## 11. Direct false pseudo-witness attack on Run 81

The stronger consequence concerns Run 81's common-eigenvalue decoder.

For any source matrix `A` of rank `rho`, the witness-like view in capsule `h` is

    D_h(A)
      = <R_h,J_t tensor A>_t + K ell(A) I_t.            (30)

Write a rank decomposition of `A` into `rho` rank-one terms. If the randomizer has rank parameter `r`, then

    <R_h,J_t tensor A>_t
       = U_h V_h^T                                      (31)

for matrices with at most

    r rho

columns.

Hence if

    r rho < t,                                           (32)

the random part has rank below `t`, so zero is necessarily an eigenvalue and

    K ell(A)

is guaranteed to be an eigenvalue of every capsule.

Because `ell(A)` is publicly known and nonzero, the attacker can divide by it.

Using the explicit family with `rho<=R+2`, every parameter regime satisfying

    boxed{t > r(R+2)}                                   (33)

has a polynomial-time false-instance pseudo-witness for which the Run-81 common-eigenvalue decoder recovers the hidden field key with the same basic mechanism as an honest witness.

This is a real false-statement key-recovery attack on that parameter region.

It does **not** attack the previously emphasized `r=t-1` regime, since then (33) fails for `R>=0`. It instead carves out a precise forbidden correctness/security region.

## 12. Quantum-security classification

### Honest algorithms

All construction and attack algorithms here are classical polynomial-time for `R=O(log N)`.

### Adversary

The distinguisher and pseudo-witness attack are classical PPT. Therefore they are automatically valid attacks against any scheme claiming QPT security.

### Hardness assumptions

None are used for the attack.

### Conclusion

This run does not establish QPT hiding. It does the opposite on the vulnerable parameter region and supplies a necessary quantitative condition outside that region.

Hair–Sahai's classical generic-group WE theorem is not imported. Only its explicit algebraic source compiler and false-rank theorem are used.

## 13. Validation actually executed

`finite_difference_lowrank_run82_check.py` is deterministic and uses the previously published `rank_field_extensions.py` implementation as a dependency.

It was executed twice and the JSON outputs were byte-identical.

Validated controls include:

* actual Hair–Sahai weighted source constraints for the finite-difference family;
* exact nonzero anchor identity;
* rank and outside-column structure;
* distinct-family count exactly `2^(N-R-1)` for:
  * `N=3,R=1,p=7`: 2 matrices, all rank 3;
  * `N=4,R=2,p=19`: 2 matrices, all rank 4;
  * `N=5,R=2,p=23`: 4 matrices, all rank 4;
  * `N=6,R=2,p=29`: 8 matrices, all rank 4;
  * `N=8,R=3,p=67`: 16 matrices, all rank 5;
* public-basis coordinate reconstruction on four small fixtures;
* exact scalar distinguisher at `q=7,r=1,rho=3`:
  * `epsilon=1/343`;
  * `Pr[Z=0]=349/2401`;
  * `Pr[Z=z!=0]=342/2401`;
  * exact shifted TV `1/343`;
* false pseudo-witness control using an actual `N=4,R=2,p=19` family member of rank 4:
  * vulnerable `t=5,r=1`: true key shift never missing across 900 trials; 54 trials ambiguous but none missing;
  * boundary `t=4,r=1`: true key shift missing in 395/400 trials, confirming the strict `r rho < t` structural boundary;
* necessary-condition parameter ledger.

These checks validate the finite algebra and attack implementation. The mathematical finite-difference/rank arguments, not the tests, support the general theorem.

## 14. Handoff

The most important Run-79 spectral question now has a concrete negative answer **in general**:

> the actual Hair–Sahai false source space can contain an exponentially large, efficiently constructible family of anchor-sensitive matrices only one or two ranks above the promised minimum.

Therefore the next useful path should not assume the low-rank tail is sparse.

For the rank-mask family, remaining possibilities are:

1. choose parameters so the explicit bias and pseudo-witness conditions are safely negligible/avoided, then prove security from the rest of the spectrum;
2. introduce a transformation that provably destroys this finite-difference family while retaining honest rank-one source extraction;
3. abandon this release family and return to a different QPT-standard-assumption encoder.

The complete practical QPT WKEM stopping condition is **not met**.
