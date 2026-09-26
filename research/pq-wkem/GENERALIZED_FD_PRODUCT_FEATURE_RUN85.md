# Run 85 — generalized finite differences survive the product-feature lift: a linear-feature practicality barrier

**Status:** this run corrects the optimistic reading of Run 84. The Vandermonde/product-feature lift really does remove all false coefficient vectors of support at most `m` and preserves supplied-low-rank ORIGINAL-source extraction. However, on an explicit false NP family, for every `m <= N-R` there is a new anchor-sensitive source codeword satisfying **all** product-feature constraints with rank at most

\[
\boxed{m(R+m+1)}.
\]

Moreover, that codeword is constructible in polynomial time from the public partial-assignment update maps by a Hamming-weight dynamic program; no `2^(R+m)` enumeration is necessary. Thus a sublinear/small feature count does not eliminate the finite-difference pathology—it raises its rank in a quantifiable way. To escape this particular family merely by running out of Boolean directions requires `m>N-R`, which is already impractical in the literal Hair–Sahai table.

This is a classical algebraic attack/boundary result and therefore applies a fortiori to any claimed QPT security. It is **not** a completed PQ witness KEM.

**Starting verified PR head:** `adcf3b578848c454c99191bc073f6ed430f4da42`.

The current-work GitHub checkpoint write in this run was blocked by the connector safety layer before reaching GitHub. It was not retried or rerouted. No production path was changed.

## 1. Exact Run-84 interface retained

For a Boolean assignment `b`, the Hair–Sahai weighted-table assignment matrix is

\[
A(b)=u(b)v(b)^T,
\qquad
v(b)=(1,b_1,\ldots,b_N).
\]

Run 84 defines, over a prime field `F_p` with `p>2^N`, the injective label

\[
\theta(b)=\sum_{i=1}^N 2^{i-1}b_i
\]

and the feature vector

\[
q_m(b)=(1,\theta(b),\ldots,\theta(b)^{m-1}).
\]

The augmented honest matrix is

\[
\widetilde A_m(b)
 =u(b)(q_m(b)\otimes v(b))^T
 =[A(b)\mid \theta(b)A(b)\mid\cdots\mid\theta(b)^{m-1}A(b)].
\tag{1}
\]

Every honest assignment remains rank one.

For every original Hair–Sahai weight `h`, source equation `f_e`, and feature index `j=0,...,m-1`, the augmented source coefficients obey

\[
\sum_b \lambda_b h(b)\theta(b)^j f_e(b)=0.
\tag{2}
\]

Run 84 correctly proved two useful facts:

1. every nonzero augmented matrix of rank at most `R` contains a nonzero old-source block of rank at most `R`, so the existing supplied-low-rank extractor yields an **ORIGINAL satisfying assignment**;
2. on a false statement, every nonzero coefficient vector satisfying (2) has Hamming support at least `m+1`.

Those facts remain valid.

What changes here is the rank-gap conclusion one might hope to draw from them.

## 2. Explicit false family

Use the same false Boolean equation as Runs 82–83:

\[
f_N(b)=\sum_{i=1}^N b_i-(N+1)=0.
\tag{3}
\]

Because `p>2^N>N+1`, this equation has no Boolean solution over `F_p`.

Fix a feature count satisfying

\[
1\le m\le N-R
\tag{4}
\]

and define

\[
s=R+m\le N.
\tag{5}
\]

Choose a free-coordinate set `T` of size `s` and fix all coordinates outside `T` to an assignment `z`.

For every `x in {0,1}^s`, let `b(x,z)` be the complete assignment and set

\[
\mu_x=(-1)^{|x|},
\qquad
\lambda_x=
 \frac{\mu_x}{f_N(b(x,z))}.
\tag{6}
\]

The denominator is always nonzero because the statement is false.

Define the augmented matrix

\[
\widetilde M_{T,z}
 =\sum_{x\in\{0,1\}^s}\lambda_x\widetilde A_m(b(x,z)).
\tag{7}
\]

## 3. Theorem 1 — the generalized finite difference satisfies every Run-84 augmented source constraint

Every Hair–Sahai listed weight `h` has total Boolean-polynomial degree at most `R`.
For feature index `j`,

\[
\deg(h(b)\theta(b)^j)\le R+j\le R+m-1=s-1.
\tag{8}
\]

For the coefficient vector (6), the left side of the augmented source equation is

\[
\begin{aligned}
\sum_x \lambda_x h(b(x,z))\theta(b(x,z))^j f_N(b(x,z))
 &=\sum_x(-1)^{|x|}h(b(x,z))\theta(b(x,z))^j.
\end{aligned}
\tag{9}
\]

As a polynomial in the `s` free Boolean variables, the summand has degree strictly below `s`.
The right side of (9) is therefore the full `s`-fold alternating finite difference of a degree-`<s` polynomial, so it is zero.

Thus

\[
\boxed{\widetilde M_{T,z}\in\widetilde S_m^{\rm false}.}
\tag{10}
\]

This is an exact member of the **actual Run-84 product-feature source space**, not a relaxation or quotient representation.

### Why Run 84 did not contradict this

Run 84 proved only that nonzero false coefficient vectors must have support at least `m+1`.
The coefficient vector (6) has support

\[
2^s=2^{R+m},
\tag{11}
\]

which is comfortably larger than `m`.

Run 84 also correctly showed that choosing `m>=2^(R+1)` rejects the **specific old** Run-82 vector obtained from only `R+1` free bits. The present construction simply raises the finite-difference order to `R+m`; it is a different vector.

## 4. Theorem 2 — the key anchor remains nonzero

Let

\[
w=|z|,
\qquad
a=N+1-w.
\]

The old `q_0=1` feature block retains the public Hair–Sahai anchor. On (7), its value is

\[
\alpha_{s,w}
 =\sum_{x\in\{0,1\}^s}\lambda_x
 =\sum_{k=0}^s \frac{(-1)^k\binom{s}{k}}{k-a}.
\tag{12}
\]

The standard partial-fraction identity gives

\[
\alpha_{s,w}
 =\frac{(-1)^{s+1}s!}
 {a(a-1)\cdots(a-s)}.
\tag{13}
\]

Because `w<=N-s`, one has `a>=s+1`, while `a<=N+1<p`. Every factor in (13) is therefore nonzero in `F_p`, as is `s!`.

Hence

\[
\boxed{\alpha_{s,w}\ne0.}
\tag{14}
\]

So these are key-sensitive false source directions, not merely anchor-zero nuisance vectors.

## 5. Theorem 3 — rank at most m(R+m+1)

Write the augmented matrix in its `m` horizontal feature blocks:

\[
\widetilde M_{T,z}
 =[M_0\mid M_1\mid\cdots\mid M_{m-1}].
\]

Within any fixed feature block `j`, every source coordinate outside `T` is constant across all assignments in (7).
For outside coordinate `c`:

* if `z_c=0`, column `c` of `M_j` is zero;
* if `z_c=1`, column `c` of `M_j` equals column `0` of `M_j`.

Therefore block `M_j` has at most

\[
s+1=R+m+1
\]

potentially independent columns: column `0` and the `s` free-coordinate columns.
Across all `m` feature blocks,

\[
\boxed{
\operatorname{rank}(\widetilde M_{T,z})
 \le m(s+1)
 =m(R+m+1).
}
\tag{15}
\]

Hair–Sahai/Run-84 source soundness still gives rank `>R` on a false statement; (15) is an explicit upper bound on how far this product-feature transformation can have amplified the rank for this family.

## 6. Theorem 4 — exponentially many distinct anchor-sensitive directions

Fix `T` and vary `z`. There are

\[
2^{N-s}=2^{N-R-m}
\tag{16}
\]

choices.

They give distinct matrices. If two outside assignments differ at coordinate `c`, then in the feature-zero block one matrix has outside column `c=0`, while the other has column `c=column 0`. The latter column is nonzero because the anchor (14) is nonzero.

They are in fact not scalar multiples for the same reason.

Thus for every `m<=N-R`, the actual false source space contains at least

\[
\boxed{2^{N-R-m}}
\]

distinct projective key-sensitive directions of rank at most `m(R+m+1)`.

This is the product-feature analogue of Run 82's low-rank spectral tail.

## 7. Theorem 5 — the construction is polynomial-time public; exponential support enumeration is unnecessary

At first glance (7) appears to require enumerating `2^(R+m)` assignments. It does not.

Run 84 proved that for each Boolean coordinate `i`, flipping that bit from zero to one acts on the augmented assignment matrix by a fixed **public linear map** `T_i`. This follows from the original Hair–Sahai partial-assignment update and

\[
(\theta+2^{i-1})^j
 =\sum_{k=0}^j\binom jk 2^{(i-1)(j-k)}\theta^k.
\tag{17}
\]

First construct the augmented assignment matrix with the outside bits fixed to `z` and every free bit zero.
For the free coordinates, maintain matrices

\[
E_{t,k}
 =\sum_{\substack{x\in\{0,1\}^t\\|x|=k}}
 \widetilde A_m(b(x,z)),
\tag{18}
\]

where only the first `t` free bits are allowed to vary.
They obey the public recurrence

\[
E_{t,k}
 =E_{t-1,k}+T_{i_t}(E_{t-1,k-1}).
\tag{19}
\]

After all `s` free bits,

\[
\widetilde M_{T,z}
 =\sum_{k=0}^{s}
 \frac{(-1)^k}{k+w-(N+1)}E_{s,k}.
\tag{20}
\]

This uses `O(s^2)` applications of explicit public linear update maps plus field arithmetic, hence polynomial time in the explicit compiler dimensions and `log p` even when `s=Theta(N)`.

Finally, the attacker expresses (20) in the published source-space basis by ordinary Gaussian elimination.

Therefore the family is not merely existential:

\[
\boxed{
\text{for every }m\le N-R,
\text{ an anchor-sensitive false direction satisfying (15) is publicly PPT-constructible.}
}
\tag{21}
\]

The checker compares this dynamic program against direct assignment enumeration on every finite control and obtains exact equality.

## 8. Consequence for the rank-mask / field-key release family

The complete-output character law used in Runs 78–82 is

\[
|\widehat P(A)|=q^{-r\operatorname{rank}(A)}
\tag{22}
\]

for randomizer rank `r`.
After normalizing the public nonzero anchor, (15) supplies a key-sensitive character with

\[
|\widehat P|
 \ge q^{-r m(R+m+1)}.
\tag{23}
\]

Thus a necessary condition even to make this **single explicit classical statistic** smaller than about `2^-lambda` is

\[
\boxed{
r\,m(R+m+1)\log_2 q\gtrsim\lambda.
}
\tag{24}
\]

This is a classical PPT observable, so whenever the bias is non-negligible it is automatically also a QPT attack.

For the Run-81 common-eigenvalue decoder, a false source matrix of rank `rho` gives an effective visible random-factor width at most `r rho`. Therefore the present family enters the same false-pseudowitness regime whenever

\[
\boxed{
t>r\,m(R+m+1).}
\tag{25}
\]

In that region the anchored key shift is necessarily an eigenvalue of every capsule; the usual independent-capsule uniqueness analysis applies with the effective width `r rho`.

Equation (25) is a parameter-region attack, not a claim that all choices are broken.

## 9. Spectral-mass lower tail

The `2^(N-R-m)` distinct projective directions from Theorem 4 each have rank at most

\[
B=m(R+m+1).
\]

Consequently this explicit family alone contributes at least

\[
\boxed{
2^{N-R-m}q^{-2rB}
}
\tag{26}
\]

to the squared key-sensitive rank/Fourier coefficient mass used by the Run-79 spectral strategy.

Therefore suppressing just this family below `2^{-2lambda}` requires the necessary inequality

\[
\boxed{
2r\,m(R+m+1)\log_2q
 \gtrsim N-R-m+2\lambda.
}
\tag{27}
\]

This is a necessary condition for that spectral-proof route. It is not, by itself, a lower bound on total variation of the entire ciphertext distribution.

## 10. A sharp feature-count/practicality boundary for this explicit attack

The generalized construction needs `s=R+m` free Boolean coordinates. Thus the first feature count at which this **particular** family cannot be formed is

\[
\boxed{m=N-R+1.}
\tag{28}
\]

This is not a security theorem for `m>N-R`; other false directions may remain. It is nevertheless a strong compression barrier for the product-feature repair: every `m<=N-R`, including every constant, logarithmic, and most sublinear choices, still has the explicit PPT low-rank family above.

For the literal Hair–Sahai weighted-table dimensions

\[
\text{rows}=(N+1)(2NR+1)\binom{2R}{R},
\quad
\text{columns}=(N+1)m,
\tag{29}
\]

and `R=floor(log_2 N)`, choosing only the first value outside the attack range, `m=N-R+1`, already costs:

| N | R | m | field entries | raw packed bytes lower bound from p>2^N |
|---:|---:|---:|---:|---:|
| 32 | 5 | 28 | 2,466,558,864 | 10.17 GB |
| 64 | 6 | 59 | 177,123,846,900 | 1.44 TB |
| 128 | 7 | 122 | 12,493,002,302,352 | 201.45 TB |
| 256 | 8 | 249 | 867,181,700,346,390 | 27.86 PB |

These are raw lower bounds before metadata or cryptographic encapsulation overhead.

So Run 84's direct table remains unsuitable for the required practical endpoint even after improving its sufficient feature count from roughly `2N` to the **necessary-to-escape-this-attack** threshold of roughly `N`.

## 11. Exact finite validation

`run85_generalized_fd_product_feature_check.py` is deterministic, standard-library-only apart from the exact already-published `rank_field_extensions.py` dependency.
It was executed twice; stdout was byte-identical.

The captured run validates:

* **22** generalized finite-difference family members across nine actual product-feature compiler settings;
* every augmented source-constraint residual is exactly zero;
* every anchor matches the closed form (13) and is nonzero;
* every rank satisfies the theorem bound `m(R+m+1)`;
* every family has exactly `2^(N-R-m)` distinct matrices;
* the polynomial Hamming-weight dynamic program matches direct `2^(R+m)` enumeration **byte-for-byte as field vectors** in every control;
* observed example ranks:
  * `N=3,R=1,m=1`: rank 3;
  * `N=3,R=1,m=2`: rank 6;
  * `N=4,R=1,m=2`: rank 6;
  * `N=4,R=1,m=3`: rank 10;
  * `N=6,R=2,m=2`: rank 8;
  * `N=6,R=2,m=3`: rank 14;
* exact complete false-space census at `N=3,R=1,p=11`:
  * `m=1`: source dimension 4, 14,640 nonzero matrices, minimum rank 3;
  * `m=2=N-R`: source dimension 1, 10 nonzero matrices, all rank 6;
  * `m=3>N-R`: source dimension 0 in this **specific** fixture;
* exact representation-cost ledger at `m=N-R+1`;
* extension-field raw-bit controls confirming that packing `m` base-field symbols into one `F_{q^m}` symbol changes element count but not raw information bits.

The tests validate finite algebra and implementation. They are not evidence of LWE/SIS/MinRank hardness or QPT security.

## 12. Literature/dependency audit in this run

Hair–Sahai's September 2026 WE result still explicitly proves NP witness encryption in the **classical generic-group model**, not concrete QPT security. Its MinRank compiler remains valuable as algebra here, but that theorem is not imported as a PQ assumption.

Jin's ePrint 2026/2063 listing is current as of September 24 and states a polylog-circuit SAT to GapMDP reduction with `omega(log lambda)` gap and extractable WE for polylog-size circuits in the generic-group model. The full paper was still not accessible through the available source in this run, so no unverified extraction arrow is imported. In particular, "extractable generic-group WE" is not silently upgraded to concrete QPT original-source extraction.

Hair–Sahai's August 2026 GapSVP result gives deterministic worst-case NP-hardness for polynomial approximation factors in `ell_p`, `p>2` (and `ell_infinity`). That is useful complexity-theoretic geometry, but it is not an average-case SIS/LWE distribution and does not itself establish QPT hardness. No norm conversion or random-instance claim is imported here.

## 13. QPT classification

**Honest compiler:** classical polynomial time in the explicit matrix dimensions.

**Attack:** the dynamic-program construction, source-basis coordinate recovery, and public rank-mask character are classical polynomial time. Therefore they are valid attacks/boundaries against a QPT-security target.

**Hardness assumptions used by the attack:** none.

**QPT false-statement hiding:** still UNPROVED outside the explicitly vulnerable/non-negligible parameter regions.

**Arbitrary-QPT early final-key recovery -> ORIGINAL witness / independent PQ break:** still UNPROVED.

**Run-84 supplied-low-rank extractor:** retained exactly, but it applies only when a low-rank representation is supplied. It does not convert arbitrary key recovery by itself.

## 14. Handoff

The Run-84 product-feature idea is not dead algebraically, but its practical compression story is now much worse:

1. a feature count `m<=N-R` always leaves a publicly constructible, anchor-sensitive generalized finite-difference family of rank at most `m(R+m+1)`;
2. avoiding this one family by feature count alone requires `m>N-R`, i.e. essentially **linear in N**;
3. in the literal weighted-table representation, that regime is already multi-GB at `N=32` and explodes thereafter;
4. extension-field packing does not reduce the raw `m log q` information cost, and allowing a larger coefficient field would change the source semantics and require a new security audit.

The next constructive route should therefore **not** be "compress the same first-m-powers product lift a little." The useful alternatives are:

* a genuinely different compact source-gap compiler (Jin's GapMDP reduction is a literature lead once its full extraction chain can be audited);
* a standard-PQ public release mechanism whose security does not depend on turning a large explicit source matrix into pseudorandomness;
* or a new feature/code transform with a provable gap against these higher-order finite differences and polynomial concrete size.

The complete practical generic-NP QPT WKEM stopping condition is **not met**.
