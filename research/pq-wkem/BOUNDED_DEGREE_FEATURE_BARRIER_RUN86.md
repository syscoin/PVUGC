# Run 86 — exact subcube-span criterion and a bounded-degree barrier for public rank-one feature lifts

**Status:** new structural theorem generalizing Runs 82–85. It gives an exact linear-algebra criterion for when a false-instance subcube supports an anchor-sensitive source pseudorepresentation, and proves that **any** rank-one-preserving feature lift whose public feature coordinates all have bounded Boolean algebraic degree `d` inherits an explicit false family whenever `R+d+1 <= N`. For `R,d=O(log N)` the family is directly constructible by a classical polynomial-time adversary by enumerating only `2^(R+d+1)=poly(N)` assignments. With the public linear bit-update property from Run 85, the same family remains polynomial-time constructible for larger `d` by the Hamming-weight dynamic program.

This does **not** prove or disprove complete-output QPT security outside the parameter regions where the resulting public statistic is non-negligible or the common-eigenvalue false-pseudowitness condition holds. It is not the completed PQ WKEM.

**Starting verified PR head:** `52b5cc0d3650ed6c29dbf2225ecbfc9c08208503`.

An attempted opening PR comment for this run returned an OpenAI safety-block error before reaching GitHub. It was not repeated or rerouted. The research below was then completed locally. Publication status of the actual Run-86 artifacts is recorded in the final provenance/readback, not inferred from that comment failure.

No production path is changed.

## 1. General feature-lift interface

Let the Hair–Sahai-style public assignment matrix be

\[
A(b)=u(b)v(b)^T,
\qquad
v(b)=(1,b_1,\ldots,b_N),
\]

with listed source weights `h` whose Boolean multilinear degree is at most `R`.
Only the algebraic source/rank/extraction interface is used here; the Hair–Sahai encryption theorem is in the **classical generic-group model** and is not imported as a concrete post-quantum assumption.

Let

\[
\Phi(b)=(\phi_1(b),\ldots,\phi_m(b))\in F^m
\]

be any public feature vector. Assume one feature is the constant function `1`, so the old public anchor remains present. The rank-one feature lift is

\[
\widetilde A_\Phi(b)
 =u(b)(\Phi(b)\otimes v(b))^T
 =[\phi_1(b)A(b)\mid\cdots\mid\phi_m(b)A(b)].
\tag{1}
\]

Every honest assignment remains rank one, regardless of the complexity of the features.

For every source relation `f_e`, old source weight `h`, and feature coordinate `j`, the natural augmented linear source constraint is

\[
\sum_b \lambda_b h(b)\phi_j(b)f_e(b)=0.
\tag{2}
\]

Runs 84–85 studied the special case `phi_j(b)=theta(b)^j`. This run separates the feature **count** from its **Boolean algebraic degree** and then removes the polynomial-degree assumption entirely in the exact subcube criterion.

## 2. Exact subcube-span criterion

Fix any false relation `f` and any finite support set `C` of Boolean assignments on which

\[
f(b)\ne0\quad\text{for every }b\in C.
\]

Define the function space

\[
W_C
 =\operatorname{span}_F
 \left\{
   (h(b)\phi_j(b))_{b\in C}
   : h\in\mathcal H,\ j\in[m]
 \right\}
 \subseteq F^C,
\tag{3}
\]

and define the reciprocal violation vector

\[
g_C=(f(b)^{-1})_{b\in C}.
\tag{4}
\]

### Theorem 1 — exact anchor-sensitive pseudorepresentation criterion

There exists a coefficient vector `lambda`, supported on `C`, that satisfies **all** constraints (2) for this relation and has nonzero old anchor

\[
\sum_{b\in C}\lambda_b\ne0
\]

if and only if

\[
\boxed{g_C\notin W_C.}
\tag{5}
\]

### Proof

Make the invertible coordinate change

\[
\mu_b=\lambda_b f(b).
\tag{6}
\]

Then every source constraint becomes

\[
\sum_{b\in C}\mu_b h(b)\phi_j(b)=0,
\]

so exactly

\[
\mu\in W_C^\perp.
\tag{7}
\]

The anchor is

\[
\sum_b\lambda_b
 =\sum_b\mu_b f(b)^{-1}
 =\langle\mu,g_C\rangle.
\tag{8}
\]

A vector in `W_C^perp` with nonzero pairing against `g_C` exists exactly when

\[
g_C\notin(W_C^\perp)^\perp=W_C.
\]

This proves (5). ∎

### Interpretation

This criterion is exact for the linear source constraints; it is not a heuristic rank argument.

A compact feature repair can eliminate all anchor-sensitive coefficient vectors on a particular support `C` only if its feature-weight span actually contains the reciprocal violation function `1/f` on `C`.

This clarifies Runs 82–85:

* the old low-degree table failed because `1/f` had a higher Boolean degree than the available feature-weight span;
* adding a few scalar checks enlarged `W_C` but did not generally place `1/f` inside it;
* the first-powers product lift enlarged the degree of `W_C` one feature step at a time, so a higher-order finite difference survived.

The criterion itself does not say that efficiently producing a reciprocal feature for arbitrary false NP statements is possible.

## 3. Bounded-degree barrier

Now use the explicit false relation

\[
f_N(b)=\sum_{i=1}^N b_i-(N+1)=0.
\tag{9}
\]

Assume the field characteristic is greater than `N+1`, so `f_N` is nonzero on every Boolean assignment and the factorials below are nonzero.

Suppose every feature coordinate has Boolean multilinear degree at most

\[
\deg_B\phi_j\le d.
\tag{10}
\]

Choose

\[
s=R+d+1
\tag{11}
\]

free Boolean coordinates, assuming `s<=N`, and fix all outside coordinates to an arbitrary assignment `z` of Hamming weight `w`.
Let `C_{T,z}` be the resulting `s`-dimensional Boolean cube.

Every product `h phi_j` restricted to this cube has degree at most

\[
R+d=s-1.
\tag{12}
\]

By contrast, the reciprocal function

\[
g(x)=\frac{1}{|x|+w-(N+1)}
\tag{13}
\]

has **exact Boolean degree `s`** on this cube.
Its top multilinear coefficient is, up to an irrelevant sign,

\[
\sum_{x\in\{0,1\}^s}
 (-1)^{|x|}\,g(x)
 =
 \frac{(-1)^{s+1}s!}
 {(N+1-w)(N-w)\cdots(N+1-w-s)},
\tag{14}
\]

which is nonzero under the field hypothesis.

Therefore `g` cannot lie in `W_C`.
By Theorem 1 an anchor-sensitive false source coefficient vector exists.

### Theorem 2 — explicit bounded-degree false family

For every public feature lift of the form (1) containing a constant feature and satisfying (10), if

\[
R+d+1\le N,
\]

then the explicit false instance (9) has an anchor-sensitive source pseudorepresentation supported on an `(R+d+1)`-dimensional Boolean cube.

An explicit choice is

\[
\mu_x=(-1)^{|x|},
\qquad
\lambda_x=
 \frac{(-1)^{|x|}}
 {|x|+w-(N+1)}.
\tag{15}
\]

Indeed every source constraint reduces to the full `s`-fold finite difference of a degree-at-most-`s-1` polynomial and vanishes identically.

Thus the obstruction is controlled by **feature degree, not feature count**. Adding arbitrarily many degree-`d` features cannot remove this family while `d<=N-R-1`.

## 4. Rank bound refined by the feature-evaluation dimension

Let

\[
r_\Phi(C)=
 \dim\operatorname{span}\{\Phi(b):b\in C\}
 \le m.
\tag{16}
\]

There is an invertible linear change of feature coordinates sending this span into the first `r_Phi(C)` coordinates. Right multiplication of (1) by the corresponding invertible block matrix preserves rank. After that change, every assignment in `C` has zero in the remaining feature blocks.

Within each surviving feature block, all source coordinates outside the `s` free bits are fixed. Hence every outside source column is either zero or a copy of the block's constant column. Each block has at most `s+1` potentially independent columns.

Therefore the pseudorepresentation in Theorem 2 satisfies

\[
\boxed{
\operatorname{rank}\widetilde M
 \le r_\Phi(C)(s+1).
}
\tag{17}
\]

Because degree-`d` functions on an `s`-cube form a space of dimension

\[
D(s,d)=\sum_{k=0}^{d}\binom{s}{k},
\tag{18}
\]

one also has

\[
\boxed{
r_\Phi(C)\le\min\{m,D(s,d)\}.}
\tag{19}
\]

Combining (11), (17), and (19),

\[
\boxed{
\operatorname{rank}\widetilde M
 \le
 (R+d+2)
 \min\left\{m,
   \sum_{k=0}^{d}\binom{R+d+1}{k}
 \right\}.
}
\tag{20}
\]

This strengthens the Run-85 coarse `m(R+m+1)` bound in two ways:

1. it applies to **arbitrary** bounded-degree feature families, not only powers of one linear label;
2. redundant low-degree features do not increase the attack rank beyond the actual feature-function dimension on the cube.

For the Run-84 powers, `d=m-1`, so the earlier `m(R+m+1)` estimate is recovered as a coarse special case.

## 5. Exponentially many directions

Fix the free coordinate set `T` and vary the outside assignment `z`.
There are

\[
2^{N-s}=2^{N-R-d-1}
\tag{21}
\]

choices.

Because the constant feature block retains the old nonzero anchor, two choices of `z` that differ in an outside coordinate give different matrices: in that block one has outside column zero while the other has that column equal to the nonzero constant column.

Thus the false source space contains at least

\[
\boxed{2^{N-R-d-1}}
\tag{22}


distinct anchor-sensitive directions satisfying the rank bound (20).

## 6. When is this an actual classical PPT construction?

There are two distinct claims and they must not be conflated.

### 6.1 Generic direct-enumeration attack for logarithmic degree

The support of (15) has size

\[
2^s=2^{R+d+1}.
\tag{23}
\]

If the public compiler can evaluate `A_tilde_Phi(b)` and each feature in polynomial time, and

\[
R+d=O(\log N),
\tag{24}
\]

then (23) is polynomial in `N`. The attacker simply evaluates the polynomially many supported assignments, forms (15), and solves for public source-basis coordinates by Gaussian elimination.

With the usual

\[
R=\lfloor\log_2N\rfloor,
\]

**every feature lift with maximum Boolean degree `d=O(log N)` is therefore subject to a direct classical-PPT construction of this false anchor-sensitive matrix.**

For `N` a power of two and `d=c log_2 N`, the support is exactly

\[
2N^{c+1}.
\tag{25}
\]

So even increasing the number of features does not fix the attack if their algebraic degree remains logarithmic.

### 6.2 Larger degree: existence versus public-update constructions

When `d` is superlogarithmic, direct enumeration of (23) may be superpolynomial. Theorem 2 remains an algebraic existence/rank result but must not automatically be called a PPT attack.

However, if the feature lift admits the same kind of **public linear bit-update operators** used in Run 85, the Hamming-weight dynamic program constructs the sum (15) using `O(s^2)` update applications. Under that additional property the family is again publicly polynomial-time constructible even for large `s`.

The Run-84 first-powers feature lift is one concrete example of this second case.

## 7. Exact degree floor for this family

The bounded-degree cube construction exists whenever

\[
d\le N-R-1.
\]

Therefore the first maximum feature degree that escapes **this particular degree argument merely by running out of Boolean directions** is

\[
\boxed{d=N-R.}
\tag{26}
\]

This is not a security theorem for degree `N-R` or larger. It only says the explicit `s=R+d+1` cube no longer fits.

The result sharpens Run 85: the apparent linear feature-count threshold there was really a consequence of the special power basis, whose maximum Boolean degree is `m-1`. The more invariant obstruction is the **maximum Boolean algebraic degree** of the feature span.

## 8. Exact local repair criterion and why it is not yet a construction

Theorem 1 is also sharp.
On a fixed cube, if the feature-weight span is augmented to contain

\[
g_C=f^{-1}|_C,
\]

then every vector satisfying the source constraints has zero old anchor on that support.
The checker validates this exact transition: before adding `g_C`, the test space has an anchor-sensitive null vector; after adding it, all null vectors pair to zero with `g_C`.

But this is only a local algebraic observation. A generic NP setup algorithm does not receive an unsatisfiability witness, and constructing compact public functions whose feature-weight span contains the required reciprocal violation on all relevant false-instance supports is itself the missing compiler problem. No claim is made that it is impossible; it simply identifies the exact object a successful repair must synthesize.

## 9. Consequence for the rank-mask / field-key family

Let

\[
B=(R+d+2)r_\Phi(C)
\]

or use the explicit upper bound from (20).
The complete-output character law from Runs 78–82 gives a public key-sensitive character of magnitude at least

\[
q^{-rB}
\tag{27}
\]

for randomizer rank `r`.

Thus, for any parameter set in which this quantity is non-negligible, the construction has a **classical PPT distinguisher** whenever Section 6 supplies a PPT construction of the source direction. That attack is automatically valid against the desired QPT-security claim.

For the Run-81 common-eigenvalue decoder, a publicly constructed false source matrix of rank `rho<=B` becomes a direct false pseudowitness whenever

\[
\boxed{t>rB.}
\tag{28}
\]

Then the visible random part is necessarily rank-deficient and the nonzero anchored key shift is an eigenvalue of every capsule.

Outside these parameter regions, this run supplies a structural/rank/spectral obstruction, not a complete break.

## 10. Validation actually executed

`bounded_degree_feature_barrier_run86_check.py` is deterministic and uses the exact already-published `rank_field_extensions.py` implementation as its compiler dependency.
It was executed twice and stdout was byte-identical.

The checker validates:

* **14** actual false-family members across five random bounded-degree feature lifts, not the first-powers lift:
  * `(N,R,d,m)=(4,1,1,5)`, observed rank 6;
  * `(5,1,2,4)`, observed rank 10;
  * `(6,2,1,6)`, observed rank 10;
  * `(6,1,3,4)`, observed rank 15;
  * `(7,2,2,5)`, observed rank 20;
* every augmented Hair–Sahai source-constraint residual is exactly zero;
* every anchor equals the closed-form finite-difference value and is nonzero;
* on every tested cube, `g=1/f` lies outside the actual feature-weight span `W_C`;
* the explicit alternating vector is orthogonal to every row of `W_C` and pairs nontrivially with `g`;
* the refined rank bound `r_Phi(C)(s+1)` holds exactly;
* feature-evaluation ranks obey the degree-space bound (18); in two controls the feature count deliberately exceeds the actual degree-`d` function-space dimension;
* an exact sharpness control on an 8-point cube:
  * `rank(W)=7`, nullity 1, and the nullspace contains an anchor-sensitive vector;
  * after adding `g`, `rank(W+<g>)=8`, nullity 0, so no anchor-sensitive null vector remains;
* direct-enumeration complexity ledgers for `d=c log_2 N`, verifying support `2N^(c+1)` for `c=0,1,2` on powers of two;
* the degree-floor and rank-mask necessary-condition ledgers.

These are finite algebra and implementation checks. They do not establish LWE/SIS/MinRank hardness or QPT security.

## 11. Literature/QPT ledger

* **Hair–Sahai, arXiv:2609.18275:** their paper constructs NP witness encryption in the **classical generic-group model**. This run uses only the weighted-table/source-rank algebra and the degree-`<=R` property of the listed weights. It does not import the generic-group encryption theorem as post-quantum security.
* **Jin, ePrint 2026/2063:** the current primary record states a Karp–Levin reduction from polylog-size circuit SAT to GapMDP with `omega(log lambda)` approximation and extractable WE for polylog-size circuits in the generic-group model. The PDF remained inaccessible through the available web path in this run, so the full extraction chain is still not treated as audited.
* **Jin, ePrint 2026/1087:** a directly relevant 2026 manuscript surfaced during the search. Its primary abstract says the proposed low-norm Nullstellensatz hypothesis for the AND code is false via an exponential coefficient-norm lower bound. The PDF was not accessible in this run. This is a caution against assuming cheap algebraic certificates; it is not used as a theorem in the Run-86 proof.
* **Evasive-LWE literature:** ordinary lattice terminology does not close the gap. Known WE candidates from evasive LWE rely on assumptions stronger than standard LWE, and private-coin variants have subsequent counterexample/attack literature. No such assumption is imported here.

### QPT classification

**Honest compiler model:** classical polynomial time in its explicit dimensions.

**Run-86 algebraic family:** unconditional finite-field algebra.

**Efficient adversary model:** classical PPT under the explicit conditions in Section 6. A classical attack is automatically a valid attack against a QPT-security claim.

**QPT false-statement hiding:** UNPROVED outside the explicit vulnerable/non-negligible regions.

**Arbitrary-QPT early final-key recovery -> ORIGINAL source witness or independent PQ break:** UNPROVED.

**Supplied low-rank source extraction:** retained from the algebraic source compiler, but this is not a reduction from arbitrary key recovery.

## 12. Handoff

Run 86 rules out a substantially larger repair class than Runs 84–85:

> **Feature count is not the relevant escape knob.** If all public rank-one-preserving feature coordinates have bounded Boolean degree `d`, an `(R+d+1)`-fold false finite difference survives whenever it fits inside the Boolean cube. For logarithmic `d`, the attack is directly classical-PPT even without special update structure.

A promising next construction therefore needs at least one of:

1. a compact **high-Boolean-degree** feature/code mechanism whose source span remains polynomial-time constructible and whose complete public output has a QPT-standard-assumption proof;
2. a genuinely coding-theoretic gap compiler such as the GapMDP route suggested by Jin, after the full source-extraction chain can actually be audited;
3. a release layer not based on turning this explicit linear assignment-table source space into pseudorandomness.

The exact subcube criterion (5) gives a concrete test for future proposals: compute the feature-weight span on a strategically chosen false subcube and ask whether it contains the reciprocal violation. If not, an anchor-sensitive false representation exists immediately.

The complete practical generic-NP QPT WKEM stopping condition is **not met**.
