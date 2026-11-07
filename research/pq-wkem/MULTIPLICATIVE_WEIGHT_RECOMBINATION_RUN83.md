# Run 83 — compact multiplicative-weight repair is recombinable: anchor-sensitive one-block attack and an L-block rank ceiling

**Status:** constructive repair attempted and then falsified. A compact high-degree multiplicative weight can reject every individual Run-82 finite-difference pseudorepresentation, while preserving rank-one honest assignments and polynomial span generation. However, two nearby pseudorepresentations can be recombined to defeat any single such challenge while retaining a nonzero key anchor and rank at most `R+4`. More generally, **any `L` appended scalar-weight blocks** leave a nonzero false codeword of rank at most `R+L+2` on an explicit false instance. These are unconditional classical algebraic attacks, so they apply a fortiori to QPT security claims.

**Starting verified PR head:** `c4a33a018607bda7d8e8b1d646d54df9c399e22e`.

The attempted Run-83 opening GitHub checkpoint was blocked by the tool safety layer before reaching GitHub. It was not retried or rerouted in this run. No production path is changed.

## 1. Why this repair looked promising

Run 82 exhibited explicit false-instance source codewords built by an `(R+1)`-fold finite difference. They survive because every original Hair–Sahai weight has total degree at most `R`.

A natural idea is therefore to append a **single compact high-degree weight**

\[
g_c(b)=\prod_{i=1}^N c_i^{b_i},
\qquad c_i\in F_p^\*,\ c_i\ne 1. \tag{1}
\]

This has three attractive properties.

1. For an honest assignment, the new block is still
   \[
   g_c(b)\,v(b)v(b)^T,
   \]
   so the complete assignment matrix remains rank one.
2. It is compact: only the `N` field multipliers `c_i` are needed.
3. It is compatible with the partial-assignment span compiler. When bit `i` changes from `0` to `1`, `g_c` is multiplied by `c_i`, while `v v^T` undergoes the same fixed row/column substitution already used by the base compiler. Hence the new block has a fixed linear update.

The checker executes 360 exact transition identities for this update.

So this is not a strawman or an exponential encoder.

## 2. False family recalled self-contained

Use the explicit false Boolean equation

\[
q_N(b)=\sum_{i=1}^N b_i-(N+1)=0 \tag{2}
\]

over a prime field `F_p` with `p>N+1`.

Let

\[
s=R+1. \tag{3}
\]

Fix a free coordinate set `T` of size `s`, and fix all outside bits to an assignment `z`.

For each `x in {0,1}^s`, let `b(x,z)` be the full assignment and set

\[
\mu_x=(-1)^{|x|},\qquad
\lambda_x=\frac{\mu_x}{q_N(b(x,z))}. \tag{4}
\]

The original weighted-table codeword is

\[
A_z=\sum_x \lambda_x A(b(x,z)). \tag{5}
\]

Because every original listed weight has degree at most `R`, multiplying its source equation by `q_N` leaves the `(R+1)`-fold alternating finite difference of a degree-`<=R` polynomial, hence zero. Thus each `A_z` satisfies all original source constraints.

Every column outside `T` is either zero or a copy of column zero according to the fixed outside bit. Therefore

\[
\operatorname{rank}(A_z)\le R+2. \tag{6}
\]

The public anchor is nonzero. Writing `w=|z|` and `a=N+1-w`,

\[
\alpha_w:=\ell(A_z)
 =\frac{(-1)^{s+1}s!}
 {a(a-1)\cdots(a-s)}
 \ne 0. \tag{7}
\]

Only this explicit algebraic family is needed below. No generic-group encryption theorem is imported.

## 3. One multiplicative challenge rejects every individual family member

The new source constraint on the multiplicative block evaluates on `A_z` as

\[
V_c(z)
 =\sum_x \lambda_x q_N(b(x,z))g_c(b(x,z))
 =\sum_x (-1)^{|x|}g_c(b(x,z)). \tag{8}
\]

Since `g_c` factorizes coordinate-wise,

\[
V_c(z)
 =
 \left(\prod_{j\notin T}c_j^{z_j}\right)
 \left(\prod_{i\in T}(1-c_i)\right). \tag{9}
\]

If all `c_i` are nonzero and every free-coordinate `c_i !=1`, then

\[
V_c(z)\ne0 \quad\text{for every }z. \tag{10}
\]

So the attractive observation is real: **the extra block kills every Run-82 member individually.**

The repair nevertheless fails because source constraints are linear and different members can be recombined.

## 4. Theorem 1 — every single multiplicative challenge has an anchor-sensitive recombination of rank at most R+4

Assume at least two outside coordinates exist:

\[
N-R-1\ge2. \tag{11}
\]

Let `A_0` be the family member with all outside bits zero.

For an outside coordinate `j`, let `A_j` denote the member with only outside bit `j` equal to one.

From (9),

\[
\frac{V_c(e_j)}{V_c(0)}=c_j. \tag{12}
\]

From the anchor formula (7),

\[
r_1:=\frac{\alpha_1}{\alpha_0}
 =\frac{N+1}{N-s}
 =\frac{N+1}{N-R-1}. \tag{13}
\]

### Case 1 — some singleton multiplier does not equal the anchor ratio

If some outside `j` has `c_j != r_1`, then

\[
B=c_j A_0-A_j \tag{14}
\]

satisfies the new multiplicative source constraint because its violation is

\[
c_jV_c(0)-V_c(e_j)=0. \tag{15}
\]

Its anchor is

\[
\ell(B)=c_j\alpha_0-\alpha_1\ne0. \tag{16}
\]

All assignments in (14) use only columns `0`, the `R+1` free columns, and outside column `j`. This remains true after appending the new multiplicative block. Hence

\[
\operatorname{rank}(B)\le R+3. \tag{17}
\]

### Case 2 — every singleton multiplier was tuned to the anchor ratio

Suppose all outside `c_j=r_1`.

Pick two outside coordinates `j,k` and let `A_{jk}` fix both to one. Then

\[
\frac{V_c(e_j+e_k)}{V_c(0)}=r_1^2. \tag{18}
\]

But

\[
r_2:=\frac{\alpha_2}{\alpha_0}
 =\frac{(N+1)N}{(N-s)(N-s-1)}. \tag{19}
\]

The equality `r_1^2=r_2` would imply

\[
(N+1)(N-s-1)=N(N-s), \tag{20}
\]

whose two sides differ by `-(s+1)`. Since `0<s+1<=N+1<p`, this is impossible in `F_p`.

Therefore

\[
B=r_1^2 A_0-A_{jk} \tag{21}
\]

satisfies the multiplicative source constraint but has

\[
\ell(B)=r_1^2\alpha_0-\alpha_2\ne0. \tag{22}
\]

Its possible nonzero columns are only `0`, the free set `T`, and `j,k`, so

\[
\operatorname{rank}(B)\le R+4. \tag{23}
\]

Combining the two cases:

\[
\boxed{\text{Every single multiplicative challenge admits a false,
anchor-nonzero survivor of rank at most }R+4.} \tag{24}
\]

The survivor is explicitly and publicly constructible from at most two finite-difference family members, each of which itself uses only `2^(R+1)` honest assignment matrices.

For `R=floor(log_2 N)`, this remains polynomial time.

## 5. Consequence for the Run-79/81 key-shift family

An anchor-nonzero false source codeword `B` of rank `rho` induces the same public scalar key statistic used in Runs 79–82, with exact key-shift Fourier bias

\[
q^{-r\rho}. \tag{25}
\]

Theorem 1 gives `rho<=R+4`, so the one-multiplicative-block repair still has an explicit classical key-sensitive statistic with bias at least

\[
\boxed{q^{-r(R+4)}}. \tag{26}
\]

This does not prove a non-negligible attack for every parameter choice, but it is a necessary parameter constraint and refutes the idea that the compact high-degree block removed the low-rank key-sensitive tail.

For the Run-81 common-eigenvalue decoder, if

\[
t>r(R+4), \tag{27}
\]

the same false survivor has random visible part of rank below `t`; its anchored key shift is then guaranteed to be an eigenvalue in every capsule. Hence that parameter region remains vulnerable to a polynomial-time false pseudo-witness.

Because these are classical algorithms, they are automatically attacks in the required QPT adversary class.

## 6. Theorem 2 — any L appended scalar-weight blocks leave false rank at most R+L+2

The preceding failure is not specific to multiplicative weights.

Append **any** `L` additional scalar weight blocks to the compiler. Each block may use an arbitrary assignment function; no efficiency assumption is needed for this upper bound. On the single-equation false family (2), every block contributes one additional linear source constraint.

Assume

\[
L\le N-R-1. \tag{28}
\]

Choose `L` distinct outside coordinates `j_1,...,j_L` and consider the `L+1` original family members

\[
A_0,A_{j_1},...,A_{j_L}. \tag{29}
\]

These matrices are linearly independent. Indeed, outside column `j_h` is zero in `A_0` and every `A_{j_k}` for `k !=h`, while in `A_{j_h}` it equals the nonzero column zero. Looking at those outside columns forces every singleton coefficient to zero, and then the nonzero `A_0` coefficient also vanishes.

Let

\[
C\in F_p^{L\times(L+1)} \tag{30}
\]

record the `L` new source-constraint violations of these `L+1` members.

Since `C` has more columns than rows, there is a nonzero

\[
\theta\in\ker C. \tag{31}
\]

Use the same coefficients `theta` on the **fully augmented** assignment combinations, including all new blocks.

Then:

* all original constraints still vanish because every `A_z` satisfied them;
* all `L` new constraints vanish because `C theta=0`;
* the original projection is nonzero by linear independence, so the augmented matrix is nonzero;
* every supporting assignment uses only the columns
  \[
  \{0\}\cup T\cup\{j_1,\ldots,j_L\}.
  \]

Hence the full vertically stacked augmented matrix has

\[
\boxed{\operatorname{rank}\le R+L+2.} \tag{32}
\]

Therefore on this explicit false NP family,

\[
\boxed{d_{\rm rank}^{\rm false}\le R+L+2} \tag{33}
\]

for **every compiler modification consisting only of `L` additional scalar-weight blocks with linear source tests**.

This is an ordinary false-minrank theorem; unlike Theorem 1, it does not guarantee that the survivor has nonzero key anchor for adversarially chosen blocks.

### Interpretation

A modest number of scalar challenge blocks cannot give superlinear rank amplification over this family. To force false rank beyond a target `G` using only this mechanism, one needs at least roughly

\[
L\ge G-R-2. \tag{34}
\]

The theorem is unconditional and challenge-agnostic. It closes a broad family of "add a few clever public weight checks" repairs.

## 7. Why the new block remains a legitimate compiler component

The failure above is not caused by an exponential setup.

For a multiplicative block

\[
G_c(b)=g_c(b)v(b)v(b)^T, \tag{35}
\]

assume bit `i` is currently zero and is changed to one. Let `v'` be the updated Boolean vector. Then

\[
g_c(b')=c_i g_c(b), \tag{36}
\]

and

\[
G_c(b')=c_i g_c(b)v'v'^T. \tag{37}
\]

Because `v_0=1`, the fixed transformation `vv^T -> v'v'^T` is exactly the standard row/column substitution used by the existing partial-assignment compiler. Multiplying by public scalar `c_i` is linear.

Thus each extra multiplicative block adds only `O((N+1)^2)` explicit coordinates and preserves the polynomial span-generation workflow.

The checker validates this exact transition 360 times across three fields.

## 8. Exact finite controls

The finalized deterministic checker was run twice with byte-identical JSON.

### Single multiplicative challenge

For actual weighted-table false instances:

* `N=5,R=2,p=23`: survivor rank `5 = R+3`;
* `N=6,R=2,p=29`: survivor rank `5`;
* `N=8,R=3,p=67`: survivor rank `6`;
* `N=10,R=3,p=83`: survivor rank `6`.

Every individual finite-difference member used in the control had **nonzero** multiplicative challenge violation, yet the explicit two-member recombination had zero new violation and nonzero anchor.

### Arbitrary-L controls

Using `L=1,2,3,4` multiplicative blocks only as convenient concrete arbitrary-weight examples, the checker constructs the nullspace combination from Theorem 2. Every result satisfies all new constraints and the theorem rank bound.

The observed survivor ranks were respectively `5,5,5,5`, below the loose theorem bounds `5,6,7,8`; anchor happened to remain nonzero in all four controls, but no general anchor theorem is claimed for arbitrary extra blocks.

### Complete small-space census

For the exact `N=3,R=1,p=7` false space:

* before augmentation: source dimension `4`, with `84` nonzero rank-3 matrices and `2316` rank-4 matrices;
* after one multiplicative block: source dimension `3`, still with `6` nonzero rank-3 matrices and `336` rank-4 matrices.

So the compact challenge removes most near-gap matrices but **does not raise the minimum rank at all** in this exact fixture.

Passing tests are not used as a security proof; they validate the explicit algebra and implementation.

## 9. QPT classification

**Honest algorithms:** the multiplicative augmentation and span compiler are classical polynomial time.

**Attacks:** Theorems 1 and 2 are constructive classical polynomial-time algebra for `R=O(log N)`. Therefore any concrete key distinguisher/pseudo-witness they induce is also available to QPT adversaries.

**Hardness assumptions:** none.

**Security conclusion:** no QPT hiding is proved. Instead, the single-multiplicative-block repair is explicitly broken as a way to remove the anchor-sensitive low-rank family, and arbitrary `L` scalar blocks obey the false-rank ceiling (33).

The Hair–Sahai generic-group security theorem remains outside the QPT/concrete model and is not used.

## 10. Handoff

The cheap repair "append one compact high-degree multiplicative weight" is now closed:

* it does kill each old finite-difference member separately;
* linear recombination immediately creates a new anchor-sensitive survivor of rank at most `R+4`.

More broadly, appending `L` scalar weight blocks cannot push false MinRank beyond `R+L+2` on the explicit family.

The next constructive route must therefore leave this **scalar-weight-plus-linear-source-test** template if it needs substantially stronger gap amplification. Possibilities that remain logically open are:

1. a genuinely coupled/nonlinear public check whose security reduction is QPT-valid and cannot be neutralized by linear recombination;
2. a source transformation with a proved standard-PQ distributional reduction rather than more public scalar moments;
3. a different encoder entirely.

The complete practical generic-NP QPT WKEM stopping condition is **not met**.
