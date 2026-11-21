# Run 131 — two-sided rank-mask uniformization, effective span capacities, and the anchor-residual criterion

**Status:** substantive algebraic checkpoint; not a generic-NP PQ witness KEM and not a computational hardness proof.

The verified GitHub state at the start of this run was `syscoin/PVUGC#1`, branch `research/pq-wkem-validation-20260918`, head `76e5b632cf00b4372955b871aadd59ded84c5167`, open/draft/unmerged. I read the current PR metadata, latest substantive ordinary comment `5850205385`, and exact-head research records including Run 79 (`ANCHOR_SHIFT_MINRANK_RUN79.md`, blob `30084603c3b35c449be4e154f6d214533526d3c5`), Run 82 (`FINITE_DIFFERENCE_LOWRANK_RUN82.md`, blob `6430557fd1596308db029d17b48549f9ed9490c8`), Run 128 (`UP_HASH_ISOLATION_ALL_WITNESS_BARRIER_RUN128.md`, blob `a534790501f9996bf5af45708d8c16a6267f9569`), and the literature assessment (`literature-20260924/ASSESSMENT.md`, blob `8a1bc1db08156c9ff6410f59963c1af3a0d5a924`).

The immediate mathematical handoff was local Run 130, whose key result was a **left-conditioned** exact-uniformization theorem and the sufficient-route barrier `2k<b`. Run 130 is not on the PR head and is not republished or retried here.

Primary external source retained for the source/rank interface: Hair–Sahai, *Witness Encryption via Prime-Order Generic Groups*, arXiv:2609.18275v1, initial submission 16 September 2026. Only its explicit weighted-table / MinRank source interface is used here. Its security theorem is classical generic-group and is **not** treated as concrete post-quantum security.

---

## 1. Capsule and notation

Let

\[
S_x=\operatorname{span}_{\mathbb F_p}\{B_1,\ldots,B_k\}
\subseteq \mathbb F_p^{a\times b}
\]

be the public statement-derived source space, with public anchor functional `alpha` and anchor coordinates

\[
\ell_i=\alpha(B_i).
\]

Every honest assignment matrix satisfies rank one and anchor one.

For block size `t` and rank parameter `r`, sample

\[
R=\sum_{j=1}^r u_jv_j^T,
\qquad
u_j\in\mathbb F_p^{ta},\quad v_j\in\mathbb F_p^{tb},
\]

and publish

\[
C_i^{(\mu)}=\langle R,J_t\otimes B_i\rangle_t+\mu\ell_i I_t.
\]

Run 79/130 correctness remains unchanged: for every valid witness,

\[
\boxed{2r<t}
\]

separates the `mu=0` and `mu=1` rank intervals deterministically.

The question here is whether the **complete public tuple** can be statistically hidden by conditioning on one side of the rank-one factors.

---

## 2. Run 130 was asymmetric: there is a right-conditioned theorem too

Run 130 conditioned on the left blocks `u_{j,q}` and varied the right blocks. This gives a linear map with domain dimension `rb` and led to the route condition `tk<=rb`.

There is an exact symmetric argument that conditions on the right blocks instead.

Write

\[
v_j=(v_{j,1},\ldots,v_{j,t}),\qquad v_{j,s}\in\mathbb F_p^b.
\]

Condition on all `V={v_{j,s}}`. For one output row `q`, define

\[
T_V:(\mathbb F_p^a)^r\longrightarrow \mathbb F_p^{tk},
\]

\[
T_V(u_1,\ldots,u_r)_{s,i}
   =\sum_{j=1}^r u_j^T B_i v_{j,s}. \tag{1}
\]

The `t` output rows use independent left blocks and therefore are independent conditioned on `V`.

### Theorem 1 — right-conditioned full-output uniformization

If

\[
\operatorname{rank}(T_V)=tk, \tag{2}
\]

then conditioned on `V` the entire unshifted public tuple is exactly uniform over

\[
\mathbb F_p^{kt^2}.
\]

Hence, if

\[
\varepsilon_R=\Pr_V[\operatorname{rank}(T_V)<tk],
\]

then

\[
\boxed{\operatorname{TV}(P_0,P_1)\le \varepsilon_R.} \tag{3}
\]

This is information-theoretic. If `epsilon_R` is negligible, it hides against unbounded adversaries and therefore against arbitrary QPT adversaries.

No computational assumption is used in (3).

### Horizontal-stack spectrum

A nonzero row dependency of `T_V` is represented by a tuple

\[
(D_1,\ldots,D_t)\in S_x^t\setminus\{0\}.
\]

For one rank-one factor `j`, the dependency condition is

\[
\sum_{s=1}^t D_s v_{j,s}=0.
\]

For uniform right blocks its probability is

\[
p^{-\operatorname{rank}([D_1\;D_2\;\cdots\;D_t])},
\]

where the matrices are concatenated **horizontally**. Across `r` independent terms,

\[
\boxed{
\varepsilon_R
\le
\sum_{(D_1,\ldots,D_t)\ne0}
 p^{-r\,\operatorname{rank}([D_1\;\cdots\;D_t])}.
} \tag{4}
\]

This is the horizontal counterpart of Run 130's vertical-stack spectrum.

---

## 3. The effective capacity is not the raw long dimension `a`

At first sight (1) appears promising because the domain has `ra` coordinates, and Hair–Sahai's weighted table has a very large row count `a`.

That is too optimistic.

Define the **total column-span capacity**

\[
\mathcal C(S_x)
=
\operatorname{span}\{B_i z:\ i\in[k],\ z\in\mathbb F_p^b\}
\subseteq\mathbb F_p^a,
\]

and

\[
c_{\rm col}=\dim \mathcal C(S_x)
=\operatorname{rank}([B_1\;B_2\;\cdots\;B_k]). \tag{5}
\]

Every row of `T_V`, viewed in `(F_p^a)^r`, lies in the direct sum of `r` copies of `C(S_x)`. Therefore

\[
\boxed{\operatorname{rank}(T_V)\le r c_{\rm col}.} \tag{6}
\]

So right-conditioned full uniformization requires

\[
tk\le r c_{\rm col}. \tag{7}
\]

Combining (7) with correctness `2r<t` forces the strict necessary condition

\[
\boxed{2k<c_{\rm col}.} \tag{8}
\]

This replaces the naive condition `2k<a`. The huge literal table height is irrelevant if all columns live in a much smaller feature span.

### Symmetric refinement of Run 130

Likewise define

\[
c_{\rm row}
=
\dim\operatorname{span}\{z^TB_i:\ i\in[k],\ z\in\mathbb F_p^a\}
=
\operatorname{rank}
\begin{bmatrix}B_1\\ \vdots\\ B_k\end{bmatrix}. \tag{9}
\]

The left-conditioned map of Run 130 actually obeys

\[
\operatorname{rank}(L_U)\le r c_{\rm row}, \tag{10}
\]

so its exact capacity condition is

\[
\boxed{2k<c_{\rm row}\le b.} \tag{11}
\]

Run 130's `2k<b` condition was therefore a valid coarse barrier for that route, but `c_row` is the sharper statement-derived invariant.

---

## 4. Hair–Sahai's long side is itself bounded by a low-degree feature span

For an honest weighted-table assignment matrix, write

\[
A(b)=g(b)v(b)^T,
\]

where `v(b)=(1,b_1,...,b_N)` and the coordinates of `g(b)` have the form

\[
h(b)v_x(b)
\]

with `deg h<=R`.

On the Boolean cube, every coordinate of `g(b)` is therefore a multilinear polynomial of degree at most `R+1`. Consequently

\[
\boxed{
c_{\rm col}
\le
\dim\operatorname{span}\{g(b):b\in\{0,1\}^N\}
\le
\sum_{d=0}^{R+1}\binom Nd.
} \tag{12}
\]

This is an algebraic feature ceiling. It explains why swapping the conditioning side does **not** automatically unlock the full Hair–Sahai row count

\[
a=(N+1)(2NR+1)\binom{2R}{R}.
\]

The right-conditioned route must be judged using the public source's actual `c_col`, not `a`.

---

## 5. Literal-v1 false fixtures: the symmetric rescue fails from `N=3` onward

The deterministic checker reconstructs the literal weighted-table source for the explicit false equation

\[
q_N(b)=\sum_i b_i-(N+1)=0
\]

and computes the exact public source dimension and both span capacities.

These are finite algebra fixtures, not Hair–Sahai's full cryptographic field-size parameters.

| N | R | p | k | a | b | `c_col` | `c_row` | `sum_{d<=R+1} C(N,d)` | `2k<c_col` |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|:---:|
| 2 | 1 | 5 | 1 | 30 | 3 | 3 | 3 | 4 | yes |
| 3 | 1 | 11 | 4 | 56 | 4 | 6 | 4 | 7 | no |
| 4 | 2 | 17 | 5 | 510 | 5 | 10 | 5 | 15 | no |
| 5 | 2 | 37 | 15 | 756 | 6 | 20 | 6 | 26 | no |
| 6 | 2 | 67 | 36 | 1050 | 7 | 41 | 7 | 42 | no |

The striking case is `N=3`: the raw row dimension is `a=56`, yet the complete source column capacity is only `6`. For correctness-compatible `t=2r+1`, the right-conditioned target has dimension `4t>8r`, while the induced map has rank at most `6r`. Full uniformization is therefore impossible for **every** `r`, despite the long matrix side.

In 200 deterministic samples for each `r=1,2,3,4`, the right-conditioned map actually saturated its algebraic ceiling `6r` every time; the left-conditioned map saturated `4r` every time. The theorem needs only the ceiling, not these samples.

The `N=2` fixture remains a genuine positive slice: `k=1`, `c_col=c_row=3`, so both capacity conditions can coexist with `2r<t`. At `r=2,t=5`, 291 of 300 deterministic right-conditioned samples had full row rank. This is validation of the finite identity, not an asymptotic security claim.

---

## 6. Full uniformity is sufficient, not necessary — exact anchor-residual criterion

The capacity barrier above must **not** be overclaimed. `P_0` and `P_1` can in principle be close even when the conditioned unshifted tuple is not uniform.

For the left-conditioned map, let

\[
K=S_x\cap\ker\alpha
\]

and choose any public `A_* in S_x` with `alpha(A_*)=1`, so

\[
S_x=K\oplus\langle A_*\rangle.
\]

In this basis split the conditioned linear map into

* `L_K`, producing all anchor-zero source coordinates; and
* `L_A`, producing the `t` anchor coordinates.

For each output column, the message shift is a pure anchor basis vector. Therefore all `t` required shifts lie in the conditioned image **iff**

\[
\boxed{
L_A\big|_{\ker L_K}:\ker L_K\to\mathbb F_p^t
\text{ is surjective.}
} \tag{13}
\]

Equivalently, after conditioning on the left factors, the two message distributions are the **same coset distribution** iff the residual rank in (13) is `t`.

This is strictly weaker than full surjectivity of `L_U`. Thus (8)/(11) are barriers to the exact-uniformization proof, not universal impossibility theorems for the capsule.

The checker independently verifies the linear-algebra equivalence between shift containment and residual rank.

---

## 7. Anchor-zero evaluation spectrum: why the relaxed same-factor coupling also fails on the `N=3` fixture

The same decomposition gives a useful diagnostic for (13).

For a tuple

\[
V=(v_1,\ldots,v_r)\in(\mathbb F_p^b)^r,
\]

define

\[
d_K(V)
=
\dim\operatorname{span}_{D\in K}
\{(Dv_1,\ldots,Dv_r)\}. \tag{14}
\]

For a fixed nonzero `V`, the probability over the `t` independent conditioned left-block groups that

\[
L_K V=0
\]

is exactly

\[
p^{-t d_K(V)}. \tag{15}
\]

Hence

\[
\boxed{
\Pr[L_K\text{ is non-injective}]
\le
Z_K(r,t)
:=
\sum_{V\ne0}p^{-t d_K(V)}.
} \tag{16}
\]

If `L_K` is injective then `ker L_K={0}`, so the residual map in (13) has rank zero and the same-left-factor coset coupling is impossible.

Again, this does **not** give a public distinguisher: the conditioned factors are not published. It only closes this particular statistical-coupling route.

### Exact `N=3,p=11` anchor-zero census

Here `dim K=3` and `b=4`. Exhausting all `11^4-1=14,640` nonzero right vectors gives

\[
\#\{v:d_K(v)=2\}=40,
\qquad
\#\{v:d_K(v)=3\}=14,600. \tag{17}
\]

The 40 exceptional vectors are exactly four projective lines. Their evaluation maps have four distinct one-dimensional kernels in `K`.

Therefore for an `r`-tuple `V`, rank two occurs exactly when all nonzero components lie on the same exceptional projective line. Thus

\[
N_2(r)=4(11^r-1), \tag{18}
\]

and every other nonzero tuple has `d_K(V)=3`. The exact first-moment bound becomes

\[
Z_K(r,2r+1)
=
\frac{4(11^r-1)}{11^{2(2r+1)}}
+
\frac{11^{4r}-1-4(11^r-1)}{11^{3(2r+1)}}. \tag{19}
\]

Its negative log2 values are approximately:

* `r=1`: 15.09 bits;
* `r=2`: 23.77 bits;
* `r=4`: 38.05 bits;
* `r=8`: 65.73 bits;
* `r=16`: 121.08 bits;
* `r=32`: 231.78 bits.

In 200 deterministic `r=1,t=3` samples, `L_K` was injective every time and the anchor-shift containment event never occurred. The general statement is the bound (19), not the sample count.

So the `N=3` actual-source fixture exhibits both obstructions simultaneously:

1. neither side can reach full conditioned uniformity because of the source's effective span capacities; and
2. the weaker **same-left-factor** anchor-residual coupling is itself overwhelmingly unavailable according to the exact `K` evaluation spectrum.

This still does not prove the unconditional public distributions are far apart. A different coupling, nonlinear argument, or computational reduction could in principle exist.

---

## 8. What this changes from Run 130

Run 130's left-conditioned theorem remains correct, but its apparent `b`-side bottleneck was not the end of the conditioning analysis.

The corrected picture is:

* there are **two** exact full-uniformization routes, left-conditioned and right-conditioned;
* their true resources are the statement-derived effective capacities `c_row` and `c_col`, not merely the raw matrix dimensions;
* Hair–Sahai's long side is compressed by low-degree feature geometry, so the right-conditioned rescue can still fail badly;
* full uniformity is only sufficient, and the exact weaker same-factor condition is the anchor-residual surjectivity (13);
* on the first nontrivial literal false fixture, the anchor-zero map is generically injective enough that this weaker coupling also does not rescue the construction.

This is a more precise barrier than simply saying `2k<b`.

---

## 9. QPT/security ledger

### Honest algorithms

All algorithms and identities in this checkpoint are classical finite-field linear algebra and sampling; they are polynomial time in the explicit source representation.

### Adversary model

The hiding implication in Theorem 1 is **information-theoretic** when its rank-failure probability is negligible, hence it includes arbitrary QPT adversaries.

The capacity and residual results are algebraic proof-route statements, not security theorems.

### Hardness assumptions

None are used for the new conditional-uniformization/capacity theorems.

### Reduction model

No rewinding, random-oracle programming, extraction, or quantum auxiliary-information argument occurs in the new statistical implication.

### Still unproved

* generic false-statement QPT hiding for the complete public transcript;
* any standard-LWE/SIS or other independently justified QPT-hard computational reduction for the cases where statistical uniformization fails;
* arbitrary-QPT unauthorized true-statement FINAL-key recovery `=>` ORIGINAL source witness or independent QPT-hardness break;
* malicious-secure erased setup/abort and auxiliary-output composition;
* practical generic-NP parameters.

Hair–Sahai's supplied-low-rank-object-to-original-witness extractor remains only a semantic last arrow. Its classical generic-group security theorem does not fill the missing concrete PQ reduction.

---

## 10. Precise next handoff

The highest-value next step is no longer to count raw left/right coordinates. It is to analyze the **unconditional** message-sensitive distribution after both rank-one factors are mixed.

Two focused options survive:

1. derive a joint two-sided rank-spectrum / bilinear image theorem that can exploit transformations of **both** `U` and `V`, rather than same-factor translation; or
2. construct a source-restricted transform that increases the effective anchor-bearing span ratio `c/k` while preserving every honest rank-one witness and the supplied-low-rank ORIGINAL-source extractor, and immediately test it against Runs 82, 120, 126, and 129.

Any candidate must still carry an explicit QPT reduction or information-theoretic proof for the full published view. A named structured-hardness assumption is not sufficient.

The practical generic-NP public/offline PQ witness-KEM stopping condition remains **unmet**.
