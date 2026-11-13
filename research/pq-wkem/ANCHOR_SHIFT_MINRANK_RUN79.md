# Run 79 — anchor-normalized MinRank syndrome: deterministic witness decoding, exact full-output spectrum, and the entropy/compression barrier

**Status:** constructive literature-derived source-release candidate with exact correctness and complete-output Fourier characterization; **not** a secure generic-NP PQ WKEM.

**Verified starting PR head:** `78a64c95f241814673f1ffbe76a4047033a7331c`.

The immediately preceding Run-78 dual-syndrome work exists only in the local artifact because its GitHub publication was tool-blocked. This run uses its proved algebraic interface but does **not** retry or reroute that blocked publication.

No production path is changed.

## 1. New ingredient: the Hair–Sahai compiler has a public honest anchor

Hair–Sahai's weighted-table source matrix for a Boolean assignment is

\[
A(b)=
\begin{pmatrix}
h_1(b)v(b)v(b)^T\\
h_2(b)v(b)v(b)^T\\
\vdots
\end{pmatrix},
\]

where the weight list contains the constant polynomial `1` and the honest right factor begins with the constant Boolean coordinate,

\[
v(b)=(1,b_1,\ldots,b_N)^T.
\]

Consequently, in the constant-weight block the `(0,0)` entry of every honest `A(b)` is exactly `1`.

This gives a public linear functional

\[
\ell(A)=\text{that anchor entry}
\]

such that every honest assignment matrix satisfies

\[
\ell(A(b))=1. \tag{1}
\]

If `B_1,...,B_k` is a public basis for the binary source space obtained after the previously recorded scalar descent, define

\[
\ell_i=\ell(B_i).
\]

For the coefficient vector `a` of any valid witness matrix,

\[
B(a)=\sum_i a_i B_i,\qquad
\ell(a):=\sum_i a_i\ell_i=1. \tag{2}
\]

This is basis-independent: the functional is defined on matrices and only its coordinate vector changes with the chosen basis.

The source interface used below is therefore:

* **YES:** every valid source witness efficiently supplies `a` with `rank B(a)=1` and `ell(a)=1`;
* **NO:** every nonzero `B(a)` has `rank B(a)>=D`;
* a supplied nonzero low-rank source matrix is still subject to the Hair–Sahai/Run-78 source extractor.

The construction below does not assume setup knows `a`.

Primary source: Hair–Sahai, *Witness Encryption via Prime-Order Generic Groups*, arXiv:2609.18275v1, especially Section 4.3 / Proposition 4.3.

## 2. Construction: put the bit in a rank-metric coset shift

Work over `F_2`.

Fix a block parameter `t` and let `J_t` be the all-one `t x t` matrix. Lift every source basis element to

\[
M_i=J_t\otimes B_i. \tag{3}
\]

This is the Run-78 repair for blockwise coefficient splitting: every block of `M_i` is the same source matrix `B_i`.

Sample a low-rank randomizer

\[
R=\sum_{j=1}^{r}u_jv_j^T,\qquad
u_j,v_j\leftarrow F_2^{ts},                             \tag{4}
\]

where each `B_i` is `s x s`. Hence `rank R <= r`.

For key bit `mu in {0,1}`, publish, for every source-basis coordinate,

\[
\boxed{
C_i^{(\mu)}
   = \langle R,M_i\rangle_t
     + \mu\,\ell_i I_t .
}                                                         \tag{5}
\]

Here `\langle\cdot,\cdot\rangle_t` is the CMV blockwise inner product: output entry `(p,q)` is the Frobenius product of the corresponding `s x s` blocks.

Setup uses only the statement-derived basis and fresh randomness.

A valid witness with coefficient vector `a` computes

\[
C(a)=\sum_i a_i C_i^{(\mu)}
     =\langle R,J_t\otimes B(a)\rangle_t+\mu I_t.        \tag{6}
\]

### Theorem 1 — deterministic same-key correctness

For every matrices `R,B`,

\[
\operatorname{rank}\big(\langle R,J_t\otimes B\rangle_t\big)
\le
\operatorname{rank}(R)\operatorname{rank}(B).           \tag{7}
\]

**Proof.** Write `R=XY^T` with `rho=rank(R)`, partition the rows of `X,Y` into `t` blocks, and write a rank decomposition
`B=sum_{d=1}^{sigma} p_d q_d^T`. Each output entry is a sum over `rho*sigma` products of a term depending only on `p` and a term depending only on `q`; hence the output is a sum of at most `rho*sigma` rank-one `t x t` matrices. ∎

For a valid witness, `rank B(a)=1`, so the unshifted matrix in (6) has rank at most `r`.

Therefore:

* if `mu=0`, `rank C(a)<=r`;
* if `mu=1`,
  \[
  \operatorname{rank}(C(a))
  =\operatorname{rank}(I_t+E)
  \ge t-\operatorname{rank}(E)
  \ge t-r.                                               \tag{8}
  \]

Whenever

\[
\boxed{2r<t,}                                            \tag{9}
\]

the two rank intervals are disjoint. Every valid witness recovers the same bit **deterministically**.

This improves the Run-78 structured-versus-uniform decoder: there is no uniform-side decryption error. It does not by itself imply hiding.

## 3. Complete-public-output Fourier theorem

A character of the complete tuple `(C_1,...,C_k)` is indexed by matrices

\[
\Lambda_i\in F_2^{t\times t}.
\]

Its base-randomizer phase is

\[
\sum_i\langle\Lambda_i,\langle R,M_i\rangle_t\rangle_F
=
\langle R,N_\Lambda\rangle_F,                           \tag{10}
\]

where the `(p,q)` source-sized block of `N_\Lambda` is

\[
N_\Lambda^{pq}
=
B(a^{pq}),\qquad
a_i^{pq}=(\Lambda_i)_{pq}.                              \tag{11}
\]

Because `R` is the sum of `r` independent uniform rank-one outer products,

\[
\boxed{
\widehat P_0(\Lambda)
=
2^{-r\,\operatorname{rank}(N_\Lambda)}.
}                                                         \tag{12}
\]

The message shift contributes

\[
\sigma(\Lambda)
=
\sum_i \ell_i\,\operatorname{tr}(\Lambda_i)
=
\sum_{p=1}^{t}\ell(a^{pp})\pmod 2,                      \tag{13}
\]

so

\[
\widehat P_1(\Lambda)
=
(-1)^{\sigma(\Lambda)}\widehat P_0(\Lambda).            \tag{14}
\]

### Theorem 2 — every message-dependent character inherits the source gap

Suppose the source statement is false and every nonzero source codeword has rank at least `D`.

If `sigma(Lambda)=1`, at least one diagonal coefficient vector `a^{pp}` has

\[
\ell(a^{pp})=1.
\]

It is therefore nonzero. By false-instance source soundness,

\[
\operatorname{rank} B(a^{pp})\ge D.
\]

That matrix is a literal submatrix block of `N_Lambda`, so

\[
\boxed{
\sigma(\Lambda)=1
\Longrightarrow
\operatorname{rank}(N_\Lambda)\ge D
\Longrightarrow
|\widehat P_\mu(\Lambda)|\le 2^{-rD}.
}                                                         \tag{15}
\]

This is stronger than checking only the intended witness decoder: it covers **every linear character of the complete public tuple**.

It still does not prove computational or statistical hiding by itself.

## 4. Why the minimum-rank gap alone is quantitatively insufficient

Let

\[
L=kt^2
\]

be the number of published bits in one capsule.

Using normalized Fourier coefficients and Parseval/Cauchy-Schwarz,

\[
\operatorname{TV}(P_0,P_1)
\le
\sqrt{\sum_{\Lambda:\sigma(\Lambda)=1}
      |\widehat P_0(\Lambda)|^2}
\le
2^{(L-1)/2-rD}.                                         \tag{16}
\]

Thus this **minimum-rank-only sufficient bound** needs

\[
rD\ge \frac{kt^2-1}{2}+\lambda                         \tag{17}
\]

for `2^{-lambda}` statistical hiding.

But deterministic correctness requires `2r<t`, so even at maximal `r` this asks roughly for

\[
D\gtrsim kt.                                             \tag{18}
\]

The currently available Hair–Sahai gap is logarithmic in matrix dimension while the source-basis dimension can be polynomial. Therefore the present minimum-rank promise is nowhere near enough for this generic statistical argument.

Important scope:

* (16) is an upper bound, not a lower bound;
* failure of the bound to become small does **not** prove an asymptotic attack;
* however the small exact false fixture in the checker has
  \[
  \operatorname{TV}(P_0,P_1)=0.765625,
  \]
  so the bare construction is concretely far from hiding there.

The useful next spectral question is therefore not only minimum rank but the **rank-weight enumerator**

\[
\sum_{\Lambda:\sigma(\Lambda)=1}
2^{-2r\operatorname{rank}(N_\Lambda)}.                  \tag{19}
\]

A strong enough enumerator theorem for the actual Hair–Sahai source space could beat the crude `2^{L-1}` character count. No such theorem is claimed yet.

## 5. Outer parity sharing amplifies the gap and the transcript at the same rate

A natural repair is to run `T` independent capsules, choose shares
`b_1,...,b_T` uniformly conditioned on

\[
b_1\oplus\cdots\oplus b_T=\mu,                          \tag{20}
\]

and encode share `b_j` in capsule `j`.

Averaging over the shares kills every Fourier character except those whose share-phase vector is either all zero or all one. Therefore every **message-dependent** surviving character is active in all `T` capsules and has bias at most

\[
2^{-rDT}.                                                \tag{21}
\]

This is a real amplification of each surviving character.

But the published length is also multiplied by `T`, so the same minimum-rank-only `L_2` argument gives

\[
\operatorname{TV}
\le
2^{Tkt^2/2-rDT}.                                        \tag{22}
\]

Thus even the strongest possible support amplification `d=T` leaves essentially the same requirement `D \gtrsim kt`.

The checker exhaustively verifies the parity-sharing Fourier support for
`T=2,...,8`. On the tiny false fixture the exact two-share TV decreases from

\[
0.765625\quad\text{to}\quad0.586181640625,
\]

but is still very large.

This does not rule out a better nonlinear outer code or a proof using the actual rank enumerator. It closes the idea that ordinary linear secret sharing alone fixes the entropy ratio.

## 6. Linear public syndrome compression cannot generically remove the `k` factor

Could one publish only a short linear sketch of the `k` syndrome coordinates?

Fix one block position and write its raw syndrome vector as

\[
y\in F_2^k.
\]

A witness coefficient vector `a` needs the scalar query

\[
a\cdot y.                                                \tag{23}
\]

Suppose setup publishes only

\[
Hy,\qquad H\in F_2^{c\times k}.                          \tag{24}
\]

For `a dot y` to be recoverable from `Hy` **for every `y`**, necessarily and sufficiently

\[
a\in\operatorname{rowspan}(H).                          \tag{25}
\]

Therefore, if the valid-witness coefficient vectors span `F_2^k`, every exact all-witness linear sketch must have

\[
\boxed{c\ge k.}                                         \tag{26}
\]

This condition occurs naturally in the Hair–Sahai precursor: by definition
`\mathcal V=span_b {A(b)}`. On a tautological/no-extra-equation true instance, the honest assignment matrices span the source space itself. In any basis, their coefficient vectors therefore span the full coefficient space.

So a generic compiler cannot erase the `k` factor by a public linear random projection while retaining exact decapsulation for **every** source witness on all true instances.

Scope: this is only a linear-sketch barrier. It does not rule out nonlinear, computationally hidden, or witness-adaptive compression.

## 7. Literature deep dive: Tsabary's lattice WE is architecturally relevant but does not close our assumption/extraction requirements

I also audited Rotem Tsabary, *Candidate Witness Encryption from Lattice Techniques*, CRYPTO 2022, because it is a direct lattice WE predecessor and therefore more relevant than treating LWE merely as an edge transport.

The construction really is a public offline witness-encryption architecture:

* compile the predicate to a branching program resilient to corrupted inputs;
* generate trapdoor matrices layer-by-layer;
* publish trapdoor-derived edge encodings;
* a witness follows the branching program to transform the initial LWE-style challenge.

However, its central security statement is **not** a reduction from standard LWE alone.

### Assumption 31

The paper samples

\[
(A,A_{\rm TD})\leftarrow TrapGen
\]

and then allows auxiliary information, target matrix `T`, a possibly exponential family of prefix matrices `S`, and additional public matrices `B` to be drawn from arbitrary distributions that may be correlated with `A` and its trapdoor. It sets

\[
K\leftarrow A_{\rm TD}(T)
\]

and assumes the relative hardness transformation

\[
LWE[B\cup\{SA\}_{S\in\mathcal S},(K,aux)]
\preceq
LWE[B\cup\{SA,ST\}_{S\in\mathcal S},aux]
+\operatorname{negl}.                                   \tag{27}
\]

The WE security corollary then uses Assumption 31 **plus** standard decisional LWE.

This assumption is exactly about the correlated trapdoor sample/prefix information needed by the construction. It is therefore not justified for our purposes merely by citing ordinary LWE.

The 2025 note by Huang–Hung–Yamada describes evasive-LWE variants introduced by Wee and Tsabary as significant strengthenings of LWE and revisits obfuscation-based attacks on the most general private-coin variant. I am **not** asserting here that Tsabary's exact Assumption 31 is broken; mapping variants requires more care. The relevant conclusion for this project is narrower: it is a nonstandard, construction-specific assumption and does not meet our current requirement for an independently justified ordinary PQ base assumption.

The paper's security statement is also ordinary false-statement WE against PPT adversaries. It does not provide our stronger theorem

\[
\text{arbitrary QPT early key recovery}
\Longrightarrow
\text{original NP witness}
\;\text{or standard-PQ break}.                           \tag{28}
\]

### What is reusable

Tsabary gives a concrete blueprint for **witness-selected hidden-state evaluation**—precisely the source/merge primitive that Run 77 showed ordinary directional LWE edges do not provide.

A potentially meaningful bridge would be to prove the *restricted* correlated-prefix step needed by that architecture from ordinary LWE/SIS using the new Hair–Sahai rank/source gap. No such reduction follows automatically:

* Hair–Sahai controls rank of nonzero matrices in a statement-derived source code;
* Assumption 31 controls LWE samples with trapdoor-derived targets and products of secret prefix matrices.

Connecting those distributions is now a concrete research target, not an assumption we may silently make.

Primary source inspected: Tsabary, CRYPTO 2022 full proceedings PDF, Sections 3.2 and 4.

## 8. Relation to CMV MinRank PKE

Chatterjee–Mu–Vasudevan's PKE is still useful for the matrix-valued duality mechanism, but its reduction samples the public MinRank generators uniformly at random. Its duality lemma's near-uniform dual basis also depends on that random source.

Our `B_i` encode a public NP statement and are not distributed as uniform random matrices. The anchor shift does not change that fact.

Therefore neither (5) nor the Run-78 Kronecker lift is currently reducible to CMV's stated average-case assumption. Naming a new "structured MinRank" assumption would simply move the missing cryptographic step.

## 9. Validation actually executed

`anchor_shift_minrank_run79_check.py` is deterministic and standard-library-only. It was executed twice; the JSON outputs were byte-identical.

The captured execution verifies:

* **2,000** deterministic true-instance rank decodes at `t=3,r=1`; all `mu=0` ranks are at most 1 and all `mu=1` ranks are at least 2;
* a false binary source code in which all three nonzero codewords have rank exactly 2;
* exact enumeration of all **256** rank-one-mask randomness pairs for a false `k=2,t=2` capsule;
* exact false single-capsule TV `0.765625`;
* **512** complete-output Fourier equalities (both message values for all 256 characters);
* all **128** message-dependent characters have spliced rank at least the source gap `D=2`;
* exact two-share parity TV `0.586181640625`;
* parity-share Fourier support for `T=2,...,8`, where the sole message-dependent surviving phase has support exactly `T`;
* normalized-query span/compression controls for `k=2,...,8`, each spanning the full `k` dimensions;
* explicit minimum-rank-only parameter ledgers showing the sufficient statistical bounds are vacuous for the representative `k,D,t` rows.

These checks validate finite identities and the implementation. They are **not** evidence of cryptographic security.

Final local SHA-256:

* checker: `e5ae70b206bb39f2b0f1728925961c5bc6cee55e3d1a07b409049214c65f4933`
* captured validation: `14213525ccbb88d2ccde8beb00e7bb56ca1eb63ce50b14e8f32784208ab48b7c`

## 10. Result classification and next handoff

### Proved in this run

1. The Hair–Sahai source interface supplies a public honest anchor functional.
2. The anchor-shift capsule (5) gives deterministic same-key witness decoding when `2r<t`.
3. Every message-dependent complete-output Fourier character on a false statement inherits rank at least `D`.
4. The minimum-rank-only statistical bound is (16), which is quantitatively inadequate at current `D/k`.
5. Parity secret-sharing forces message-dependent characters to span all copies but does not improve that crude entropy ratio.
6. Exact all-witness **linear** syndrome compression cannot reduce below source coefficient dimension when valid coefficient vectors span the source.

### Constructed / implemented

The anchor-shift encoder/decoder, exact complete-output character evaluator, exhaustive false tiny-distribution census, two-share outer code, and linear-compression controls.

### Literature result

Tsabary's lattice WE gives a valuable hidden-state architecture, but its proof relies on a strong correlated-trapdoor/evasive-LWE-style assumption in addition to ordinary LWE and does not give our QPT source extractor. It is a research component, not the stopping-condition solution.

### Still unresolved

* statistical or computational hiding of the full anchor-shift transcript for the actual Hair–Sahai source spaces;
* a reduction of the statement-derived public distribution to standard LWE/SIS/random-MinRank rather than a new tailored assumption;
* arbitrary-QPT early-key-recovery -> **original** source witness or independent standard-PQ break;
* auxiliary-input / multiple-capsule composition;
* malicious-secure erased setup and abort proof;
* concrete practical parameters.

### Precise next target

The most targeted next calculation is the **rank-weight spectrum**, not another minimum-rank variant:

\[
\sum_{\Lambda:\sigma(\Lambda)=1}
2^{-2r\operatorname{rank}(N_\Lambda)}.
\]

If the actual Hair–Sahai code has sufficiently little low-rank spectral mass, the full-output statistical bound can be much stronger than (16) even though `D << k`. If it does not, the failure gives a quantitative certificate that this entire low-rank-mask family cannot be salvaged by spectral analysis.

In parallel, Tsabary suggests a second concrete route: isolate the exact restricted prefix/trapdoor distribution needed for its branching-program evaluator and test whether the Hair–Sahai gap can prove that restricted step from ordinary LWE, instead of assuming full Assumption 31.

The generic-NP practical PQ WKEM stopping condition is **not met**.
