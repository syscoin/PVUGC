# Run 78 — MinRank dual-syndrome source release: exact correctness, block-splicing audit, Kronecker repair, and entropy barrier

Date: 24 September 2026.

Starting verified PR head: `78a64c95f241814673f1ffbe76a4047033a7331c`.

**Classification:** literature-derived constructive witness-release candidate plus exact complete-output algebra and finite validation. This is **not** a completed generic-NP PQ witness KEM, not a reduction from our statement-derived matrix distribution to average-case MinRank, and not a security claim inferred from passing tests.

No production path was modified.

## 1. Literature interface used in this pass

This pass uses two previously separated ingredients.

1. Hair–Sahai, *Witness Encryption via Prime-Order Generic Groups*, arXiv:2609.18275v1, supplies a polynomial homogeneous matrix space with a Boolean rank-one witness on true statements and a logarithmic lower bound on every nonzero rank on false statements. The preceding literature-integration pass additionally established a binary scalar descent preserving honest rank one and supplied-low-rank source extraction.
2. Chatterjee–Mu–Vasudevan (CMV), *Public-Key Encryption from the MinRank Problem*, arXiv:2510.03752v1, introduces the block-wise matrix inner product

   \[
   \langle A,B\rangle_t[p,q]=\langle A^{pq},B^{pq}\rangle_F
   \]

   and proves a dual-MinRank reduction when the public matrices are **uniform random** binary matrices.

A third paper, Debris-Alazard–Gaborit–Neveu–Ruatta, *A Minrank-based Encryption Scheme à la Alekhnovich-Regev*, arXiv:2510.07584v1, independently emphasizes that correlated low-rank instances require a stationary-MinRank variant rather than automatically reducing to ordinary random MinRank. That warning is directly relevant to our statement-derived public matrix space.

The goal here is to test whether the CMV dual-syndrome mechanism can turn the Hair–Sahai source representation into a public offline witness release, and to audit the **entire** syndrome transcript rather than only the intended witness decoder.

## 2. Source-space interface

Let

\[
\mathcal S_x=\operatorname{span}_{\mathbb F_2}\{M_1,\ldots,M_k\}
\]

be the binary source matrix space for statement `x`. The desired semantic guarantees are:

* if `x` is true, every valid source witness deterministically supplies a nonzero coefficient vector `a` such that

  \[
  M(a)=\sum_i a_iM_i=u v^T,
  \]

  with rank one;
* if `x` is false, every nonzero `M(a)` has rank at least `D`;
* any supplied nonzero matrix in the source space with rank below the extraction threshold yields an original source witness.

For the Hair–Sahai logarithmic-gap compiler, `D` is one more than the allowed low-rank threshold. The exact compiler dimensions depend on the verifier and chosen basis; the construction below treats `(M_i)` only through this interface.

## 3. Constructive candidate: dual-syndrome witness encryption of one bit

Choose `t` dividing the square matrix dimension and choose a mask-rank parameter `r`.

To encode bit `0`, sample

\[
R=\sum_{j=1}^{r}u_jv_j^T
\]

for independent uniform binary vectors `u_j,v_j` and publish

\[
C_i=\langle R,M_i\rangle_t\in\mathbb F_2^{t\times t},\qquad i=1,\ldots,k.
\]

To encode bit `1`, publish independent uniform matrices

\[
C_i\leftarrow\mathbb F_2^{t\times t}.
\]

A witness with coefficient vector `a` computes

\[
C(a)=\sum_i a_iC_i.
\]

### 3.1 Exact correctness inequality

For every matrices `R,M`,

\[
\operatorname{rank}(\langle R,M\rangle_t)
\leq
\operatorname{rank}(R)\operatorname{rank}(M). \tag{1}
\]

To see this, write `R=UV^T`, `M=XY^T`. For output block position `(p,q)`,

\[
\langle U_pV_q^T,X_pY_q^T\rangle_F
 =\operatorname{tr}\big((U_p^TX_p)(Y_q^TV_q)\big).
\]

This is an inner product between vectors of length
`rank(R)*rank(M)`, so the whole `t x t` output factors through that many coordinates and has rank at most the product.

Therefore, for a valid witness with `rank(M(a))=1`, an encoded zero yields

\[
\operatorname{rank}(C(a))\le r. \tag{2}
\]

For an encoded one, because `a != 0` and the `C_i` are independent uniform, `C(a)` is itself a uniform `t x t` binary matrix. A rank threshold therefore gives a public offline witness decoder. All valid witnesses obey the same bound and therefore decode the same message bit except for the uniform-side correctness error.

This is a genuine statement-only construction interface: setup samples `R` without knowing any witness.

It is **not yet secure**, because false-instance hiding must hold for the entire tuple `(C_1,...,C_k)`.

## 4. Complete-output Fourier identity

Let a Fourier character of the published tuple be specified by matrices

\[
\Lambda_1,\ldots,\Lambda_k\in\mathbb F_2^{t\times t}.
\]

Define the block-spliced source matrix `N_Λ` by

\[
N_\Lambda^{pq}=\sum_i (\Lambda_i)_{pq}M_i^{pq}. \tag{3}
\]

Then the entire transcript satisfies the exact character identity

\[
\sum_i\langle \Lambda_i,C_i\rangle_F
=\langle R,N_\Lambda\rangle_F. \tag{4}
\]

For `R=sum_{j=1}^r u_jv_j^T` with independent uniform `u_j,v_j`,

\[
\mathbb E\left[(-1)^{\langle R,N\rangle_F}\right]
=2^{-r\operatorname{rank}(N)}. \tag{5}
\]

For one rank-one summand, conditioning on `v`, averaging over `u` gives zero unless `Nv=0`; the kernel event has probability `2^{-rank(N)}`. Independence across the `r` summands gives (5).

Equation (5) is useful because it reduces **full-output** pseudorandomness to lower bounds on `rank(N_Λ)` for every nonzero transcript character. It also exposes the first failure.

## 5. Exact failure of the naive block-wise composition

The original source-space gap controls only matrices of the form

\[
\sum_i a_iM_i
\]

with **one common coefficient vector** `a` across all matrix positions.

A Fourier character (3) instead chooses an independent coefficient vector

\[
a^{pq}_i=(\Lambda_i)_{pq}
\]

for each block. The complete public transcript therefore enlarges the relevant matrix family to a blockwise splice closure of the source space.

The source MinRank gap need not survive this closure.

### 5.1 Minimal fixture

Take `t=2` and the one-dimensional source code generated by

\[
M=\operatorname{diag}(E_{11},E_{11}).
\]

Its only nonzero source matrix has global rank two. A character selecting only the upper-left syndrome block produces `N_Λ` with only one `E_11` block, hence rank one.

Thus

\[
\text{source minrank}=2
\quad\not\Rightarrow\quad
\min_{\Lambda\ne0}\operatorname{rank}(N_\Lambda)\ge2.
\]

This is a complete-output coefficient-splitting attack on the **proof route**: it does not by itself recover a key, but it invalidates the attempt to derive false-instance hiding from the original global MinRank gap.

The finalized checker verifies this exact fixture and 240 random character identities.

## 6. Positive repair of blockwise coefficient splitting: rank-one Kronecker replication

Let the original source matrices be `B_i` of size `s x s`. Define

\[
\widetilde M_i = J_t\otimes B_i, \tag{6}
\]

where `J_t` is the all-ones `t x t` matrix and hence has rank one.

Then for every common coefficient vector `a`,

\[
\operatorname{rank}\left(\sum_i a_i\widetilde M_i\right)
=
\operatorname{rank}(J_t)\operatorname{rank}(B(a))
=
\operatorname{rank}(B(a)). \tag{7}
\]

So honest rank-one witnesses remain rank one and the original false-instance MinRank threshold is preserved exactly.

More importantly, every block of the character-spliced matrix becomes

\[
N_\Lambda^{pq}=\sum_i(\Lambda_i)_{pq}B_i=B(a^{pq}). \tag{8}
\]

On a false statement, every nonzero block in (8) has rank at least `D`. A nonzero character has at least one nonzero block, and the rank of the entire matrix is at least the rank of any submatrix block. Therefore

\[
\boxed{\Lambda\ne0\implies\operatorname{rank}(N_\Lambda)\ge D.} \tag{9}
\]

Combining (5) and (9), every nontrivial Fourier coefficient of the **complete structured ciphertext distribution** is bounded by

\[
|\widehat P(\Lambda)|\le2^{-rD}. \tag{10}
\]

This is a real positive full-output theorem for the candidate distribution. It does not yet imply practical hiding.

The checker exhaustively validates a two-dimensional false binary code in which all three nonzero source matrices have rank two. After the `J_2` lift, all 255 nonzero full-output characters have spliced rank at least two. It separately verifies that a true rank-one matrix remains rank one.

## 7. Information-theoretic entropy barrier

The published transcript contains

\[
L=k t^2
\]

bits. By Parseval and Cauchy–Schwarz, (10) gives the sufficient statistical bound

\[
\operatorname{TV}(P,U)
\le
\frac12\sqrt{\sum_{\Lambda\ne0}\widehat P(\Lambda)^2}
\le
2^{L/2-rD-1}. \tag{11}
\]

To make this at most `2^-lambda`, the sufficient condition is

\[
rD\ge \frac{k t^2}{2}+\lambda-1. \tag{12}
\]

Intended decoding of a structured zero needs the structured witness output to have rank at most `r`, while the uniform output should exceed the threshold with overwhelming probability; at minimum `r<t` is necessary.

Hence the route through (11) cannot succeed unless approximately

\[
D>\frac{k t}{2}. \tag{13}
\]

For the source spaces already instantiated in the preceding scalar-descent validation, the dimension/gap ratio is far outside this region: one representative fixture has `k=20,D=3`. The finalized checker records several parameter rows; all have a positive exponent in (11), i.e. this sufficient statistical bound is nontrivial in none of them.

This is **not an impossibility theorem for computational hiding**. It is an exact limitation of the simplest low-rank-mask distribution plus this all-character statistical proof.

## 8. Scalar (`t=1`) bias route is correct but quickly impractical

For one scalar Frobenius output and a rank-one witness matrix, (5) gives

\[
\Pr[\langle R,M(a)\rangle_F=0]
=
\frac12+2^{-(r+1)}. \tag{14}
\]

Thus repeated independent capsules can distinguish an encoded zero from uniform without any blockwise splice closure. This avoids the matrix-character issue entirely.

But the bias is `2^-r`. A conservative Hoeffding midpoint analysis needs on the order of `lambda*2^(2r)` repetitions. At `lambda=128`, the checker records approximately:

* `r=1`: 2,840 repetitions;
* `r=4`: 181,705;
* `r=8`: 46,516,320;
* `r=16`: 3,048,493,539,144.

False-instance hiding simultaneously pushes `rD` upward relative to the source dimension. Therefore this scalar route rapidly trades correctness efficiency for false-instance entropy. It remains a mathematically valid control, not a practical solution at the present source parameters.

## 9. Why CMV's average-case MinRank reduction still does not apply

CMV's dual-MinRank theorem samples the public generator tuple uniformly from binary `n x n` matrices. Our `M_i` are deterministically derived from the statement and the source compiler. A semantic minimum-rank gap does not imply that this public distribution is computationally equivalent to CMV's random-code distribution.

Two simple de-structuring attempts can be ruled out exactly.

### 9.1 Zero padding plus rank isometries

The scalar-descent matrices are naturally tall. Padding them with zero columns to make them square creates a large common right kernel. For matrices `M_i`, define

\[
K_R=\bigcap_i\ker(M_i).
\]

Under invertible left/right scrambling `M_i -> P M_i Q`, the dimension of `K_R` is preserved, and invertible changes of the public basis preserve the generated code and hence its common kernel.

For `k` independent uniform `n x n` binary matrices, the exact probability of a nonzero common right kernel is the probability that the stacked `kn x n` matrix lacks full column rank:

\[
1-\prod_{i=0}^{n-1}(1-2^{i-kn}), \tag{15}
\]

which is less than `(2^n-1)2^{-kn}` by a union bound.

The checker pads a `4 x 2` basis to `4 x 4`, obtaining common-kernel dimension two, and verifies invariance under 100 random invertible left/right scramblers and basis changes. As a control, 309 of 5,000 uniform pairs of `4 x 4` matrices had a nonzero common kernel; the exact probability is `0.0575327724`.

Therefore ordinary zero padding and invertible scrambling do **not** give a reduction to CMV's uniform-generator distribution.

### 9.2 Random left projection

A more plausible attempt is to map a tall `m x b` source matrix to `b x b` by a random linear projection `P` on the left.

For a fixed rank-`d` matrix `B`, uniform `P in F_2^{b x m}` preserves rank `d` with probability

\[
\prod_{i=0}^{d-1}(1-2^{i-b}). \tag{16}
\]

Thus the probability of dropping below rank `d` is

\[
1-\prod_{i=0}^{d-1}(1-2^{i-b}) < 2^{d-b}. \tag{17}
\]

If a false source space has dimension `k` and minimum rank at least `D+1`, a direct union bound over all `2^k-1` nonzero codewords is below roughly

\[
2^{k+D+1-b}. \tag{18}
\]

To drive that below `2^-lambda` by this simple argument requires

\[
b\gtrsim k+D+1+\lambda. \tag{19}
\]

The preceding small source fixture has `b=6,k=20,D=3`, already violating the inequality before any 128-bit margin. Also, a projected honest rank-one witness can vanish with probability `2^-b` per fixed nonzero left factor, so simultaneous correctness over many witness encodings would need a separate analysis.

The checker exhaustively enumerates all `2^16` projections for a fixed rank-three `4 x 4` matrix and obtains failure probability `0.384765625`, exactly matching (16).

These facts do not prove no better randomized condenser exists. They show that the two most immediate distribution-randomization bridges do not justify importing CMV security.

## 10. Relation to the stationary-MinRank literature

Debris-Alazard et al. explicitly explain that their low-rank error instances are correlated and therefore their encryption security is based on **stationary-MinRank**, not automatically on ordinary MinRank. Their motivating obstruction is closely analogous to the one here: algebraically useful correlations in the public/ciphertext objects alter the distribution to which hardness must apply.

This does not prove our candidate insecure. It reinforces that naming a new "structured dual syndrome" assumption for the Hair–Sahai source basis would not satisfy the project's requirement for an independently justified base assumption unless a reduction or mature external hardness foundation is provided.

## 11. Validation actually executed

`minrank_dual_syndrome_run78_check.py` is a deterministic standard-library checker. The finalized bytes were executed twice and the two JSON outputs are byte-identical.

Recorded checks include:

* 240 exact blockwise-character identities;
* the explicit source-minrank-2 / spliced-character-rank-1 counterexample;
* all 255 nonzero characters of the lifted two-dimensional false code, with minimum spliced rank two;
* honest rank-one preservation under the Kronecker lift;
* six exact scalar Fourier-coefficient checks for `r=1,2`;
* 500 instances of inequality (1), all with intended rank at most two;
* 600 separate valid-witness structured-output correctness checks;
* exact and sampled uniform `4 x 4` low-rank controls;
* 100 common-kernel invariance checks;
* 5,000 uniform-pair common-kernel controls plus the exact probability (15);
* exhaustive `2^16` left-projection control matching (16);
* the information-theoretic parameter ledger and scalar repetition costs above.

Checker SHA-256:

`c8522798f0dcb48562b0d141362c3800d51fbc563bc116ea681205b714f96cd2`

Captured validation SHA-256:

`571086a3425f0c7f28866f0aef7cbcfe20c6a2dc95984953d4e4e0903563ec14`

The finite checks validate identities and implementation only; they are not cryptographic evidence.

## 12. Result and precise handoff

### New proved/implemented progress

The CMV blockwise inner product gives a real statement-only witness decoder when composed with the Hair–Sahai rank-one source representation. The complete-output Fourier transform can be written exactly in terms of a block-spliced source matrix. Naively the source gap is insufficient, but the simple rank-one Kronecker lift `J_t tensor B_i` repairs this coefficient-splicing defect **for every character**, preserving both the honest rank-one witness and the false minimum-rank threshold.

That is the substantive positive result of this pass.

### Central unresolved obligation

The repaired public generator tuple remains highly statement-structured. CMV's dual-MinRank reduction applies to uniform random generators, not to this tuple. The direct information-theoretic hiding bound is far too weak at the available source dimensions/gaps, while zero-padding/isometric scrambling and plain random projection do not bridge the distribution.

The next high-value target is therefore a **source-preserving randomization/condenser** that simultaneously:

1. preserves every valid rank-one witness in a decodable form;
2. preserves a strong false-instance gap with negligible failure;
3. makes the complete public generator/syndrome distribution reducible to ordinary average-case MinRank, SIS/LWE, or another independently justified PQ assumption;
4. preserves source extraction from any adversarial representation used to recover the final key.

A second route is to determine from Jin's full GapMDP/SNARG construction whether its compressed circuit changes the critical code-dimension/gap ratio enough to make a dual-syndrome or scalar-bias release practical, while retaining extraction all the way to the **original** NP witness. The full Jin manuscript was not obtained in this pass, so no theorem from its proof is being assumed.

Arbitrary-QPT final-key recovery, auxiliary-input/full-transcript composition, malicious-secure erased setup, and practical end-to-end parameters remain unresolved. The stopping condition is not met.

## 13. Publication status for this run

A GitHub checkpoint publication was attempted once and was blocked by the tool safety layer before reaching GitHub. Per the research-record rule, it was **not retried or rerouted**. The research is therefore preserved in the local artifact for this run; no GitHub publication of Run 78 is claimed.
