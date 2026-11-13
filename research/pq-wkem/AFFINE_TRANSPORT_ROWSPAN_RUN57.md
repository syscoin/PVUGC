# Run 57 — singular affine transport still exposes a public endpoint evaluator

**Status:** constructive follow-up to Run 56 plus a stronger complete-output attack on the *noiseless* affine-transport family, and a scoped minimum-noise theorem for real isotropic/Gaussian noise. This is **not** a completed witness KEM, is **not** a modular-LWE break, and is **not** a generic impossibility theorem for nonlinear/computational witness encodings.

Starting verified PR head: `89ffa533bca1ff913614814ee8dd34cb7b9de51f` (Run 56). The Run-56 noisy affine transport result, the earlier branching-intertwiner result, and the Run-42 SIS source-binding lemma were read before this pass. No external literature or web search was used. Production code is unchanged.

## 1. Constructive escape hatch tested

Run 56 rejected the natural well-conditioned realization

\[
C_{i,b}=R_{i+1}-R_iA_{i,b}+E_{i,b}
\]

because branch differences

\[
C_{i,0}-C_{i,1}=-R_i(A_{i,0}-A_{i,1})+(E_{i,0}-E_{i,1})
\]

can recover the erased frame whenever the branch difference is invertible and its inverse preserves the error scale.

The obvious escape is therefore to force **every** branch difference to be singular / underdetermined. This run tests that escape against the *complete affine transcript*, rather than trying to invert one difference at a time.

The result is stronger than Run 56 in the exact/noiseless setting: on every true targeted instance, the desired endpoint carrier is itself a publicly synthesizable linear functional of the complete transcript. No branch-difference inverse and no frame reconstruction are needed.

## 2. Public transport operator

Work over a field `F`. Let

\[
A_{i,b}\in F^{d\times d},\qquad i=0,\ldots,L-1,\quad b\in\{0,1\},
\]

and public target `T`. A valid source path `w` obeys

\[
A(w):=A_{0,w_0}A_{1,w_1}\cdots A_{L-1,w_{L-1}}=T. \tag{1}
\]

For hidden frames `R_0,...,R_L`, define the noiseless public affine-transport table

\[
C_{i,b}=R_{i+1}-R_iA_{i,b}. \tag{2}
\]

Programming the key carrier means

\[
R_L=R_0T+S_K, \tag{3}
\]

so the endpoint functional is

\[
\mathcal L_T(R):=R_L-R_0T=S_K. \tag{4}
\]

Let `M_A` denote the public linear operator taking the frame tuple to the *entire* branch table:

\[
(M_A R)_{i,b}=R_{i+1}-R_iA_{i,b}. \tag{5}
\]

All coefficients of `M_A` and of `L_T` are public.

Everything below can be applied row-by-row to the frame matrices. The matrix notation is retained because it makes the path identity transparent.

## 3. Proved theorem: a true path puts the endpoint functional in the public row span

For a path `w`, define suffix products

\[
U_i(w)=A_{i+1,w_{i+1}}\cdots A_{L-1,w_{L-1}},
\]

with `U_{L-1}=I`, and define the linear transcript evaluator

\[
Q_w(C):=\sum_{i=0}^{L-1} C_{i,w_i}U_i(w). \tag{6}
\]

Substituting (2) telescopes:

\[
Q_w(M_A R)=R_L-R_0A(w). \tag{7}
\]

Hence if `w` is a valid source path with `A(w)=T`,

\[
\boxed{Q_w M_A=\mathcal L_T.} \tag{8}
\]

Equation (8) is an identity of public linear maps. It has an immediate consequence that does **not** require the attacker to know `w`:

> **Endpoint row-span theorem.** If the targeted branching instance is true, then every scalar row of `L_T` lies in the row span of the complete public transport operator `M_A`.

Therefore an attacker can solve the public linear system

\[
\boxed{Q M_A=\mathcal L_T} \tag{9}
\]

by Gaussian elimination and obtain *some* evaluator `Q`. On an exact transcript,

\[
\boxed{Q C=Q M_A R=\mathcal L_T(R)=S_K.} \tag{10}
\]

The recovery algorithm does not search for, output, or use a witness. The witness is used only in the proof that (9) is consistent on a true instance.

### Equivalent kernel proof

The same fact can be stated without constructing `Q_w`. If `X` is in `ker(M_A)`, then for every layer and both branches

\[
X_{i+1}=X_iA_{i,b}. \tag{11}
\]

Following any valid path gives

\[
X_L=X_0A(w)=X_0T, \tag{12}
\]

so

\[
\mathcal L_T(X)=X_L-X_0T=0. \tag{13}
\]

Thus

\[
\ker(M_A)\subseteq\ker(\mathcal L_T), \tag{14}
\]

which over a field is equivalent to the row-space inclusion required by (9).

## 4. Why singular branch differences do not repair the exact construction

The theorem makes **no** rank assumption on

\[
A_{i,0}-A_{i,1}. \tag{15}
\]

They may all be singular, rank one, or even zero. Run 56's local estimator may then be unavailable, yet the complete transcript still supplies the public system (9).

The fresh finite-field checker deliberately uses `d=3`, `L=6`, `q=101`, with

\[
A_{i,1}=A_{i,0}+u_iv_i^T, \tag{16}
\]

so every branch difference has rank exactly one. In all **500/500** true fixtures, public Gaussian elimination synthesized `Q` and recovered the exact endpoint functional without the witness.

This rejects the specific escape hatch “make all branch differences singular” for the noiseless affine-transport candidate.

### Important non-extraction control

The row-span test is **not** a source-witness extractor and is not an iff characterization of truth.

For every one of the 500 finite-field programs, the checker also sampled a matrix target `T_false` that was not equal to any of the `2^L` public path products. In **500/500** such false-target controls, the same public linear system still had a solution.

So in this tested rank-deficient family, endpoint synthesis is even weaker than statement truth: the complete transport operator spans those false endpoint functionals too. One must not turn “a public evaluator exists” into a witness claim.

In particular, if a noiseless setup nevertheless programs `R_L=R_0T_false+S_K`, then the synthesized evaluator exposes `S_K` even though no path reaches `T_false` in that fixture.

## 5. Noisy transcript: exact public evaluator identity

Now publish

\[
C=M_A R+E, \tag{17}
\]

where `E` is the complete branch-error table. For any public solution of (9),

\[
\boxed{Q C=S_K+Q E.} \tag{18}
\]

Every honest valid-path evaluator `Q_w` is simply one feasible solution of the same public linear constraint.

This isolates the remaining issue cleanly: in a noisy construction the question is no longer whether a public evaluator exists—it does—but whether a public evaluator can be found whose coefficients preserve the intended small-noise decoding geometry.

## 6. Proved scoped theorem for real iid Gaussian noise

Flatten one output coordinate. Let `M` be the real transport matrix, `ell` the corresponding endpoint row, and let

\[
\mathcal Q=\{q:qM=\ell\}. \tag{19}
\]

Because a valid witness path gives `q_w in Q`, this affine set is nonempty on a true instance.

Let

\[
q_*=\arg\min_{q\in\mathcal Q}\|q\|_2. \tag{20}
\]

`q_*` is public and computable by ordinary constrained least-norm linear algebra. By definition,

\[
\|q_*\|_2\le \|q_w\|_2 \tag{21}
\]

for every witness-path evaluator.

If transcript errors are independent real Gaussians

\[
E_j\sim N(0,\sigma^2), \tag{22}
\]

then

\[
qE\sim N(0,\sigma^2\|q\|_2^2). \tag{23}
\]

Therefore

\[
\boxed{\operatorname{StdDev}(q_*E)\le
\operatorname{StdDev}(q_wE)}. \tag{24}
\]

So under this *real isotropic/Gaussian* error model, a public witness-free endpoint evaluator is never noisier, coordinate by coordinate, than the particular honest path evaluator used for comparison.

This is a theorem from Euclidean minimum norm and Gaussian covariance; the Monte Carlo below is only a diagnostic of the implementation.

## 7. Why this is not yet a modular-LWE attack

The previous theorem must **not** be transplanted silently into `Z_q`.

A rational or real minimum-norm solution can contain denominators. Reducing, for example, `1/2` modulo an odd prime produces the large residue `2^{-1} mod q`; multiplying a centered small modular error by that residue need not remain centered-small. Likewise, Euclidean minimum norm over `R` is not the same optimization problem as finding a short centered representative among solutions of

\[
qM=\ell\pmod q. \tag{25}
\]

Accordingly this run does **not** prove:

* an attack on standard LWE;
* that every modular noisy affine transport has a short public evaluator;
* that ill-conditioned/singular modular transitions are insecure under a named standard assumption;
* or arbitrary-QPT key recovery -> source witness / SIS break.

A surviving modular construction can now be stated more precisely: it must make the public endpoint-preimage problem (25) computationally hard *at the exact coefficient norm required for decoding*, while valid witnesses produce structured short solutions `q_w`. Any claimed security must then reduce that concrete complete-output distribution to an independently justified PQ problem; calling it “LWE-like” is insufficient.

This is closely analogous to, but not already solved by, Run 42: Run 42 gives source-witness-or-SIS **after** a sufficiently short normalized representation is supplied. Here the missing step would be to connect successful endpoint/key recovery to an appropriate short evaluator or to a standard-assumption break.

## 8. Fresh validation actually executed

`affine_transport_rowspan_run57_check.py` is deterministic and standard-library-only. After finalization it was executed twice; the JSON outputs were byte-identical.

### Finite-field exact checks

Over `F_101`, `d=3`, `L=6`:

* **500** random true targeted programs;
* every branch difference had rank exactly `1 < d`;
* **500/500** public endpoint evaluators synthesized without a witness;
* **500/500** exact endpoint recoveries on fresh random frames;
* **31,500** scalar checks of `Q M = L_T`;
* **500** false targets, each explicitly checked against all `2^6=64` path products;
* **500/500** of those false-target controls also admitted a public endpoint evaluator.

### Exact rational / Gaussian-noise checks

For `d=3`, `L=8`, `A_{i,0}=I`, and `A_{i,1}=P` where `P` swaps the first two coordinates, every branch difference has rank one. A nontrivial even-parity path has target `T=I`.

The checker computed exact rational minimum-Euclidean-norm evaluators. Their squared-norm ratios relative to the chosen honest path evaluator were

\[
0.3125,\quad 0.3125,\quad 0.5, \tag{26}
\]

for the three endpoint coordinates. The largest denominator appearing in the exact minimum solutions was `4`.

It additionally checked:

* **81** exact rational constraint identities;
* **300/300** noiseless rational endpoint recoveries;
* **30,000** iid standard-Gaussian diagnostic trials for one output coordinate.

For that coordinate, the theorem predicts standard deviations

\[
\sqrt{2.5}=1.581138830084\ldots
\]

for the public minimum-energy evaluator and

\[
\sqrt{8}=2.828427124746\ldots
\]

for the chosen honest path. The observed RMSEs were `1.5805142822628546` and `2.8216995757011083`, respectively. These samples are diagnostics only; equation (24) is the actual claim.

The finalized checker SHA-256 is

`de629afc5e0384fb4e32d80f9f5d8ddafc23b69eea2e03c0bc7c5fba3575e1da`.

The byte-identical captured validation SHA-256 is

`8b9895ae60bab25ac4e93081415ff79df763deaa2dad5b37c1a2b1841f994af6`.

## 9. What is proved, tested, and still missing

### Proved

1. On every true targeted instance of the Run-56 affine transport, the endpoint carrier functional lies in the public row span of the complete noiseless transport operator.
2. Hence a witness-free public evaluator can be synthesized by Gaussian elimination and exactly recovers `S_K` from a noiseless transcript, with no branch-difference invertibility and no frame recovery.
3. With arbitrary additive error, every such evaluator obeys the exact identity `Q C=S_K+QE`.
4. With real iid Gaussian transcript error, the public minimum-Euclidean-norm evaluator has no larger per-coordinate noise standard deviation than any honest witness-path evaluator.

### Implemented and actually tested

The finite-field and rational/Gaussian diagnostics listed in Section 8 were executed twice with byte-identical JSON.

### Not proved / remaining central gap

* No modular-LWE small-coefficient theorem was obtained.
* No generic-NP branching compiler with a surviving short-evaluator gap was obtained.
* No false-instance hiding proof for a surviving noisy construction was obtained.
* No arbitrary-QPT early-key-recovery -> source-witness / independent-PQ-break reduction was obtained.
* No final malicious-secure ceremony composition or practical end-to-end parameters can be claimed until the inner release survives the complete-output audit.

The stopping condition is therefore **not met**. The useful handoff is narrower: exact affine transport is now closed even under deliberately singular branch differences. The only potentially surviving affine-transport direction is a **modular short-evaluator gap** in which valid witnesses provide short structured endpoint evaluators but public linear algebra only yields decoding-useless long modular ones, with that gap reduced non-circularly to SIS/LWE or another independently justified PQ assumption. Whether such a generic-NP distribution exists remains unresolved.
