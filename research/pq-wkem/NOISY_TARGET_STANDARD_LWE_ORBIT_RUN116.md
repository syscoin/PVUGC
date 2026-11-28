# Run 116 — noisy target sample closes the targeted-value gap under standard LWE, conditional on a uniform-matrix short-preimage compiler

## Status

Verified PR head at the start of this run:
`a0803edfa691f184e33ca92620471a81c17c611c`
on branch `research/pq-wkem-validation-20260918`.
PR #1 was open, draft, and unmerged. The latest ordinary PR comment was
`5843580758`, recording verified publication through Runs 104–111. Runs 112–115 are
local-only in the current conversation after their original publication attempts; this run does
not retry or republish them.

This run starts from the Run-115 noisy short-preimage interface. Run 115 used

\[
 b=A^Ts+e,\qquad z=t^Ts,
\]

and a short preimage `u` with `Au=t` to obtain `b^T u=z+e^Tu`. Its most important
remaining cryptographic gap was that `z=t^Ts` is a **noiseless, statement-derived
linear function of the LWE secret**. Ordinary decision-LWE does not by itself state
that such a value is pseudorandom.

The present run repairs exactly that gap by adding one fresh LWE error to the target:

\[
 \boxed{y=t^Ts+e_0.}
\]

For a suitable matrix/target distribution, `(t,y)` is literally one additional LWE
sample sharing the same secret as `b`, so target-value hiding becomes a direct
straight-line consequence of ordinary decisional LWE. The price is now explicit:
we need a source compiler whose public affine matrix is statistically close to a
**uniform LWE matrix** while every valid source witness still maps to a short preimage.

The run also proves why the two obvious public randomizations do not solve that compiler
problem simultaneously:

* left multiplication by a random invertible matrix preserves witness shortness and
  randomizes a nonzero target, but preserves the row-space structure of the source matrix;
* right multiplication can uniformize a full-row-rank matrix over its rank orbit, but sends
  every fixed nonzero witness to a uniform nonzero field vector, destroying shortness with
  the exact small-ball probability derived below.

This is a genuine constructive narrowing, not a completed WKEM.

---

## 1. Exact noisy-target wrapper

Let

\[
 A\in\mathbb F_q^{n\times m},\qquad t\in\mathbb F_q^n\setminus\{0\}.
\]

A source witness `w` is compiled to an integer vector `u_w` satisfying

\[
 A u_w=t\pmod q,
 \tag{1}
\]

with a public norm guarantee

\[
 \|u_w\|_1\le B_{\rm hon}.
 \tag{2}
\]

Setup samples

\[
 s\leftarrow\mathbb F_q^n,
 \qquad e\leftarrow\chi^m,
 \qquad e_0\leftarrow\chi,
\]

and forms

\[
 b=A^Ts+e\pmod q,
 \tag{3}
\]

\[
 \boxed{y=t^Ts+e_0\pmod q.}
 \tag{4}
\]

For a one-bit raw key `K`, let

\[
 c_0=0,\qquad c_1=\lfloor q/2\rfloor,
\]

and publish

\[
 d=c_K-y\pmod q.
 \tag{5}
\]

A witness computes

\[
 b^T u_w+d
  =s^TAu_w+e^Tu_w+c_K-t^Ts-e_0
  =\boxed{c_K+e^Tu_w-e_0}\pmod q.
 \tag{6}
\]

Thus all valid witnesses recover the same bit whenever the final projected error remains
inside the nearest-center decoding radius.

If

\[
 \|e\|_\infty\le B_e,
 \qquad |e_0|\le B_0,
\]

then deterministically

\[
 |e^Tu_w-e_0|
 \le B_e\|u_w\|_1+B_0
 \le B_eB_{\rm hon}+B_0.
 \tag{7}
\]

A sufficient correctness condition is therefore

\[
 \boxed{B_eB_{\rm hon}+B_0<q/4-O(1).}
 \tag{8}
\]

For discrete-Gaussian or other unbounded errors, (8) is applied on the usual high-probability
tail event; exact tail parameters remain a later concrete-parameter obligation.

---

## 2. Exact FINAL-key -> target-sample recovery

The new target noise does not lose the useful extraction interface of Run 115.
From the exact recovered bit `K` and public `d`, compute

\[
 \boxed{y=c_K-d\pmod q.}
 \tag{9}
\]

So

\[
 \boxed{\text{exact FINAL-key recovery}\Longrightarrow\text{exact recovery of the noisy target LWE sample }y.}
 \tag{10}
\]

No KDF inversion, classical or quantum rewinding, extraction from an internal
representation, or random-oracle programming is used.

For a `kappa`-bit raw key, use independent secrets/errors (or otherwise separately
proved pseudorandom rows). Exact recovery of the whole raw key recovers all target
samples. Parallel repetition is not claimed bandwidth-optimal.

---

## 3. Uniform-matrix compiler assumption

The next theorem isolates the exact source-distribution property that makes (4) an
ordinary LWE sample.

For every fixed source statement `x`, suppose a randomized compiler outputs

\[
 (A,t)\leftarrow\mathsf{Comp}(x;r)
\]

with the following properties.

1. `t != 0`.
2. `A` is uniform over `F_q^{n x m}` and independent of `t`; or the joint distribution
   is within an explicitly bounded statistical distance `delta_comp` of such a pair.
3. Every valid source witness maps efficiently to a short `u_w` satisfying (1)–(2).

Property 2 is intentionally strong. Run 116 **does not construct such a compiler for
arbitrary NP**. The value of this formulation is that, if it exists, the missing
Run-115 targeted-value assumption disappears and ordinary LWE suffices.

---

## 4. Left-GL orbit lemma

Fix any nonzero `t`. Sample

\[
 R\leftarrow GL_n(\mathbb F_q)
\]

and define

\[
 \widetilde A=RA,\qquad \widetilde t=Rt.
 \tag{11}
\]

Then:

### 4.1 Target distribution

`GL_n(F_q)` acts transitively on nonzero vectors, so

\[
 \boxed{\widetilde t\text{ is uniform over }\mathbb F_q^n\setminus\{0\}.}
 \tag{12}
\]

### 4.2 Matrix distribution and independence

If `A` is uniform and independent of `R`, then for every fixed invertible `R`, `RA`
is uniform. Therefore `RA` is independent of `R`, hence independent of `Rt`.
Thus

\[
 \boxed{(\widetilde A,\widetilde t)
  \equiv
  (U_{n\times m},U_{\mathbb F_q^n\setminus\{0\}}).}
 \tag{13}
\]

### 4.3 Witness preservation

The same source-derived preimage works unchanged:

\[
 \widetilde A u_w=RAu_w=Rt=\widetilde t.
 \tag{14}
\]

So left randomization preserves every integer norm of `u_w` exactly.

### 4.4 Secret change of basis

Define

\[
 \widetilde s=R^{-T}s.
 \]

Then

\[
 \widetilde A^T\widetilde s=A^Ts,
 \qquad
 \widetilde t^T\widetilde s=t^Ts.
 \tag{15}
\]

Therefore the left-randomized instance changes neither the LWE outputs nor the target
inner product; it only randomizes the public sample vectors.

---

## 5. Distance from an ordinary LWE sample matrix

Let

\[
 C=[\widetilde A\mid\widetilde t]
 \in\mathbb F_q^{n\times(m+1)}.
\]

The first `m` columns are fully uniform. The final column is uniform conditioned on
being nonzero.

Let `U` denote a fully uniform vector in `F_q^n`. The exact statistical distance is

\[
 \Delta(U\mid U\ne0,\ U)
 =\boxed{q^{-n}}.
 \tag{16}
\]

Hence

\[
 \boxed{C\text{ is }q^{-n}\text{-close to a standard fully uniform LWE sample matrix.}}
 \tag{17}
\]

If the compiler itself is `delta_comp`-close to the required uniform/independent
matrix distribution, the total statistical loss becomes at most

\[
 \delta_{\rm comp}+q^{-n}.
 \tag{18}
\]

---

## 6. Straight-line QPT reduction to ordinary decisional LWE

Define the exact decisional-LWE distribution with `m+1` samples by

\[
 C\leftarrow\mathbb F_q^{n\times(m+1)},\quad
 s\leftarrow\mathbb F_q^n,\quad
 E\leftarrow\chi^{m+1},
\]

\[
 (C,C^Ts+E)
 \quad\text{vs.}\quad
 (C,U_{q}^{m+1}).
 \tag{19}
\]

The adversary model required here is **arbitrary QPT**. Honest setup and decapsulation
remain classical PPT.

For the left-randomized compiler instance, write

\[
 C=[\widetilde A\mid\widetilde t],
 \qquad
 C^T\widetilde s+E=(b,y).
 \]

By (17), replacing the conditioned-nonzero final column with a fully uniform column
changes the public distribution by at most `q^{-n}`. After that replacement,
`(C,b,y)` is exactly an `(m+1)`-sample LWE distribution.

Now replace `(b,y)` by a uniform vector using the decisional-LWE challenge. In this
hybrid, `y` is uniform and independent of `K`, so

\[
 d=c_K-y
\]

is exactly uniform and independent of `K`.

Therefore, for any QPT adversary attacking the one-bit wrapper,

\[
 \boxed{
 \operatorname{Adv}_{\rm key}
 \le
 \delta_{\rm comp}+q^{-n}
 +\operatorname{Adv}^{\rm QPT}_{\rm DLWE}(n,m+1,q,\chi).
 }
 \tag{20}
\]

Here `Adv_key` is prediction advantage over `1/2` for a uniformly sampled hidden bit,
using the usual compatible advantage convention.

The reduction is quantum-safe as a *reduction architecture*:

* it calls the QPT adversary once;
* all surrounding transformations are classical and straight-line;
* there is no rewinding;
* no quantum state is cloned;
* no random oracle is programmed;
* no extractor is invoked on quantum auxiliary information.

Thus the only quantum assumption needed for this arrow is that the exact DLWE
distribution in (19), at the selected parameters, is hard for QPT distinguishers.

Regev's LWE result provides the foundational quantum worst-case-to-average-case
connection for suitable LWE parameters. Peikert later gave classical worst-case
reductions for corresponding LWE variants. Those results justify treating ordinary
LWE as an independently studied PQ assumption; they do **not** instantiate the missing
source compiler or automatically certify arbitrary concrete parameters chosen here.

---

## 7. Unauthorized FINAL-key recovery now has a clean hardness-break endpoint

This is an important improvement over Runs 111–115.

Suppose a QPT adversary outputs the exact hidden `kappa`-bit raw key with probability
`epsilon`, while a key independent of its full public/quantum view can be guessed with
probability exactly `2^{-kappa}`.

A straight-line reduction chooses the key itself, embeds either the real LWE outputs or
the uniform challenge outputs, runs the recovery adversary once, and checks whether its
classical output equals the chosen key.

Therefore any non-negligible gap

\[
 \epsilon-2^{-\kappa}
\]

yields a QPT distinguisher for the LWE hybrid, up to the statistical losses in (18).

So **conditional on the compiler distribution**, the project's required true-instance
endpoint can use the allowed alternative:

\[
 \boxed{
 \text{unauthorized FINAL-key recovery}
 \Longrightarrow
 \text{break ordinary QPT-hard DLWE}
 }
 \tag{21}
\]

rather than requiring FINAL-key recovery to reconstruct an ORIGINAL witness.

This does not solve the project, because the generic-NP compiler is still missing.
But it removes the separate Run-115 noiseless-target leakage assumption and the need
for a process extractor at the final KEM wrapper.

---

## 8. Why source-matrix randomization is the remaining bottleneck

A deterministic or structured source compiler generally will not output a uniform LWE
matrix. Could a public change of basis fix this after the fact?

There are two natural actions.

### 8.1 Left multiplication preserves shortness but not matrix entropy

For fixed full-row-rank `A`, the orbit

\[
 \{RA:R\in GL_n(\mathbb F_q)\}
\]

contains exactly the different ordered bases of the **same row space**. Every linear
dependency among columns is preserved.

Therefore left mixing is perfect for target randomization and witness preservation, but
it cannot turn an arbitrary structured source matrix into a standard uniform LWE matrix.

### 8.2 Right multiplication uniformizes rank orbits but randomizes the witness

Let `A_0` have full row rank and choose

\[
 Q\leftarrow GL_m(\mathbb F_q),\qquad A'=A_0Q.
 \tag{22}
\]

The right action is transitive on full-row-rank `n x m` matrices, so `A'` is uniform
over that rank orbit.

If a fixed nonzero `u_0` satisfies

\[
 A_0u_0=t,
\]

then the corresponding witness is

\[
 u'=Q^{-1}u_0,
 \tag{23}
\]

and

\[
 A'u'=t.
\]

But `GL_m(F_q)` is transitive on nonzero vectors, so

\[
 \boxed{u'\text{ is uniform over }\mathbb F_q^m\setminus\{0\}.}
 \tag{24}
\]

Hence right mixing destroys a fixed short witness except with the exact small-ball
probability of a uniform nonzero field vector.

For odd `q`, use centered representatives in
`[-(q-1)/2,(q-1)/2]`. If `B<q/2`, the number of integer vectors with

\[
 \|u\|_1\le B
\]

is

\[
 N_{m,B}=\sum_{k=0}^{\min(m,B)}2^k\binom{m}{k}\binom{B}{k}.
 \tag{25}
\]

Therefore

\[
 \boxed{
 \Pr_{u'\leftarrow\mathbb F_q^m\setminus\{0\}}
 [\|u'\|_1\le B]
 =\frac{N_{m,B}-1}{q^m-1}.
 }
 \tag{26}
\]

This is exact whenever `B<q/2`.

The checker validates, for example:

* `q=5,m=2,B=1`: probability `1/6`;
* `q=11,m=4,B=2`: probability `1/366`;
* `q=13,m=4,B=3`: probability `8/1785`.

For cryptographic dimensions and a genuinely small honest radius, this is the wrong
regime for correctness.

### 8.3 Conditioning on full row rank is not the main issue

A uniform `n x m` matrix with `m>=n` is rank deficient with probability bounded by

\[
 \Pr[\operatorname{rank}(A)<n]
 \le(q^n-1)q^{-m}<q^{n-m}.
 \tag{27}
\]

Thus when `m-n` is sufficiently large, a uniform full-row-rank orbit is statistically
close to a completely uniform LWE matrix. Right mixing could therefore solve the
**matrix-distribution** issue. Equation (24) shows why it simultaneously destroys the
**short-witness** issue.

This uniformity-versus-shortness tension is the main new structural boundary of Run 116.

---

## 9. Consequences for the two Run-115 source-compiler leads

### 9.1 Hair–Sahai polynomial-gap lattice construction

Hair–Sahai 2608.14529v3 gives a deterministic Karp reduction from 3SAT to
polynomial-gap `GapSVP_p` for every fixed `p>2` (and a corresponding infinity-norm
statement). Their technical overview constructs a highly structured linear code from
the formula; a satisfying assignment gives a sparse codeword, while unsatisfiable
instances force every sufficiently small-support nonzero codeword into a dense regime,
and a Hadamard transform turns the support gap into an `l_p` norm gap.

This is genuinely useful source geometry. But it is **not an average-case uniform
matrix distribution**. Run 116 shows why one cannot simply append a uniform right
basis change to make it look like standard LWE: that transformation also sends the
honest short/sparse witness to a uniform nonzero field vector, destroying the very norm
gap needed by the noisy projective decoder.

So the Hair–Sahai result remains a source-gap component, not yet a standard-LWE
short-preimage compiler.

### 9.2 Lattice linear-PCP / designated-verifier SNARKs

Ishai–Su–Wu compile a linear PCP to a designated-verifier zkSNARK by encrypting the
linear-PCP query matrix under a lattice-based **linear-only** vector encryption scheme.
Their prover homomorphically computes encrypted responses, and the verifier decrypts
and applies the PCP verification predicate. Their Theorem 3.21 obtains knowledge from
statistical linear-PCP soundness plus CPA security and a **strict linear-only property**.
The concrete lattice construction relies on MLWE in addition to a separately stated
linear-only conjecture.

That is not the Run-116 compiler:

* the linear PCP proof/response is witness dependent rather than a single common
  affine target shared by all witnesses;
* the public security theorem uses an extra linear-only conjecture, not standard LWE
  alone;
* converting the proof vector into a uniform-matrix short preimage would still need
  the missing uniformity/shortness transformation.

The paper is valuable evidence that lattices can enforce linear-only proof behavior,
but it does not currently close the generic-NP WKEM target from independently justified
standard LWE alone.

---

## 10. QPT / assumption ledger after Run 116

### Unconditional algebra/distribution results

* Noisy-target identity (6).
* Exact FINAL-key -> noisy target value recovery (9).
* Left-GL target randomization and secret change of basis (11)–(15).
* Exact `q^{-n}` statistical distance in (16).
* Right-GL witness uniformization (24).
* Exact centered-`l1` small-ball probability (26).
* Rank-deficiency bound (27).

These statements hold against unbounded adversaries.

### Conditional QPT theorem

Assume decisional LWE for the exact distribution

\[
(C,C^Ts+E)\approx(C,U)
\]

against arbitrary QPT distinguishers, with `C` uniform and the selected
`(n,m+1,q,chi)` parameters. Then the Run-116 key wrapper is QPT-hidden **provided** the
source compiler supplies the uniform/independent matrix-target distribution up to
`delta_comp`.

The reduction is straight-line and uses the QPT adversary as a black box once, so no
quantum rewinding/QROM/extraction issue is hidden in the composition.

### Still unproved

1. a practical generic-NP compiler that outputs a uniform or quantified-close LWE
   matrix independent of a nonzero target while mapping **every** valid source witness
   to a short affine preimage;
2. source-invalid short-preimage resistance for the complete compiler output,
   including all auxiliary proving/checking material;
3. concrete LWE/error/norm parameters satisfying correctness and security
   simultaneously;
4. malicious-secure multi-party generation of all compiler/LWE randomness with abort,
   erasure, and full auxiliary-input composition;
5. practical end-to-end size and decapsulation cost.

The stopping condition is not met.

---

## 11. Exact validation

`noisy_target_lwe_orbit_run116_check.py` is deterministic and standard-library-only.
Three finalized executions are byte-identical and record **56,134 assertions**.

It independently checks:

1. complete `q=3,n=2,m=2` left-GL orbit counts, proving uniform `A'` and independent
   uniform-nonzero `t'` in the finite model;
2. exact secret change-of-basis identities;
3. exact `q^{-n}` target-conditioning TV distance;
4. the noisy target wrapper, all-witness decoding on the tested radius, and exact
   `K,d -> y` inversion;
5. the deterministic projected-error norm bound;
6. perfect masking when `y` is uniform;
7. the complete `q=5,m=2` right-GL orbit, including uniform matrix/witness marginals;
8. exact centered-`l1` ball counts and small-witness probabilities;
9. exact small-space rank-deficiency probabilities against the elementary union bound.

These tests validate algebra and finite distributions. They do not establish computational
LWE hardness or construct the missing source compiler.

---

## 12. Next handoff

Do **not** return to the noiseless target value from Run 115. The extra target error
turns that value into an ordinary LWE sample and removes a distinct nonstandard
assumption.

The next research question is now almost entirely a compiler question:

\[
\boxed{
\begin{array}{c}
\text{generic NP statement }x\\
\downarrow\\
(A_x,t_x)\text{ with }A_x\approx U,\ t_x\ne0,\ A_x\perp t_x\\
\text{every valid }w\mapsto u_w:\ A_xu_w=t_x,\ \|u_w\|_1\le B_{\rm hon}
\end{array}}
\]

with source-invalid short preimages either impossible or reducible to an independently
justified QPT-hard problem.

The highest-value next pass should test whether a trapdoor/dual-mode lattice compiler
can generate **statistically uniform `A_x` without right-mixing the witness**, perhaps
by programming the statement into the target or into a hidden trapdoor correlation,
while making the trapdoor erasable after setup. Any candidate must be audited against
Run 104's searchable-support issue, Runs 108–110's gadget pseudowitness/decoding attacks,
and the Run-116 right-randomization shortness loss.
