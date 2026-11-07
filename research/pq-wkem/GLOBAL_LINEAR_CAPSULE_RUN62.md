# Run 62 — one stacked linear capsule really enforces one representation, but exact generic-NP compilation cannot stay linear

**Status: exact positive theorem for public linear relations, complete-output audit, and an unconditional affine-geometry barrier for the Run-61 one-hot verifier; not a completed WKEM.**

This run starts from verified PR #1 head

`4cc75b8b351db5e7aba142c83b750600f521b922`

(Run 61). No external literature or web search was used. Production code is unchanged.

Run 61 proved that 48 public self-challenges can eliminate the explicit Run-53/60 false fibers *semantically* if one and the same representation must satisfy the whole stack. The remaining question was whether the stack can be consumed by one genuinely nonseparable public offline capsule instead of 48 separately decodable shares.

This run studies the cleanest possible realization of that idea. It gives a surprisingly strong exact result for **linear** relations: stacking all constraints into one additive capsule completely removes representation switching and gives information-theoretic false-instance hiding whenever the stacked linear relation is inconsistent. The complete public output has no key-dependent Fourier mode at all.

The same result also exposes the central obstruction. Run 61's soundness comes from checking that many local blocks are **one-hot**. One-hotness is not an affine property, and in fact cannot be represented exactly as the projection of *any* system of linear equations over `F_2`, regardless of the number of linear auxiliary variables. More generally, an efficient public exact reduction of generic NP to ordinary linear solvability would make generic NP publicly decidable by Gaussian elimination. Thus the new capsule is a useful exact nonseparable baseline, but the missing generic-NP step must remain nonlinear/computational or must rely on a metric/shortness distinction whose complete projective/native output still needs a cryptographic proof.

---

## 1. Constructive attempt: one stacked linear capsule

Let a public finite-field relation be

\[
A z=b,
\qquad
A\in\mathbb F_q^{m\times n},\quad b\in\mathbb F_q^m.
\]

To hide a field key `K in F_q`, sample

\[
s\leftarrow\mathbb F_q^m
\]

uniformly and sample an arbitrary additive noise pair

\[
(e,e_0)\leftarrow\mathcal D
\]

independently of `(s,K)`. Publish

\[
\boxed{
 c=A^Ts+e,
 \qquad
 d=b^Ts+e_0+K.
}
\tag{1}
\]

A representation `z` satisfying `Az=b` computes

\[
\begin{aligned}
d-z^Tc
 &=b^Ts+e_0+K-z^T(A^Ts+e)\\
 &=K+e_0-z^Te.
\end{aligned}
\tag{2}
\]

With zero noise this gives exact correctness for **every** valid `z`. With a small-noise/reconciliation layer, equation (2) is the intended noisy decoder identity.

The important change from Run 60 is that there is only one public vector `c`. There are no per-challenge ciphertexts on which different representations can be used independently.

---

## 2. Exact common-representation stacking

Suppose the semantic layer supplies `R` public linear relations on the **same** representation:

\[
A_1z=b_1,\ldots,A_Rz=b_R.
\]

Stack them vertically:

\[
A=\begin{bmatrix}A_1\\ \vdots\\ A_R\end{bmatrix},
\qquad
b=\begin{bmatrix}b_1\\ \vdots\\ b_R\end{bmatrix}.
\tag{3}
\]

Then

\[
Az=b
\iff
A_rz=b_r\quad\text{for every }r.
\tag{4}
\]

So a single stacked capsule enforces the exact property that Run 61 needed: one representation must satisfy the complete stack. A tuple of inconsistent local representations `(z_1,...,z_R)` is useless unless there is also one common `z` satisfying (3).

This is not merely an API convention. It is an algebraic property of the one public capsule.

### Resource observation

If all `R` checks use the same `n` representation coordinates, stacking increases the secret-row dimension

\[
m=\sum_r m_r
\]

but the key-bearing public vector `c` still has only `n` field coordinates, plus one target coordinate `d`. Decapsulation with a supplied `z` is one inner product `z^Tc`; it does not require independently decoding `R` key shares.

This is substantially more compact than publishing one full capsule per challenge. It is therefore a real constructive target, not just a negative thought experiment.

---

## 3. Perfect false-instance hiding for inconsistent linear relations

The complete-output security statement for (1) is exact.

### Theorem 3.1 — dual separator

If

\[
b\notin\operatorname{im}(A),
\tag{5}
\]

then there exists

\[
v\in\ker(A^T)
\]

such that

\[
b^Tv=1.
\tag{6}
\]

**Proof.** `im(A)` and `ker(A^T)` are orthogonal complements. Since `b` is outside `im(A)`, some vector in `ker(A^T)` has nonzero pairing with `b`; rescale it to pairing one. QED.

### Theorem 3.2 — exact key-conditioned transcript equality

Under (5), for **every** additive noise distribution `D` independent of `(s,K)`, the public capsule distributions are identical for every pair of keys

\[
K,K'\in\mathbb F_q.
\]

In particular, false-instance hiding is information-theoretic and holds against unbounded classical or quantum adversaries.

**Coupling proof.** Let `v` satisfy (6). A capsule for key `K` and secret `s` has

\[
c=A^Ts+e,
\qquad
d=b^Ts+e_0+K.
\]

Set

\[
s'=s+(K-K')v.
\]

Then

\[
A^Ts'=A^Ts
\]

and

\[
b^Ts'+K'
=b^Ts+(K-K')+K'
=b^Ts+K.
\]

Translation by a fixed vector is a bijection of uniform `s`, while the same noise tape is used. Thus the full transcripts are exactly coupled. QED.

This proof does not assume independent noise coordinates, Gaussian noise, bounded noise, or even nonzero noise.

---

## 4. Complete Fourier audit

The same conclusion appears directly in the complete public character spectrum and connects the construction to the earlier projective/native analysis.

Let `omega` be a nontrivial additive character of `F_q`. For a public frequency

\[
(z,t)\in\mathbb F_q^n\times\mathbb F_q,
\]

the capsule character is

\[
\begin{aligned}
\mathbb E[\omega^{z^Tc+td}]
={}&
\mathbf 1[Az+t b=0]\;\widehat{\mathcal D}(z,t)\;\omega^{tK}.
\end{aligned}
\tag{7}
\]

The derivation is just averaging the `s`-dependent phase

\[
s^T(Az+t b)
\]

over uniform `s`.

If `b` is outside `im(A)`, then for every nonzero `t`, the equation

\[
Az=-tb
\]

has no solution. Hence every surviving character has `t=0`, and **every complete-output Fourier coefficient is key-independent**.

This is stronger than saying that no intended false decoder exists. The whole public distribution is key-independent.

Conversely, if `b in im(A)`, a public solution `z` to `Az=b` exists by Gaussian elimination. In the noiseless case this immediately recovers the key from (2). With noise, (7) shows that the corresponding target-sensitive projective mode exists; whether the noise suppresses it enough is then a metric/noise question rather than exact linear inconsistency.

---

## 5. Explicit separable-vs-stacked splice

Over `F_5`, use a scalar representation `z` and two individually satisfiable relations

\[
A_1=[1],\quad b_1=[0]
\]

and

\[
A_2=[1],\quad b_2=[1].
\]

Block 1 accepts `z_1=0`; block 2 accepts `z_2=1`. There is no common representation.

If the key is additively shared and each block gets its own capsule, the attacker simply decodes the first share with `z_1=0`, the second with `z_2=1`, and adds them. The checker recovered **1000/1000** such keys with inconsistent representations.

Now stack the relations:

\[
A=\begin{bmatrix}1\\1\end{bmatrix},
\qquad
b=\begin{bmatrix}0\\1\end{bmatrix}.
\tag{8}
\]

There is no solution to `Az=b`. The checker found the explicit separator

\[
v=(4,1),
\]

for which

\[
A^Tv=0,
\qquad
b^Tv=1\pmod 5.
\]

Using a deliberately correlated, nonuniform-looking additive noise support, the checker exhaustively confirmed equality of the complete transcript counters for all five keys. Thus the splicing repair is not a statistical artifact of zero noise.

---

## 6. Why this does **not** solve generic NP

The preceding construction would be a complete answer if generic NP could be compiled exactly into public linear solvability while preserving the intended source-witness semantics. That is precisely where the construction stops.

### Theorem 6.1 — exact public linear compiler complexity barrier

Suppose an efficient deterministic public compiler maps every instance `x` of an NP-complete language to polynomial-size `(A_x,b_x)` over an efficiently represented finite field such that

\[
x\in L
\iff
b_x\in\operatorname{im}(A_x).
\tag{9}
\]

Then `L` is in `P`: run the compiler and use Gaussian elimination to test (9). Consequently a generic exact compiler of this form would imply

\[
P=NP.
\]

For a randomized efficient compiler having high-probability completeness and soundness of (9), the same public rank test gives a randomized polynomial-time decision procedure, placing the language in `BPP` (or a one-sided subclass under corresponding one-sided guarantees).

This is a complexity consequence, not a proof that `P != NP` or `NP not subset BPP`. The point is that **ordinary public linear inconsistency cannot simply be assumed to encode generic NP**. Doing so would hide the missing witness-restricted compiler in the statement-generation algorithm itself.

An erased setup ceremony does not change this observation for its completed public transcript: if the final security boundary is exactly whether public `b` lies in public `im(A)`, anybody can test that boundary after setup.

---

## 7. Stronger local barrier: one-hotness is not even an affine projection

Run 61 does not merely need arbitrary NP computation. Its explicit semantic gain depends on a very concrete local property: checked blocks must be **one-hot**.

For a block of length `r>=3`, define

\[
\mathrm{OH}_r=\{e_1,\ldots,e_r\}\subset\mathbb F_2^r.
\]

### Theorem 7.1 — no exact linear extended formulation for one-hot blocks

There is no system of linear equations over `F_2`, in any number of auxiliary variables, whose projection onto the visible block coordinates is exactly `OH_r` for `r>=3`.

**Proof.** The solution set of any linear system is an affine subspace. The projection of an affine subspace under a linear map is again an affine subspace. But `OH_r` is not affine: it contains `e_1,e_2,e_3`, so affine closure over `F_2` would also contain

\[
e_1+e_2+e_3,
\]

which has Hamming weight three and is not one-hot. QED.

This is unconditional and does not depend on `P != NP`. It applies even to an exponentially large collection of **linear** auxiliary equations. Therefore the exact Run-61 verifier cannot be turned into the capsule of Sections 1–4 by merely adding more public linear helper variables.

The checker instantiated this affine-closure witness for every block size `r=3,...,12`.

To encode one-hotness exactly one needs a nonlinear condition, for example pairwise products

\[
y_i y_j=0\quad(i\ne j)
\]

together with normalization. Introducing formal product coordinates without enforcing that they equal the actual products is only a relaxation; enforcing multiplication returns us to a nonlinear relation/circuit and therefore to the missing cryptographic compiler.

---

## 8. Concrete Run-53 false pseudolift over `F_2`

The failure of the naive linear relaxation is explicit, not only complexity-theoretic.

Use the Run-53 width-`k` all-exclusions false core. There are

\[
B=2^k
\]

blocks. Block `f` has one local coordinate for every Boolean row

\[
a\in\{0,1\}^k\setminus\{f\}.
\]

The public linear constraints require:

1. each block has total mass one;
2. every block has the same first marginals `x_1,...,x_k`.

The conjunction has no Boolean witness, because every assignment `t` is excluded from block `t`.

Fix any assignment `t`. Define an `F_2` representation:

- in every block `f != t`, put a single `1` on row `a=t`;
- in the malformed block `f=t`, put `1` on **all** `2^k-1` allowed rows.

The malformed block is just the Run-53 signed integral lift reduced modulo two, since `+1` and `-1` both become `1`.

Its normalization is correct because `2^k-1` is odd. Its `i`-th marginal is exactly `t_i`:

- if `t_i=1`, the malformed block contains `2^{k-1}-1` rows with bit one, an odd number;
- if `t_i=0`, it contains `2^{k-1}` such rows, an even number.

Thus the **entire naive public linear system is satisfiable on the false source statement**.

The checker verified every such pseudolift for all widths `k=2,...,6`, totaling **124 exact false representations**. Their Hamming weight is

\[
\boxed{2(2^k-1)},
\tag{10}
\]

versus `2^k` for an all-one-hot representation. At `k=3` this is only `14` versus `8`; asymptotically the factor approaches two.

This matters to the cryptographic audit. Once false linear solutions exist, Sections 3–4 no longer give perfect hiding. A noisy/metric construction must instead argue that every false algebraic/projective solution is too expensive to decode while genuine source-witness solutions remain cheap. That is exactly the complete projective/native obligation identified in the earlier OHLC/Fourier work, not a solved problem.

Run 61 eliminates these false fibers only because its global verifier actually *tests one-hotness*. Dropping that nonlinear property to fit an ordinary linear capsule discards the semantic theorem that made Run 61 useful.

---

## 9. Exact scope of the positive result

The single stacked capsule therefore gives a useful clean interface:

### Proved

- One public capsule algebraically forces one representation for all stacked **linear** relations.
- If the stacked relation is inconsistent (`b notin im(A)`), the complete transcript is perfectly key-hiding for every additive noise distribution independent of the key.
- The same fact has both an exact coupling proof and a full Fourier-spectrum proof.
- With zero noise, every solution `z` recovers exactly the same key.
- An explicit two-block example that is totally broken under separable share release becomes perfectly hiding under one stacked capsule.
- Exact one-hot sets of block size at least three are not projections of linear systems over `F_2`.
- The naive Run-53 normalization/marginal linearization has explicit low-weight false `F_2` solutions.

### Implemented and actually tested

The finalized standard-library checker was executed twice with byte-identical JSON output. It performed:

- **180** false linear fixtures over `F_2,F_3,F_5`, with **180** explicit dual separators and **420** exact key-conditioned distribution equalities under arbitrary finite correlated noise supports;
- **180** true fixtures with **65,680** exact noisy decoder residual identities;
- **1000/1000** separable inconsistent-representation key recoveries in the two-block splice fixture, followed by exact equality of all five key distributions for the stacked capsule;
- **124** exact Run-53 modulo-two false pseudolifts for widths 2 through 6;
- affine-closure counterexamples for one-hot block sizes 3 through 12;
- **900** independent Gaussian-elimination membership controls.

The tests validate the finite algebra and implementation. They are not the security proof; the coupling, Fourier, affine-projection, and complexity arguments above are the claims.

### Not proved / not implemented

- No nonlinear generic-NP relation has been encoded into a secure public offline capsule here.
- No LWE/SIS reduction is obtained.
- No arbitrary-QPT early-key-recovery-to-source-witness reduction is obtained.
- No proof says every noisy metric linearization is impossible; such a construction may permit false algebraic solutions but try to make all unauthorized solutions/projective modes computationally or metrically useless.
- No malicious-secure ceremony or end-to-end practical parameter set follows from this linear baseline.

---

## 10. Handoff

Run 61 isolated **nonseparable common-representation enforcement** as the missing primitive. This run shows that the nonseparability part itself is easy and exact for linear relations: one stacked capsule solves it perfectly.

The remaining difficulty is therefore not “how do we stop per-share switching?” in the abstract. It is:

> **How can one embed the nonlinear source-witness condition into a single public offline capsule without making source validity publicly decidable, without admitting cheap algebraic/projective pseudowitnesses, and with a complete-output reduction to an independently justified PQ assumption?**

The next constructive branch should therefore leave exact affine solvability and attack one of two narrower possibilities:

1. a genuinely nonlinear/computational single capsule whose key-dependent output can be reduced directly to LWE/SIS; or
2. a metric linearization in which false algebraic solutions are unavoidable but every non-source projective mode is provably outside the decodable short/noise region, with the proof applying to the **complete native output** and not only the intended witness decoder.

A named “nonlinear release compiler” is not a result. The next candidate must expose concrete public algorithms and survive this same complete-output audit.
