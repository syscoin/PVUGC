# Run 104 — searchable hidden-support barrier: efficient correctness collapses generic-NP witness search

## Status

Verified starting PR head: `93ae96ba977d96e435c41c86ffeb037e8dbc2ff5` on branch `research/pq-wkem-validation-20260918`. PR #1 was open, draft, and unmerged.

This run corrects an important optimism in the immediately preceding hidden-subspace consistency-bundle direction.

That construction hid the actual random support `U` from the ciphertext recipient and achieved perfect false-statement hiding. However, the *distribution* of candidate supports is public and efficiently samplable, and for any sampled `U` the source relations annihilated by its mask are computable by ordinary linear algebra.

The resulting theorem is stronger than the previous Fourier concern:

> if the random hidden support is informative often enough for polynomial-time honest decryption, then an unauthorised algorithm can independently sample candidate supports, solve a public linear system, and recover an ORIGINAL NP witness in polynomial time.

For a generic NP compiler, polynomial-time correctness of this architecture would therefore imply `NP subseteq RP`.

This is a barrier to the hidden-subspace architecture itself, not merely to the Run-102/103 Fourier proof. The prior suggestion that source compression could make the good-support probability inverse-polynomial and thereby make the release practical was incomplete: that same change makes the ORIGINAL witness publicly searchable.

No production path is changed.

## 1. Source interface

Let

\[
C_x\subseteq \mathbb F_q^{n\times c}
\]

be a public linear source space with semantic rank cutoff `D`.

Assume:

### False statements

\[
x\notin L
\Longrightarrow
0\ne Y\in C_x
\implies
\operatorname{rank}(Y)\ge D.
\tag{1}
\]

### Supplied-low-rank ORIGINAL-witness extraction

There is a polynomial-time `Ext` such that

\[
0\ne Y\in C_x,\qquad \operatorname{rank}(Y)<D
\]

implies

\[
R(x,\operatorname{Ext}(x,Y))=1.
\tag{2}
\]

## 2. Hidden-support mask

Choose

\[
m=n-D+1
\]

and a uniformly random hidden subspace

\[
U\le \mathbb F_q^n,\qquad \dim U=m.
\]

Define

\[
W_U=\{E:\operatorname{col}(E)\subseteq U\}
\tag{3}
\]

and

\[
S_U=C_x^\perp+W_U.
\tag{4}
\]

Its orthogonal complement is

\[
S_U^\perp
=C_x\cap W_U^\perp
=\{Y\in C_x:\operatorname{col}(Y)\subseteq U^\perp\}.
\tag{5}
\]

Write

\[
\boxed{K_U:=S_U^\perp.}
\tag{6}
\]

The prior consistency bundle sampled one or more masks from `S_U`, then added a public bit-dependent translation such as `bH`. The theorem below is independent of the bundle width and decoder.

## 3. `K_U` is publicly computable

Given a basis of `C_x` and a sampled basis of `U`, membership in `K_U` is a homogeneous linear system in the public coefficients of `C_x`.

For every column `y_j` of `Y` and every basis vector `u` of `U`, impose

\[
u^T y_j=0.
\tag{7}
\]

Gaussian elimination yields a basis of `K_U` in polynomial time.

Moreover, every `Y in K_U` has

\[
\operatorname{col}(Y)\subseteq U^\perp,
\]

and

\[
\dim U^\perp=D-1.
\]

Hence every nonzero `Y in K_U` satisfies

\[
\boxed{\operatorname{rank}(Y)\le D-1<D.}
\tag{8}
\]

Therefore

\[
\boxed{K_U\ne\{0\}\Longrightarrow\text{public polynomial-time ORIGINAL-witness recovery}.}
\tag{9}
\]

No ciphertext is needed.

## 4. Searchable-support probability

Define

\[
\boxed{p_x=\Pr_U[K_U\ne\{0\}].}
\tag{10}
\]

An unauthorised algorithm can independently repeat:

1. sample a fresh `U` from the same public Grassmannian distribution;
2. compute `K_U`;
3. if nonzero, choose any nonzero `Y in K_U`;
4. run `Ext(x,Y)` and verify the ORIGINAL NP relation.

Its expected number of trials on a true instance is

\[
\boxed{1/p_x.}
\tag{11}
\]

On a false instance, (1) and (8) force `K_U={0}` for every `U`, so the search never outputs a false witness.

## 5. Bit information exists only on searchable supports

If

\[
K_U=S_U^\perp=\{0\},
\]

then

\[
S_U=\mathbb F_q^{n\times c}.
\tag{12}
\]

Every mask sampled from `S_U` is therefore uniform over the full ambient matrix space. Adding any public bit-dependent translation preserves uniformity.

So conditioned on any `U` with `K_U=0`, the *entire public bundle distribution* is identical for bit 0 and bit 1, regardless of consistency width `T`.

Let `P_0,P_1` be the complete one-bundle public distributions after averaging over hidden `U`. Coupling the two experiments with the same `U` gives

\[
\boxed{\operatorname{TV}(P_0,P_1)\le p_x.}
\tag{13}
\]

This is a full-public-view statement, not a witness-projection statement.

## 6. Polynomial correctness forces inverse-polynomial searchable support

Suppose one encrypted bit uses `L` independent bundles. Then

\[
\boxed{
\operatorname{TV}(P_0^{(L)},P_1^{(L)})
\le 1-(1-p_x)^L
\le Lp_x.
}
\tag{14}
\]

A fixed valid witness is the same side information in both bit experiments and does not change their statistical distance.

For equiprobable bits, every decoder, even computationally unbounded, has success at most

\[
p_{\rm dec}\le\frac12\left(1+\operatorname{TV}(P_0^{(L)},P_1^{(L)})\right).
\tag{15}
\]

Therefore, if honest correctness satisfies

\[
p_{\rm dec}\ge\frac12+\eta,
\]

then

\[
1-(1-p_x)^L\ge2\eta,
\]

so

\[
\boxed{
p_x\ge1-(1-2\eta)^{1/L}\ge\frac{2\eta}{L}.
}
\tag{16}
\]

The bound is independent of the first-accepted decoder, majority decoding, consistency width, Fourier analysis, or the rank of a particular honest witness.

## 7. Generic-NP consequence

Combine (11) and (16).

If this is a generic NP compiler with

* `L=poly(lambda)`, and
* correctness advantage `eta>=1/poly(lambda)`,

then

\[
p_x\ge1/poly(\lambda).
\]

Sampling `U`, solving for `K_U`, and invoking the supplied-low-rank extractor finds and verifies an ORIGINAL witness in randomized polynomial time.

For decision:

* on `x notin L`, every `K_U` is zero, so reject with certainty;
* on `x in L`, polynomially many trials find a verified witness with constant probability.

Thus such a generic polynomial-time instantiation would imply

\[
\boxed{\mathrm{NP}\subseteq\mathrm{RP}.}
\tag{17}
\]

This is a conditional complexity consequence, not a claim that this collapse is known.

For the intended cryptographic use the consequence is already disqualifying: the same public source representation and public support sampler that make release efficient also give anyone an efficient ORIGINAL-witness search algorithm.

## 8. Hiding the actual `U` does not repair the problem

The attack never recovers the particular `U` used by encapsulation. It samples a fresh independent `U` from the same public distribution.

Therefore the following do not repair the searchable-support issue:

* erasing the actual `U` after encapsulation;
* secret-sharing the actual `U` among setup participants;
* an N-of-N ceremony whose only purpose is preventing reconstruction of that particular `U`;
* increasing consistency width `T`;
* replacing the first-accepted decoder by majority or an optimal decoder.

As long as candidate supports are publicly samplable, `K_U` is publicly computable from `(x,U)`, and nonzero `K_U` supplies an extractable witness, inverse-polynomial informative-support mass is itself a public witness-search algorithm.

A future ceremony can help only if it breaks at least one of those properties—for example, an informative seed distribution that cannot be publicly resampled without an erased trapdoor, or an extractable intersection whose detection remains hard even given the seed under an independently justified QPT-hard assumption. That is a materially different architecture.

## 9. Correction to the prior compression handoff

For the published binary scalar descent of the Hair--Sahai source, the rank-one good-support benchmark has

\[
\alpha_1=\frac{2^R-1}{2^{N+1}-1},
\qquad R=\lfloor\log_2N\rfloor.
\tag{18}
\]

The preceding consistency-bundle note observed that if future source compression made the effective ambient-minus-gap dimension `O(log lambda)`, the number of hidden-support trials could become polynomial.

Operationally that count statement is true. Cryptographically it is incomplete.

If compression makes the informative support probability inverse-polynomial, then Section 4 makes ORIGINAL-witness search inverse-polynomial as well. The direct route therefore cannot be salvaged merely by shrinking `n-D`.

The exponential cost in the uncompressed source is not just an implementation accident: in this publicly samplable support architecture it is what prevents the support sampler itself from becoming a generic NP search algorithm.

## 10. Exact finite validation

The standard-library checker reuses the exact binary `3 x 2`, `D=2` fixture from the hidden-subspace work.

It verifies:

1. all seven two-dimensional hidden subspaces of `F_2^3`;
2. true searchable-support probability exactly `1/7`;
3. false searchable-support probability exactly `0`;
4. every nonzero element found in any `K_U` has rank below `D`;
5. the exact complete-public one-bundle distributions for widths `T=1` and `T=2` have

   \[
   \operatorname{TV}(P_0,P_1)=3/28<1/7=p_x;
   \]

6. every false-instance mask sum is the full 64-element ambient matrix space;
7. the exact correctness-to-search lower bound (16) and the simpler `p_x>=2 eta/L` bound on multiple parameter rows;
8. the Hair--Sahai binary inverse-probability benchmark;
9. polynomial repetition of the lower-bound search probability gives constant one-sided witness-finding success.

The checker validates finite algebra/probability controls. The `NP subseteq RP` statement is the theorem-level conditional consequence of a generic polynomial-time compiler satisfying the stated source interface.

## 11. Quantum-security classification

**Honest algorithms.** Source compilation, support sampling, `K_U` computation, and supplied-low-rank extraction are classical.

**Adversary model.** The search attack is classical randomized polynomial time whenever `p_x` is inverse-polynomial, so it is automatically available to QPT adversaries.

**Hardness assumptions.** None are introduced. The barrier uses public linear algebra and the existing supplied-low-rank extractor.

**Reduction model.** Straight-line randomized sampling and Gaussian elimination only. No rewinding, QROM, superposition queries, or quantum auxiliary-state handling is involved.

**Exact conclusion.** For this hidden-subspace mask architecture, generic polynomial-time correctness plus supplied-low-rank ORIGINAL-witness extraction yields randomized polynomial-time ORIGINAL-witness search.

**Not proved.** This does not prove `NP` is not contained in `RP`, and it does not rule out rank-based releases that make the informative setup seed non-publicly-samplable or computationally hidden under an independently justified QPT-hard assumption.

## 12. Next handoff

Do not continue optimizing the publicly samplable hidden-subspace consistency bundle.

The next candidate must break the searchable-support implication. The most relevant surviving direction is the previously identified correlated-trapdoor/prefix architecture:

* informative setup randomness should be generated inside a malicious-secure ceremony;
* no public algorithm should be able to resample an equivalent informative seed and test for an extractable source intersection;
* at least one honest participant plus erasure must prevent any participant from retaining a witness-finding trapdoor;
* complete public output still needs arbitrary-QPT hiding/extraction under an independently justified QPT-hard assumption;
* ordinary QPT-LWE does not automatically justify any extra correlated-trapdoor or evasiveness assumption.

The searchable-support theorem should be a mandatory audit criterion for future public random-subspace, annihilator, quotient, or hidden-kernel proposals.

The stopping condition remains unmet.
