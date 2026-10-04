# Run 105 — trapdoor reverse sampling, rank-aware programmability, and the compact-merge barrier

## Status

Verified starting PR head:
`5a612472b4f5e16120a6a07097ef25788415cb94`
on branch `research/pq-wkem-validation-20260918`.
PR #1 was open, draft, and unmerged.

Runs 100--103 were already published and verified at that head.  The immediately
preceding Run 104 searchable-hidden-support barrier remains local-only because its
single publication attempt was safety-blocked; this run does not retry, rename, or
re-route that denied payload.

This run returns to the exact correlated trapdoor/prefix step in Tsabary's lattice
witness-encryption architecture and asks a narrower question:

> How much of the trapdoor transition can be generated statistically or exactly
> without a trapdoor, and exactly where does compact branching force the
> nonstandard private-coin assumption back in?

The answer is more constructive than the previous audit.

For **one freely programmable transition**, a trapdoor is not inherently necessary.
There is an exact reverse-sampling normal form in which the source LWE matrix remains
uniform and independent of the short transition key.  More generally, conditioned
Gaussian preimages admit an exact Bayes reverse-sampling identity whose deviation
from an independently uniform target is governed by a rank-distance collision
spectrum.

The obstruction appears when one already-fixed source matrix must support several
independently prescribed outgoing targets, or when a branching computation must both
split and later merge while reusing compact state matrices.  A naive reverse sampler
then pays an exponential compatibility probability.  Tsabary's trapdoor preimages
are doing **compact target programming**, not merely "sampling a short matrix."

This does not complete a practical PQ WKEM.  It identifies a standard-assumption
subprimitive and a much sharper missing merge primitive.

No production path is changed.

---

## 1. Current literature correction: the exact Tsabary sampler is narrower than the broad broken assumption

Run 80 correctly rejected the broad published Assumption 31 as an acceptable
foundation for this project.  Later literature requires a more precise statement
about the **actual construction sampler**.

Tsabary's construction first samples trapdoor matrices and all transition preimages,
and only afterwards samples the LWE secret `s` used in the start-layer ciphertext.
The public ciphertext consists of the start-layer LWE vectors, the branching program,
and the transition preimages.

In the terminology of Huang--Hung--Yamada (IACR Communications in Cryptology 2026),
this construction-specific auxiliary sampler is therefore in the
**LWE-secret-oblivious** direction: the transition auxiliary data are generated
without knowledge of the challenge secret.

The 2026 Huang--Hung--Yamada paper revisits the private-coin evasive-LWE attack
landscape after the 2024--2025 counterexamples.  It refutes the earlier
Vaikuntanathan--Wee--Wichs obfuscation attack in the secret-oblivious regime and
states that the then-known private-coin zeroizing/counterexample results, including
the 2025 Döttling--Jain--Malavolta--Mathialagan--Vaikuntanathan line, target
secret-dependent regimes (apart from public-coin/circular special cases).  Their
conclusion is that the private-coin **secret-oblivious** regime still has no known
attack.

This corrects an overbroad reading of the 2025 abstract phrase "all known variants."
It does **not** make Tsabary an acceptable endpoint here:

* the published Tsabary theorem is still quantified over classical PPT attackers;
* the exact restricted secret-oblivious transition has no reduction to ordinary
  QPT-LWE/SIS;
* absence of a known attack is not a hardness theorem;
* ordinary false-statement WE hiding still does not give our required
  arbitrary-QPT FINAL-key-recovery -> ORIGINAL-witness extraction.

The useful question is therefore whether the transition can be re-generated from
standard-assumption distributions, rather than renaming a restricted evasive-LWE
assumption.

---

## 2. Ideal preimage distribution

Work first over the finite field `F_q`.

Let

\[
A\leftarrow\mathbb F_q^{n\times m}
\]

and let

\[
K\leftarrow\mu
\]

for an arbitrary distribution `mu` over
\(\mathbb F_q^{m\times r}\), independent of `A`.

Define

\[
T=AK.
\tag{1}
\]

For every pair `(A,T)` in the support, Bayes' rule gives

\[
\boxed{
\Pr[K=k\mid A,T]
=
\frac{\mu(k)\mathbf 1[Ak=T]}
     {\sum_{k':Ak'=T}\mu(k')}.
}
\tag{2}
\]

Thus the reverse experiment

\[
K\leftarrow\mu,\quad A\leftarrow U,\quad T:=AK
\tag{3}
\]

already samples **exactly** from `mu` conditioned on the preimage equation after
conditioning on `(A,T)`.

When `mu` is the reduction modulo `q` of a discrete Gaussian, (2) is precisely the
ideal "Gaussian conditioned on \(AK=T\)" distribution that lattice trapdoor
preimage samplers are designed to realize statistically.

The trapdoor is therefore not conceptually required to define that conditional
distribution.  Its role is to sample it efficiently for a **target chosen in advance**.

---

## 3. Exact joint-TV reduction to the target marginal

Consider only full-row-rank `A` so every target is reachable.

Let `Q` be the reverse joint distribution from (3).  Let `P` be the idealized
forward distribution

\[
A\leftarrow U_{\rm full-rank},\qquad
T\leftarrow U_{\mathbb F_q^{n\times r}},
\qquad
K\leftarrow\mu\mid AK=T.
\tag{4}
\]

The conditional law of `K` given `(A,T)` is identical in `P` and `Q`.  Therefore

\[
\boxed{
\operatorname{TV}(P,Q)
=
\operatorname{TV}\bigl(
 (A,U_T),
 (A,AK)
\bigr).
}
\tag{5}
\]

So replacing trapdoor-forward sampling by reverse sampling is an entirely
information-theoretic question about whether \(AK\) is close to uniform given `A`.

This statement is adversary-model agnostic.  If the right side is negligible, the
replacement is valid even against unbounded and therefore arbitrary QPT attackers.

---

## 4. Exact rank-aware collision formula

The matrix-preimage case needs more than ordinary min-entropy.

Let `A` be fully uniform over
\(\mathbb F_q^{n\times m}\), and let

\[
p_A(t)=\Pr_{K\leftarrow\mu}[AK=t].
\]

For the conditional output distribution \(P_{AK\mid A}\),

\[
1+\chi^2(P_{AK\mid A}\|U)
=
q^{nr}\sum_t p_A(t)^2.
\]

Averaging over `A` and two independent samples \(K,K'\leftarrow\mu\),

\[
\boxed{
\mathbb E_A\chi^2(P_{AK\mid A}\|U)
=
q^{nr}
\mathbb E_{K,K'}
q^{-n\,\operatorname{rank}(K-K')}
-1.
}
\tag{6}
\]

### Proof

Expand the collision probability:

\[
\mathbb E_A\sum_t p_A(t)^2
=
\mathbb E_{K,K'}
\Pr_A[A(K-K')=0].
\]

If

\[
\rho=\operatorname{rank}(K-K'),
\]

one uniform row of `A` annihilates \(K-K'\) with probability \(q^{-\rho}\).
The `n` rows are independent, giving \(q^{-n\rho}\).  Substitution proves (6).

Hence

\[
\operatorname{TV}((A,AK),(A,U))
\le
\frac12
\sqrt{
q^{nr}\,
\mathbb E_{K,K'}q^{-n\operatorname{rank}(K-K')}
-1
}.
\tag{7}
\]

For a single target column `r=1`, every nonzero difference has rank one, so (6)
collapses to

\[
\boxed{
\mathbb E_A\chi^2
=
(q^n-1)\operatorname{CP}(\mu),
}
\tag{8}
\]

where

\[
\operatorname{CP}(\mu)=\sum_k\mu(k)^2.
\]

For matrix preimages `r>1`, ordinary collision entropy is not the whole story:
pairs whose difference has unexpectedly low rank receive the much larger weight
\(q^{-n\rho}\).  The relevant source statistic is a **rank-distance collision
spectrum**.

This connects the trapdoor-reversal problem directly to the rank-spectrum work
already developed elsewhere in this research record.

---

## 5. Stronger special case: exact trapdoor-free programming of one invertible edge

There is an even simpler exact normal form when the transition key can be chosen
invertible modulo `q`.

Let

\[
T\leftarrow \mathbb F_q^{n\times m}
\]

be uniform.  Independently sample `K` from **any** distribution supported on

\[
\mathrm{GL}_m(\mathbb F_q).
\]

Define

\[
\boxed{
A:=TK^{-1}.
}
\tag{9}
\]

Then

\[
AK=T
\tag{10}
\]

exactly.

For every fixed invertible `K`, right multiplication by \(K^{-1}\) is a bijection on
\(\mathbb F_q^{n\times m}\).  Consequently

\[
\boxed{
A\ \text{is exactly uniform and independent of }K.
}
\tag{11}
\]

This is important cryptographically.

For this isolated transition, handing out `K` does not create correlated auxiliary
information about the LWE matrix `A`: `K` is literally independent of uniform `A`.
A straight-line reduction can sample `K` itself and embed an ordinary decisional-LWE
challenge at `A`.

Therefore, if the base decisional LWE instance is hard against QPT adversaries at
the chosen parameters, this **single-edge transition** does not need evasive LWE at
all.

The remaining practical question is whether one can sample matrices that are both
sufficiently short over the integers for correctness and invertible modulo `q` with
the required probability and noise growth.  This is a concrete parameter question,
not a new security assumption.

---

## 6. Why this does not immediately replace Tsabary's trapdoors: fanout collision

Tsabary does not need one freely chosen target per source matrix.

A source state participates in multiple possible transitions.  Abstract the
problem as follows.  One already-shared source matrix `A` must satisfy

\[
AK_j=T_j,\qquad j=1,\ldots,d,
\tag{12}
\]

for several prescribed targets.

Assume for the moment that all \(K_j\) are independently sampled invertible matrices.
Then necessarily

\[
A=T_1K_1^{-1}
 =T_2K_2^{-1}
 =\cdots
 =T_dK_d^{-1}.
\tag{13}
\]

If the \(T_j\) are independent uniform
\(n\times m\) matrices, the normalized candidates
\(T_jK_j^{-1}\) are independent uniform matrices.  Hence

\[
\boxed{
\Pr[\text{all }d\text{ targets are compatible}]
=
q^{-nm(d-1)}.
}
\tag{14}
\]

Already for binary fanout `d=2` the expected rejection cost is

\[
\boxed{q^{nm}.}
\tag{15}
\]

Sampling a single transition backwards is therefore easy; programming two
independent targets into the same already-fixed source by rejection is exponentially
bad in the matrix dimension.

Tsabary's trapdoor sampler avoids exactly this rejection: once `A` and its trapdoor
exist, it can sample a short `K_j` for every prescribed target \(T_j\).

---

## 7. Branching versus merging

One may try to avoid (14) by never sharing a source matrix between outgoing edges.

Give every edge its own carrier and reverse-sample each transition independently.
That removes the fanout collision.

But a branching computation must also merge paths back into a compact state space.
If carriers are never merged, a binary depth-`t` computation has

\[
2^t
\]

leaf carriers and

\[
\boxed{2^{t+1}-1}
\tag{16}
\]

total tree carriers.

A forward construction encounters **fanin compatibility** when two independently
generated edge carriers are required to become the same next state.  A backward
construction encounters **fanout compatibility** when one source must hit two
prescribed next states.

The trapdoor is therefore best understood as a compact branch/merge programming
device.

This reframes the missing primitive:

> construct a compact merge gadget whose public transcript is reducible to an
> independently justified QPT-hard assumption, while preserving permissionless
> witness evaluation and ORIGINAL-source extraction.

Simply replacing `TrapGen` with reverse sampling does not supply that gadget.

---

## 8. How this changes the interpretation of the restricted Tsabary direction

The current evidence supports four separate statements.

### 8.1 A single transition is not the hard part

Equations (9)--(11) give an exact standard-LWE-compatible transition when the target
is free and the edge key can be sampled invertible.

Equations (2)--(7) give a more general statistical route for Gaussian-like preimages.

### 8.2 Compact target programming is the hard part

The difficulty appears when the target is already fixed by another part of the
computation and the same matrices must serve many branching and merging paths.

This is precisely the setting in which Tsabary invokes the extra private-coin
relative-hardness assumption.

### 8.3 The current attack literature does not prove the exact secret-oblivious sampler broken

The later 2026 Huang--Hung--Yamada analysis explicitly separates
secret-oblivious from secret-dependent private-coin evasive LWE and says the
secret-oblivious regime has no known attack after their refutation of the VWW route.

That is relevant to scientific accuracy.

It still does not satisfy this project's target, because an **open nonstandard
assumption** is not an independently justified QPT-hard foundation.

### 8.4 A newer lattice direction may provide a different merge technology

A very recent preprint, Abram--Malavolta--Roy,
*Tree Encodings IV: Depth-Unbounded Attribute-Based Encryption and Delay Encryption*
(ePrint 2026/2094, last updated 22 September 2026), advertises depth-unbounded
bounded-space CP-ABE from **Decomposed LWE**, explicitly contrasting this with earlier
evasive-LWE-based routes.

A separate August 2026 preprint by
Abram--Arnon--Cini--Lou--Malavolta--Roy states that Decomposed LWE and Succinct LWE
are equivalent under appropriate parameters.

This does not solve our problem:

* Decomposed/Succinct LWE is still a strengthened lattice assumption, not ordinary
  standard LWE at the relevant growing width;
* the fresh Tree Encodings result is ABE, not permissionless generic-NP witness
  encryption;
* no arbitrary-QPT ORIGINAL-witness extraction theorem is supplied by the abstract;
* the full 2026/2094 proof was not accessible through the primary PDF path in this
  run, so no theorem-level import is made.

But it is a more relevant next source of **compact merge machinery** than trying to
rehabilitate broad private-coin evasive LWE.

---

## 9. Exact validation

The deterministic standard-library checker runs the finite analogues of the new
identities.

It verifies:

1. the exact reverse-posterior identity for every reachable `(A,T)` in a
   Gaussian-like distribution over \(\mathbb F_3^2\);
2. exact equality between joint TV and `(A,T)`-marginal TV when comparing reverse
   sampling with an ideal uniform-target/conditioned-preimage experiment over
   full-rank `A`;
3. the exact rank-aware chi-square identity (6) for a nonuniform distribution over
   `2 x 2` matrices over `F_3`;
4. the vector specialization (8);
5. all 48 matrices in `GL_2(F_3)`: for every one and every target row, the
   reverse-programmed source is uniform and satisfies `AK=T`;
6. exact independence of `A` and a deliberately nonuniform invertible-`K`
   distribution;
7. an exhaustive `q=5`, source-row-width `m=2`, two-target fanout fixture with
   compatibility probability exactly

   \[
   1/25=q^{-m};
   \]

8. the general \(q^{-m(d-1)}\) fanout arithmetic and binary tree-size identities.

Passing these checks validates finite algebra/probability, not LWE hardness and not a
complete witness-encryption construction.

---

## 10. Quantum-security ledger

### Honest algorithm model

The reverse-sampling algorithms are classical.

For one invertible edge, matrix inversion and multiplication are polynomial time.

### Adversary model

Equations (2)--(8) are information-theoretic distribution identities and therefore
hold against unbounded and arbitrary QPT distinguishers.

For the exact single-edge construction (9)--(11), `K` is independent classical
auxiliary information.  A straight-line reduction to decisional LWE can therefore
invoke an arbitrary QPT adversary once without rewinding.

### Hardness distribution

The single-edge computational claim requires **ordinary decisional LWE to be
QPT-hard at the exact parameters**.

No evasive-LWE, generic-group, random-oracle, or newly named assumption is introduced
for that isolated transition.

The compact multi-edge/merge construction still has no such reduction.

### Reduction model

No QROM, superposition-query oracle, classical rewinding, or extraction oracle occurs
in the new lemmas.

### Exact conclusion

A freely programmable single transition can be made standard-LWE compatible without
a trapdoor.

A compact branching/merging witness-encryption graph cannot be obtained by naively
applying that reverse sampler edge-by-edge without an exponential compatibility or
state-expansion cost.

### Still UNPROVED

1. a compact branch/merge gadget from standard QPT-LWE/SIS;
2. a practical generic-NP permissionless public/offline source compiler;
3. arbitrary-QPT FINAL-key recovery -> ORIGINAL witness for a complete compact
   construction;
4. malicious-secure setup/abort and auxiliary-input composition for any future
   ceremony-based variant;
5. final concrete resource estimates.

The stopping condition is not met.

---

## 11. Next handoff

The next pass should not spend effort naming a narrower evasive-LWE assumption.

The two useful avenues are now concrete.

**Standard-assumption merge search.**
Audit whether the adaptive lattice encodings / succinct oblivious tensor evaluation
machinery underlying the recent Tree Encodings line can implement the missing compact
branch/merge operation while keeping the relevant reduction on ordinary QPT-LWE.
The 2025 OTE construction itself advertises standard-LWE security, whereas the
depth-unbounded 2026 layer moves to Decomposed LWE; the exact point where the stronger
assumption becomes necessary is especially important.

**Rank-spectrum reverse programming.**
For non-invertible Gaussian-like transition matrices, evaluate the exact statistic

\[
q^{nr}
\mathbb E_{K,K'}q^{-n\operatorname{rank}(K-K')}-1
\]

at realistic lattice parameters.  If it is negligible for useful short distributions,
single-target conditioned preimages can be statistically reverse-generated even
without requiring invertibility.

Neither avenue may silently reintroduce a publicly searchable support event of the
kind ruled out by Run 104.

The practical generic-NP PQ WKEM remains open.
