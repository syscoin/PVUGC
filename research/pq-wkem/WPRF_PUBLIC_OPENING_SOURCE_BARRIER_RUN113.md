# Run 113 — WPRF reduction and public-opening source barrier

## Status

Verified starting PR head: `a0803edfa691f184e33ca92620471a81c17c611c` on
`research/pq-wkem-validation-20260918`. PR #1 was open, draft, and unmerged.
The latest substantive ordinary PR comment was `5843580758`, which records the
verified interactive publication of Runs 104–108 and 110–111.

This run does **not** retry or republish the Run-112 payload whose first GitHub write
was reported as safety-blocked. It instead follows Run 112's mathematical handoff.

The main correction is conceptual but important:

> The desired same-key public/offline witness-release functionality is not a new
> abstraction. At the functionality level it is exactly the interface of a witness
> pseudorandom function (WPRF), and Zhandry already gave the direct WPRF -> witness
> encryption / reusable witness-KEM transforms in 2014.

The unsolved part is therefore narrower and harder:

> We need a **post-quantum, process-extractable WPRF** for generic NP (or an
> equivalent primitive), with a quantum-valid extraction theorem for the actual
> source relation and auxiliary public output.

A second result rules out a tempting lattice detour. The new public shifted
multi-preimage / hidden-bits machinery of Waters--Wee--Wu can efficiently sample
valid local openings without a source witness. Therefore ordinary local-opening
validity cannot itself be a universally source-extractable encoding of a hard NP
witness. Any compiler that tries to use a local-opening WPRF must introduce a
**strict witness-restricted subclass** of openings; that restriction is precisely the
missing source compiler rather than a free consequence of the HBG/vector-commitment
machinery.

No production path is changed.

---

## 1. Prior-art correction: WPRF is the exact same-value interface

Mark Zhandry, *How to Avoid Obfuscation Using Witness PRFs*, ePrint 2014/301 / TCC
2016, defines a WPRF `(Gen,F,Eval)` for a relation `R`:

- `Gen(lambda,R)` outputs a secret function key `fk` and public evaluation key `ek`;
- `F(fk,x)` deterministically outputs a value `Z`;
- `Eval(ek,x,w)` outputs that **same** `F(fk,x)` for every valid witness
  `R(x,w)=1`, and rejects invalid witnesses.

The paper's Definition 3.1 gives exactly this equality. Its baseline security notion
is explicitly quantified over **PPT** adversaries and protects challenge instances
outside the language.

This means the all-valid-witness same-key problem isolated in Runs 107--112 already
has the canonical syntax

\[
\boxed{
  Z_x := F(fk,x),
  \qquad
  R(x,w)=1 \Longrightarrow Eval(ek,x,w)=Z_x.
}
\tag{1}
\]

There is no need to invent a new "invariant adaptor" syntax for this part.

### Direct witness-KEM / WE transform already in the paper

Zhandry's Construction 4.13 is the exact one-mask witness-encryption transform:

\[
(fk,ek)\leftarrow Gen(\lambda,R),
\qquad
Z_x=F(fk,x),
\qquad
c=Z_x\oplus m,
\tag{2}
\]

and a witness decrypts using `Eval(ek,x,w)`.

The paper then defines a **reusable witness key encapsulation mechanism** in Definition
4.15, with public parameters, a master decryption key, witness decapsulation, and a
common message-encryption key.

So the project's target can be stated much more precisely as a post-quantum,
source-extractable, setup-compatible specialization of this known interface.

---

## 2. Exact transform to the current raw-key target

For a fixed source relation `R` and statement `x`, suppose we had a WPRF whose
algorithms are classical polynomial time.

### Setup / encapsulation

1. Run
   \[
   (fk,ek)\leftarrow Gen(1^\lambda,R).
   \]
2. Compute
   \[
   Z := F(fk,x).
   \]
3. Treat `Z` itself as the raw final key, or derive a final key using an injective or
   separately justified wrapper.
4. Publish `ek` and any setup transcript required by the WPRF, then erase or
   distributedly destroy the secret material according to the ceremony model.

### Witness decapsulation

Given any valid witness `w`, compute

\[
Z_w := Eval(ek,x,w).
\]

Correctness of the WPRF gives

\[
\boxed{Z_w=Z\quad\text{for every valid }w.}
\tag{3}
\]

This exactly solves the all-witness same-key functionality.

### False statement hiding

If `x` is false, ordinary WPRF pseudorandomness says `F(fk,x)` is hidden/pseudorandom
from the public evaluation key in the paper's classical model.

For this project we would require the corresponding theorem against **arbitrary QPT
adversaries** for the full published setup distribution. The 2014 theorem does not
supply that: it explicitly says PPT.

---

## 3. Exact final-key recovery gives a WPRF distinguisher

This is the most useful new reduction in this run.

Let the WPRF range be a finite set `Y` of size `M`. Let an unauthorized algorithm
`A` receive the complete public view and output a classical candidate `Zhat` for

\[
Z=F(fk,x).
\]

Suppose

\[
\Pr[\widehat Z=Z]=\varepsilon.
\tag{4}
\]

Build a distinguisher `D` for a WPRF challenge `y`, where `y` is either the real
`Z` or a uniform independent element of `Y`:

1. run `A` once to obtain `Zhat`;
2. output 1 iff `Zhat=y`.

Then

\[
\Pr[D=1\mid y=Z]=\varepsilon,
\tag{5}
\]

whereas for uniform independent `y`, regardless of the distribution of `Zhat`,

\[
\Pr[D=1\mid y\leftarrow Y]=\frac1M.
\tag{6}
\]

Therefore

\[
\boxed{
Adv_D=\left|\varepsilon-\frac1M\right|.
}
\tag{7}
\]

For a `kappa`-bit output, `M=2^kappa`, so any non-negligible exact recovery
probability yields essentially the same non-negligible distinguishing advantage.

### Quantum validity of this reduction step

This reduction is **straight-line**. It invokes the recovery adversary once and
compares two classical outputs. It does not rewind the adversary, clone auxiliary
state, make superposition random-oracle queries, or extract from a measurement
transcript.

Hence if `A` is QPT with arbitrary quantum auxiliary information and a classical
output register, `D` is also QPT. This particular arrow is quantum-valid.

What is **not** supplied is the next arrow:

\[
\text{QPT WPRF distinguisher}
\Longrightarrow
\text{ORIGINAL source witness}.
\tag{8}
\]

That requires a genuine quantum-secure extractable-WPRF theorem.

---

## 4. Run-112's process-extraction correction is old territory, not a new primitive

Zhandry already defined **extractable WPRFs**. The paper's Definition 3.5 says,
roughly, that a PPT adversary that distinguishes the real WPRF value from random
with inverse-polynomial advantage gives rise to an efficient extractor that outputs a
witness. Importantly, the extractor is tied to the adversary's behavior: the formal
experiment supplies the extractor the adversary's random coins and the queries made
by that adversary.

That is much closer to the process-extraction requirement identified in Runs 102 and
112 than a map from the final value alone.

The paper also contains a warning that directly supports Run 112. Remark 3.8 notes
that semi-static/adaptive extractability is not attainable for many relations when an
instance sampler can itself sample a witness and include

\[
y^*=Eval(ek,x^*,w)=F(fk,x^*)
\]

as auxiliary information: knowing the correct PRF value is then trivial but does not
imply knowing a witness.

Our setup-known-value obstruction is an even simpler special-case composition:

\[
\boxed{
Setup(x)\to(P,Z)
\quad\text{and}\quad
E(x,P,Z)\to w
\Longrightarrow
Setup;E\text{ solves witness search.}
}
\tag{9}
\]

So the correct target is **not** a value-only source extractor. It is an
adversary/process extractor whose input contains something setup itself cannot
manufacture merely by knowing `Z`.

This is a correction to the wording of Run 111's "extractable invariant adaptor"
proposal: the useful known abstraction is closer to an extractable WPRF, with the
same auxiliary-input caveats.

---

## 5. 2026 restricted-language WPRF: important positive evidence, not a PQ endpoint

Bhadauria--Branco--Döttling--Garg--Policharla,
*Witness Pseudorandom Functions for Vector Commitments and Applications*, ePrint
2026/1079 / ASIACRYPT 2026, is directly relevant.

The current primary ePrint abstract says:

1. general-purpose WPRFs are currently known only from assumptions that imply
   indistinguishability obfuscation;
2. the paper constructs a WPRF for a **specific language related to the Libert--Yung
   vector commitment**;
3. public evaluation is possible given a valid **local opening**;
4. the construction is fully black-box and uses standard assumptions on **pairing
   groups**.

This is strong evidence that the exact witness-gated same-value primitive can be much
cheaper for a structured local-opening language.

But it does not close this project:

- Pairing-group implementations are not post-quantum; Shor's algorithm destroys the
  discrete-log hardness underlying ordinary pairing groups.
- The construction is language-specific, not a generic NP compiler.
- The primary PDF was not retrievable in this run, so the exact theorem statement,
  assumption names, adversary model, and whether any extractability notion is proved
  were **not** independently audited beyond the primary abstract.

The useful question therefore becomes whether generic NP can be compiled into a
**PQ local-opening WPRF language** while preserving ORIGINAL-witness extraction.

The next section shows a basic obstruction to the most direct lattice/HBG version.

---

## 6. Waters--Wee--Wu shifted multi-preimage/HBG machinery

Waters--Wee--Wu,
*New Techniques for Preimage Sampling: Improved NIZKs and More from LWE*, ePrint
2024/1401, gives a shifted multi-preimage sampler and a dual-mode hidden-bits
generator.

The full primary PDF text was audited in this run. Relevant exact facts are:

- Lemma 4.1 gives an explicit polynomial-time algorithm producing a **public gadget
  trapdoor** for a structured lattice matrix.
- Construction 5.4 defines `GenBits(crs)` by expanding the CRS to matrices and a
  trapdoor, then invoking `SampleMultPre` to obtain a commitment `c` and short
  preimages/openings `pi_1,...,pi_ell`.
- `GenBits` outputs the commitment, the complete hidden-bit string, and **all** local
  openings; no NP source witness is an input to `GenBits`.
- Corollary 5.19 gives a dual-mode HBG under LWE with polynomial modulus-to-noise
  ratio and CRS size `ell * poly(lambda,log ell)`; in hiding mode setup is
  transparent.
- Corollary 5.20 compiles this to a dual-mode NIZK for NP.

The paper's mode-indistinguishability definition says "all efficient adversaries" but
does not explicitly quantify quantum adversaries in the text audited here. Therefore
its computational theorem is **not** promoted to QPT security in this record.
Statistical hiding in hiding mode is explicitly against computationally unbounded
adversaries and is information-theoretic.

---

## 7. Public-opening source-extraction barrier

The HBG facts above give an unconditional compiler barrier.

Let `R_src(x,w)` be the ORIGINAL source relation. Suppose a proposed compiler maps
`x` to public parameters `P_x` and defines an auxiliary local-opening relation

\[
Q(P_x,\pi)=1.
\]

Assume there is a classical polynomial-time public sampler

\[
\pi\leftarrow Samp(P_x)
\]

which outputs an accepting opening with non-negligible probability **without a source
witness**.

Suppose further that every accepting auxiliary opening is source-extractable:

\[
Q(P_x,\pi)=1
\Longrightarrow
R_{src}(x,Ext(x,P_x,\pi))=1.
\tag{10}
\]

Then the composition

\[
Comp(x);\ Samp(P_x);\ Ext(x,P_x,\pi)
\tag{11}
\]

is itself a polynomial-time source-witness search algorithm with the sampler's
success probability.

Therefore:

\[
\boxed{
\text{publicly samplable local openings}
+
\text{universal local-opening->source extraction}
\Longrightarrow
\text{public source-witness search}.
}
\tag{12}
\]

No cryptographic assumption appears in this implication.

### Application to HBG openings

Construction 5.4's `GenBits` explicitly samples valid local openings from the public
CRS machinery. Consequently, **ordinary HBG local-opening validity cannot itself be
the missing generic-NP source-witness relation** if the source search problem is hard.

This does not attack the HBG or its NIZK application. In the NIZK compiler, source
witness information lives in how the prover uses/selects the hidden bits to prove the
NP statement; the mere existence of a local opening is not an NP witness.

---

## 8. The only escape is a witness-restricted subclass — which is the missing gate

A compiler can avoid (12) if the WPRF evaluator does **not** accept every ordinary
local opening. It could require a stricter predicate

\[
Q_x^{src}(P_x,\pi)=1
\]

such that witness-derived openings satisfy it, while openings generated by the
public sampler generally do not.

But then the construction must answer exactly the question we already had:

> How does the public evaluator recognize/use this witness-restricted subclass
> without exposing a public completion oracle, a searchable support, an affine
> pseudowitness, or a complete noisy gadget encoding?

Thus replacing the missing release layer with an HBG/vector-commitment local opening
does not remove the bottleneck. It **moves the bottleneck into the predicate that
separates source-witness openings from publicly samplable openings**.

This is the same structural boundary reached independently by Runs 104, 107, 109,
110, and 112.

---

## 9. Stronger process-extraction consequence: simulatable transcripts are useless

Run 102 gives a positive example of process extraction: a QPT adversary's circuit and
adjoint can expose Fourier information that is not present in the final value alone.

The HBG/local-opening perspective gives a useful negative complement.

Suppose a proposed extractor sees only a transcript `T` of local-opening evaluations,
and suppose there is a public polynomial-time simulator whose transcript distribution
is identical to the unauthorized adversary's transcript distribution.

For every transcript-only extractor `E`,

\[
\Pr[E(T_A)\text{ outputs a source witness}]
=
\Pr[E(T_{sim})\text{ outputs a source witness}].
\tag{13}
\]

If the left side is non-negligible, then public simulation followed by `E` solves
source witness search.

Hence a viable process extractor must use a feature that the public setup/sampler
cannot reproduce, for example:

- adversary-specific circuit structure;
- adversary coins or a supplied short representation;
- coherent circuit/adjoint access of the Run-102 type;
- a source-bound algebraic object whose distribution cannot be publicly sampled.

Merely seeing valid local openings, their rerandomizations, or the final canonical
value cannot suffice.

---

## 10. Exact reduction ledger

| Component | Honest model | Adversary model actually proved/audited | Assumption/distribution | Reduction model | Exact conclusion for this project |
|---|---|---|---|---|---|
| Zhandry WPRF correctness | classical PPT | n/a | n/a | direct | every valid witness gets same `F(fk,x)` |
| Zhandry baseline WPRF security | classical PPT | **PPT** | paper's multilinear-map construction / relation-specific assumptions | classical | false-instance classical pseudorandomness only |
| Zhandry extractable WPRF definition | classical PPT | **PPT** | definition/sampler-dependent | extractor gets adversary-side information/queries | process-style classical extraction notion; not QPT |
| exact-recovery -> WPRF distinguishing (this run) | classical setup; QPT recovery allowed | **QPT** | none | straight-line, one call, classical equality test | QPT exact final-key recovery yields QPT distinguisher with advantage `|epsilon-1/|Y||` |
| Bhadauria et al. 2026 VC-WPRF | classical | full theorem not audited | primary abstract: standard pairing-group assumptions | full proof unavailable | restricted local-opening WPRF; **not PQ** |
| Waters--Wee--Wu HBG | classical PPT | text says efficient for computational mode; statistical hiding unbounded | LWE polynomial modulus/noise for Cor. 5.19; exact parameters in paper | full computational QPT extension not audited | public local openings + statistical hiding/NIZK machinery, not source-gated release |
| public-opening source barrier (this run) | classical PPT | unconditional | none | direct composition | universal local-opening source extraction collapses source search |
| transcript-simulation barrier (this run) | classical or quantum extractor with classical transcript input | unconditional equality of distributions | none | distributional identity | transcript-only extraction cannot distinguish adversary from public simulator |

The missing theorem is now explicit:

\[
\boxed{
\text{generic-NP, classical-algorithm, QPT-secure process-extractable WPRF}
}
\tag{14}
\]

from independently justified post-quantum assumptions, together with malicious-secure
distributed setup/erasure and practical parameters.

---

## 11. Reproducible checker

`wprf_public_opening_run113_check.py` is standard-library-only and deterministic.
Three finalized executions were byte-identical.

It validates **73,309 assertions**, including:

1. finite WPRF all-valid-witness same-value correctness;
2. exact equality-test reduction
   \(Adv=|\varepsilon-1/M|\) for many output ranges and recovery probabilities;
3. setup-known-value/value-only-extractor composition;
4. public accepting-opening sampler + universal source extractor composition;
5. the restricted-subclass escape hatch;
6. exhaustive transcript-only extractor equality for identical adversary/simulator
   transcript distributions through 4-bit transcript spaces.

These are semantic/algebraic controls. They do not instantiate or validate any
computational WPRF security theorem.

---

## 12. Next handoff

Do **not** spend the next pass inventing another name for the same-value primitive.
Use the WPRF/reusable-witness-KEM syntax directly.

The most valuable next work is one of the following:

1. audit whether any **post-quantum restricted-language WPRF / witness map** from
   standard lattice assumptions appeared after the classical multilinear-map line,
   with exact QPT adversary model;
2. study whether Run 102's circuit+adjoint extractor can be embedded into a WPRF
   security game so that exact raw-key recovery supplies the source frequency needed
   by the existing algebraic source extractor;
3. attempt a source-preserving compiler into a local-opening language that is **not
   publicly samplable** on true hard instances, and immediately test it against the
   Run-104 searchable-support and Runs-108--110 gadget/projection barriers.

The practical generic-NP post-quantum witness KEM remains open. The stopping
condition is not met.
