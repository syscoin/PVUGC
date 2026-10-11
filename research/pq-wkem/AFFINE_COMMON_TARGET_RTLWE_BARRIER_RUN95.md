# Run 95 — affine common-target preimage compiler: all-witness common-key correctness, source-tail transfer, and the exact RTLWE transversality obstruction

## Status

Starting verified PR head: `f127e33fb43ed2898bcc0a67ddbc944c5f514ca9` on branch `research/pq-wkem-validation-20260918`.

This run does **not** complete the requested generic-NP post-quantum witness KEM. It makes one constructive step and one corresponding impossibility-style classification:

1. it gives a concrete classical dual-Regev-style skeleton in which **every normalized short source relation decrypts the same encapsulated key**, with setup knowing the statement but no witness, and with an identity tail that preserves the original source relation exactly;
2. it proves that the public preimage directions needed for that construction are necessarily **aligned** with the LWE challenge direction whenever *any* normalized source relation exists, including dense false-instance pseudorepresentations. Therefore the generalized related-trapdoor-LWE theorem of Waters–Wee–Wu cannot justify this source gate from plain LWE: its exact full-rank/transversality precondition fails.

This is a sharper continuation of Runs 91–94. Run 91 showed how target-kernel relations zeroize correlated LWE. Run 93 showed identity-tail source transfer but projected the release problem back to a structured target. Run 94 showed that Waters–Wee–Wu's standard-LWE theorem protects only transverse preimage access. Run 95 constructs the natural common-target variant and proves precisely why its source-capability directions fall on the **forbidden aligned side** of that theorem.

No production code is changed.

---

## 1. Source interface

Let `q` be prime. A public statement-derived source interface consists of

- `P in F_q^{r x ell}`,
- `h in F_q^ell`,
- a normalization/source relation

\[
P y = 0,
\qquad
h^T y = 1.
\tag{1}
\]

The cryptographic intent is **not** that (1) has no solution on false statements. In the useful gap setting, true statements have a *short / low-support* solution associated with an ORIGINAL witness, whereas false statements may still have dense solutions.

Run 92 recorded one exact source-extraction interface of this form: if every supplied short relation falls within the source extractor's low-support range, then supplied-short representation implies an ORIGINAL witness. The current run uses that as a conditional source gate and does not silently assume Jin's unverified amplitude/source-extraction details.

A basic public-algebra fact will matter later:

\[
\exists y:\; Py=0,\;h^Ty=1
\quad\Longleftrightarrow\quad
h\notin \operatorname{rowspan}(P).
\tag{2}
\]

So exact existence of a normalized relation is publicly decidable by Gaussian elimination. The semantic hardness can only live in an additional property such as shortness, low support, bounded rank, or source extraction.

---

## 2. Construction: affine common-target identity-tail compiler

Choose public `u in F_q^n`, which will be the **common lattice target** for every valid witness.

During setup, generate a near-uniform trapdoored matrix

\[
A_0\in F_q^{n\times m_0},
\]

sample an independent public

\[
B\in F_q^{n\times \ell},
\qquad
G\in F_q^{n\times r},
\]

and define the statement-derived target matrix

\[
T_x := u h^T + GP - B.
\tag{3}
\]

Using the temporary trapdoor for `A_0`, sample a short matrix `K_0` satisfying

\[
A_0 K_0 = T_x.
\tag{4}
\]

Publish

\[
A := [A_0\mid B],
\qquad
F := \begin{bmatrix}K_0\\I_\ell\end{bmatrix}.
\tag{5}
\]

Then, exactly,

\[
AF
= A_0K_0+B
= u h^T + GP.
\tag{6}
\]

The setup trapdoor can be erased after `F` is generated. Setup never needs a source witness.

The checker uses an equivalent toy generation that samples a short `K_0` first and sets `B` so that (6) holds. This validates only the algebra; it is **not** a claim about GPV/MP12 sampling distributions or production parameters.

---

## 3. All-witness common-target theorem

Let `y` satisfy (1), and define

\[
z_y := Fy.
\tag{7}
\]

Then by (6),

\[
Az_y
= AFy
= u(h^Ty)+GPy
= u.
\tag{8}
\]

Thus **every** normalized source relation yields a preimage of the **same** public target `u`.

The identity tail gives the exact source-transfer property

\[
\pi_{\rm tail}(z_y)=y,
\tag{9}
\]

hence

\[
\|y\|_2\le \|z_y\|_2.
\tag{10}
\]

So any supplied decoder known to lie in `Im(F)` immediately reveals the original source relation; if the source compiler has the Run-92 low-support/source-extraction property, a sufficiently short such decoder yields the ORIGINAL source witness.

This is a supplied-representation theorem only. An arbitrary successful adversary need not output a vector in `Im(F)`.

---

## 4. Dual-Regev common-key capsule

A standard dual-Regev-style capsule for a bit `mu` is

\[
c_1=A^Ts+e,
\qquad
c_2=u^Ts+e' + \mu\Delta,
\tag{11}
\]

for random `s in F_q^n`, small errors `e,e'`, and a decoding spacing `Delta`.

A witness computes `z_y=Fy` and forms

\[
c_2-z_y^Tc_1.
\]

Using `Az_y=u`,

\[
\begin{aligned}
c_2-z_y^Tc_1
&=u^Ts+e'+\mu\Delta-z_y^T(A^Ts+e)\\
&=\mu\Delta + e'-z_y^Te.
\end{aligned}
\tag{12}
\]

Therefore every normalized witness decrypts the **same** payload. Correctness reduces to the ordinary short-preimage/noise inequality for `z_y`.

This is the first constructive positive of the run: the common-key requirement itself is not the blocker once the source witness can be turned into a short preimage of one common target.

---

## 5. The complete public projection

The public matrix `F` gives the exact projection

\[
F^Tc_1
=(AF)^Ts+F^Te
=h(u^Ts)+P^TG^Ts+F^Te.
\tag{13}
\]

So the complete public view contains a noisy encoding of the common scalar `u^Ts` in the anchor direction `h`, masked by the row-space term `P^TG^Ts` and transformed noise.

A short normalized source relation `y` removes that mask:

\[
y^TF^Tc_1=u^Ts+y^TF^Te.
\tag{14}
\]

A dense normalized relation does the same algebraically but amplifies the noise through `Fy`. This is the desired **norm-sensitive** distinction.

Equation (13) also shows why plain LWE cannot simply be cited after publishing `F`: the auxiliary preimages expose exactly the correlated target information whose security has to be justified.

---

## 6. The exact Waters–Wee–Wu transversality obstruction

Waters, Wee and Wu, *Multi-Authority ABE from Lattices without Random Oracles*, ePrint 2022/1194, Assumption 4.1 and Theorem 4.2, define generalized related-trapdoor LWE. Their challenge uses a nonzero direction `u`, while a preimage query is indexed by a matrix `M`. The oracle only answers when

\[
\bar M=
\begin{bmatrix}M\\u^T\end{bmatrix}
\]

has full row rank, equivalently

\[
u^T\notin\operatorname{rowspan}(M).
\tag{15}
\]

The paper then proves this **transverse** game from plain LWE. In their subset-policy instantiation, this condition is exactly the unauthorized-key condition.

Primary source:

- https://eprint.iacr.org/2022/1194.pdf
- Assumption 4.1 / Theorem 4.2, especially the full-rank gate and proof around Section 4.

Now transpose the target matrix from (6):

\[
M_x := (u h^T+GP)^T\in F_q^{\ell\times n}.
\tag{16}
\]

If *any* normalized source relation exists, then

\[
M_x^T y=u,
\]

or equivalently

\[
y^T M_x=u^T.
\tag{17}
\]

Therefore

\[
\boxed{u^T\in\operatorname{rowspan}(M_x)}
\tag{18}
\]

and hence

\[
\boxed{
\operatorname{rank}
\begin{bmatrix}M_x\\u^T\end{bmatrix}
=
\operatorname{rank}(M_x).
}
\tag{19}
\]

So the exact generalized related-trapdoor-LWE theorem does **not** cover the public set of preimage directions needed for the common-target source compiler.

This failure is algebraic and independent of the norm of `y`.

---

## 7. Dense false relations still violate the full-rank gate

This is the crucial point for the gap-based source architecture.

Suppose a false statement has no normalized relation below the security norm/support threshold, but does have a dense normalized relation. This is precisely the kind of source gap we have been trying to exploit.

Equation (17) still holds for that dense relation. Hence the Waters–Wee–Wu full-rank gate fails **even though the relation is too long to decrypt correctly**.

The checker contains a deterministic tiny-field false-gap control where

- `ker(P)` is one-dimensional;
- the unique normalized relation has centered squared norm `1630`;
- the designated short cutoff is `200`, so there is no short normalized relation;
- nevertheless `y^T M_x=u^T`, and appending `u^T` does not increase the rank in every trial.

Thus exact transversality is too coarse for the witness-KEM source gate: it distinguishes **existence of any relation**, while the desired semantics distinguishes **short/source-extractable relations from dense pseudorepresentations**.

---

## 8. Why exact transversality cannot be repaired generically

By (2), if a generic compiler arranged that

- every true instance has some normalized relation, while
- every false instance has **no** normalized relation at all,

then the language could be decided by the public test

\[
h\notin\operatorname{rowspan}(P).
\]

For a deterministic generic NP compiler this would place the language in `P`; for an appropriately probabilistic compiler with overwhelming completeness/soundness it would give the corresponding randomized decision algorithm.

So the source gate cannot generically be repaired by forcing all false instances into the exact-transverse regime. The hardness must remain in **shortness / low support / another computationally hidden property**, which is invisible to the full-rank condition (15).

This is the parity-check form of the public-anchor barrier recorded earlier, now applied directly to the related-trapdoor-LWE route.

---

## 9. What kind of lattice assumption this lands on

The closest existing lattice literature is not plain LWE but the family of LWE-with-short-hints assumptions.

Hoeteck Wee, *Circuit ABE with poly(depth, lambda)-sized Ciphertexts and Keys from Lattices*, ePrint 2024/1416, introduces `ell`-succinct LWE. Its public view contains a random short gadget trapdoor `T` for a structured matrix `[I_ell tensor B | W]`, while an LWE sample for `B` must remain pseudorandom. The paper explicitly presents this as a **new falsifiable assumption**, shows it is implied by evasive LWE (plus LWE in the stated reduction), and does not claim a reduction from ordinary LWE for the general succinct regime.

Primary source:

- https://eprint.iacr.org/2024/1416.pdf
- Assumption 1 and Section 6.

The paper notes that `1`-succinct LWE follows readily from LWE in the easy parameter regime, while the useful growing-`ell` versions enable stronger functionality and are treated as distinct assumptions. It also states its security notions against PPT adversaries; this is not by itself an arbitrary-QPT theorem.

Run 95 does **not** claim that the present `F` distribution is literally Wee's succinct-LWE distribution. The point is classificatory: once the public view contains short correlated preimages whose linear span reaches the challenge direction, we have left the part of related-trapdoor access already reduced to plain LWE by Waters–Wee–Wu and entered exactly the kind of norm-sensitive short-hint territory studied by succinct/evasive LWE.

That is a research lead, not an acceptable endpoint for the user's target: the final scheme still needs an independently justified assumption secure against QPT attackers, not merely a new assumption asserting the desired correlated-view pseudorandomness.

---

## 10. Arbitrary-key-recovery gap remains

Even if the correlated public view were hidden, the current source-transfer theorem only handles decoders of the form

\[
z=Fy.
\]

A general attacker could potentially recover the final key without outputting any such `z`, or could find a short preimage of `u` outside `Im(F)`.

Two separate obligations therefore remain:

1. **release security:** the full public distribution `(A,F,u,c_1,c_2,...)` must hide the key on false instances against arbitrary QPT adversaries under an independently justified QPT-hard assumption;
2. **recovery extraction:** arbitrary QPT final-key recovery on a true statement must yield either the ORIGINAL source witness or an independently justified PQ-hardness break.

Run 95 proves neither.

A supplied outside-image short preimage can sometimes be converted to a short SIS difference if a suitable public reference preimage is available within the SIS norm bound, but that does not convert an arbitrary key-recovery algorithm into such a preimage and is therefore not the missing theorem.

---

## 11. Quantum-security ledger

### Honest algorithm model

The compiler/capsule algorithms above are classical polynomial-time *conditional on* an efficient classical trapdoor sampler and a polynomial-size source interface.

### Adversary model

No complete hiding theorem is proved here. The algebraic attacks/barriers are classical PPT and therefore also available to QPT adversaries.

### Hardness assumptions

- The new correctness/source-tail/transversality statements are unconditional finite-field algebra.
- Ordinary LWE may separately be instantiated at parameters with quantum worst-case foundations, but those foundations do **not** automatically cover the public correlated-preimage matrix `F`.
- Waters–Wee–Wu prove their generalized **transverse** related-trapdoor-LWE game from LWE; the present aligned source directions violate the theorem's full-rank precondition.
- `ell`-succinct LWE is a separate falsifiable short-hint assumption; its 2024 paper states classical computational indistinguishability and relates it to evasive LWE. It is not silently relabeled here as QPT-hard standard LWE.

### Reduction model

The new theorems use straight-line algebra only. There is no rewinding, QROM, superposition-query oracle simulation, or quantum extraction.

### Exact conclusion

Run 95 establishes:

- all-witness **common-target/common-key correctness** for the affine compiler;
- exact identity-tail **supplied image-decoder -> source relation** transfer;
- an exact proof that **any normalized relation forces aligned preimage directions**, violating the Waters–Wee–Wu full-rank gate;
- an exact proof that eliminating all such false aligned relations would make the source language publicly decidable.

Still **UNPROVED**:

- false-statement complete-public-output QPT hiding;
- arbitrary-QPT early final-key recovery -> ORIGINAL source witness or independently justified QPT-hard break;
- malicious-secure distributed setup/abort composition;
- practical final parameters.

---

## 12. Fresh checker and validation

`affine_common_target_run95_check.py` is standard-library-only and deterministic. It was executed twice with byte-identical JSON output.

It checks:

1. **500** fresh affine common-target systems, including
   - `AF = u h^T + GP`,
   - `Py=0`, `h^Ty=1`,
   - `A(Fy)=u`,
   - exact identity-tail recovery,
   - the dual-Regev decryption residual,
   - the complete public projection `F^T c_1`;
2. **500** false-gap controls with a unique normalized relation of centered squared norm `1630 > 200`, confirming there is no short normalized relation while the WWW-style full-rank gate still fails every time;
3. **1000** random public row-space controls confirming
   `exists y: Py=0 and h^Ty=1` iff `h notin rowspan(P)`;
4. a bounded-alphabet norm-gap table illustrating the Run-92 `B=1` interface.

The toy systems do **not** implement GPV/MP12 Gaussian trapdoor sampling, real LWE hardness, a full KEM security game, or QPT experiments. Passing them validates only the exact algebra claimed above.

Checker SHA-256: `2c9f8301997a641cb26f2fe6f7bef807da2c7fd8f0682f59ecd20ca08b033988`.

Captured validation SHA-256: `4faebcd873fb8b30f669b2d8528809fd802ed00e9654416f977fe340f498bf13`.

---

## 13. Precise next handoff

The next useful step is **not** another attempt to fit the source gate into exact Waters–Wee–Wu transversality. Run 95 rules that out for the natural linear-synthesis route.

The two credible directions are now:

1. **standard-assumption norm-sensitive simulation:** find a distribution of public short preimages for which aligned *dense* source combinations are harmless but aligned *short* combinations are witness-extractable, with a direct straight-line reduction to a QPT-hard standard problem rather than a succinct/evasive-LWE-style assumption; or
2. **source compression before the lattice layer:** compress the effective normalized-relation space enough that a standard-LWE transverse interface becomes possible without making normalized relation existence itself publicly decide the language.

Any proposal should be rejected immediately if its proof step is merely “LWE remains hard given these aligned short preimages,” because that is exactly the missing statement isolated here.

The stopping condition remains unmet.
