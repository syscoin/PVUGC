# Run 96 — Hamming-spectral public release with statistical false-statement hiding

## Status

Starting verified PR head: `f127e33fb43ed2898bcc0a67ddbc944c5f514ca9` on `research/pq-wkem-validation-20260918`.

This is **not** the completed practical PQ WKEM. It is a new release theorem that removes the Run-92 field-amplitude condition and avoids the aligned related-trapdoor/LWE obstruction from Runs 93–95.

Given a public Hamming-gap source `C_x = ker P_x`, a q-ary symmetric-noise capsule has an exact complete-output Fourier spectrum depending only on Hamming weight. On false statements its hiding can therefore be **statistical**, hence valid against arbitrary QPT adversaries without LWE, SIS, generic groups, or a random oracle.

The remaining central obligation is still true-instance extraction: arbitrary QPT early FINAL-key recovery must imply an ORIGINAL source witness or an independently justified QPT-hardness break.

## 1. Source interface

Let `q` be prime and let the statement compiler output

\[
P_x\in\mathbb F_q^{r\times m},\qquad h_x\in\mathbb F_q^m,
\]

with

\[
C_x=\ker P_x,\qquad k=\dim C_x.
\]

Carry forward the normalized source interface from Runs 92/95:

* every valid ORIGINAL witness gives `y_w in C_x` with `wt(y_w) <= d` and `h_x^T y_w = 1`;
* for eventual true-instance extraction, every sufficiently low-support normalized relation must extract an ORIGINAL source witness;
* on a false statement every nonzero `y in C_x` has `wt(y) >= D`, with `D >= gamma d`.

Shortness, not exact linear feasibility, is the hard property. Dense normalized relations may be publicly computable.

## 2. q-ary symmetric noise

For `0 <= beta <= 1`, define `E_beta in F_q` by

\[
\Pr[E_\beta=0]=\frac{1+(q-1)\beta}{q},
\qquad
\Pr[E_\beta=a]=\frac{1-\beta}{q}\quad(a\ne0).
\]

Every nontrivial additive character has expectation `beta`.

For every nonzero scalar `a`,

\[
aE_\beta\overset d=E_\beta,
\]

and the sum of `w` independent copies is distributed as `E_{beta^w}`.

This scalar invariance is the key correction to Run 92: field-symbol magnitude disappears; only support size matters.

## 3. Public capsule and all-witness correctness

To encapsulate one symbol `mu in F_q`, sample

\[
s\leftarrow F_q^r,\qquad e\leftarrow E_\beta^m
\]

and publish

\[
\boxed{c=P_x^Ts+e+\mu h_x.}
\]

There is no trapdoor.

A valid witness relation gives

\[
y_w^Tc=\mu+y_w^Te.
\]

If `w=wt(y_w)`, then `y_w^T e` is `E_{beta^w}`. Thus the correct symbol has probability

\[
p_0(w)=\frac{1+(q-1)\beta^w}{q},
\]

every fixed wrong symbol has probability

\[
p_1(w)=\frac{1-\beta^w}{q},
\]

and the probability gap is exactly `beta^w`.

Publish `L` independent capsules for the same symbol and let the witness take plurality. Put

\[
t=\beta^d.
\]

Since every valid witness has weight at most `d`, Hoeffding plus a union bound gives

\[
\boxed{
\Pr[\text{honest error}]
\le(q-1)e^{-Lt^2/2}.
}
\tag{1}
\]

This is an explicit classical polynomial-time decoder whenever `L` is polynomial.

## 4. Exact complete-public-output spectrum

Let `H_x = rowspan(P_x) = C_x^\perp`. Because `P_x^Ts` is uniform on `H_x`, the one-capsule law is

\[
W_\mu=U_{H_x}*E_\beta^m+\mu h_x.
\]

For a Fourier character indexed by `y in F_q^m`,

\[
|\widehat W_\mu(y)|
=
\begin{cases}
\beta^{wt(y)},&y\in C_x,\\
0,&y\notin C_x.
\end{cases}
\]

The message shift contributes only a phase.

Let `U` be uniform on `F_q^m`. Parseval gives the exact identity

\[
\boxed{
\chi^2(W_\mu\|U)
=
S_x(\beta)
:=
\sum_{0\ne y\in C_x}\beta^{2wt(y)}.
}
\tag{2}
\]

So the relevant security object is precisely the false code's Hamming weight enumerator evaluated at `beta^2`.

For `L` independent repetitions of the same message,

\[
1+\chi^2(W_\mu^{\otimes L}\|U^{\otimes L})
=
(1+S_x(\beta))^L.
\]

Therefore for any two messages,

\[
\boxed{
TV(W_\mu^{\otimes L},W_{\mu'}^{\otimes L})
\le
\sqrt{(1+S_x(\beta))^L-1}.
}
\tag{3}
\]

Equation (3) is information-theoretic. If its right side is negligible, false-statement hiding holds against an unbounded adversary and therefore against arbitrary QPT adversaries.

## 5. Minimum-distance corollary

If the false code has dimension `k` and minimum distance at least `D`,

\[
\boxed{
S_x(\beta)\le(q^k-1)\beta^{2D}.
}
\tag{4}
\]

If `D >= gamma d` and `t=beta^d`,

\[
\boxed{
S_x(\beta)\le(q^k-1)t^{2\gamma}.
}
\tag{5}
\]

Together, (1), (3), and (5) give an explicit correctness/hiding tradeoff.

This changes the Run-92 audit target. A large prime field no longer hurts because honest nonzero symbols may be large; it hurts through `q^k`, or more accurately through the full weight enumerator (2).

## 6. Polynomial repetition criterion

Set

\[
t=\lambda^{-c}
\]

for fixed `c>0`, and

\[
L=2t^{-2}A(\lambda)
\]

for polynomially bounded `A`.

Then correctness is at most

\[
(q-1)e^{-A}.
\]

Thus `A - ln q = omega(ln lambda)` gives negligible correctness error.

Using the distance-only bound,

\[
L S_x(\beta)
\le
2A(q^k-1)t^{2(\gamma-1)}.
\]

A sufficient condition for negligible false leakage with polynomial `L` is

\[
\boxed{
2c(\gamma-1)\ln\lambda
-k\ln q
-\ln A
=
\omega(\ln\lambda).
}
\tag{6}
\]

A convenient sufficient regime is `gamma -> infinity` and

\[
\frac{k\ln q}{(\gamma-1)\ln\lambda}=O(1).
\]

Then a sufficiently large fixed `c` can satisfy (6) while `L` stays polynomial.

Jin 2026/2063 publicly advertises `gamma = omega(log lambda)` over a prime field of size `lambda^{omega(1)}`, but the accessible metadata does not expose the resulting code dimension `k` or full weight enumerator. Therefore this run does **not** claim that Jin's current reduction already satisfies (6).

The exact source audit target is now:

\[
S_x(\beta)
=
\sum_{0\ne y\in C_x}\beta^{2wt(y)},
\]

or, as a coarse fallback, `k ln q / ((gamma-1) ln lambda)`.

## 7. Stronger outer coding is a lead, not part of the proved construction

For one inner capsule the valid witness sees a q-ary symmetric channel. Its uniform-input capacity is

\[
C_{main}
=
\log_2q-H_2(p)-p\log_2(q-1),
\]

where `p=(q-1)(1-t)/q`.

For a false statement,

\[
I(\mu;c)\le\log_2(1+S_x(\beta))
\]

for uniform `mu`, using `D_KL <= ln(1+chi^2)` and the KL chain identity.

So a positive information-theoretic secrecy-rate gap exists whenever

\[
C_{main}>\log_2(1+S_x(\beta)).
\]

Classical channel-resolvability/wiretap coding can exploit such a gap, and strong-secrecy polar constructions are known even for general non-degraded wiretap channels. But I do **not** claim a final practical outer compiler here: a universal efficiently constructible code that does not need to decide whether `x` is true, and that handles the huge public-output alphabet efficiently, still needs specification and audit.

The fully explicit result of Run 96 is the repetition construction above.

## 8. Partial true-instance extraction interface

A supplied normalized linear relation of weight `w` gets channel bias `beta^w`. With `L` repetitions, relation-based plurality decoding only becomes useful once roughly

\[
L\beta^{2w}
\]

is non-negligible.

Therefore, if the source extractor covers every relation through that weight range, every **supplied relation-based decoder** yields the ORIGINAL source witness.

This is still weaker than the project requirement. An arbitrary QPT key-recovery algorithm need not output a relation and may exploit the whole spectrum jointly. The missing theorem remains

\[
\boxed{
\text{arbitrary QPT key recovery}
\Longrightarrow
\text{extractable low-weight normalized source relation}
}
\]

or an independently justified QPT-hardness break.

Because the public spectrum is now explicit and supported exactly on `ker P_x`, a quantum-valid heavy-Fourier/source-extraction theorem for this distribution is the next constructive target.

## 9. Relation to prior literature

This run does **not** claim that GapMDP-to-WE is novel.

Barta–Ishai–Ostrovsky–Wu (CRYPTO 2020) already use strong GapMDP hardness in a generic-group WE route. Jin 2026/2063 explicitly combines a new Karp–Levin GapMDP reduction with that framework.

The new point for this research thread is narrower: the capsule above is a fully classical public distribution; false hiding is an exact statistical Fourier statement rather than generic-group hardness; Hamming support directly drives correctness; and the Run-93–95 aligned trapdoor problem disappears from the false-hiding layer.

I have not established whether the exact q-symmetric-noise capsule appears elsewhere.

Fresh literature also surfaced ePrint 2026/2113 by Ghosal, Lou, and Sahai, *Post-Quantum PKE and More from a Noisy Unstructured Linear Algebraic Assumption: Beyond LWE and LPN*. Its public listing presents a new noisy linear assumption. No theorem from that paper is used here; its full current proof was not audited in this run.

## 10. Quantum-security ledger

**Honest algorithms:** classical PPT if the source compiler and `L` are polynomial.

**False-statement adversary:** unbounded for the theorem (3), hence arbitrary QPT is covered.

**Hardness assumption for false hiding:** none once the false code satisfies the spectral bound.

**Reduction model:** finite-field Fourier analysis and elementary probability only; no rewinding, QROM, superposition oracle, generic group, LWE, or SIS.

**Established conditionally on the source interface:**
1. all-witness same-symbol correctness;
2. exact complete-output false spectrum;
3. statistical false-statement hiding;
4. explicit polynomial-efficiency criterion;
5. supplied relation-based extraction when the source extractor covers the relevant support.

**Still UNPROVED:**
1. arbitrary-QPT true-instance FINAL-key recovery -> ORIGINAL source witness / independent QPT-hard break;
2. Jin's exact `k`, normalization and low-support extraction parameters;
3. final practical parameters/outer coding if repetition is too large;
4. malicious-secure source/setup composition if the chosen source compiler requires setup randomness.

The stopping condition is not met.

## 11. Validation

The deterministic standard-library checker was executed twice with byte-identical JSON.

It checks:
* 37 exact q-ary symmetric scalar/convolution identities over `q=2,3,5,7`;
* 40 exact small-code spectral/chi-square identities;
* 40 distance-based coarse bounds;
* 10 message-shift invariance identities;
* 15 witness-channel laws;
* 9 exact plurality-error computations against the Hoeffding union bound;
* 12 product chi-square identities;
* 20 asymptotic exponent identities.

These are algebra/probability checks only, not evidence for Jin's missing source parameters or arbitrary-QPT extraction.

## 12. Next handoff

1. Audit Jin's full current GapMDP proof for `k,m,D,d`, common normalization, low-support ORIGINAL-witness extraction, and ideally the full false-code weight enumerator. Evaluate (2) directly and (6) as fallback.
2. Attack the true-instance black-box extraction problem for
   `c=P^T s+e+mu h`: prove or refute that a QPT key recoverer yields a heavy/low-weight Fourier mode that source-extracts.
3. If repetition parameters are too large but the inner secrecy-capacity gap is positive, instantiate and audit a universal efficient strong-secrecy outer code rather than introducing another cryptographic release assumption.

The project remains active.
