# Run 91 - trapdoor-target zeroizers: restricted correlated-prefix barrier

**Status:** new exact classical algebraic barrier for the restricted Tsabary-style trapdoor/prefix route. This is not a completed WKEM and not a claimed break of Tsabary's full Assumption 31 or construction.

**Starting verified PR head:** `ff14c55c7d3449d692d0f1da0243239f2472bd21` on `research/pq-wkem-validation-20260918`.

Production code is unchanged. This run builds on the published short-kernel boundary, Run 42 SIS lift, Run 72 standard-LWE transport, Run 79 Tsabary audit, and Run 89 spectral barrier. It does not retry denied/unpublished Runs 86-88 or Run 90.

## 1. Target interface

Work over prime `F_q`. Let

\[
A\in F_q^{n\times m},\quad T\in F_q^{n\times d},
\]

and let the public trapdoor-preimage table

\[
K\in Z^{m\times d}
\]

satisfy

\[
AK=T\pmod q. \tag{1}
\]

An LWE sample for `A`, in column form, is

\[
c=A^T s+e\pmod q. \tag{2}
\]

Tsabary's Assumption 31 explicitly gives the adversary a trapdoor sample `K <- A^TD(T)` together with correlated target/prefix/auxiliary data. `EncodeEdge` uses a target of the form `S A'`. The paper's relative-hardness definition and WE theorem are stated for PPT distinguishers. Its separate standard-LWE theorem recalls parameter regimes with a quantum worst-case lattice foundation; that does not turn Assumption 31 itself into a QPT theorem.

Primary source: Rotem Tsabary, *Candidate Witness Encryption from Lattice Techniques*, CRYPTO 2022, Sections 3.2 and 4.1:
https://crypto.iacr.org/2022/papers/530630_1_En_19_Chapter_OnlinePDF.pdf

## 2. Theorem - target right-kernel relation gives an LWE zeroizer

Suppose an efficiently known integer vector `a` satisfies

\[
Ta=0\pmod q. \tag{3}
\]

Define

\[
z=Ka. \tag{4}
\]

Then

\[
Az=AKa=Ta=0\pmod q. \tag{5}
\]

Therefore every LWE sample (2) satisfies the exact public identity

\[
\boxed{\langle z,c\rangle=\langle z,e\rangle\pmod q.} \tag{6}
\]

If `z mod q != 0`, then for a uniform `u <- F_q^m`, the value
`<z,u>` is exactly uniform in `F_q`.

This is unconditional linear algebra. It assumes no LWE/SIS hardness, random oracle, generic group, rewinding, or extraction.

### Prefix closure

For every left prefix matrix `S`,

\[
(SA)z=0, \tag{7}
\]

so the same `z` simultaneously zeroizes LWE samples attached to every public `SA`:

\[
c_S=(SA)^Ts+e
\quad\Longrightarrow\quad
\langle z,c_S\rangle=\langle z,e\rangle\pmod q. \tag{8}
\]

This is directly relevant to the `{SA}` side of Tsabary's Assumption 31. It does **not** refute that relative-hardness assumption. It does rule out a proof step that treats the correlated `SA` samples as pseudorandom solely by ordinary decisional LWE while exposing such a dangerous `K`.

## 3. Exact bounded-error distinguisher

If every coordinate obeys `|e_i| <= B_e`, put

\[
\tau=B_e\|z\|_1<(q-1)/2.
\]

Test whether the centered residue of `z^T c` lies in `[-tau,tau]`.

For LWE the test accepts with probability `1`. For uniform input it accepts with probability

\[
(2\tau+1)/q.
\]

Hence the exact distinguishing advantage is

\[
\boxed{1-(2\tau+1)/q.} \tag{9}
\]

This is a classical PPT attack whenever `a` is efficiently available, and therefore also an attack in the QPT threat model.

For independent mean-zero `sigma`-subgaussian error coordinates, threshold `0 <= tau < q/2` gives advantage at least

\[
1-2\exp\!\left(-\frac{\tau^2}{2\sigma^2\|z\|_2^2}\right)
-\frac{2\tau+1}{q}. \tag{10}
\]

If every column `K_j` has `||K_j||_2 <= beta`, then

\[
\boxed{\|Ka\|_2\le\beta\|a\|_1.} \tag{11}
\]

The actual criterion remains the public object `z=Ka`: if `Ka=0 mod q`, this particular nonzero character is degenerate and the above distinguisher does not follow.

## 4. Transparent semantic targets preserve false pseudokernels

Let `H` be a public statement-derived semantic matrix and choose a transparent target

\[
T=GH. \tag{12}
\]

Every semantic relation `Ha=0` remains a target relation `Ta=0`. If a public preimage table satisfies `AK=T`, it maps that relation to

\[
z=Ka,\qquad Az=0. \tag{13}
\]

Thus a trapdoor-preimage wrapper cannot by itself delete an efficiently known semantic pseudokernel. It transports it into a candidate LWE zeroizer.

The published normalized-short-kernel false family gives exactly such a relation. For the unsatisfiable formula

\[
(z\lor z\lor z)\wedge(\neg z\lor\neg z\lor\neg z)
\]

and padded variants, the public false normalized kernel vector satisfies

\[
Ha_{\rm false}=0,\quad (a_{\rm false})_h=1,
\]

while, with honest threshold `B^2=N+1`,

\[
\boxed{
\|a_{\rm false}\|_2^2=B^2+4,\qquad
\|a_{\rm false}\|_1=B^2+2.
} \tag{14}
\]

So direct targets `T=H` or `T=GH` preserve the explicit false relation. If `K a_false` is nonzero and sufficiently quiet under the LWE error, Theorem 2 gives a false-instance public distinguisher.

Run 42 does not repair this specific issue: its SIS randomized lift gives a useful supplied-short-representation witness-or-SIS theorem, but it also preserves every exact semantic pseudomode `(a,0)`. Feeding that lifted target into a trapdoor sampler therefore preserves this known false relation as well.

## 5. What this means for the Tsabary route

Tsabary's actual target is `S A'`. For random/trapdoor-generated `A'`, finding a sufficiently short right-kernel relation may itself be SIS-hard. Therefore this run does **not** break the actual construction or Assumption 31.

The result is narrower and directly relevant to our attempted standard-assumption specialization:

> Ordinary LWE cannot justify the correlated trapdoor view merely because `A` is LWE-hard if the chosen statement-derived target makes an efficient short right-kernel relation public.

Recent evasive-LWE work reinforces the need to audit this exact distribution rather than rename it standard LWE. Huang-Hung-Yamada (ePrint 2025/421) explicitly describes evasive LWE as a significant strengthening of standard LWE. Agrawal-Modi-Yadav-Yamada, *Zeroizing Attacks Against Evasive and Circular Evasive LWE* (TCC 2025; ePrint 2025/375), gives zeroizing attacks against some public/private-coin evasive-LWE instantiations. Neither fact is asserted here to break Tsabary's exact Assumption 31.

## 6. Necessary direct-zeroizer safety contract

For every efficiently obtainable target relation `a` relevant to the complete public view, a surviving construction needs at least one of:

1. `Ta != 0`;
2. `Ka = 0`;
3. `Ka` is too noise-amplifying to distinguish;
4. producing `a` already gives an **ORIGINAL source witness**;
5. producing `a` gives an independently justified QPT-hard SIS/LWE break.

This is only a necessary direct-zeroizer condition. An arbitrary final-key adversary need not output `a`, so the full arbitrary-QPT extraction theorem remains separate.

## 7. Executed validation

`trapdoor_target_zeroizer_run91_check.py` is deterministic and standard-library-only. It ran twice with byte-identical JSON output.

The checker reconstructs the published short-kernel contradiction family, then builds toy exact preimage tables

\[
K=\begin{pmatrix}I\\R\end{pmatrix},
\qquad
A=[H-A_2R\mid A_2],
\]

so `AK=H mod q`. This fixture is **not TrapGen** and is not a security experiment.

It checks:

- 32 exact `AK=H` and `A(Ka)=0` identities;
- 3,200 bounded-error LWE samples satisfying `z^T(A^Ts+e)=z^T e`;
- 320 random prefix matrices `S` satisfying `(SA)z=0` and the same zeroizer identity;
- 32 column-norm controls for (11);
- 9 exact uniform-functional enumeration controls over `q in {5,7,11}`;
- padded false fixtures with 0, 4, 16, and 64 dummy variables, retaining the exact `+4` squared-norm and `+2` l1 gaps.

Toy parameters are `q=65537` and coordinate error bound `1`. The minimum exact bounded-error distinguishing advantage across the recorded toy fixtures remains above `0.997`. These values validate the algebra, not deployment security.

## 8. Quantum/security classification

- Honest trapdoor/LWE algorithms: classical PPT.
- Run-91 attack: classical PPT, hence automatically available to QPT.
- Standard LWE: may be instantiated with independently justified QPT-hard parameters for its **standard distribution**.
- Correlated `K,T,S` view: not automatically covered by standard LWE.
- Tsabary Assumption 31: nonstandard correlated-trapdoor relative-LWE assumption, stated in the paper for PPT distinguishers.
- Run 42: supplied-representation extraction to original witness or SIS, not arbitrary key recovery.
- Desired false-statement QPT hiding: **UNPROVED**.
- Desired arbitrary-QPT final-key recovery -> original witness / independent PQ break: **UNPROVED**.

## 9. Result / next handoff

**New result:** a public target right-kernel relation is transported by its public trapdoor-preimage table into a simultaneous zeroizer for `A` and every left-prefixed `SA`.

**Rejected integration:** raw Run-32/Run-42 transparent semantic targets inside a Tsabary-style trapdoor-preimage layer.

**Constructive next target:** build a compact statement-derived target whose efficiently usable short right-kernel relations already imply an original witness or a standard QPT-hard SIS break, while valid witnesses still support a common-key offline decoder. Then prove the complete correlated auxiliary-view hybrid straight-line against QPT adversaries. Hair-Sahai/Jin gap machinery may help with source extraction/compression, but a rank gap alone is not yet a short right-kernel guarantee.

The practical generic-NP PQ WKEM stopping condition is **not met**.
