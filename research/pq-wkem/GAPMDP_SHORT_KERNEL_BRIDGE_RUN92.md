# Run 92 — GapMDP-to-short-kernel bridge: bounded honest amplitudes are the missing normalization condition

## Status

Starting verified PR head: `ff14c55c7d3449d692d0f1da0243239f2472bd21` on `research/pq-wkem-validation-20260918`.

This run does **not** complete the requested PQ witness KEM. It isolates a constructive source-side bridge suggested by Jin's GapMDP reduction, and proves a normalization barrier showing exactly when that bridge can and cannot be converted into the short-Euclidean-kernel interface needed by our SIS/LWE source-binding work.

The positive result is conditional on an exact property that is **not yet verified from Jin's full 2026/2063 proof**: bounded centered amplitudes for the honest low-weight codeword, together with a source-preserving extractor for every sufficiently low-support codeword. The accessible primary/author metadata confirms the GapMDP field and gap, but not that amplitude bound. That missing theorem detail is therefore left **UNVERIFIED**, not silently assumed.

Production code is unchanged. All new artifacts for this run are research-only.

---

## 1. Why this is the right interface after Runs 42, 89 and the latest target audit

Run 42 already gave a clean source-binding wrapper:

> supplied sufficiently short normalized lifted kernel representation -> ORIGINAL source witness or a nonzero SIS solution.

But its natural additive release leaked through a public semantic quotient, so it did not turn arbitrary key recovery into such a representation.

Run 89 then ruled out the specific additive-share/Parseval amplification route on an actual Hair–Sahai false family.

The remaining useful source question is therefore narrower:

> Can a source-preserving gap compiler produce a public linear target in which every *cryptographically relevant short relation* is already an original source witness (or a standard-hardness break), without transparently preserving easy false pseudokernels?

Jin's 2026/2063 abstract gives exactly the kind of combinatorial object worth testing: a Karp–Levin reduction from `polylog(lambda)` circuit SAT to GapMDP over a prime field of size `lambda^{omega(1)}`, with approximation factor `omega(log lambda)`. The paper then plugs this into generic-group witness encryption. The generic-group security does not meet our concrete QPT target, but the **source code gap** may still be reusable.

---

## 2. Conditional source interface

Let a statement `x` compile to a public linear code

\[
C_x = \ker P_x \subseteq \mathbb F_p^m.
\]

Assume the source reduction has the following properties for parameters `d`, `gamma>1`, and centered honest-amplitude bound `B`.

### YES completeness

Every valid source witness `w` gives a nonzero codeword

\[
y_w\in C_x
\]

with

\[
\operatorname{wt}(y_w)\le d,
\qquad
\|\operatorname{ctr}(y_w)\|_\infty\le B.
\tag{1}
\]

Here `ctr` maps each field coordinate to its integer representative in `[-(p-1)/2,(p-1)/2]`.

### Low-support source extraction

There is a polynomial-time extractor which, from any supplied nonzero codeword `y in C_x` satisfying

\[
\operatorname{wt}(y)\le D_{\rm ext},
\tag{2}
\]

returns an ORIGINAL source witness for `x`.

This is stronger than ordinary GapMDP decision soundness. It is the source-preserving/Karp–Levin property our WKEM needs.

### NO gap

For false statements,

\[
0\ne y\in C_x
\quad\Longrightarrow\quad
\operatorname{wt}(y)>\gamma d.
\tag{3}
\]

The exact `B` and `D_ext` for Jin's reduction have **not** been verified in this run because the full 2026/2063 manuscript was not accessible through the available primary-source path. Only the public abstract-level GapMDP statement is used as literature input.

---

## 3. Exact support-to-Euclidean bridge

For every nonzero field coordinate, its centered representative has absolute value at least one. Hence for every `y in F_p^m`,

\[
\boxed{
\operatorname{wt}(y)
\le
\|\operatorname{ctr}(y)\|_2^2.
}
\tag{4}
\]

If additionally every nonzero honest coordinate has centered absolute value at most `B`, then

\[
\boxed{
\|\operatorname{ctr}(y_w)\|_2
\le B\sqrt d.
}
\tag{5}
\]

On a false statement, (3) and (4) imply every nonzero codeword obeys

\[
\boxed{
\|\operatorname{ctr}(y)\|_2
>
\sqrt{\gamma d}.
}
\tag{6}
\]

Therefore the Hamming gap implies a Euclidean gap of at least

\[
\boxed{
\frac{\sqrt\gamma}{B}.
}
\tag{7}
\]

The prime `p` disappears from this ratio **if `B` is independently bounded**.

This is the first constructive point of the run: a large prime field is not itself a problem for a short-kernel source gate. The actual issue is the centered amplitude of the honest codeword.

---

## 4. Supplied-short-relation -> source witness

Suppose an adversary supplies a nonzero codeword `y in C_x` with

\[
\|\operatorname{ctr}(y)\|_2\le B\sqrt d.
\tag{8}
\]

By (4),

\[
\operatorname{wt}(y)
\le
\|\operatorname{ctr}(y)\|_2^2
\le B^2d.
\tag{9}
\]

Thus if the source extractor works through

\[
D_{\rm ext}\ge B^2d,
\tag{10}
\]

then **every supplied short Euclidean relation in the honest norm range already extracts an ORIGINAL source witness**.

In particular, if the false-instance distance promise is `> gamma d` and

\[
\boxed{B^2<\gamma,}
\tag{11}
\]

then an honest-range short relation cannot exist on a false statement. If the low-support extractor is source preserving through `B^2d`, the same relation is useful on true statements as an original-witness object rather than merely a native-code witness.

For `B=1` (e.g. genuinely Boolean/`{0, +/-1}` honest codewords), the gap becomes

\[
\sqrt\gamma,
\]

independent of the large field size. This is exactly the shape wanted by the Run-42 source-binding interface.

**But `B=1` is not asserted for Jin's reduction here.** It is the theorem property that must be audited next.

---

## 5. Why a generic large-prime code is not enough

If all we know is that the honest codeword has Hamming weight at most `d`, with arbitrary nonzero field symbols, then in the worst case

\[
B=\frac{p-1}{2}.
\]

The guaranteed Euclidean gap from (7) degenerates to

\[
\boxed{
\frac{2\sqrt\gamma}{p-1}.
}
\tag{12}
\]

Jin's abstract places the code over a prime field of size `lambda^{omega(1)}`. Therefore one cannot take the Hamming gap alone and silently claim a useful SIS-style Euclidean gap. A bounded honest-symbol theorem, or a different source-preserving norm interface, is necessary.

This is a parameter/interface correction, not a criticism of the GapMDP theorem: minimum distance is a Hamming-weight statement, whereas our short-kernel/SIS interface is norm-sensitive.

---

## 6. Linear symbol normalization cannot manufacture bounded amplitude

A natural repair would be to linearly expand each field symbol before feeding the codeword into a short-kernel target.

Let

\[
E:\mathbb F_p\to\mathbb F_p^L
\]

be a nonzero linear symbol encoder. There is a fixed nonzero vector `r in F_p^L` such that

\[
E(a)=a r.
\]

Choose any coordinate `j` with `r_j != 0`. As `a` ranges over `F_p`, `a r_j` ranges over **all** of `F_p`. Therefore

\[
\boxed{
\max_{a\in\mathbb F_p}
\|\operatorname{ctr}(E(a))\|_\infty
=
\frac{p-1}{2}.
}
\tag{13}
\]

So no nonzero **linear** symbol encoder can turn arbitrary field symbols into a representation whose centered coordinate amplitudes are bounded independently of `p`.

This rules out the simplest way of deriving a bounded-amplitude SIS target from an arbitrary large-prime GapMDP code.

---

## 7. Nonlinear radix expansion has an exact linear-kernel/canonicality problem

The obvious nonlinear alternative is canonical radix expansion. For a base `b>=2`, write

\[
a=\sum_{j=0}^{L-1} d_j b^j,
\qquad d_j\in\{0,\ldots,b-1\}.
\]

The public linear decoding row is

\[
D=(1,b,b^2,\ldots,b^{L-1}).
\]

But it has the explicit local kernel vector

\[
\boxed{g=(b,-1,0,\ldots,0),\qquad Dg=0,}
\tag{14}
\]

with support `2` and squared Euclidean norm `b^2+1`.

One might try to add homogeneous linear checks that enforce canonical digits. That cannot work for every field symbol. Provided `b^{L-1}<p`, the canonical encoding of the valid symbols `1,b,b^2,...,b^{L-1}` is exactly

\[
e_0,e_1,\ldots,e_{L-1}.
\]

These span all of `F_p^L`. Hence any homogeneous linear checker `J` satisfying

\[
J\,\mathrm{Enc}(a)=0
\quad\text{for every canonical field symbol }a
\]

must satisfy

\[
J e_j=0\quad\forall j,
\]

and therefore

\[
\boxed{J=0.}
\tag{15}
\]

So a purely linear target cannot both accept every canonical radix representation and remove the local digit kernel. Enforcing canonicality requires a nonlinear/witness-restricted mechanism—the very capability the WKEM is still missing.

This is an unconditional linear-algebra barrier. It does not depend on LWE, SIS, MinRank, or a generic-group model.

---

## 8. Relation to small-field minimum-distance hardness

Minimum-distance hardness over small or binary fields is known. Dumer–Micciancio–Sudan show inapproximability results over every finite field, including binary codes. More recent fixed-field/PCP-free hardness results also exist.

That observation is a **research lead**, not a cryptographic endpoint:

1. worst-case NP-hardness is not an average-case QPT-hard cryptographic assumption;
2. those results do not automatically give Jin's particular Karp–Levin/source-preserving reduction from a polylogarithmic verification circuit;
3. they do not by themselves prove the exact low-support-to-ORIGINAL-witness extractor required here;
4. they do not solve the public offline release layer.

A bounded-alphabet version of the **source-preserving compressed reduction**, not generic MDP hardness, is the useful target.

---

## 9. Quantum-security ledger

This run proves only finite-field/norm interface statements.

- **Honest algorithm model:** the conditional compiler/extractor interface is classical PPT if instantiated by a suitable source reduction. The algebra/checker here is classical polynomial time.
- **Adversary model:** no security theorem against either PPT or QPT adversaries is proved in this run.
- **Hardness distribution:** none is assumed for the new norm/normalization lemmas. Ordinary GapMDP NP-hardness is not promoted to a QPT cryptographic assumption.
- **Reduction model:** the supplied-short-to-sparse implication is straight-line algebra. There is no rewinding, QROM, superposition-query simulation, or quantum auxiliary-state handling.
- **Exact conclusion:** **conditional supplied-representation extraction**: if the actual source compiler has bounded honest amplitude `B` and source extraction through support `B^2 d`, then a supplied relation of Euclidean norm at most `B sqrt(d)` yields the ORIGINAL source witness. This is **not arbitrary-QPT key-recovery extraction**.
- **Still UNPROVED:** false-statement full-public-output QPT hiding; arbitrary-QPT early FINAL-key recovery -> original witness or independently justified QPT-hard break; malicious-secure setup/abort composition; practical final parameters.

Jin's advertised WE remains in the generic-group model. Its source-gap component can be studied independently, but generic-group extractability is not concrete post-quantum security.

---

## 10. Literature evidence actually checked this run

### Zhengzhong Jin, ePrint 2026/2063

Primary author page: https://zhengzhongjin.github.io/ lists **Witness Encryption for NP from SNARGs and Groups** as a current manuscript.

The current ePrint listing/metadata states that the construction uses:

- any SNARG with subexponential soundness and polylogarithmic online verification after input preprocessing;
- the first Karp–Levin reduction from satisfiability for `polylog(lambda)`-size circuits to GapMDP;
- a prime field of size `lambda^{omega(1)}`;
- approximation factor `omega(log lambda)`;
- generic-group extractable WE for polylogarithmic circuits.

The full 2026/2063 proof was not accessible through the available primary-source path in this run. Therefore the honest-codeword symbol set/amplitude and exact low-weight source-extractor threshold are **not claimed verified**.

### Dumer–Micciancio–Sudan

Primary ECCC report TR99-029: https://eccc.weizmann.ac.il/eccc-reports/1999/TR99-029/index.html . It states minimum-distance inapproximability over every finite field, including binary codes. This is complexity hardness, not the missing concrete-PQ release theorem.

---

## 11. Fresh validation actually executed

`gapmdp_short_kernel_bridge_run92_check.py` is standard-library-only and deterministic. It was run twice; the outputs were byte-identical.

The checker validates:

1. **7,200** random centered-field vectors over six primes and four dimensions, confirming
   `wt(v) <= ||ctr(v)||_2^2 <= B^2 wt(v)`.
2. the exact criterion table `B^2 < gamma` and Euclidean-gap factor `sqrt(gamma)/B`.
3. **480** independently sampled nonzero linear symbol encoders, exhaustively over every input symbol, confirming the maximum centered output amplitude is exactly `(p-1)/2`.
4. five radix parameter sets, confirming the explicit support-two kernel `(b,-1,0,...)` and that canonical encodings of powers `b^j` span the full digit space.
5. raw large-prime Hamming-to-Euclidean gap tables showing the worst-case field-amplitude loss.
6. positive bounded-symbol (`B=1`) cases whose Euclidean gap is exactly `sqrt(gamma)` independent of `p`.
7. exhaustive tiny-field checks of the implication `||v||_2 <= B sqrt(d) => wt(v) <= B^2 d`.

The captured validation SHA-256 is recorded in provenance. These checks validate the algebra only; they are not cryptographic evidence.

---

## 12. Exact next handoff

The most valuable next step is **not another release capsule**. It is to settle the missing source theorem exactly:

1. obtain/audit Jin's full 2026/2063 GapMDP reduction and determine the honest codeword alphabet/amplitude `B`;
2. verify the precise source-preserving statement for *every* codeword of weight up to the extraction threshold, not merely existence of one honest low-weight codeword and a NO-instance distance gap;
3. if `B^2 < gamma`, instantiate the Run-42/SIS source-binding interface with this code target and calculate actual dimensions/norms;
4. if `B` grows with `p`, do **not** try linear digit normalization; instead look for a bounded-alphabet source-preserving reduction or a different standard-PQ norm-sensitive source compiler;
5. only once that source gate is real, return to the missing complete-public-output release theorem under an independently justified QPT-hard assumption.

The stopping condition remains unmet.
