# Run 42 — SIS-randomized short-kernel lift: a real source-binding lemma, and an exact public-quotient separation

## Status

Starting verified PR head: `e334bcb2b569905aa72f328789f9a14eb2fc241e` (Run 41).

This run does **not** complete the requested witness KEM. It makes a constructive lattice attempt that cleanly separates two obligations which previous candidates repeatedly conflated:

1. **source binding:** if an attacker hands us a sufficiently short normalized kernel representation, can we turn it into a source witness or a break of an independently standard PQ assumption?
2. **key release / hiding:** does the complete public capsule force an arbitrary successful key-recovery algorithm to hand us such a representation?

For the first obligation, the randomized lift below gives a direct reduction to standard SIS. This is a useful positive lemma.

For the second obligation, the natural LWE/SIS-style additive capsule fails to gain anything from the random lift: a public semantic quotient removes *all* of the SIS randomization and leaves exactly the old witness-noise channel. Exact semantic pseudomodes also survive every lift unchanged. Thus the construction is a source-binding wrapper, not a WKEM.

No external literature or web search was used. Production code is unchanged.

---

## 1. Semantic interface inherited from the short-kernel compiler

Let

\[
H \in \mathbb Z_q^{r\times N}
\]

be a public semantic matrix with distinguished normalization coordinate `h`.
Assume the compiler/extractor provides a bound `B_sem` such that any centered vector

\[
x\in\mathbb Z_q^N,\qquad Hx=0,\qquad x_h=1,\qquad \|x\|_2\le B_{\rm sem}
\]

extracts a valid source witness. The Run-32 normalized short-kernel compiler is one concrete instance of this interface under its stated no-wrap condition.

The crucial limitation is already known: false statements can still have exact normalized semantic kernel vectors just *outside* the extraction bound. Those are pseudowitnesses, not source witnesses.

---

## 2. Constructive attempt: random SIS lift

Choose dimensions `n,m` and sample independently uniform matrices

\[
C\leftarrow \mathbb Z_q^{n\times r},\qquad
A\leftarrow \mathbb Z_q^{n\times m}.
\]

Write

\[
D=[\,C\mid A\,]\in\mathbb Z_q^{n\times(r+m)}
\]

and publish the lifted matrix

\[
\boxed{M=[\,CH\mid A\,]}\in\mathbb Z_q^{n\times(N+m)}.\tag{1}
\]

The factorization through `D` may be public or retained only by the reduction/setup transcript; the negative quotient result below does not require the attacker to know it.

For a semantic source representation `x`, define the lifted vector

\[
E(x)=(x,0_m).\tag{2}
\]

If `Hx=0`, then immediately

\[
M E(x)=CHx=0.\tag{3}
\]

The normalization coordinate and norm are unchanged:

\[
E(x)_h=x_h,\qquad \|E(x)\|_2=\|x\|_2.\tag{4}
\]

So every valid source witness still gives a short normalized kernel vector of the new, randomized public matrix.

This construction is polynomial size and setup does not need a source witness.

---

## 3. Positive theorem: short lifted kernel vector -> source witness or SIS

Take any lifted vector

\[
e=(x,z)\in\mathbb Z_q^{N+m}.
\]

Define its public semantic image

\[
\boxed{v=L(e):=(Hx,z)\in\mathbb Z_q^{r+m}.}\tag{5}
\]

By construction,

\[
\boxed{Me=Dv.}\tag{6}
\]

Therefore, if `Me=0`, exactly one of two cases holds.

### Case A — `v != 0`

Then

\[
Dv=0,\qquad v\ne0,
\]

so `v` is a nonzero SIS solution for the uniformly sampled matrix `D`.

If `H` is represented by centered integer entries and `e` is centered, then

\[
\|v\|_2^2
=\|Hx\|_2^2+\|z\|_2^2
\le \|H\|_{2\to2}^2\|x\|_2^2+\|z\|_2^2
\le \kappa_H^2\|e\|_2^2,\tag{7}
\]

where

\[
\kappa_H=\max(1,\|H\|_{2\to2}).
\]

For a simple explicit bound one may replace the spectral norm by `||H||_F`.
Centered reduction modulo `q` can only reduce the absolute coordinate magnitude relative to the corresponding unreduced integer sum, so the same upper bound is safe in the usual no-wrap/source-extraction regime.

Thus an algorithm that outputs a lifted kernel vector of norm at most `B` in this case yields an SIS solution of norm at most `kappa_H B`.

### Case B — `v = 0`

Then

\[
Hx=0,\qquad z=0.\tag{8}
\]

If additionally

\[
x_h=1,\qquad \|x\|_2\le B_{\rm sem},\tag{9}
\]

then the existing semantic extractor returns a genuine source witness.

### Source-binding lemma

Under the semantic extraction hypothesis above, any algorithm which outputs

\[
e=(x,z),\quad Me=0,\quad x_h=1,\quad \|e\|_2\le B_{\rm sem}
\]

can be transformed in polynomial time into either:

* a valid source witness; or
* a nonzero SIS solution for uniform `D` of norm at most `kappa_H B_sem`.

This is an actual reduction from a **supplied short normalized lifted representation**. It is not a reduction from arbitrary key recovery.

This distinction matters: the latter is still the central missing step.

---

## 4. Exact semantic pseudomodes survive the lift

The SIS layer does not repair exact modes of the original semantic kernel.
For every

\[
Hx=0,
\]

regardless of whether `x` is a real witness encoding or a false pseudowitness,

\[
M(x,0)=0.\tag{10}
\]

So every exact semantic pseudomode survives **every** random choice of `C,A` with exactly the same semantic coordinates and the same norm.

A tiny diagnostic false relation is

\[
H=[1\;1\;-3],\qquad x_{\rm false}=(1,2,1)^T.\tag{11}
\]

Then

\[
Hx_{\rm false}=0,
\]

and the normalization coordinate is `1`, while no Boolean pair `(x_0,x_1) in {0,1}^2` obeys `x_0+x_1=3`.
For every random lift,

\[
M(x_{\rm false},0)=0.\tag{12}
\]

This toy is only a diagnostic of the algebraic survival phenomenon; the Run-32 record contains the stronger compiler-specific false families and exact extraction bound.

---

## 5. Natural additive capsule

The obvious KEM attempt is to use the lifted matrix as an LWE/SIS-style mask.
Let

\[
\widetilde\Delta=(e_h,0_m)
\]

and publish

\[
\boxed{c=M^Ts+\eta+K\widetilde\Delta\pmod q,}\tag{13}
\]

where `s` is fresh and `eta=(eta_x,eta_z)` is a noise vector.

A valid source witness with lifted vector `E(x)=(x,0)` gets

\[
\langle E(x),c\rangle
=\langle E(x),\eta\rangle+K
=\langle x,\eta_x\rangle+K.\tag{14}
\]

Thus with a suitable small-noise decoding rule, all valid witnesses can in principle obtain the same key.

The temptation is to claim that the random SIS matrix `D` now computationally binds the complete view. That claim is false for this capsule.

---

## 6. Complete-public-output audit: exact semantic quotient

Split the capsule into its first `N` and last `m` coordinates. From (1),

\[
c_x=H^T C^T s+\eta_x+K e_h,\tag{15}
\]

\[
c_z=A^T s+\eta_z.\tag{16}
\]

Consider the public quotient

\[
\pi_H:\mathbb Z_q^N\to
\mathbb Z_q^N/\operatorname{im}(H^T).
\]

Because `H^T C^T s` lies in `im(H^T)`, one obtains the exact identity

\[
\boxed{\pi_H(c_x)=\pi_H(\eta_x+K e_h).}\tag{17}
\]

Every bit of entropy contributed by `C`, by the random SIS instance, and by the fresh mask `s` disappears from this public quotient.

Equivalently, every public semantic character

\[
u\in\ker H
\]

obeys

\[
\boxed{\langle u,c_x\rangle
=\langle u,\eta_x\rangle+K u_h.}\tag{18}
\]

Equation (18) is exact. It does not know or use `C`, `A`, `D`, or `s`.

### Consequence

The random SIS lift can bind **nonsemantic** short directions, but it contributes exactly zero hiding against **semantic** key-sensitive modes.
The complete-view hiding problem on those modes is identical to the pre-lift channel.

In particular:

* if `eta_x=0`, any key-sensitive semantic mode recovers `K` exactly;
* if a true source witness exists, then `e_h` cannot lie in `im(H^T)` and public linear algebra can find a key-sensitive kernel direction even without finding a short/source witness;
* if `eta_x` is product noise, the Run-36 product-noise obstruction and the later Gap-OHLC spectrum issues apply unchanged to this quotient;
* if `eta_x` is replaced by a public affine-subspace carrier, Run 41 applies unchanged after quotienting.

The SIS layer has therefore not solved the release problem.

---

## 7. Why hiding the factorization does not repair the quotient

One might keep `C,A,D` secret after setup and publish only `M`.
That does not affect (17)-(18): the attacker needs only the original public semantic matrix `H` and the capsule's first `N` coordinates.

The reduction can still remember `D` internally in a proof and map a returned short lifted vector to `v=(Hx,z)`, but the adversary does not need `D` to remove the randomization from the semantic quotient.

Likewise, a **public** column mixing can simply be inverted or incorporated into the public quotient. A **secret** column mixing would prevent the source witness from constructing the corresponding lifted decryption vector unless one adds exactly the missing witness-restricted evaluation mechanism. This run does not assume such a mechanism.

---

## 8. What was gained

This run does establish a useful modular statement that was missing from the previous noisy-channel attempts:

> **If a future inner release mechanism can force any successful early key recovery to yield a sufficiently short normalized kernel vector of the randomized lift, then that representation already has a clean source-witness-or-SIS reduction.**

So the source-binding half can be made standard-assumption-based without inventing a new assumption.

What remains unsolved is forcing **arbitrary** key recovery—classical or quantum—to expose such a vector while preserving useful completeness for every source witness.

The natural additive capsule (13) does not do so; its semantic quotient is exactly the old channel.

---

## 9. Fresh local validation actually executed

`SIS_RANDOMIZED_SHORT_KERNEL_LIFT_RUN42_CHECK.py` is standard-library-only and deterministic.
It was executed twice locally; the two captured JSON files were byte-identical.

The executed checks were:

* **4,500** random lift identities `M(x,z)=D(Hx,z)` over `q=5,7,101`;
* classification of every randomly encountered lifted kernel sample into semantic (`v=0`) or SIS (`v!=0, Dv=0`) form;
* **1,000** independent random lifts of the explicit false semantic pseudomode `(1,2,1)`, all of which remained exact lifted kernel vectors;
* **1,200** public quotient/character identities over `q=5,7,11,101`;
* **32** exact small-noise distribution comparisons, enumerating all `3^3=27` errors in `{-1,0,1}^3`, confirming that the false semantic scalar channel is independent of the random SIS lift;
* **2,000** centered norm-bound controls for small `{-1,0,1}` semantic matrices.

There were zero recorded failures.

These tests validate finite algebra used in the proof. They do **not** establish SIS parameters, LWE security, arbitrary-key-recovery extraction, or a completed WKEM.

---

## 10. Unresolved obligations / next handoff

The stopping condition is not met.

The next constructive target is more precise than after Run 41:

1. retain the SIS source-binding wrapper or an equivalent standard-assumption binder;
2. replace the additive release channel with a mechanism whose complete public output does **not** admit the semantic quotient (17), or prove that arbitrary recovery from that quotient yields a short semantic representation;
3. preserve same-key decapsulation for every valid witness without publishing a local input-label capability that can be run on both choices;
4. give a QPT reduction, not only a fixed-character argument;
5. only after that, compose the already-allowed malicious-secure N-of-N / threshold-erasure ceremony and calculate concrete resources.

A secret/public linear change of basis, more SIS rows, a different distribution of `C,A`, or more noise inside `im(H^T)` cannot repair (17). A genuinely surviving construction must alter the release semantics, not merely randomize the public linear mask.
