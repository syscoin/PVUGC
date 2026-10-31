# Run 43 — normalization-column puncturing gives a native preimage KEM interface, but the Run-32 false family decrypts at the tight honest threshold

## Status

Starting verified PR head: `def4c09bc8f506593dca217739c5327965dcb713` (Run 42).

This run does **not** complete the requested witness KEM. It follows the later Run-43 checkpoint on erased-trapdoor/public preimage transfer and separates three statements that must not be conflated:

1. a **positive algebraic bridge** from the Run-42 normalized kernel binder to a native short-preimage decryption interface;
2. a **positive source-binding reduction for a supplied sufficiently short preimage** to either a source witness or the existing uniform-SIS instance; and
3. a **negative complete-output result** for the natural dual-Regev-style release: the explicit Run-32 false normalized kernel family becomes a public exact preimage only additive `+4` in squared norm beyond the honest boundary, and it decodes with overwhelming probability even when the modulus is chosen at the tightest integer threshold giving deterministic honest correctness for ternary noise.

No external literature or web search was used. The dual-Regev form below is used as a native algebraic encryption interface; this run does **not** claim an LWE reduction for its structured public matrix. Production code is unchanged.

---

## 1. Inherited Run-42 interface

Let

\[
M=[CH\mid A_0]\in \mathbb Z_q^{n\times (N+m)}
\]

be the Run-42 lift of a public normalized semantic compiler `H`, with distinguished semantic normalization coordinate `h`. For every source witness there is

\[
e=(x,0_m),\qquad Me=0,\qquad e_h=x_h=1,
\]

with `||e||_2 <= B_sem`.

Run 42 proved the following supplied-representation lemma. Writing

\[
D=[C\mid A_0],\qquad L(e)=(Hx,z)
\]

for `e=(x,z)`, one has `Me=D L(e)`. Hence a supplied normalized lifted kernel vector below the semantic bound gives either:

* `L(e)=0`, in which case the semantic extractor returns a source witness; or
* `L(e) != 0`, in which case it is a nonzero short solution to the uniform SIS matrix `D`.

The missing piece was release: the additive Run-42 capsule exposed the old semantic quotient.

---

## 2. Constructive bridge: puncture the normalization column

No extra public syndrome-transfer matrix is required to turn the normalized kernel relation into a preimage relation.

Let `m_h` be column `h` of `M`, and let

\[
\bar A=M_{\setminus h},\qquad u=-m_h.\tag{1}
\]

For a vector `y` over all non-`h` coordinates, let

\[
\iota(y)=(1,y)
\]

mean insertion of `1` in coordinate `h` (with the obvious coordinate ordering).

Then exactly

\[
\boxed{M\iota(y)=0\iff \bar A y=u.}\tag{2}
\]

This is only column expansion:

\[
M\iota(y)=m_h+\bar A y.
\]

Therefore every valid source witness immediately yields a public short preimage

\[
y_w=(x_{\setminus h},0_m),\qquad \bar A y_w=u.\tag{3}
\]

The norm relation is exact:

\[
\|\iota(y)\|_2^2=1+\|y\|_2^2.\tag{4}
\]

### Corollary 2.1 — supplied short preimage -> source witness or SIS

Suppose an algorithm outputs

\[
\bar A y=u,
\qquad
\|y\|_2^2\le B_{\rm sem}^2-1.
\]

Then `e=iota(y)` satisfies `Me=0`, `e_h=1`, and `||e||_2<=B_sem`. Applying the Run-42 lemma gives, in polynomial time, either:

* a source witness; or
* a nonzero SIS solution for the uniform matrix `D`, with the Run-42 explicit norm inflation.

This is a real source-binding reduction for a **supplied short preimage**. It is still not a reduction from arbitrary key recovery.

### Why this is better than the checkpoint's abstract adapter

The checkpoint considered a public transfer matrix satisfying

\[
A R = C H + u e_h^T.\tag{5}
\]

For every normalized semantic kernel point `x`, equation (5) gives

\[
A(Rx)=CHx+u x_h=u.\tag{6}
\]

Thus a public linear `R` transfers *every* normalized semantic kernel point, not only genuine source encodings. The puncturing construction (1)-(3) reaches the native preimage interface without adding such an adapter and makes the remaining problem explicit: distinguish sufficiently short source preimages from the public false preimages that the semantic relaxation already contains.

---

## 3. Native preimage-release attempt

The standard algebraic preimage-decryption pattern is now available. Encapsulation samples fresh `s` and small errors `(epsilon,epsilon_0)` and publishes

\[
a=\bar A^T s+\epsilon,\tag{7}
\]

\[
b=u^T s+\epsilon_0+\Delta K,\qquad K\in\{0,1\}.\tag{8}
\]

For **any** preimage `y` with `Abar y=u`,

\[
\boxed{b-y^T a=\Delta K+\epsilon_0-y^T\epsilon.}\tag{9}
\]

Thus every source witness can decapsulate through its punctured preimage whenever the residual error is inside the decision interval.

This is materially different from the rejected Run-42 additive quotient: cancellation now uses a native preimage equation rather than a semantic character of the original quotient.

However, equation (9) accepts every sufficiently good preimage. The source-binding lemma only says what follows if a preimage is **below the extraction norm bound**; it does not make slightly longer preimages stop decrypting.

---

## 4. The explicit false family becomes an exact public preimage

Use the Run-32 unsatisfiable formula

\[
(z\lor z\lor z)\land(\neg z\lor\neg z\lor\neg z)
\]

and add `d` unconstrained Boolean pairs. Let

\[
B_d^2=d+6.
\]

Run 32 gives a public normalized semantic kernel vector `x_f` with

\[
Hx_f=0,\qquad (x_f)_h=1,
\]

\[
\|x_f\|_2^2=B_d^2+4=d+10,
\qquad
\|x_f\|_1=B_d^2+2=d+8.\tag{10}
\]

Because Run 42 preserves every semantic kernel vector as `(x,0)`, puncturing the `h` coordinate gives a public exact preimage

\[
y_f=((x_f)_{\setminus h},0_m),\qquad \bar A y_f=u,\tag{11}
\]

with

\[
\boxed{\|y_f\|_2^2=d+9=(B_d^2-1)+4,}\tag{12}
\]

\[
\boxed{\|y_f\|_1=d+7=(B_d^2-1)+2.}\tag{13}
\]

An honest punctured source preimage of the same compiler size has exactly

\[
\|y_w\|_2^2=\|y_w\|_1=d+5=B_d^2-1.\tag{14}
\]

So puncturing preserves the old additive gap exactly: `+4` in squared Euclidean norm and `+2` in L1. The multiplicative gap again tends to one.

This does **not** violate the Run-42 source-binding theorem: `y_f` lies just *outside* its short-preimage extraction threshold. The problem is that native noisy decryption has no hard norm gate at that threshold.

---

## 5. Exact tight-threshold ternary attack

The near-threshold issue can be made exact, without a generous modulus.

Take iid errors

\[
\epsilon_i,\epsilon_0\leftarrow\{-1,0,1\}
\]

uniformly and use the usual half-modulus bit shift `Delta=q/2`. For the padded compiler define

\[
L=B_d^2=d+6.\tag{15}
\]

### Honest residual

After puncturing, an honest source vector has `d+5=L-1` unit coefficients. Including `epsilon_0`, its decryption noise is distributed as

\[
S_L=E_1+\cdots+E_L,\qquad E_i\stackrel{iid}{\leftarrow}\{-1,0,1\}.\tag{16}
\]

Thus `|S_L|<=L` deterministically.

Choose the **smallest integer quarter-modulus with one unit of strict decoding room**:

\[
\boxed{q=4(L+1),\qquad q/4=L+1.}\tag{17}
\]

Then every honest error sample is decoded correctly: `|S_L|<L+1`.

### False residual

The false vector differs from a one-hot pair by replacing one coefficient `1` with the nonbinary pair `(2,-1)`. After absorbing signs into the symmetric ternary errors, its residual has the exact law

\[
\boxed{S_L+2E,}\tag{18}
\]

where `E` is an additional independent uniform ternary variable.

Count a boundary tie conservatively as attack failure. Since `|S_L|<=L`, failure at threshold `L+1` is possible only when:

* `E=+1` and `S_L>=L-1`, or
* `E=-1` and `S_L<=-(L-1)`.

Now

\[
\Pr[S_L\ge L-1]
=\Pr[S_L=L]+\Pr[S_L=L-1]
=\frac{1+L}{3^L}.\tag{19}
\]

Therefore

\[
\boxed{
\Pr[\text{false attack fails}]
\le \frac{2(L+1)}{3^{L+1}},
}\tag{20}
\]

and hence

\[
\boxed{
\Pr[\text{false key recovery}]
\ge 1-\frac{2(L+1)}{3^{L+1}}.
}\tag{21}
\]

The inequality is conservative because it counts exact quarter-modulus ties as total failures instead of half-successful guesses.

At the **tightest deterministic-honest threshold**, the public false preimage therefore succeeds with probability tending exponentially fast to one:

* `d=0`, `L=6`: at least `1-14/2187 = 0.9935985368...`;
* `d=4`, `L=10`: at least `1-22/177147 = 0.9998758093...`;
* `d=16`, `L=22`: at least `0.999999999511...`;
* the bound rapidly rounds to `1.0` in ordinary floating point for larger padding.

This is stronger than the earlier generous-modulus Run-32 demonstration. Merely tightening `q` until honest correctness is just deterministic does not make the near-threshold false preimage unusable.

Because `y_f` is public and satisfies the same exact preimage equation, the attack operates on the **complete native capsule** `(a,b)` and cancels the fresh `s` term exactly. There is no appeal to the old semantic quotient in this attack.

---

## 6. Continuous-Gaussian diagnostic

For an isotropic continuous Gaussian diagnostic, let coordinate error variance be `sigma^2` and scalar-error variance be `sigma_0^2`. The honest and false residual variances are

\[
V_H=\sigma_0^2+\sigma^2(d+5),\qquad
V_F=V_H+4\sigma^2.\tag{22}
\]

At threshold `tau=kappa sqrt(V_H)`, honest and false success are exactly

\[
P_H=2\Phi(\kappa)-1,
\]

\[
P_F=2\Phi\!\left(\kappa\sqrt{V_H/V_F}\right)-1.\tag{23}
\]

For fixed `kappa`, `P_F-P_H -> 0` as `d -> infinity`. The checker records this numerical convergence for `kappa=3,5,8`.

This section is a diagnostic for the absence of a useful isotropic norm gap; it is **not** an LWE security proof and is not used to claim an impossibility for all error geometries.

---

## 7. What this run proves and what it does not

### Proved / constructive

* Normalization-column puncturing converts the Run-42 normalized kernel binder exactly into a public preimage relation; no extra syndrome adapter is needed.
* A supplied preimage below `sqrt(B_sem^2-1)` reduces immediately to the Run-42 source-witness-or-SIS lemma.
* Any public affine transfer satisfying (5) necessarily transfers every normalized semantic pseudomode as well as every source representation.
* The Run-32 padded false family gives an explicit public exact preimage only additive `+4` in squared norm beyond the honest punctured boundary.
* For iid ternary errors and the minimal integer modulus giving deterministic honest nearest-half decoding, that false preimage recovers the bit with probability at least (21), exponentially close to one under padding.

### Implemented

The checker independently implements the Run-32 3CNF short-kernel compiler for the relevant true/false fixtures, Run-42 random lifts, normalization-column puncturing, the public affine-transfer identity, the native `(a,b)` preimage capsule, exact ternary convolution, and the Gaussian variance diagnostic.

### Not proved

* No LWE/dual-Regev security theorem is claimed for the structured `(Abar,u)` produced here.
* No theorem says every possible nonlinear/highly anisotropic preimage-release channel must accept `y_f`.
* No arbitrary QPT key-recovery -> short-preimage extraction has been obtained.
* No malicious-secure ceremony composition or final concrete security parameters are supplied.

A future preimage construction therefore needs more than a standard short-preimage KEM correctness condition. It needs a **cryptographic hard cutoff or source-aware geometry** that reliably accepts every source preimage while rejecting all slightly longer public pseudopreimages, and its complete public output must reduce arbitrary QPT recovery to a source witness or an independently justified PQ break. Merely using a trapdoor to manufacture a public affine syndrome adapter does not create that source restriction.

---

## 8. Fresh validation actually executed

`punctured_preimage_run43_check.py` is standard-library-only and deterministic. It was executed twice locally and the two stdout captures were byte-identical.

The captured run records:

* **1,200** random normalization-column puncture identities over `q=17,29,101`;
* **500** public affine-transfer checks on the explicit false semantic family through `d=64`, all mapping the false normalized kernel point to the target syndrome exactly;
* exact norm/L1 checks for the Run-32 padded false family;
* **750** full native-capsule true-witness decapsulations over even moduli, all correct;
* exact ternary-convolution verification of (20)-(21) for `d=0,1,4,8,16,32,64`;
* **7,000** full false-preimage capsule trials at the tight threshold, with **6,994** key recoveries in the seeded run; the six observed failures all occur in the smallest fixture and are consistent with the exact distribution (the proof uses the exact count, not the Monte Carlo result);
* continuous-Gaussian diagnostic values through `d=4096`.

The locally executed checker SHA-256 is recorded in the accompanying provenance file. Tests validate the finite identities and implemented attack; they do not establish security of a surviving replacement.

---

## 9. Handoff

The native-preimage idea is not useless: puncturing plus Run 42 gives a particularly clean **source-bound short-preimage interface under SIS**. That is a reusable positive result.

The new failure identifies the missing property much more sharply. A release layer cannot merely say “short preimages decrypt” while relying on the Run-42 extraction threshold, because the compiler has public exact preimages just beyond that threshold and ordinary inner-product noise treats them almost identically. The next constructive attempt should therefore target one of:

1. a generic-NP compiler with a genuine multiplicative/preimage-decoding gap while retaining the Run-42 SIS reduction;
2. a nonlinear source-aware preimage map whose public evaluation cannot be inherited by semantic pseudomodes, with an actual standard PQ reduction; or
3. a native computational release whose arbitrary-QPT recovery reduction does not rely on separating preimages by this vanishing norm gap.

The complete generic-NP public offline PQ witness KEM remains open.
