# Run 44 — nonlinear radial preimage gate: exact contraction, public affine-line escape, and complete-output false-key recovery

## Status

Starting verified PR head: `8122d88e0f1b4c749c752bccbe4f5e6f044fabb1` (Run 43).

This run continues from the Run-43 normalization-column puncturing interface. It does **not** complete the requested generic-NP witness KEM. The constructive attempt is a nonlinear quadratic release layer on the native public preimage relation. The attempt has a useful exact algebraic identity, but the complete public output is broken by a different exact preimage on the same unsatisfiable Run-32 relation.

No external literature or web search was used. Production code is unchanged.

---

## 1. Inherited source-bound preimage interface

Run 43 starts from the Run-42 lifted matrix

\[
M=[CH\mid A_0]
\]

with distinguished normalization column `h`, punctures that column, and defines

\[
A=M_{\setminus h},\qquad u=-m_h.
\]

For a vector `y` over the remaining coordinates, let `iota(y)` insert `1` at coordinate `h`. Then

\[
\boxed{M\,\iota(y)=0\iff Ay=u.}\tag{1}
\]

A supplied preimage below the Run-42 semantic norm threshold therefore yields, in polynomial time, either a source witness or a nonzero short solution to the uniform SIS matrix used by the Run-42 lift. That is a source-binding lemma for a **supplied sufficiently short preimage**. It is not a reduction from arbitrary key recovery.

Run 43 also showed that ordinary inner-product preimage decryption is not enough: the false relation has a public exact preimage only an additive `+4` in squared norm beyond the extraction threshold, and that preimage decrypts with probability tending rapidly to one under ordinary isotropic noise.

The question here is whether a public **nonlinear radial gate** can create an exact notch at that false radius while preserving all genuine source preimages.

---

## 2. Constructive quadratic radial capsule

Work over `Z_q` with `q` divisible by `8`, and put

\[
\mu=q/8.
\]

Let `A in Z_q^{m x n}` and `u in Z_q^m` be the Run-43 public preimage instance. To encapsulate a bit `K in {0,1}`, sample:

- `s in Z_q^m`;
- `R in Z_q^{m x n}`;
- small vector errors `epsilon, eta` and scalar error `epsilon_0`;
- a small symmetric matrix error `E=E^T`.

Publish

\[
a=A^Ts+\epsilon,\tag{2}
\]

\[
b=u^Ts+\epsilon_0+\mu K,\tag{3}
\]

\[
Q=A^TR+R^TA+E+\mu K I_n,\tag{4}
\]

\[
\ell=2R^Tu+\eta.\tag{5}
\]

For a candidate exact preimage `y` satisfying `Ay=u`, define the public contraction

\[
W_T(y)=y^TQy-y^T\ell-T\bigl(b-y^Ta\bigr).\tag{6}
\]

Here `T` is a public integer radius selected from the statement/compiler size.

### Lemma 2.1 — exact radial contraction

For every exact preimage `Ay=u`,

\[
\boxed{
W_T(y)
=
\mu K(\|y\|_2^2-T)
+y^TEy-\eta^Ty-T(\epsilon_0-\epsilon^Ty)
\pmod q.
}\tag{7}
\]

**Proof.** Since `Ay=u`,

\[
y^T(A^TR+R^TA)y=2u^TRy.
\]

Also

\[
y^T\ell=2u^TRy+\eta^Ty,
\]

and

\[
b-y^Ta
=\epsilon_0-\epsilon^Ty+\mu K.
\]

Substitution in (6) cancels both setup-random linear terms and leaves (7). `□`

This is a real nonlinear preimage-side observable. It does not use the old Run-42 semantic quotient.

---

## 3. Honest radius and a deterministic correctness parameterization

Use the same compiler size as the Run-43 padded contradiction. Write

\[
H=d+5.
\]

A genuine punctured Boolean source preimage has exactly `H` unit nonzero coordinates, hence

\[
\|y_w\|_2^2=\|y_w\|_1=H.\tag{8}
\]

The known Run-43 false preimages at `t=0,1` have squared norm `d+9=H+4`, so choose the radial notch

\[
\boxed{T=H+4.}\tag{9}
\]

Then every honest source preimage has key coefficient

\[
\|y_w\|_2^2-T=-4.
\]

With `mu=q/8`,

\[
-4\mu K=-qK/2\equiv qK/2\pmod q,\tag{10}
\]

which is the desired binary half-modulus phase.

For the executed finite candidate, take every independent upper-triangular entry of symmetric `E`, every entry of `epsilon,eta`, and `epsilon_0` uniformly in `{-1,0,1}`. For an honest `H`-sparse unit preimage,

\[
|y_w^TEy_w|\le H^2,
\]

\[
|\eta^Ty_w|\le H,
\]

and

\[
T|\epsilon_0-\epsilon^Ty_w|\le T(H+1).
\]

Therefore the deterministic honest noise bound is

\[
B_H=H^2+H+T(H+1)
=2H^2+6H+4.\tag{11}
\]

Choose

\[
\boxed{q=4(B_H+2).}\tag{12}
\]

`B_H` is even, so `q` is divisible by `8`. The nearest-half threshold is

\[
q/4=B_H+2,
\]

and every honest noise sample satisfies `|noise| <= B_H < q/4`. Thus this concrete candidate has deterministic honest bit correctness.

This is only correctness of the attempted release channel. No LWE or hiding reduction is claimed for its structured public distribution.

---

## 4. The false relation contains a public affine preimage line

Use the Run-32/34/43 unsatisfiable source relation

\[
(z\lor z\lor z)\land(\neg z\lor\neg z\lor\neg z),\tag{13}
\]

plus `d` unconstrained Boolean padding pairs.

At normalization `h=1`, keep `z=0`; keep the negative-clause slack values fixed as

\[
(c,d_s)=(1,0),
\]

and parameterize the positive-clause slack values by

\[
a=2t,\qquad b=2-t.\tag{14}
\]

Their complements are `1-a` and `1-b`. The positive clause equation is

\[
a+2b=4,
\]

so **every integer `t`** gives an exact normalized semantic kernel point. Let that point be `x_t`.

Equivalently, if `x_0` and `x_1` are the two public Run-33/34 pseudovectors,

\[
\boxed{x_t=x_0+t(x_1-x_0),\qquad Hx_t=0,\qquad (x_t)_h=1.}\tag{15}
\]

Run 42 preserves every semantic kernel point as `(x_t,0)`, and Run 43 puncturing therefore makes

\[
y_t=(x_t,0)_{\setminus h}
\]

an exact public preimage

\[
\boxed{Ay_t=u}\tag{16}
\]

for **every** Run-42 random lift.

### Lemma 4.1 — exact radial law on the false fiber

The punctured squared norm is

\[
\boxed{
\|y_t\|_2^2=d+9+10t(t-1)
=T+10t(t-1).
}\tag{17}
\]

The checker verifies this identity directly from the compiler coordinates.

Consequences:

- `t=0`: `||y_0||^2=T`;
- `t=1`: `||y_1||^2=T`;
- `t=2`: `||y_2||^2=T+20=d+29`.

So the exact radius notch really suppresses both previously highlighted short false representatives `y_0,y_1`, but it does not bind the whole affine preimage fiber.

For `t=2`,

\[
\|y_2\|_1=d+11=H+6.\tag{18}
\]

---

## 5. Exact complete-output false-key attack

Apply the public contraction (6) using the public exact preimage `y_2`.

Its key coefficient is

\[
\|y_2\|_2^2-T=20.
\]

Since `mu=q/8`,

\[
\boxed{
20\mu K=20(q/8)K=5qK/2\equiv qK/2\pmod q.
}\tag{19}
\]

Thus the false preimage receives **exactly the same binary half-modulus key phase** as every genuine source preimage in (10). The only remaining question is its noise tail.

This is a complete-public-output attack: the attacker knows `y_2` from the public false statement, verifies `Ay_2=u`, evaluates `(a,b,Q,ell)` directly through (6), and performs the same public nearest-half decision. It uses no source witness and no old semantic quotient.

### Exact false-noise coefficients

For `y_2`, the nonzero coordinates consist of `H-1` unit entries and the two special entries `4` and `-3`. Therefore

\[
\|y_2\|_1=H+6,
\qquad
\|y_2\|_2^2=H+24.
\]

For independent symmetric ternary `E`, the squared coefficients appearing in `y_2^TEy_2` sum to

\[
2\|y_2\|_2^4-\sum_i y_{2,i}^4.
\]

Here

\[
\sum_i y_{2,i}^4=(H-1)+4^4+3^4=H+336.
\]

After adding the independent `eta`, `epsilon`, and `epsilon_0` terms from (7), the sum of squared scalar ternary coefficients is exactly

\[
\boxed{
\Sigma_F=H^3+35H^2+312H+1240.
}\tag{20}
\]

The full absolute-support bound is

\[
\boxed{
B_F=2H^2+24H+70.
}\tag{21}
\]

The nearest-half decoder fails only if

\[
|N_F|\ge \tau,
\qquad
\tau=q/4=B_H+2=2H^2+6H+6.\tag{22}
\]

Because `N_F` is a sum of independent centered variables, each supported on `{-c_i,0,+c_i}`, Hoeffding gives

\[
\boxed{
\Pr[\text{false decoder fails}]
\le
2\exp\!\left(-\frac{\tau^2}{2\Sigma_F}\right).
}\tag{23}
\]

The exponent is `-2H+O(1)`. Hence the false decoder succeeds with probability tending exponentially fast to one under padding.

The checker also computes the **exact** weighted-ternary distribution for `d<=32`; the proof of the concrete break uses those exact counts, while (23) supplies the scalable analytic bound.

Exact false recovery probabilities from the executed enumeration are:

| `d` | `H=d+5` | false recovery probability |
|---:|---:|---:|
| 0 | 5 | `0.9106920289387037...` |
| 1 | 6 | `0.9639089153731180...` |
| 4 | 9 | `0.9994044520398043...` |
| 8 | 13 | `0.9999999342058076...` |
| 16 | 21 | `1 - 2.10225566267e-22` |
| 32 | 37 | `1 - 2.44065741878e-102` |

This is a direct confidentiality failure on a false statement. There is no source witness to extract.

---

## 6. Limited generalization: finite radial polynomial notches do not bind this fiber

The concrete attack above is enough to reject the quadratic capsule. The false affine line also yields a useful algebraic boundary for a broader class of radial gates.

Let

\[
P(S)\in\mathbb Q[S]
\]

be a nonzero characteristic-zero polynomial of degree `r`, with

\[
P(H)\ne0
\]

so that the honest radius is not rejected. On the false line define

\[
F(t)=P\!\left(T+10t(t-1)\right).\tag{24}
\]

Because the inner polynomial is nonconstant quadratic, `F` is a nonzero polynomial of degree at most `2r`. Hence it has at most `2r` integer roots. Therefore a public scan of any `2r+1` distinct integer candidates necessarily finds a `t` with

\[
P(\|y_t\|_2^2)\ne0.\tag{25}
\]

So a finite-degree characteristic-zero radial polynomial cannot vanish on the whole public false fiber while remaining nonzero at the honest radius. Likewise any explicitly finite set of forbidden radii can be escaped by scanning the public line.

### Scope of this statement

This is **not** an impossibility theorem for:

- arbitrary nonlinear or anisotropic functions of the full preimage;
- modular predicates where polynomial identities can behave differently over rings;
- computational source-aware gates whose security has an independent PQ reduction;
- constructions that change the source compiler and eliminate the public affine false fiber.

It says only that finitely many radial norm notches, and characteristic-zero finite-degree radial polynomial gates, cannot by themselves source-restrict the current punctured compiler.

---

## 7. What is proved, implemented, and still conjectural

### Proved

1. The quadratic capsule (2)-(5) has the exact preimage contraction (7).
2. With (9)-(12), every genuine unit source preimage has deterministic honest correctness for the executed ternary-error candidate.
3. The unsatisfiable Run-32 source relation has the public affine family (15), every member of which becomes an exact Run-43 punctured preimage under every Run-42 random lift.
4. Its squared norm obeys the exact law (17).
5. `t=2` receives the exact half-modulus key phase (19), so the false statement has a public complete-output key decoder.
6. The exact false-noise coefficient identities (20)-(22) and the Hoeffding bound (23) hold for the implemented independent ternary noise.
7. The limited radial-polynomial escape statement in Section 6 holds over characteristic zero.

### Implemented

`radial_preimage_gate_run44_check.py` independently implements:

- the Run-32/43 3CNF short-kernel compiler for the relevant true/false fixtures;
- the full false affine family `x_t`;
- Run-42 random lifts and Run-43 normalization-column puncturing;
- the complete public quadratic capsule `(a,b,Q,ell)`;
- direct evaluation of both sides of (7);
- exact weighted-ternary convolution for the false decoder;
- deterministic finite-degree radial-polynomial escape controls.

### Not proved

- No LWE theorem is claimed for this structured public capsule.
- No reduction from arbitrary QPT key recovery to a supplied short preimage has been obtained.
- No theorem says every nonlinear or anisotropic release channel must accept the false affine line.
- No generic impossibility result is claimed for computational source-aware geometry.
- No malicious-secure ceremony composition or final concrete end-to-end parameters are supplied.

Passing tests is not being treated as a security proof. The surviving candidate was instead broken by an explicit algebraic false-instance decoder.

---

## 8. Fresh validation actually executed

The standard-library-only checker was executed twice locally. The two stdout captures were byte-identical, and the captured JSON matched the independently saved result byte-for-byte.

Executed checks:

- exhaustive Boolean truth check of the contradiction (`2` assignments, `0` witnesses);
- **65** exact affine-line/kernel/radius identities over `d in {0,1,4,16,64}` and `t=-6..6`;
- **24** finite-degree radial-polynomial escape controls for degrees `1..8` on three padded sizes;
- **600** random Run-42 lift / Run-43 exact-preimage checks for both the notched `t=0` and escaping `t=2` representatives;
- **800/800** honest full quadratic-capsule decapsulations with deterministic correctness;
- **800** false full-capsule attack trials, with **783/800** seeded recoveries (`183/200` at `d=0`, and `200/200` at each of `d=4,8,16`);
- exact weighted-ternary false-noise enumeration at `d=0,1,4,8,16,32`, giving the probabilities in Section 5;
- analytic Hoeffding controls through `d=1024`.

Local SHA-256 values:

- checker: `407d05c2a119f7e1e688419278cf631783637b530a474736264e691a3983d38f`;
- captured JSON: `e83ab1075824db28098db281c16455bd05a45270d4349d5d3649a4555e198de0`;
- each stdout capture: `1d597a2bcd2769797a0def69c3d0511b815057b748f93c63e612001d4174995d`.

These executions validate the stated finite identities and the implemented attack path. They are not evidence for security of an unbroken replacement.

---

## 9. Handoff

The Run-42/43 **short-preimage source-binding interface under SIS remains useful**: if a future release mechanism forces successful recovery into a sufficiently short supplied preimage, the existing reduction can extract a source witness or a standard-assumption SIS break.

What this run removes is the simplest nonlinear repair: a radial norm notch does not bind the source representation, because the current false semantic relaxation has an entire public affine preimage fiber. The exact notch catches the two closest known false representatives and the attacker simply moves to `t=2`, which still receives the same key phase and has overwhelming decoding probability as padding grows.

A credible next construction therefore needs at least one of:

1. a source compiler whose false preimage fibers have a genuine multiplicative/metric gap rather than an additive near-honest direction;
2. a **non-radial, globally coupled** public geometry that all genuine source representations satisfy but the whole false affine relaxation cannot satisfy, together with a complete-output reduction;
3. a computational source-binding release layer reduced to an independently justified PQ assumption, without assuming the missing WE-equivalent evaluator.

The central stopping obligation remains unchanged: arbitrary unauthorized QPT early key recovery must imply a source witness or an independently justified PQ hardness break for the **complete public output**, followed by setup/auxiliary-input composition and concrete practical parameters.
