# Run 132 — one-hot near-witness/noise barrier: the exact short-preimage compiler has only an additive-two false gap

**Status:** focused falsification of the direct Run-115/116/117 noisy-HPS composition. This is **not** a general impossibility theorem for lattice witness release and not a completed PQ witness KEM.

## 0. Verified starting point

This run began from the connected GitHub source for `syscoin/PVUGC#1` at the actual PR head

- branch `research/pq-wkem-validation-20260918`;
- SHA `76e5b632cf00b4372955b871aadd59ded84c5167`;
- PR open, draft, unmerged;
- latest substantive ordinary PR comment `5850205385`, recording publication through Runs 122--128.

The exact-head files used most directly were:

- `research/pq-wkem/NOISY_SHORT_PREIMAGE_HPS_BOUNDARY_RUN115.md`, blob `cf2ec9575948e16b58acbd870208686759f14e44`;
- `research/pq-wkem/NOISY_TARGET_STANDARD_LWE_ORBIT_RUN116.md`, blob `6f13b37b33779b36072ffc7366ae0d3a6dda6699`;
- `research/pq-wkem/ONEHOT_AFFINE_AND_SHIFTED_MULTIPREIMAGE_BOUNDARY_RUN117.md`, blob `ffe4a4c7fba46ac35639cb9a7260af750048de77`;
- `research/pq-wkem/LWE_DIRECTIONAL_TRANSPORT_RUN72.md`, blob `4fefd6c364a76fd12fe76169ddbec47e486c786b`;
- `research/pq-wkem/DUAL_MODE_HASH_SECRET_RESAMPLING_BARRIER_RUN126.md`, blob `94d1a6246da77f561ecacd84ce78917d6121dc33`;
- `research/pq-wkem/UP_HASH_ISOLATION_ALL_WITNESS_BARRIER_RUN128.md`, blob `a534790501f9996bf5af45708d8c16a6267f9569`.

Runs 129--131 are newer conversation-local checkpoints and are not silently treated as published. Their rank-mask/two-sided-distribution branch remains open. This pass follows a parallel branch with a credible standard-LWE objective: test whether Run 117's exact one-hot affine compiler can actually instantiate the noisy projective-hash interface of Runs 115--116.

It cannot in its direct or left-mixed form. The reason is stronger than the earlier statement that the matrix is merely “structured”: on a false formula one can publicly construct an **exact affine preimage only two `l1` units longer than an honest witness**, and every clause also contributes a public four-sparse dual/kernel relation. Under ordinary i.i.d. small-error decoding these two facts give a direct false-key attack and an unconditional distinguisher for the proposed left-mixed LWE carrier.

No production path is changed.

---

## 1. Recall the Run-117 one-hot affine compiler

For a 3CNF formula `phi` with `n` variables and `m` clauses, Run 117 builds

\[
M_\phi z=t_\phi
\]

over the integers/modulo `q` as follows.

There is one two-coordinate one-hot group for each global variable and one seven-coordinate group for each clause, indexed by the seven local Boolean triples satisfying that clause. Rows impose:

1. every variable-group sum is `1`;
2. every clause-group sum is `1`;
3. for each clause position, the local selected bit equals the corresponding global variable bit.

A satisfying assignment has an encoding with exactly one `+1` in each variable group and each clause group, hence

\[
B:=n+m,
\qquad
\|z_w\|_1=B.
\]

Run 117 proved the useful supplied-representation theorem

\[
M_\phi z=t_\phi\pmod q,
\quad \|z\|_1\le B,
\quad q>2(B+1)
\Longrightarrow
\text{an ORIGINAL satisfying assignment}.
\]

That theorem is correct. The new issue is that a noisy HPS needs much more than a sharp threshold exactly at `B`: it needs false preimages to have enough additional **projected-error energy** that the decoder rejects them with overwhelming probability.

---

## 2. Main algebraic theorem: every assignment has an exact `B+2u` preimage

Let `a in {0,1}^n` be **any** Boolean assignment, satisfying or not. Let

\[
u(a)=\#\{\text{clauses of }\phi\text{ falsified by }a\}.
\]

### Theorem 1 — near-witness affine preimage

There is a deterministic polynomial-time construction of an integer vector `z_a` such that

\[
\boxed{M_\phi z_a=t_\phi}
\]

**over the integers**, every coefficient of `z_a` lies in `{-1,0,1}`, and

\[
\boxed{\|z_a\|_1=B+2\nu(a).}
\]

### Construction and proof

For every variable group, put `+1` on the coordinate selected by `a_i`.

For a clause satisfied by `a`, put `+1` on its ordinary local satisfying triple. That clause contributes `1` to the `l1` norm.

Now consider a clause falsified by `a`. Its local triple

\[
f=(f_1,f_2,f_3)
\]

is the **unique** Boolean point omitted from the clause's seven allowed local coordinates.

Choose any two local positions, say `1,2`, and define

\[
 x=f\oplus e_1,
\qquad
 y=f\oplus e_2,
\qquad
 w=f\oplus e_1\oplus e_2.
\]

All three points differ from `f`, so all three satisfy the clause and are present in the public clause group. Put coefficients

\[
+1\text{ on }x,
\qquad +1\text{ on }y,
\qquad -1\text{ on }w.
\]

Their coefficient sum is `1`, so the clause-group sum row is satisfied. Coordinatewise over the integers,

\[
\boxed{x+y-w=f.}
\]

Hence every one of the three local-bit moments is exactly the falsifying local bit `f_p`, which is precisely the global bit selected by `a` at that clause position. Every consistency row is therefore satisfied as well.

The falsified clause contributes `3` rather than `1` to `l1`, an additive cost of exactly `2`. Summing over all groups proves the theorem.

This is not a heuristic rank argument and does not require a lattice oracle. Given `a`, `z_a` is an explicit public vector.

---

## 3. Explicit false family with a public `B+2` pseudowitness

The theorem becomes a false-statement attack rather than merely an approximation observation on an explicit scalable family.

For `n>=1`, use the contradictory pair

\[
(x_0\vee x_0\vee x_0)
\quad\wedge\quad
(\neg x_0\vee\neg x_0\vee\neg x_0),
\]

and for every `i=1,...,n-1` add the filler clause

\[
(\neg x_0\vee x_i\vee x_i).
\]

The formula is false for every assignment because of the first two clauses. The public assignment

\[
a=0^n
\]

falsifies **exactly one** clause: the positive repeated-literal clause. Here

\[
m=n+1,
\qquad B=n+m=2n+1,
\]

and Theorem 1 yields, publicly and deterministically,

\[
\boxed{M_\phi z_a=t_\phi,
\qquad \|z_a\|_1=B+2=2n+3.}
\]

Thus Run 117's exact threshold `<=B` is sharp only in the literal combinatorial sense. Immediately outside it there are false instances with a source-invalid exact preimage just two units longer.

---

## 4. Direct attack on the Run-115 noisy projective-hash wrapper

Run 115 publishes, for a carrier matrix `A`, secret `s`, small error vector `e`, and public target `t`,

\[
hp=A^Ts+e\pmod q,
\]

with hidden target value

\[
z_\star=s^Tt\pmod q.
\]

A candidate preimage `u` satisfying `Au=t` computes

\[
hp^Tu=z_\star+e^Tu\pmod q.
\]

The one-bit wrapper publishes

\[
d=c_K-z_\star,
\qquad c_0=0,
\quad c_1=\lfloor q/2\rfloor,
\]

and decodes `hp^T u+d` to the nearest center.

### Left mixing does not repair the one-hot compiler

Let `H` be **any** public matrix of compatible dimensions and use the natural Run-116-style left-mixed carrier

\[
A=H M_\phi,
\qquad
 t=H t_\phi.
\]

For the false-family pseudowitness of Section 3,

\[
A z_a
=H M_\phi z_a
=H t_\phi
=t.
\]

Therefore its decoder view is exactly

\[
\boxed{hp^T z_a+d=c_K+e^Tz_a\pmod q.}
\]

No computational assumption remains between the attacker and the real decapsulation rule.

### Bounded-error corollary

If each error coordinate obeys `|e_j|<=E` and

\[
(B+2)E<\tau_q,
\]

where `tau_q` is the nearest-center correctness radius (approximately `q/4`), then the false pseudowitness recovers `K` **deterministically**.

Any implementation that leaves the usual nontrivial correctness margin `BE << q/4` therefore also admits the false `B+2` vector once that margin exceeds only two additional error coordinates.

### Symmetric i.i.d. errors: exact distribution statement

Suppose the error coordinates are independent from a symmetric distribution `chi`, so `e` and `-e` have the same law. Because every nonzero coefficient of `z_a` is `+1` or `-1`, on a `u`-clause near witness

\[
\boxed{e^Tz_a\ \overset{d}=\ \chi^{*(B+2u)}.}
\]

An honest one-hot witness has projected error `chi^{*B}`. Therefore, for **any** fixed decoder acceptance event `D`,

\[
\Pr[\chi^{*(B+2)}\in D]
\ge
\Pr[\chi^{*B}\in D]
-
\operatorname{TV}(\chi^{*B},\chi^{*(B+2)}).
\]

The checker evaluates this distance exactly for Rademacher `+/-1` errors. It falls from `0.125` at `B=3` to about `4.83e-4` at `B=1000`; `B*TV` approaches about `0.484` in the tested range. Those finite values are validation data, not the security theorem.

### Subgaussian corollary

If `chi` is centered `sigma`-subgaussian in the usual mgf sense, then for a coefficient vector with `h` nonzero `+/-1` entries,

\[
\Pr[|e^Tu|\ge T]
\le
2\exp\!\left(-\frac{T^2}{2\sigma^2 h}\right).
\]

For the public false pseudowitness `h=B+2`, taking `T` at the nearest-center radius gives approximately

\[
\boxed{
\Pr[\text{false decode fails}]
\le
2\exp\!\left(-\frac{q^2}{32\sigma^2(B+2)}\right).
}
\]

Thus any asymptotic parameter family with the ordinary robust honest-correctness margin

\[
\frac{q^2}{\sigma^2 B}=\omega(\log\lambda)
\]

also gives **overwhelming false-key recovery** on this `u=1` false family, because replacing `B` by `B+2` does not change that asymptotic margin.

This is a classical polynomial-time false-statement key-recovery attack. It therefore directly refutes the required QPT hiding for this composition in that normal small-error correctness regime.

A deliberately razor-thin bounded-error parameter choice with `BE<tau_q<=(B+2)E` is not ruled out by the deterministic corollary. It would still need its own stochastic correctness/security analysis and does not obtain a standard-LWE theorem from this note.

---

## 5. Independent carrier barrier: every clause gives a public four-sparse kernel vector

There is a second, assumption-free reason that random left mixing cannot turn the one-hot matrix into the uniform carrier required by Run 116.

Fix any clause and let `f` be its unique forbidden local triple. Choose one local coordinate and fix it to the bit opposite `f` in that position. The resulting two-dimensional face of the Boolean cube contains four points, all of which differ from `f` and therefore all satisfy the clause.

Write those four points as the corners

\[
p_{00},p_{01},p_{10},p_{11}.
\]

Their affine moments satisfy

\[
[1;p_{00}]+[1;p_{11}]-[1;p_{01}]-[1;p_{10}]=0.
\]

Putting coefficients `(+1,+1,-1,-1)` on the corresponding four clause columns and zero elsewhere therefore gives

\[
\boxed{c\ne0,
\qquad \|c\|_1=4,
\qquad M_\phi c=0.}
\]

This remains true with repeated variables because each local-position consistency moment cancels separately.

### 5.1 The left-mixed matrix is publicly far from uniform

For every `H`,

\[
(HM_\phi)c=0.
\]

For a genuinely uniform matrix `U in F_q^{d x L}`, the same fixed nonzero `c` satisfies

\[
Uc=0
\]

with probability exactly `q^{-d}`. Hence the public matrix alone has distinguishing advantage

\[
\boxed{1-q^{-d}}
\]

between the left-mixed one-hot family and a uniform LWE matrix.

This turns Run 116's qualitative “left multiplication preserves row-space structure” warning into an explicit four-coordinate public test.

### 5.2 The LWE sample also has an immediate noise-only distinguisher

For

\[
hp=(HM_\phi)^Ts+e,
\]

we have

\[
\boxed{c^Thp=c^Te.}
\]

If `|e_j|<=E`, then `|c^Te|<=4E`. When `4E<q/2`, a uniform vector would land in that centered interval with probability exactly

\[
\frac{8E+1}{q}.
\]

So the event `|c^T hp|_q<=4E` distinguishes the structured LWE sample from uniform with advantage

\[
\boxed{1-\frac{8E+1}{q}.}
\]

The checker exhaustively validates the `q=31,E=1` instance, where the advantage is `22/31 ~= 0.709677`.

For subgaussian errors the same test uses a high-probability tail interval for the sum of four errors; the conclusion remains that this highly structured carrier is not justified by ordinary uniform-matrix LWE.

This does **not** say standard LWE is insecure. The attacked matrix distribution is visibly nonuniform and has public short dual relations.

---

## 6. What this corrects in the previous handoff

Run 117 correctly concluded that its exact one-hot compiler solved the **supplied `l1<=B` semantic extraction** problem. It was too optimistic to treat that as nearly sufficient for the noisy HPS path.

For a noise-based release, the relevant source-soundness condition is not merely

\[
\text{false preimage norm}>B.
\]

It must create a meaningful **projected-error gap** between every honest witness and every source-invalid public preimage. The explicit family here has only

\[
B\quad\text{versus}\quad B+2.
\]

For standard smooth/symmetric small noise, that is asymptotically no separation at all.

A viable short-preimage compiler for this route therefore needs something closer to a multiplicative energy gap, for example a guarantee that every false/source-invalid preimage has `l2^2` (or the exact dual norm governing the chosen error law) larger than the honest value by a factor sufficient for negligible-overwhelming decoder separation. A sharp threshold at one extra integer unit is not enough.

Likewise, merely randomizing rows cannot supply the uniform-matrix premise of Run 116 when the public source matrix contains constant-weight kernel relations.

---

## 7. Relation to Runs 129--131 and the rank path

This run does not change Run 131's two-sided Hair--Sahai rank-mask question. It does, however, sharpen why the alternative short-preimage/LWE branch is hard:

- the source compiler must not only extract from supplied short vectors;
- it must have a **noise-aligned false gap**;
- and its public carrier must avoid short dual relations while preserving every honest witness.

That points back toward source geometries with a genuine multiplicative gap rather than the additive-one-hot geometry. Hair--Sahai's MinRank compiler has a rank gap and supplied-low-rank ORIGINAL-source extraction, but Runs 82/85/86/89/129--131 already show that turning that geometry into a complete public QPT-hiding release is nontrivial. No claim is made here that MinRank automatically solves the noise-energy problem.

The strongest next constructive test is therefore not another left randomization of `M_phi`. It is one of:

1. prove or falsify a **gap-preserving randomized carrier** that simultaneously hides short dual relations and keeps every valid source representation in the decoder's low-noise region, with a straight-line reduction to a recognized QPT-hard LWE/SIS distribution; or
2. return to Run 131's unconditional two-sided bilinear distribution and ask whether its remaining anchor coordinate has enough residual entropy after the complete public anchor-zero transcript, without relying on the already-failed public quotient/canonicalization tricks.

---

## 8. Reproducible checker

`onehot_near_witness_noise_run132_check.py` is deterministic and standard-library-only.

It was syntax-checked and executed twice; the two captured JSON outputs were byte-identical. The finalized run records **1,092 assertions** and checks:

- all `8` literal-sign patterns of a single 3-literal clause and all `8` assignments, proving the exact `B+2u` construction in `64` complete local cases;
- mixed/repeated-variable fixtures;
- the explicit scalable contradictory false family for `n=1,...,10`;
- exact `M z=t` and coefficient `{-1,0,1}` identities;
- the four-sparse clause-kernel relation for every tested clause;
- `280/280` direct false-key recoveries through the exact Run-115 wrapper after independently sampled arbitrary left mixers `H`;
- exact Rademacher projected-error TVs for `B=3,5,10,20,50,100,200,500,1000`;
- event-transfer inequalities for every symmetric threshold in several complete random-walk distributions;
- exhaustive bounded-error kernel/noise checks and the exact uniform-functional probability for `q=31,E=1`.

The finite checks validate algebra and finite probability identities. They are not evidence for or against generic LWE hardness.

---

## 9. QPT / assumption ledger

| Component | Honest algorithm model | Adversary model | Assumption / distribution | Reduction model | Exact conclusion |
|---|---|---|---|---|---|
| `B+2u` preimage theorem | classical deterministic polytime | none | none | direct algebra | any Boolean assignment gives exact affine preimage of norm `B+2u` |
| explicit false-family attack | classical public/offline | classical PPT, hence also QPT | bounded or symmetric i.i.d. small error as stated | direct use of public pseudowitness and real decoder | false key recovered with the stated probability; overwhelming under the stated subgaussian margin |
| four-sparse kernel theorem | classical deterministic polytime | none | none | direct affine cube identity | every clause gives public `c`, `||c||_1=4`, `M c=0` |
| left-mixed matrix distinguisher | classical PPT | classical PPT, hence also QPT | uniform-matrix comparison only | direct test `Ac=0` | `HM` is distinguished from uniform with advantage `1-q^{-d}` |
| structured LWE-sample distinguisher | classical PPT | classical PPT, hence also QPT | bounded-error case exactly; subgaussian variant by tail bound | direct test `c^T hp` | ordinary uniform-LWE hybrid is invalid for this carrier |
| standard LWE itself | classical sample generation | target project requires arbitrary QPT | **not attacked here** | none | no claim that uniform-matrix LWE is weak |
| complete generic-NP PQ WKEM | classical public/offline | arbitrary QPT | still missing full standard-assumption composition | still missing | **UNPROVED** |

No PPT-only theorem is relabeled QPT-secure. The new attacks are classical, so their applicability to a QPT security target is immediate.

---

## 10. Result

The new checkpoint is a concrete negative result with a sharper design criterion:

> **Run 117's exact one-hot affine compiler does not provide the quantitative false-preimage gap needed by the Run-115 noisy HPS. Every assignment with `u` unsatisfied clauses has an exact public preimage of norm `B+2u`; an explicit false family has `u=1`, so ordinary small-noise correctness also lets the false pseudowitness decode the key. Random left mixing does not repair this and, independently, preserves a four-sparse public kernel relation that makes the carrier overwhelmingly distinguishable from a uniform LWE matrix.**

The practical generic-NP public/offline PQ witness-KEM stopping condition remains **unmet**.
