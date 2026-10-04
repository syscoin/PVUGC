# Run 61 — globally stacked self-challenges bind the Run-53 false fibers semantically, but separable key release destroys the gain

**Status: positive semantic binder theorem plus exact separability countercontrol; not a completed WKEM.**

This run starts from verified PR #1 head

`117328390e67a302d2605100010e42073d7a71c0`

(Run 60). No external literature or web search was used. Production code is unchanged.

Run 60 showed that one public affine self-indexer per key-share round does not bind a common representation. The one malformed block of the all-exclusions false core has a large exact integral fiber, and each round can solve its own `k x D` selector system inside that fiber. The key shares are then spliced across different false representations.

The natural repair is to stop giving each challenge an independently decodable share. Instead, stack enough independent self-challenges and require **one supplied representation** to pass the entire stack before the key-bearing release is allowed.

This run proves that this repair is semantically real for the Run-53/60 false core: the stacked challenge family eliminates every exact false representation with an explicit information-theoretic bound while preserving every genuine all-one-hot witness. The same selectors become useless again if implemented as separable public share releases. This isolates the remaining primitive more sharply: the missing cryptographic object is a nonseparable public offline release that consumes one representation across the whole stack.

The positive theorem below is a semantic verifier/compiler result. It is **not** itself an implementation of that missing release and is not promoted into a WKEM security claim.

---

## 1. Starting false family

Use the Run-60 width-`k` all-exclusions core. There are

\[
B=2^k
\]

local blocks indexed by `f in {0,1}^k`. Block `f` contains every local row except `f`, with the normalization and shared-marginal equations from Run 53.

The conjunction is false: every Boolean assignment `t` equals one excluded row.

Any exact representation with **all but one block one-hot** forces the shared marginal to one Boolean assignment `t`, all honest blocks to use row `t`, and the unique malformed block to be block `f=t`.

For each `t`, the malformed block has the exact affine integral fiber from Run 60. Modulo 2 it is

\[
F_t = y_t^0 + N_t \mathbf F_2^D,
\qquad
D=2^k-k-2,
\]

where `N_t` has full column rank `D`. The different `t` give at most `B` one-bad-block false fibers.

Any exact false representation with two or more malformed blocks automatically fails a dense check that examines every block except at most one. Therefore only these `B` one-bad-block fibers need probabilistic analysis.

---

## 2. Constructive repair: one representation must pass the whole stack

For rounds `r=1,...,R`, sample independent public affine selectors

\[
J_r(y)=G_r \bar y+h_r\in \mathbf F_2^k,
\]

where `bar y` is the parity vector of the complete representation, each `G_r` is uniform, and each `h_r` is uniform.

Challenge `r` checks every local block except block `J_r(y)`.

### Honest completeness

A genuine source witness has every block one-hot. It therefore passes **every** challenge for **every** selector output. Stacking more challenges does not reject or distinguish honest witnesses.

### False one-bad-block condition

A false representation in fiber `F_t` has exactly one malformed block, namely `t`. It passes challenge `r` iff

\[
J_r(y)=t.
\]

To pass the whole global stack, the **same** `y` must satisfy

\[
J_1(y)=t,\ldots,J_R(y)=t.
\]

This is the point at which Run 60's per-round switching is removed at the semantic level.

---

## 3. Exact fiber-survival theorem

Fix one false fiber

\[
F_t=y_t^0+N_t\mathbf F_2^D.
\]

Write `ell=Rk` and stack the selectors. Restriction to the fiber gives

\[
J(y_t^0+N_t u)-t^{\|R}
=A_t u+c_t
\in \mathbf F_2^{\ell}.
\]

### Lemma 3.1 — the restricted system is uniform

`A_t` is a uniform `ell x D` binary matrix and `c_t` is an independent uniform binary vector.

**Proof.** For one selector row `g`, full column rank of `N_t` makes `g N_t` uniform in `F_2^D`. The independent affine offset bit in `h_r` makes the restricted constant term uniform independently of `g N_t`. Stack all rows and rounds. QED.

### Theorem 3.2 — one false fiber survives with probability at most `2^(D-ell)`

For fixed `A_t`, its image has size `2^rank(A_t)`. Since `c_t` is uniform,

\[
\Pr[c_t\in\operatorname{im}A_t\mid A_t]
=2^{\operatorname{rank}(A_t)-\ell}
\le 2^{D-\ell}.
\]

Therefore

\[
\boxed{\Pr[F_t\text{ contains a globally passing false representation}]
\le 2^{D-Rk}.}
\]

Equivalently, the expected number of solutions in that fiber is exactly `2^(D-Rk)`, and Markov gives the same nonemptiness bound.

### Corollary 3.3 — all one-bad-block false fibers

There are at most `B=2^k` such fibers, so no independence between fibers is needed:

\[
\boxed{\Pr[\exists\text{ exact false representation passing the whole stack}]
\le B\,2^{D-Rk}=2^{k+D-Rk}.}
\]

Representations with two or more malformed blocks already fail deterministically. Thus this is an information-theoretic semantic soundness bound for the complete Run-53 all-exclusions false family.

---

## 4. Concrete Run-60 parameters

Take

\[
k=8,\quad B=256,\quad D=246.
\]

To make the union bound at most `2^-128`, it is enough that

\[
Rk\ge D+k+128.
\]

The smallest integer `R` is

\[
\boxed{R=48},
\]

so `ell=384`, and the actual bound is

\[
2^{8+246-384}=\boxed{2^{-130}}.
\]

The same formula gives:

- 64-bit semantic bound: `R=40`, exponent `-66`;
- 96-bit semantic bound: `R=44`, exponent `-98`;
- 128-bit semantic bound: `R=48`, exponent `-130`;
- 192-bit semantic bound: `R=56`, exponent `-194`.

This is polynomial overhead. In the literal Run-60 representation there are 65,288 parity coordinates. Storing 384 fully dense selector rows would cost about

\[
384\cdot65288\approx25.1\text{ million bits}\approx3.0\text{ MiB}
\]

before ordinary encoding overhead. A PRG/hash-compressed selector could reduce this storage, but no computational replacement for the uniform-selector proof is claimed here.

---

## 5. Why this does not contradict Run 60

Run 60 gave each challenge its **own key share**. The attacker could choose a different false representation `y_r` for each round.

For one round restricted to one false fiber, the system has only

\[
k\text{ equations in }D\text{ variables}.
\]

For a uniform `k x D` matrix with `D>=k`, full row rank occurs with probability

\[
\prod_{i=0}^{k-1}(1-2^{i-D}),
\]

and whenever it has full row rank every target offset is solvable.

The elementary union bound from Run 60 gives

\[
\Pr[\operatorname{rank}<k]\le \frac{2^k-1}{2^D}.
\]

Across `R` independently decodable share rounds, one fixed false fiber therefore supports the roundwise switching attack with failure probability at most

\[
R\frac{2^k-1}{2^D}.
\]

At `k=8,D=246,R=48`, this is below `2^-232`.

So the **same selector family** has opposite behavior depending on how the key-bearing layer composes it:

- one globally enforced representation across all 48 checks: false survival at most `2^-130`;
- 48 separable public share releases: false roundwise switching succeeds with overwhelming probability.

This is not a paradox. It is the exact common-representation requirement.

---

## 6. The separability boundary

Suppose a public offline construction exposes independently usable component evaluators

\[
\operatorname{Eval}_r(T_r,y_r)\to s_r
\]

and the final key is a public deterministic reconstruction

\[
K=F(s_1,\ldots,s_R).
\]

If a false statement admits, for every `r`, some efficiently computable `y_r` that makes component `r` output the genuine share `s_r`, then the adversary simply evaluates those different `y_r` and applies `F`.

A procedural API instruction saying all `y_r` must be equal is not a secrecy boundary. A public commitment/tag checked after the shares are already individually obtainable does not repair this either.

Run 60 is an explicit efficient instance of this theorem. The stacked result above shows what is needed instead: the key-bearing cryptography must make **one representation** simultaneously responsible for the entire challenge stack.

That is a stronger requirement than ordinary XOR/Shamir/N-of-N composition. It is exactly the nonseparable witness-restricted public encoding still missing from the project.

---

## 7. Fresh validation actually executed

`global_stacked_self_challenge_run61_check.py` was executed twice after finalization with byte-identical JSON output.

The checker performed the following independent controls:

1. **Exact exhaustive small-system check.** For `k=3` (`D=3`) and `k=4` (`D=10`), it enumerated every `u in F_2^D` for hundreds of random affine systems around the `m=D` threshold and compared the exact solution count with Gaussian-elimination rank prediction. There were zero count mismatches.

2. **Run-60 global stack.** For `k=8,D=246,R=48`, it sampled 256 restricted false-fiber systems with 384 challenge bits. All **256/256** were inconsistent; zero false fibers survived. This is a finite diagnostic, not the proof. The proved union bound is `2^-130`.

3. **Separable roundwise control.** For 32 rounds and all 256 false-fiber labels per round, it sampled **8,192** independent `8 x 246` systems. All **8,192/8,192** were full row rank and solvable, reproducing the Run-60 switching condition at scale.

4. **Dimension threshold diagnostic.** With `D=246`, 250 systems were sampled at each of `m=232,240,246,248,256,264`. Observed solvability fell from `1.0` below the dimension to `0.236` at `m=248`, and to zero in the finite samples at `m=256,264`; the theorem uses the exact `2^(D-m)` upper bound rather than these frequencies.

The tests validate the finite GF(2) implementation and the rank/solution identities. They do not establish cryptographic security.

Final local SHA-256 values before GitHub publication:

- checker: `d427c0c38193fa58e91f0282357db6bd82ad0f7e7c6e8dd7350f7755bcbfc90c`;
- captured validation: `f64e73fc046042ca98c5558c3541623292ce83487fcac8e2205b41d0dda3e8ff`.

---

## 8. What is proved, what is conjectural, and what remains missing

### Proved here

- The globally stacked affine self-challenge eliminates the complete Run-53 all-exclusions exact false family with probability at least `1-2^(k+D-Rk)`.
- Honest all-one-hot witnesses pass every challenge for every selector output.
- At the Run-60 parameters, 48 globally enforced challenges give a `2^-130` semantic false-survival bound.
- Decomposing those same challenges into independently decodable share releases restores the roundwise switching attack with overwhelming probability.

### Implemented and tested here

- Exact GF(2) consistency/rank checker;
- exhaustive small-dimensional solution-count validation;
- 256-fiber `k=8,R=48` global-stack diagnostic;
- 8,192-system separable-switching control;
- dimension-threshold experiments.

### Not proved / not implemented

- No public offline cryptographic release has yet been built that nonseparably consumes one representation across the whole challenge stack.
- Compiling the stacked verifier into an ordinary public linear/noisy release is not claimed secure; the earlier projective, full-output, affine-hull, and source-transfer attacks remain applicable audit obligations.
- No arbitrary-QPT early-key-recovery -> source-witness / independent-PQ-break reduction is obtained here.
- No malicious-secure ceremony or end-to-end parameter set is promoted from this semantic lemma.

The most concrete next construction is therefore to compile the **whole stacked verifier as one relation** into a single candidate inner lattice capsule and audit its complete projective/Fourier output, rather than assigning one independently decodable capsule per challenge. If that single-capsule route again admits short nonsemantic projective modes, those modes must be exhibited explicitly rather than hidden behind the now-solved semantic switching issue.
