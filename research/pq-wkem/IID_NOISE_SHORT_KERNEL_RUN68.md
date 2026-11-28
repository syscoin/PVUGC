# Run 68 — arbitrary iid modular noise does not repair the normalized short-kernel compiler

**Status: proved negative result for one concrete architecture; not a completed generic PQ witness KEM.**

Starting verified PR head: `c4e7047290edceb5258a6716bc3044ed3b05cd7b` (Run 67).  This pass keeps the earlier complete-public-view input-label attack, native-encryption/source-transfer distinction, false-cover attacks, affine-lift failures, and transparent nonlinear interpolation failure in force.  It does **not** retry those candidates.

The constructive attempt here is narrower and lattice-native.  `SHORT_KERNEL_LWE_BOUNDARY.md` gave a useful 3CNF-to-normalized-kernel source compiler but rejected iid ternary noise because one explicit unsatisfiable formula had a false exact kernel vector only `+4` in squared norm above the honest threshold.  A natural repair is to choose a more sophisticated public iid distribution `D` on `Z_q` whose ordinary odd harmonic remains useful for an honest 0/1 witness while a coefficient `2` falls into a spectral notch.

This pass shows that this repair fails much more generally.  There are two new ingredients:

1. every Boolean assignment — satisfying or not — has a simple exact normalized-kernel **pseudovector**; each violated clause adds only one coefficient `+2` and one extra coefficient `-1`;
2. for every probability distribution on `Z_q`, positive definiteness of its characteristic function forces

   `|phi(2t)| >= max(0, 2|phi(t)|^2 - 1)`.

Combining these with the complete capsule Fourier character gives an explicit no-source-witness key statistic.  If the honest scalar channel has nonnegligible correctness advantage and `q` is polynomial, then for sufficiently large compiler size the pseudovector retains at least a **fifth power** of an inverse-polynomial odd-harmonic signal.  Polynomial independent repetition can amplify that signal too.

This is a theorem about the normalized short-kernel compiler with **public iid additive coordinate noise**.  It is not a theorem about all LWE/SIS systems, correlated or statement-dependent noise, nonlinear key-bearing binders, or arbitrary final-key privacy amplification.

No external literature or web search was used.  Production code is unchanged.

---

## 1. Recalled normalized short-kernel compiler

For a 3CNF with `n` Boolean variables and `m` clauses, let

`N = n + 2m`

be the number of complementary pairs and let `h` be the normalization coordinate.  Each pair `(u, ubar)` has the homogeneous equation

`u + ubar - h = 0`.                                                    (1)

For clause `j`, with literal coordinates `l1,l2,l3` and the first coordinates `s1,s2` of its two slack pairs, use

`l1 + l2 + l3 + s1 + 2 s2 - 4 h = 0`.                                 (2)

Write the resulting integer matrix as `H`.  Put

`L := N + 1 = n + 2m + 1`.                                             (3)

A satisfying Boolean assignment gives an integer vector `x_w` with

`H x_w = 0`, `x_w,h = 1`, and exactly `L` coefficients equal to `1`, so

`||x_w||_2^2 = L`.                                                      (4)

Conversely, the earlier theorem proves that an integer normalized kernel vector of squared norm at most `L` extracts a satisfying assignment.

The iid additive raw-bit capsule considered here, modulo even `q >= 4`, is

`c = H^T y + e + (q/2) mu g`,                                          (5)

where `g` selects `h`, `mu in {0,1}`, `y` is arbitrary/publicly masked, and the coordinates of `e` are iid from a public distribution `D` on `Z_q`.

A valid witness obtains

`<x_w,c> = <x_w,e> + (q/2) mu`.                                        (6)

The question is whether a clever `D` can make every non-witness normalized kernel direction useless while leaving (6) decodable.

---

## 2. New theorem: every Boolean assignment has an exact kernel pseudovector

Fix **any** Boolean assignment `a`, whether or not it satisfies the formula.  Encode every variable pair as the corresponding one-hot pair.  In a clause let `t in {0,1,2,3}` be its number of true literals.  Choose the two slack first-coordinates as

| `t` | `(s1,s2)` | `s1+2s2 = 4-t` |
|---:|:---:|---:|
| 3 | `(1,0)` | 1 |
| 2 | `(0,1)` | 2 |
| 1 | `(1,1)` | 3 |
| 0 | `(0,2)` | 4 |

and use complementary pairs `(s_i,1-s_i)` as required by (1).

For `t=0`, the second slack pair is therefore

`(2,-1)`.                                                              (7)

All pair equations hold, and (2) holds because `t+s1+2s2=4`.  Hence:

### Theorem 1 — arbitrary-assignment exact pseudovector

For every Boolean assignment `a` there is an efficiently constructible integer vector `x_a` such that

`H x_a = 0`, `x_a,h = 1`.                                              (8)

If `v(a)` clauses are violated, then `x_a` contains:

- exactly `L` coefficients of absolute value `1`;
- exactly `v(a)` additional coefficients equal to `+2`;
- among the `L` unit coefficients, exactly `v(a)` are `-1`;
- no coefficient of larger absolute value.

Consequently

`||x_a||_2^2 = L + 4 v(a)`.                                            (9)

Also

`v(a) <= m < L/2`.                                                      (10)

This strictly strengthens the earlier single false-vector fixture.  A public attacker does not have to solve the CNF, optimize an assignment, or find a near-witness: **all-zero assignment is already enough**.  On a hard satisfiable instance, this gives a same-statement public pseudovector without knowing any source witness.

The vector does not satisfy the earlier extraction threshold unless `v=0`; there is no contradiction with the source-extraction theorem.

---

## 3. New theorem: a spectral notch at `2t` cannot coexist with a very strong harmonic at `t`

For public iid noise `E <- D`, define

`phi(t) = E[ exp(2 pi i t E / q) ]`.                                   (11)

### Theorem 2 — characteristic-function doubling inequality

For every `t`,

`|phi(2t)| >= max(0, 2 |phi(t)|^2 - 1)`.                               (12)

**Proof.** Let `Z = exp(2 pi i tE/q)` and rotate it by a unit phase so that `E[Z] = r := |phi(t)|` is nonnegative real.  Writing the rotated variable as `W=e^{i theta}`,

`Re E[W^2] = E[cos(2 theta)] = 2 E[cos^2 theta] - 1`

`>= 2 (E[cos theta])^2 - 1 = 2 r^2 - 1`.                               (13)

Rotation does not change `|E[Z^2]|`, and modulus is at least the real part when the latter is positive.  QED.

This is an exact property of every probability distribution; it is not a new cryptographic assumption.

The inequality is sharp.  At `q=8`, the public distribution uniform on `{+1,-1}` has

`|phi(1)| = 1/sqrt(2)`, `phi(2)=0`.                                     (14)

But this sharp notch is not free: convolution of many copies drives the honest half-shift distinguishability down rapidly.  The checker records exact cyclic convolutions for this control.

---

## 4. Complete-transcript character of the pseudovector

For any modular kernel vector `x`, the row-space term cancels exactly:

`<x,H^T y> = <Hx,y> = 0 mod q`.                                        (15)

For an odd harmonic `t`, the key shift contributes

`exp(2 pi i t (q/2) mu / q) = (-1)^mu`                                (16)

because `x_h=1`.

For the arbitrary-assignment vector of Theorem 1, iid factorization gives the exact expectation magnitude

`A_a(t) = |phi(t)|^L |phi(2t)|^{v(a)}`.                                (17)

Signs `-1` do not change magnitude because `|phi(-t)|=|phi(t)|`.

Let

`beta_t := |phi(t)|^L`.                                                 (18)

Then (12) gives

`A_a(t) >= beta_t * max(0, 2 beta_t^{2/L} - 1)^{v(a)}`.                (19)

This is a property of the **full public capsule (5)**.  It is not obtained by querying an intended witness decoder, and adding an LWE-looking/random row-space mask inside `y` does not affect it.

The checker includes a tiny complete-transcript enumeration over all noise vectors of a two-point distribution and verifies both the exact product formula and the key-conditioned sign flip.

---

## 5. Any useful honest scalar decoder exposes an odd harmonic

For an honest source witness, all `L` selected coefficients are `+1`.  Its residual-noise distribution is

`P = D^{*L}`                                                            (20)

on `Z_q`.  Let `P^shift` be its translate by `q/2` and define

`delta := TV(P, P^shift)`.                                              (21)

The optimal honest raw-bit decoder has success `(1+delta)/2`; therefore any actual decoder with success `p_h` implies

`delta >= 2p_h - 1`.                                                    (22)

Fourier inversion of `P-P^shift` has support only on odd harmonics.  Triangle inequality gives

`delta <= sum_{t odd} |phi(t)|^L = sum_{t odd} beta_t`.                 (23)

There are `q/2` odd residues, so some odd `t` obeys

`beta_t >= beta_0 := 2 delta / q`.                                     (24)

When `q` is polynomial and honest advantage `delta` is inverse-polynomial or larger, `beta_0` is inverse-polynomial.  Because `D` is public and `q` is polynomial in this candidate, the attacker can enumerate the odd harmonics and select one with large `beta_t` (or estimate the public sampler's coefficients to inverse-polynomial accuracy).

This step does not assume that the intended witness decoder itself is a Fourier/character decoder.

---

## 6. Quantitative fifth-power lower bound

Take an odd `t` satisfying (24) and write

`beta = beta_t`, `a = ln(1/beta)`.                                     (25)

Suppose

`L >= 8 ln(1/beta)`.                                                    (26)

Then `x := 4a/L <= 1/2`.  From `e^{-u} >= 1-u`,

`2 beta^{2/L} - 1 = 2 e^{-2a/L}-1 >= 1 - 4a/L = 1-x`.                 (27)

For `0 <= x <= 1/2`, `ln(1-x) >= -2x`.  Using `v(a) < L/2`,

`(1-x)^{v(a)} >= exp(-2v(a)x) >= exp(-4a) = beta^4`.                   (28)

Substituting into (19):

### Theorem 3 — fifth-power pseudodecoder bound

Under (26), every arbitrary-assignment pseudovector obeys

`A_a(t) >= beta^5`.                                                     (29)

Combining with (24), a sufficient public lower bound is

`A_a(t) >= (2 delta/q)^5`,                                             (30)

provided

`L >= 8 ln(q/(2 delta))`.                                               (31)

This is the same qualitative phenomenon as the earlier finite-cover `gamma_h^5` theorem, but it now applies to the normalized short-kernel compiler and **every iid additive noise distribution**, not merely ternary/Gaussian noise.

For polynomial `q` and nonnegligible honest `delta`, the RHS of (30) is inverse-polynomial for all sufficiently large instances.

### Turning the character into an explicit predictor

The complete expectation under `mu=0` is a publicly computable complex number `M` of magnitude `A_a(t)`; under `mu=1` it is `-M`.  Rotate the unit character by `-arg M` and define the bounded real statistic

`f(c) = Re( exp(-i arg M) * exp(2 pi i t <x_a,c>/q) ) in [-1,1]`.       (32)

Randomize the guess with

`Pr[guess 0 | c] = (1+f(c))/2`.                                        (33)

For a uniform raw key bit, this predictor succeeds with probability

`1/2 + A_a(t)/2`.                                                       (34)

Thus a direct raw-bit capsule has a public no-source-witness inverse-polynomial predictor whenever the honest channel has nonnegligible scalar advantage under the stated polynomial-`q`/size conditions.

If the construction repeats independent capsules of the **same raw bit** to amplify honest correctness, the public attacker can amplify (34) using `O(A^{-2} log(1/eps))` copies, which is polynomial when (30) is inverse-polynomial.

This does **not** by itself prove recovery of an arbitrary hashed/derived final KEM key through every possible outer layer; final-key composition remains a separate obligation, as already recorded by the QPT Fourier checkpoint.

---

## 7. What the result does and does not reject

### Rejected in this pass

The following architecture is not a source-witness-restricted public release mechanism:

1. normalized short-kernel 3CNF compiler from the earlier checkpoint;
2. public capsule `H^T y + e + (q/2)mu g`;
3. coordinates of `e` sampled iid from an arbitrary public distribution `D` on `Z_q`;
4. polynomial `q` and a useful honest scalar channel.

The attacker needs no source witness and no lattice break.  It chooses any Boolean assignment, builds `x_a` in linear time, and applies the public character statistic above.  The mask `H^T y` cancels exactly.

In particular, “put a spectral notch at coefficient 2” does not solve the near-threshold false-vector problem: if the first harmonic is strong enough across `L` honest coordinates, positive definiteness forces the doubled harmonic to remain strong enough across at most `L/2` violated-clause doubles.

### Not proved

This pass does **not** rule out:

- correlated coordinate noise;
- statement-dependent, non-iid error geometry that couples coordinates globally;
- a different source compiler whose arbitrary assignments do not admit such exact low-complexity kernel pseudovectors;
- nonlinear/nonadditive key-bearing binders;
- an implementation with exponentially large `q` (which also raises independent efficiency/resource questions);
- a complete final-key compiler whose proof handles raw-channel leakage in some different way.

No LWE or SIS instance is solved here, and no new assumption is named to assert the desired conclusion.

---

## 8. Tests actually executed

`iid_noise_short_kernel_run68_check.py` is standard-library-only and deterministic.  The finalized checker was executed twice with byte-identical JSON output.

It checked:

1. **500 arbitrary-assignment compiler cases** across random 3CNFs: every constructed pseudovector had `Hx=0`, `h=1`, exactly `L` unit-magnitude coordinates, exactly `v` coefficients `+2`, exactly `v` coefficients `-1`, and squared norm `L+4v`;
2. **22,260 characteristic-function inequalities** over public random rational distributions and `q in {8,10,12,16,24,32,64}`; every case satisfied (12);
3. the exact `q=8`, `D=Uniform{+1,-1}` sharp-notch control, including `|phi(1)|=1/sqrt(2)` and `phi(2)=0`, plus exact cyclic-convolution half-shift TVs through `L=32`;
4. **225 complete honest-TV/Fourier cases**, verifying both `delta <= sum_odd beta_t` and `max_odd beta_t >= 2delta/q`;
5. one explicit tiny complete-transcript enumeration over **128 noise vectors**, verifying (17) and exact key-conditioned sign reversal;
6. **3,000 quantitative fifth-power controls**, all satisfying the lower bound under `L >= 8 ln(1/beta)` and `v<=L/2`;
7. four public `rho*delta_0+(1-rho)*Uniform` examples, for which the exact honest TV, direct pseudodecoder amplitude, and conservative `(2delta/q)^5` guarantee are recorded;
8. **400 random formula/distribution factorization cases**, checking the exact product magnitude and the doubling lower bound.

The checker output is finite validation of the identities and implementation only.  The mathematical claims are the proofs above; the tests are not used as a substitute for security.

Finalized local SHA-256 values are recorded in the accompanying provenance file.

---

## 9. Handoff / unresolved obligations

The normalized short-kernel route is now narrower than it was after the ternary-noise counterexample.  Merely changing the iid modular error distribution — including deliberately placing a notch at the doubled coefficient — cannot create the missing source-restricted gap.

A surviving lattice route must change something structural, for example:

1. a source compiler in which every efficiently constructible non-witness exact/projective relation has a **superconstant** decryption-complexity gap under the actual complete-output norm/support geometry; or
2. a globally correlated/statement-aware error mechanism that preserves every true witness direction while suppressing the arbitrary-assignment pseudovectors, together with a complete-output reduction to standard LWE/SIS or another independently justified PQ assumption; or
3. a genuinely nonlinear key-bearing mechanism rather than additive kernel cancellation.

Still unresolved are the required arbitrary-QPT final-key recovery -> source-witness / independent-PQ-break reduction for a surviving inner primitive, false-instance hiding for that primitive, malicious-secure erased-setup and auxiliary-input composition, and concrete practical parameters/resources.

**Stopping condition not met.**
