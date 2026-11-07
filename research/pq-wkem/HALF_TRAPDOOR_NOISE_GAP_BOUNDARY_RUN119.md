# Run 119 — half-trapdoor offset boundary and the constant-noise-gap obstruction

## Status

Verified starting PR head: `a0803edfa691f184e33ca92620471a81c17c611c` on branch `research/pq-wkem-validation-20260918`. PR #1 was open, draft, and unmerged. The latest substantive ordinary PR comment was `5843580758`, recording verified publication of Runs 104–108 and 110–111.

This run builds on the local Run-118 checkpoint rather than replaying unpublished history. Run 118 gave a source-preserving one-hot affine compiler with a bounded-occurrence constant norm gap, but left the uniform random carrier / public short-lift distribution as the central blocker.

The present result has three parts:

1. **Positive literature lead:** Wee's half-trapdoor theorem is a real standard-LWE-derived result that tolerates arbitrarily many adaptive *restricted Gaussian preimage* outputs. This is closer to the needed auxiliary-output security than ordinary trapdoors.
2. **Offset-half obstruction:** the exact source offset in Wee's sampler lives in the complementary half. Algebraically moving that offset into the LWE-protected linear form turns each public sampler output into an explicit short preimage of the source target, collapsing witness gating.
3. **Noise-gap obstruction:** a constant multiplicative norm gap cannot by itself enforce source validity through a zero-centered Gaussian threshold decoder. This sharply limits what Run 118's constant gap can buy in the Run-115/116 noisy-HPS layer.

A fourth literature calculation shows that Hair–Sahai's advertised polynomial `l_p` gap for `p>2` does **not** black-box transfer to a polynomial Euclidean gap through generic norm inequalities; the dimension loss is larger than their permitted exponent.

No production path is changed.

---

## 1. Wee's half trapdoor is a genuine auxiliary-preimage theorem from standard LWE

Hoeteck Wee, *ABE for DFA from LWE against Bounded Collusions, Revisited* (TCC 2021; ePrint 2022/1348), splits a public matrix into two row halves and uses a low-norm half trapdoor `T_{1/2}` satisfying, in the paper's notation,

\[
A_{\rm top}T_{1/2}=0,
\qquad
A_{\rm bot}T_{1/2}=G.
\]

The restricted sampler, on a public pair `(M,Z)`, returns a short Gaussian matrix `K` whose image is distributed as

\[
A_{\rm top}K=D,
\qquad
A_{\rm bot}K=DM+Z,
\tag{1}
\]

for uniform random `D`.

The important security statement is not "LWE given the trapdoor"—the paper explicitly says that is false—but rather LWE given adaptive access to the restricted sampler. Theorem 1 derives this `T_{1/2}`-LWE game from ordinary LWE, with an enlarged error parameter `\hat\chi=\chi\, n^{\omega(1)}` and unbounded adaptive sampler queries.

The proof constructs the public matrix from a standard-LWE matrix and a short random matrix `R`, uses a single ordinary-LWE computational hybrid, noise smudging, and a leftover-hash step, while simulating the restricted sampler from `R`.

### Security classification

The author's theorem is stated in the paper's classical framework (`PPT` adversaries). It is **not** being relabeled as a QPT theorem here.

However, its proof architecture is unusually favorable for a future quantum lift: it is straight-line, does not rewind the distinguisher, does not extract from a quantum state, and has no random-oracle programming. For an adversary making classical sampler queries, a formal QPT restatement looks plausible if the base LWE computational step is assumed hard for QPT algorithms and all statistical hybrids are promoted to trace-distance statements. That formal quantum game rewrite has **not** been completed in this run, so the QPT status remains `UNPROVED`.

---

## 2. Exact offset-half identity

Equation (1) is tantalizing because `Z` may be chosen by the caller. Could the Run-118 source matrix/target be placed into that offset and then hashed through the LWE-protected matrix?

Take the special query

\[
M=\mu I.
\]

Then any sampler output `K` obeys

\[
A_{\rm top}K=D,
\qquad
A_{\rm bot}K=\mu D+Z.
\tag{2}
\]

Define the public row combination

\[
B:=A_{\rm bot}-\mu A_{\rm top}.
\tag{3}
\]

Subtracting `\mu` times the first equation from the second gives the exact identity

\[
\boxed{BK=Z.}
\tag{4}
\]

So if one attempts to use `B` as the carrier whose projected hash is gated by a short source witness for `Z`, the sampler has already published such a short preimage `K` **without the source witness**.

If an LWE-shaped public value were

\[
b_B=B^Ts+e,
\]

then anyone holding `K` can compute

\[
K^Tb_B=Z^Ts+K^Te,
\tag{5}
\]

which is precisely the projective evaluation that was supposed to require the source witness.

This is a syntactic source-gating failure. No LWE attack is required.

### Why this does not contradict Wee's theorem

Wee's theorem protects its specific half-trapdoor LWE experiment. It does not assert that arbitrary public row transformations placing the caller-selected offset `Z` in the protected linear form remain hard while all returned preimages are exposed.

In fact the paper motivates the specialized experiment precisely because full "LWE given the half trapdoor" is false. The new observation is narrower: **the arbitrary offset feature is in the wrong half for our application**. Moving it to the desired hash carrier causes the restricted sampler output itself to become the missing witness.

Call this the **offset-half barrier**.

---

## 3. Partial lattice trapdoors do not remove this requirement

Albrecht–Lai–Lapiha–Woo, *Partial Lattice Trapdoors: How to Split Lattice Trapdoors, Literally* (ASIACRYPT 2025), goes substantially further in distributing preimage sampling. The paper explicitly notes that reducing ordinary SIS/LWE with respect to `A` to the *same* problem in the presence of even one corrupt partial-trapdoor holder is impossible, because a partial trapdoor yields a short kernel vector. Their solution uses `kappa`-SIS / `kappa`-LWE instances containing Gaussian kernel hints.

For the integer case, their Theorem 1 gives a PPT reduction from ordinary LWE to varying-width `kappa`-LWE under explicit parameter loss, including

\[
\chi_0 > \Omega\!\left(m^{3/2}\max_i \sigma_i'\,\chi\right).
\tag{6}
\]

Their definitions and application theorems quantify over PPT adversaries. The ring/module extensions of the plain-assumption reduction are not all supplied as theorems; the paper marks some as conjectural/generalized directions.

This is valuable evidence that **some** large families of Gaussian preimage hints can coexist with LWE-derived security. But it does not furnish the object needed here: a public short lift of an arbitrary statement-derived nonzero source target in the same carrier component whose LWE projection hides the canonical key.

Again, no QPT theorem is imported. The reductions are classical PPT statements in the source paper.

---

## 4. Constant Gaussian norm gaps cannot enforce witness validity

Run 118 proved a constant multiplicative norm separation for bounded-occurrence gap instances. That is useful for source extraction, but it is not enough for the most natural noisy projective decoder.

Consider the *best-case idealized* model in which projected errors are exact centered Gaussians.

Let an honest witness produce

\[
X_h\sim N(0,\sigma_h^2),
\]

and suppose a source-invalid affine pseudowitness has only a constant-factor larger standard deviation

\[
X_f\sim N(0,C^2\sigma_h^2),
\qquad C>1\text{ constant}.
\]

A symmetric decoder accepts whenever `|X|<=T_lambda`.

For honest rejection to vanish, and in particular to be negligible, one must have

\[
\frac{T_\lambda}{\sigma_h}\longrightarrow\infty.
\tag{7}
\]

But then for constant `C`,

\[
\frac{T_\lambda}{C\sigma_h}\longrightarrow\infty
\tag{8}
\]

as well. Hence

\[
\Pr[|X_f|>T_\lambda]\longrightarrow0,
\qquad
\boxed{\Pr[|X_f|\le T_\lambda]\longrightarrow1.}
\tag{9}
\]

So a constant variance/norm factor cannot produce

- overwhelming honest acceptance, **and simultaneously**
- negligible acceptance of source-invalid pseudowitnesses,

when both errors are centered at the same canonical value and validity is enforced only by a Gaussian threshold.

For the common correctness scaling

\[
T_\lambda=\sigma_h\sqrt{2\lambda\ln2},
\]

honest rejection is about `2^{-lambda}` up to polynomial factors, while a false standard deviation `C sigma_h` has tail exponent only divided by `C^2`. That tail is still negligible, so the invalid pseudowitness is accepted with overwhelming probability.

### Application to Run 118

Run 118 gives an explicit affine preimage from any Boolean assignment with

\[
\|z\|_2^2=B+2V(a),
\qquad B=n+m.
\]

Even on a false formula, `V(a)<=m`, so this explicit invalid preimage satisfies

\[
\frac{\|z\|_2^2}{B}\le 1+\frac{2m}{n+m}<3.
\tag{10}
\]

Thus, under isotropic Gaussian coordinate noise, its projected standard deviation is at most `sqrt(3)` times the honest one. The theorem above applies with `C<=sqrt(3)`.

Therefore:

\[
\boxed{\text{Run-118's constant gap cannot by itself be the noisy-HPS validity filter.}}
\]

This strengthens Run 118's earlier caveat that a constant variance gap was not yet a hiding proof.

The statement is deliberately limited to the zero-centered Gaussian/noise-only threshold mechanism. It does **not** rule out a nonlinear validity transformation, a mean/phase separation, a superconstant norm gap, or a cryptographic proof that makes invalid evaluation computationally unrelated to the canonical value.

---

## 5. Hair–Sahai's polynomial `l_p` gap does not black-box become an `l_2` gap

Hair–Sahai, arXiv:2608.14529v3, prove that for constant `2<p<infinity` and

\[
0<\varepsilon<\min\left\{\frac{p-2}{4p},\frac18\right\},
\]

`M^epsilon`-GapSVP_p is NP-hard under a deterministic polynomial-time reduction. For `p=infinity`, they obtain every constant `epsilon<1/8`.

For `p>2`, let

\[
\theta:=\frac12-\frac1p=\frac{p-2}{2p}.
\]

Generic norm comparison in ambient dimension `d` gives

\[
\|v\|_p\le\|v\|_2\le d^\theta\|v\|_p.
\tag{11}
\]

A black-box conversion of an `l_p` YES radius `r` and NO lower bound `M^epsilon r` therefore gives at best

\[
\text{YES: }\|v\|_2\le d^\theta r,
\qquad
\text{NO: }\|v\|_2>M^\varepsilon r.
\]

In their geometric conversion the ambient dimension is `d<2M`, so the generic Euclidean gap factor is only

\[
\Omega(M^{\varepsilon-\theta}).
\tag{12}
\]

But

\[
\frac{p-2}{4p}=\frac\theta2,
\]

and therefore every advertised `epsilon` is strictly smaller than `theta`, indeed at most half of it before the separate `1/8` cap. The exponent in (12) is negative.

For `p=infinity`, generic conversion loses `d^{1/2}`, while the theorem supplies only `M^epsilon` with `epsilon<1/8`; again no nontrivial Euclidean gap follows.

Thus:

\[
\boxed{\text{the advertised Hair–Sahai }\ell_p\text{ theorem alone does not supply a polynomial }\ell_2\text{ gap.}}
\]

This is a statement about **black-box norm conversion**, not about every finer property of their construction. A construction-specific Euclidean analysis could in principle recover more and would need a separate proof.

It also matters cryptographically: linear forms of independent finite-variance Gaussian/LWE noise naturally scale with `l_2`, not `l_p` for `p>2`. There are no `p`-stable distributions for stability index `p>2`. Hence simply importing the worst-case `l_p` gap into the Run-115/116 noise layer is not justified.

Finally, worst-case deterministic NP-hardness of SVP is not random-instance LWE/SIS hardness or a QPT cryptographic assumption in the first place.

---

## 6. QPT / assumption ledger

### New algebraic offset-half identity

- Honest algorithm model: classical polynomial-time matrix arithmetic.
- Adversary model: unbounded; the identity is unconditional.
- Assumption: none.
- Conclusion: a public restricted sampler output for `[D; mu D+Z]` becomes an explicit preimage of `Z` for the row-combined carrier `B=A_bot-mu A_top`.

### Gaussian constant-gap obstruction

- Honest algorithm model: ideal continuous Gaussian threshold decoder.
- Adversary model: none needed; information-theoretic probability statement.
- Assumption: centered Gaussian projected errors whose standard deviations differ by a fixed constant factor.
- Conclusion: constant norm separation cannot make honest acceptance overwhelming while invalid acceptance negligible.

### Wee half-trapdoor theorem

- Honest algorithms: classical PPT.
- Adversary in source theorem: PPT with adaptive classical restricted-sampler queries.
- Base assumption: ordinary LWE at the stated dimensions/noise; theorem incurs noise flooding.
- Reduction model: source proof is straight-line; no rewinding observed in the audited theorem proof.
- Conclusion here: useful **classical** auxiliary-preimage theorem and credible QPT research lead; arbitrary-QPT security remains `UNPROVED` until formally restated from QPT-LWE.

### Albrecht–Lai–Lapiha–Woo partial trapdoors

- Honest algorithms: classical PPT.
- Adversary in definitions/theorems: PPT.
- Base assumptions: varying-width `kappa`-SIS / `kappa`-LWE; integer reductions to plain SIS/LWE have explicit width/noise losses.
- Conclusion: does not supply the source-offset carrier needed here; no QPT claim imported.

### Hair–Sahai `l_p` gap

- Honest reduction: deterministic classical polynomial time.
- Security meaning: worst-case NP-hardness, not cryptographic QPT hardness.
- Conclusion here: generic norm comparison loses more dimension exponent than the advertised gap supplies, so it cannot be used as an `l_2` noise-gap theorem without new construction-specific analysis.

---

## 7. Resulting bottleneck

The source semantics are no longer the only problem. Run 117/118 give an exact source extractor and a constant source-gap geometry. Run 116 gives a clean ordinary-LWE final wrapper **if** a suitable carrier exists.

Run 119 now rules out two natural ways of connecting them:

1. **Restricted preimage oracle / half-trapdoor placement:** the arbitrary source offset is in the complementary half; moving it into the protected carrier makes the public sampler output itself a source-independent preimage.
2. **Constant-gap Gaussian filtering:** even an ideal isotropic Gaussian error layer accepts constant-factor-longer invalid preimages with overwhelming probability when honest correctness is negligible-error.

The next construction therefore needs at least one genuinely new ingredient:

- a superconstant (preferably polynomial) **Euclidean** source gap compatible with an average-case LWE/SIS carrier;
- a nonlinear projective hash whose invalid evaluations are not merely the same canonical value plus a constant-factor larger centered error; or
- a standard-QPT-LWE auxiliary-preimage theorem that allows source-programmed nonzero targets in the **protected** component without exposing a public short preimage of those targets.

A newly named correlated/evasive assumption that simply asserts this missing property does not close the project.

The practical generic-NP public/offline PQ witness KEM remains open.
