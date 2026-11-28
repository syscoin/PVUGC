# Run 47 — Tensor metric amplification and CP/rank-one compression audit

## Status

This note records a constructive attempt starting from the Run-42/43 native short-preimage interface. It does **not** claim a complete witness KEM, a post-quantum security proof, or an arbitrary-key-recovery extractor.

The attempted idea was to amplify the small Run-43 metric gap by tensor powers and then compress the exponentially large tensor object into a polynomial number of public rank-one factors. The explicit tensor algebra does amplify the metric gap exactly. The natural CP/rank-one compression, however, has a sharp complete-output problem: noiseless factors expose the pad by public linear algebra, while local LWE-style noise turns the desired additive tensor noise into multiplicative cross terms that can erase even a valid witness's key information. An exact-linear-sketch variant also has a conditional dimension lower bound.

The negative results below are scoped to the stated representations. They are not an impossibility theorem for every nonlinear or computational tensor encoding.

## 1. Starting interface from Runs 42/43

Let

- `A in F_q^{m x N}` and `u in F_q^m` be public,
- a genuine source witness map to an exact public preimage `y` satisfying `Ay=u`, and
- the Run-42/43 source-binding theorem apply when a **supplied** normalized preimage is inside the proved shortness bound.

On the Run-43 diagnostic family, a genuine punctured Boolean preimage has squared Euclidean norm

`H = ||y_w||_2^2`,

while a public false pseudopreimage can have squared norm

`H+4`.

The obstacle was that this additive gap has multiplicative ratio tending to one as `H` grows, so an ordinary dual/preimage LWE capsule accepts the false preimage with almost the same reliability as the honest one.

## 2. Explicit tensor-power lift: exact positive identity

For an integer tensor power `t >= 1`, define

`B = A^{\otimes t}`, `v = u^{\otimes t}`, `Y = y^{\otimes t}`.

Then

`B Y = (A y)^{\otimes t} = u^{\otimes t} = v`.

This is an exact algebraic identity over any field.

The Euclidean norm also tensorizes exactly over the integer/real lift:

`||y^{\otimes t}||_2^2 = ||y||_2^{2t}`.

Hence if an additive tensor-coordinate noise vector has isotropic variance, the standard deviation of its contraction with the honest tensor direction scales as `H^{t/2}`, whereas the known false direction scales as `(H+4)^{t/2}`. Their ratio is

`G(H,t) = ((H+4)/H)^{t/2}`.

For `t=H`,

`G(H,H) -> e^2`.

To make this ratio polynomial in a security parameter, say at least `lambda^c`, one needs

`t >= 2 c ln(lambda) / ln(1+4/H) = Theta(H log lambda)`.

The explicit tensor coordinate count is `N^t`. Thus the direct representation is already superpolynomial for growing `H` and `t=Theta(H log lambda)` (and is exponential in `H` even for `t=H` when `N>1`).

This is a **metric-amplification identity and resource count**, not a security proof.

## 3. A second source-binding gap appears after tensorization

Even before compression, the original supplied-preimage extraction theorem does not automatically transfer to the full tensor relation.

If `rank(A)=r`, then

`rank(A^{\otimes t}) = r^t`,

so the tensor relation has kernel dimension

`N^t - r^t`.

In particular, for every `k in ker(A)` and arbitrary vectors `z_2,...,z_t`,

`k \otimes z_2 \otimes ... \otimes z_t in ker(A^{\otimes t})`.

Therefore a solution to

`A^{\otimes t} Y = u^{\otimes t}`

need not be rank one and need not equal `y^{\otimes t}` for a source preimage `y`. Run 42/43 proves source-witness-or-SIS extraction for a supplied sufficiently short **original** representation; it does not prove that every sufficiently useful or short tensor-space representation factors back to such a source preimage. A separate extraction theorem would be required.

This is an unresolved obligation, not a demonstrated tensor-space attack at the target parameters.

## 4. Natural CP/rank-one compression attempt

A natural way to avoid publishing `N^t` tensor coordinates is to sample independent secrets `s_1,...,s_t in F_q^m` and publish local factors

`z_j = A^T s_j + e_j in F_q^N`.

Let

`alpha_j = <u,s_j>`.

The intended hidden rank-one tensor pad is

`P = product_j alpha_j`.

A binary capsule could publish, schematically,

`beta = P + mu K`,

where `mu != 0` is the key phase. A valid exact preimage `y` computes

`<y,z_j> = alpha_j + delta_j`,

where

`delta_j = <y,e_j>`.

Its residual after trying to cancel the pad is therefore

`R_y = product_j (alpha_j + delta_j) - product_j alpha_j`.

The hoped-for additive tensor noise has become a polynomial with multiplicative cross terms.

### 4.1 Noiseless complete-output break

Set all `e_j=0`. Then each public factor is

`z_j=A^T s_j`.

Anyone can solve the public linear system

`A^T shat_j = z_j`

for any solution `shat_j` whenever the factor is in the image, as it is by construction.

For the native preimage instances under study, `u=Ay` for at least one exact preimage. Hence for any two solutions `s_j,shat_j`,

`A^T(s_j-shat_j)=0`

and therefore

`<u,s_j-shat_j> = <Ay,s_j-shat_j> = <y,A^T(s_j-shat_j)> = 0`.

So

`<u,shat_j> = <u,s_j> = alpha_j`.

The adversary recovers every `alpha_j`, computes `P`, and obtains `K` from `beta-P` without a source witness. The attack does not require recovering the original `s_j`; any public linear-system solution suffices.

The same argument applies term-by-term to a publicly labelled finite sum of rank-one pad terms.

This is a **complete-public-output key-recovery attack** on the noiseless natural CP encoding.

### 4.2 Exact noisy correctness barrier for one corrupted factor

Now keep local errors. Assume `u != 0` and the `s_j` are independent uniform over `F_q^m`. Then each `alpha_j=<u,s_j>` is independent uniform over `F_q`.

Condition on the particularly simple contracted-error event

`delta_1=c != 0`, and `delta_2=...=delta_t=0`.

The valid witness residual becomes

`R_y = c product_{j=2}^t alpha_j`.

Because multiplication by nonzero `c` is a permutation of `F_q`, its exact distribution is independent of `c`. Let `D_t` denote it. Then

`Pr[D_t=0] = 1-(1-1/q)^{t-1}`,

and for every nonzero `r in F_q`,

`Pr[D_t=r] = (q-1)^{t-2}/q^{t-1}`.

For any nonzero binary key shift `mu`, the total-variation distance between `D_t` and `D_t+mu` is exactly

`TV(D_t,D_t+mu) = |p_0-p_1|`,

where

`p_0 = 1-(1-1/q)^{t-1}`,

`p_1 = (q-1)^{t-2}/q^{t-1}`.

Thus the optimal key-bit success probability from this witness residual is

`1/2 + |p_0-p_1|/2`.

Two notable consequences are exact:

- `t=2`: `D_t` is exactly uniform, so the valid witness gets zero information about the shifted key on this event.
- for fixed/moderate `t` and large `q`, `|p_0-p_1| = O(t/q)`, so the conditional valid-witness advantage is tiny.

This does **not** by itself prove that every local-noise distribution makes the construction incomplete; one must also account for the probability of the conditioning event. It does prove that the factorized representation has lost the simple additive-noise geometry that made tensor norm amplification attractive. A security/correctness claim must control the full multiplicative residual distribution, not merely `||y^{\otimes t}||`.

## 5. Conditional lower bound for exact public linear sketches

There is also a representation-level obstruction for exact **linear** compression of the explicit tensor contraction.

Let `S:F^{N^t}->F^r` be a public linear sketch. Suppose that for every allowed preimage `y` there is a public/witness-derived linear decoder `lambda_y` such that, for every tensor vector `a`,

`lambda_y^T S a = <a, y^{\otimes t}>`.

Then equality of linear functionals for all `a` forces

`S^T lambda_y = y^{\otimes t}`.

Hence every required tensor direction lies in the row space of `S`, and

`r >= dim span{ y^{\otimes t} : y in Y }`.

If the required `y` range over a `d`-dimensional affine patch

`y(r)=a+sum_{i=1}^d r_i b_i`

with the affine directions independent, and the field characteristic is zero or larger than `t`, the span of the pure tensor powers has dimension

`binom(d+t,t)`.

Therefore exact linear sketch size obeys

`r >= binom(d+t,t)`.

For `d=t=n`, this is about `4^n/sqrt(pi n)`. For fixed `d` or fixed `t` it can remain polynomial, so this is **not** a universal compression lower bound. It applies only to exact public linear sketches with the stated affine-patch requirement. Nonlinear/computational encodings are not ruled out.

## 6. What was implemented and actually executed

`check_tensor_metric_compression_run47.py` is a deterministic Python standard-library checker with seed `470047`.

It was executed twice locally after the final edits. The two JSON outputs were byte-identical.

The checker validates:

1. **1,421 tensor-preimage coordinates** over 100 random small `F_101` fixtures, checking `A^{\otimes t} y^{\otimes t}=u^{\otimes t}`.
2. **200 integer tensor norm identities**.
3. **21 metric-gap/resource rows** for Run-43-style squared-norm gap `H` versus `H+4`.
4. **9 exhaustive one-corrupted-factor distributions** for `q in {5,7,11}`, `t in {2,3,4}`, including the exact `p_0`, `p_1`, TV, and optimal shifted-key success formulas.
5. **15 large-q analytic controls** for `q in {257,769,12289}` and `t in {2,4,8,16,32}`.
6. **300 noiseless CP public-recovery fixtures** and **1,039 solution-invariance checks**, verifying that any public solution of `A^T shat=z` recovers the same `<u,s>`.
7. **1,000 noisy CP residual identity fixtures** with one contracted unit error, verifying the multiplicative cross-term formula directly.
8. **12 affine tensor-power span checks** for `d in {1,2,3}`, `t in {1,2,3,4}`, matching `binom(d+t,t)` by finite-field rank.
9. **80 tensor-rank checks** and **80 explicit tensor-kernel-direction checks**, validating the tensor-relation kernel expansion described above.

These tests validate finite algebra and exact finite distributions only. Passing them is not evidence of PQ hiding.

Final local hashes:

- checker SHA-256: `c27b00dd616c649112ada6ffe921d4f8f841f555e6c3da0ca37f71fd768dd68d`
- captured JSON SHA-256: `5ad4036ba7fcc48c84e1c041078bcfc5f0d19f5333246553028994447a5a662e`

## 7. Result and remaining obligations

### Proved in this run

- Exact tensor preimage and norm identities.
- Explicit tensor metric-gap amplification and its exponential coordinate cost.
- Tensor-relation kernel expansion and the resulting need for a new source-extraction theorem.
- Complete-view noiseless key recovery for the natural public CP/rank-one factor representation.
- Exact valid-witness residual law, TV, and optimal bit advantage on the one-corrupted-factor event.
- Conditional dimension lower bound for exact public linear sketches over an affine witness patch.

### Implemented/tested, not promoted to proof of security

- Deterministic finite-field/integer checker for all identities above.
- Exhaustive small-field distributions and independent random algebraic fixtures.

### Still unresolved

- A polynomial-size nonlinear/computational tensor encoding whose complete public output is hidden under an independently justified PQ assumption.
- A proof that arbitrary successful key recovery yields a source witness or breaks that assumption.
- A tensor-space extraction theorem if an explicit tensor relation is used.
- Full false-instance hiding against QPT adversaries with all auxiliary public data.
- Malicious-secure ceremony composition, abort semantics, t-of-X/N-of-N operator structure, and concrete deployment parameters.

The stopping condition for a complete generic-NP offline PQ witness KEM is therefore **not met**.
