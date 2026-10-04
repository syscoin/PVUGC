# Run 64 — Public-covariance dual minimization and a signed-dual attack on the noisy nonlinear mask

## Scope and starting point

This run continues directly from Run 63's single-object Boolean-quotient mask. Run 63 established the noiseless dichotomy for

\[
F=K u+v,\qquad v\in V,
\]

where `V` is a public mask subspace and every valid source witness supplies a linear evaluation functional `ell_w` satisfying

\[
\ell_w(V)=0,\qquad \ell_w(u)=1.
\]

The remaining idea was to add noise,

\[
F=K u+v+e,
\]

and hope that source-witness evaluations remain decodable while every public non-source annihilator becomes too noisy.

This note audits the most natural version of that repair: public covariance/noise shaping. It also gives an exact finite-ring signed-dual control for the simplest Boolean-quotient clause mask. The results below are barriers for these specific additive-linear continuations. They are **not** a generic impossibility theorem for modular LWE/SIS, nonlinear decoding, hidden noise geometry, or witness encryption.

No external literature or web search was used.

---

## 1. Candidate: covariance-shaped additive noise

Let the public coefficient space be `R^N`. Let `V <= R^N` be a public subspace and let `u notin V` be the public key direction. Setup publishes

\[
Y=K u+v+e,
\qquad v\in V,
\qquad e\sim N(0,\Sigma),
\]

where `Sigma` is public and positive definite.

A valid witness `w` provides a linear functional `ell_w` such that

\[
\ell_w^T v=0\ \text{for all }v\in V,
\qquad
\ell_w^T u=1.
\]

Hence

\[
\ell_w^T Y=K+\ell_w^T e,
\]

with Gaussian noise variance

\[
\operatorname{Var}(\ell_w^T e)=\ell_w^T\Sigma\ell_w.
\]

The attempted repair is to choose `Sigma` so all source-witness functionals have low variance while non-source public duals have high variance.

---

## 2. Proved theorem: public minimum-variance dual is at least as good as every witness

Take any public basis `v_1,...,v_r` of `V` and define

\[
C=
\begin{bmatrix}
 v_1^T\\
 \vdots\\
 v_r^T\\
 u^T
\end{bmatrix},
\qquad
b=(0,\ldots,0,1)^T.
\]

Because `u notin V`, `C` has full row rank. Every valid witness functional is feasible for

\[
C\lambda=b.
\]

Consider the public convex program

\[
\lambda_* = \arg\min_{C\lambda=b}\lambda^T\Sigma\lambda.
\]

For positive-definite `Sigma`, the minimizer is unique and is computable by ordinary linear algebra:

\[
\boxed{
\lambda_*
=
\Sigma^{-1}C^T
(C\Sigma^{-1}C^T)^{-1}b.
}
\]

Since every witness functional `ell_w` is feasible,

\[
\boxed{
\lambda_*^T\Sigma\lambda_*
\le
\ell_w^T\Sigma\ell_w
\quad\text{for every valid witness }w.
}
\]

Also `lambda_*` annihilates `V` and has `lambda_*^T u=1`, so the complete public transcript gives

\[
\boxed{
\lambda_*^T Y=K+\lambda_*^T e.
}
\]

Thus, for public Gaussian covariance shaping, a polynomial-time no-witness decoder obtains a residual whose Gaussian variance is no larger than that of **any** legitimate witness evaluation.

For binary phase encoding and midpoint/maximum-likelihood decoding, smaller Gaussian variance means no larger decoding error. Consequently, if every valid source witness has high-probability correctness in this model, the public minimum-variance dual has at least that correctness without using a witness.

This is a complete-public-output attack. It does not reconstruct a source witness, and it does not solve LWE/SIS.

### Proof

Use Lagrange multipliers for

\[
\min_\lambda \frac12\lambda^T\Sigma\lambda
\quad\text{s.t.}\quad C\lambda=b.
\]

Stationarity gives `Sigma lambda = C^T alpha`; hence

\[
\lambda=\Sigma^{-1}C^T\alpha.
\]

Substituting the constraint gives

\[
C\Sigma^{-1}C^T\alpha=b.
\]

The middle matrix is positive definite because `C` has full row rank and `Sigma` is positive definite. Therefore the displayed closed form follows. Optimality gives the variance inequality against every feasible witness functional.

---

## 3. Exact Run-63 Boolean-quotient fixture: `(x1 OR x2)`

Use coefficient basis

\[
(1,x_1,x_2,x_1x_2).
\]

The single clause-falsity generator is

\[
g=(1-x_1)(1-x_2)
=1-x_1-x_2+x_1x_2,
\]

so at full degree the public mask space is

\[
V=\operatorname{span}\{(1,-1,-1,1)\}.
\]

The key direction is `u=(1,0,0,0)`.

The three source-witness evaluation vectors are

\[
\ell_{10}=(1,1,0,0),
\quad
\ell_{01}=(1,0,1,0),
\quad
\ell_{11}=(1,1,1,1).
\]

All annihilate `g` and map `u` to one.

For isotropic covariance `Sigma=I`, the exact public minimum-norm dual is

\[
\boxed{
\lambda_*=(1,1/3,1/3,-1/3).
}
\]

Its squared norm is

\[
\|\lambda_*\|_2^2=4/3,
\]

while the witness squared norms are

\[
2,\ 2,\ 4.
\]

So the no-witness public residual is strictly *cleaner* than every source-witness residual in this natural Gaussian realization.

---

## 4. Proved finite/integral control: a signed dual has exactly the same iid symmetric noise law as a valid witness

The rational minimizer above leaves an obvious modular concern: a small real coefficient such as `1/3` is not a small centered coefficient modulo `q`. The following exact signed construction removes that concern for the single-clause Boolean-quotient mask.

For an `r`-variable OR clause (`r>=2`), use the squarefree monomial basis indexed by subsets `S subseteq [r]`. The falsifying indicator is

\[
\delta_0(x)=\prod_{i=1}^r(1-x_i),
\]

whose coefficient at monomial `x_S` is

\[
(-1)^{|S|}.
\]

Choose any nonempty proper subset `T subset [r]` and define the public signed functional

\[
\boxed{
\lambda_T(S)=(-1)^{|S\cap T|}.
}
\]

Then `lambda_T(empty)=1`, and

\[
\begin{aligned}
\langle \lambda_T,\delta_0\rangle
&=
\sum_{S\subseteq[r]}
(-1)^{|S|+|S\cap T|}\\
&=
\prod_{i\in T}(1+1)
\prod_{i\notin T}(1-1)\\
&=0,
\end{aligned}
\]

because `T` is proper. Hence `lambda_T` is a public integral annihilator with coefficients only `+1/-1`. It is not a Boolean source-evaluation vector because `T` is nonempty and therefore some entries are negative.

The all-ones assignment is a valid witness, and its evaluation functional is the all-`+1` vector on all `2^r` monomials. If coefficient noise is iid and symmetric under sign (`e_S` has the same law as `-e_S` independently for every coordinate), then

\[
\sum_S\lambda_T(S)e_S
\stackrel{d}{=}
\sum_S e_S.
\]

Therefore

\[
\boxed{
\lambda_T^T Y
\text{ has exactly the same key-conditioned residual distribution as the valid all-ones witness.}
}
\]

This identity is exact over integers before modular reduction, and the coefficients remain `+1/-1` modulo any modulus. It does not rely on a rational inverse or on solving a lattice problem.

### Two-witness identity

For the particularly simple choice `T={1}`, let `W=[r]\\T`. Then

\[
\boxed{
\lambda_T=2\ell_W-\ell_{[r]}.
}
\]

So the signed public dual lies in the linear span of just two legitimate witness evaluations. This also shows why perfect additive-noise cancellation for *all* valid witnesses cannot privilege the source evaluations here: any error annihilated by both witness functionals is automatically annihilated by this public combination.

This single-clause fixture is not by itself a hard-witness security counterexample—the clause has trivial witnesses. Its role is narrower: it falsifies the idea that iid symmetric coefficient noise, modular `+/-1` coefficients, or simple witness-span shaping inherently separates source evaluation from the public dual space.

---

## 5. What this closes and what survives

### Closed by the theorem in this run

The Run-63 noisy continuation does **not** become secure merely by assigning a public positive-definite Gaussian covariance to coefficient noise. For every satisfiable instance, the complete public description gives a minimum-variance annihilator computable by polynomial-time linear algebra, and that annihilator has no worse Gaussian residual than any valid witness.

The simplest iid symmetric modular/integer coefficient-noise variant also fails to privilege witnesses even at the level of coefficient magnitudes: the OR-clause signed dual uses only `+/-1` coefficients and exactly matches a valid witness's residual law.

### Not closed

This does **not** prove a generic impossibility for discrete modular LWE/SIS-style noise. In a modular construction, the relevant problem can become:

> find a sufficiently short centered representative in the public affine dual coset.

Unlike the real positive-definite quadratic minimization above, that modular short-vector problem need not be solvable by Gaussian elimination or convex optimization. A surviving route would have to make source witnesses map to short dual representatives while ensuring that obtaining any unauthorized decoding-quality short representative from the **actual structured statement-dependent public matrix** reduces to standard SIS/LWE (or another independently justified PQ assumption).

That reduction is not supplied here. In particular, simply naming the modular short-dual search problem as hard would restate the desired witness-encryption property.

Other unresolved obligations remain:

1. a polynomial-size generic-NP compiler whose source witnesses produce the required short duals and whose false instances hide the final key;
2. a complete-public-output reduction covering arbitrary QPT key recovery, including native decoding algorithms that never output a dual vector;
3. auxiliary-input and malicious-secure erased-setup composition;
4. concrete practical parameters and resource estimates.

The stopping condition is therefore not met.

---

## 6. Executed validation

`public_covariance_dual_run64_check.py` is standard-library only and was executed twice after finalization with byte-identical JSON output.

It checks:

- the exact OR2 minimizer `(1,1/3,1/3,-1/3)` and squared norm `4/3`;
- witness squared norms `2,2,4`;
- the integral non-source dual `(1,-1,1,-1)`;
- the `r`-OR Walsh/signed-dual identities for every `r=2..8`;
- exact iid ternary-noise histogram equality for `r=2` (`3^4=81` vectors) and `r=3` (`3^8=6561` vectors);
- 120 random public-covariance affine-dual instances, with 1,440 independently generated feasible vectors, verifying exactly that the computed public minimizer has no larger quadratic noise cost;
- a 100,000-trial Gaussian OR2 diagnostic. The public minimum-variance decoder succeeded about `0.9997`, the two weight-2 witnesses about `0.9975`, and both the all-ones witness and the signed public dual about `0.978`, matching their exact variances `4/3`, `2`, and `4`.

The Monte Carlo numbers are implementation controls only. The security-relevant claims in this note are the exact algebraic/covariance and distribution identities above.
