# Run 45 — anisotropic polynomial ideal mask: exact source evaluation, exact complete-view dichotomy, and a linear-degree false family

## Status

Starting verified PR head: `39f3dc3ef68ee586fb91b1ea51dc7e3e8884ed68` (Run 44).

This run does **not** complete the requested generic-NP witness KEM. It makes a substantive anisotropic/non-radial constructive attempt: publish a random bounded-degree element of the polynomial ideal of the source constraints, shifted by the encapsulated field key. Every genuine source witness evaluates the resulting polynomial to the same key. The complete public coefficient vector, however, has an exact all-or-nothing linear-algebra audit: either the bounded-degree source ideal already contains `1`, in which case the two false-instance key distributions are identical, or a publicly computable dual linear functional recovers the key exactly.

The run also gives a self-contained sparse quadratic unsatisfiable family whose exact minimum ideal-refutation degree is `n+1`. Thus the direct monomial-coefficient realization needs a linearly growing degree on this family, and its dense coefficient ambient space is exponential. This is a proof-complexity/resource barrier for this specific release architecture, **not** a generic impossibility theorem for every sparse/circuit representation or computational source-aware gate.

No external literature or web search was used. Production code is unchanged.

---

## 1. Construction: bounded-degree ideal masking

Work over a prime field `F_p`. Let a source statement be represented by public polynomials

\[
g_1(z)=\cdots=g_m(z)=0
\]

in variables `z=(z_1,...,z_N)`. A source witness is any `w` satisfying all equations.

For cutoff `D`, let `P_{<=D}` be the coefficient space of all `N`-variate polynomials of total degree at most `D`, and define the truncated ideal span

\[
V_D = \operatorname{span}_{F_p}\{m(z)g_j(z): m \text{ a monomial},\ \deg(mg_j)\le D\}\subseteq P_{\le D}.
\tag{1}
\]

To encapsulate a field key `K in F_p`, sample `R` uniformly from `V_D` and publish the **complete coefficient vector** of

\[
\boxed{C_K(z)=K+R(z).}
\tag{2}
\]

Decapsulation with source witness `w` outputs

\[
\operatorname{Dec}(C_K,w)=C_K(w).
\tag{3}
\]

### Lemma 1 — exact honest correctness

If `g_j(w)=0` for every `j`, then every generator `m g_j` vanishes at `w`, so every `R in V_D` vanishes there. Therefore

\[
\boxed{C_K(w)=K.}
\tag{4}
\]

This gives the desired "all valid witnesses recover the same key" property for this candidate, with no source witness needed by setup.

---

## 2. Complete-output theorem: exact hiding-or-public-recovery dichotomy

Let `e_1` denote the coefficient vector of the constant polynomial `1`.

### Theorem 2 — exact dichotomy

For the complete coefficient output in (2), exactly one of the following holds.

1. **`1 in V_D`.** Then `V_D + 0 = V_D + e_1`; hence for uniform `R in V_D`, the distributions of `R` and `R+e_1` are identical. More generally, every key shift `K e_1` lies in `V_D`, so all key-conditioned output distributions are identical. False-instance hiding is information-theoretically perfect.

2. **`1 notin V_D`.** Then finite-dimensional linear algebra gives a linear functional

   \[
   L:P_{\le D}\to F_p
   \]

   such that

   \[
   L(V_D)=0,\qquad L(1)=1.
   \tag{5}
   \]

   The functional is publicly computable from the public generators by Gaussian elimination. On the complete capsule,

   \[
   \boxed{L(C_K)=K.}
   \tag{6}
   \]

   Thus a classical polynomial-time public algorithm recovers the encapsulated key exactly; there is no source witness to extract on a false statement.

**Proof.** Case 1 is equality of affine cosets of the public subspace. In Case 2, extend a basis of `V_D` by `1` and choose the dual coordinate functional that is zero on the basis of `V_D` and one on `1`. Equation (6) follows from linearity. `□`

### Consequence

For this release architecture, false-instance security is not based on LWE, SIS, or another computational assumption. It is exactly the bounded-degree algebraic statement

\[
\boxed{1\in V_D.}
\tag{7}
\]

That is a bounded-degree Nullstellensatz/ideal-refutation condition. If it fails, the complete public output itself contains an exact public key extractor.

This is stronger than observing that an intended witness decoder fails: the attack acts on the complete published coefficient vector.

---

## 3. A sparse quadratic false family with exact minimum degree `n+1`

For every `n>=1`, use variables

\[
x_0,x_1,...,x_n,y_1,...,y_n
\]

and public constraints

\[
g_0=x_0,
\tag{8}
\]

\[
g_i=x_i-y_i x_{i-1}\qquad (1\le i\le n),
\tag{9}
\]

\[
g_{n+1}=x_n-1.
\tag{10}
\]

All internal constraints have degree `2`, the two endpoints degree `1`, and the description is `O(n)`.

The system is unsatisfiable over every field: `x_0=0`, and the recurrence forces `x_1=...=x_n=0`, contradicting `x_n=1`.

### Theorem 3 — exact degree lower bound

For the truncated ideal span of (8)-(10),

\[
\boxed{1\notin V_D\quad\text{for every }D\le n,}
\tag{11}
\]

while

\[
\boxed{1\in V_{n+1}.}
\tag{12}
\]

Therefore the exact minimum refutation degree is `n+1`.

### Proof of the lower bound

Define a ring homomorphism into Laurent polynomials in the `y_i`:

\[
\psi(y_i)=y_i,
\tag{13}
\]

\[
\psi(x_i)=\prod_{k=i+1}^{n} y_k^{-1}.
\tag{14}
\]

For every recurrence constraint,

\[
\psi(x_i-y_i x_{i-1})=0,
\tag{15}
\]

and

\[
\psi(x_n-1)=1-1=0.
\tag{16}
\]

The start constraint maps to

\[
\psi(g_0)=\prod_{k=1}^{n}y_k^{-1}.
\tag{17}
\]

Let `CT` denote Laurent constant-term extraction and define

\[
L=\operatorname{CT}\circ\psi.
\tag{18}
\]

Then `L(1)=1`. All monomial multiples of (9) and (10) map identically to zero. Consider a monomial multiple `m g_0` with

\[
\deg(mg_0)\le D\le n.
\]

Then `deg(m)<=n-1`. To cancel all `n` negative exponents in (17), `psi(m)` would need at least one positive `y_k` contribution for every `k=1,...,n`, hence at least `n` positive `y` factors in total. A source monomial of total degree at most `n-1` cannot supply them; occurrences of any `x_i` only add further nonpositive Laurent exponents. Therefore

\[
L(mg_0)=0.
\tag{19}
\]

So `L` annihilates all of `V_D` while `L(1)=1`; hence `1 notin V_D`. `□`

### Matching degree-`n+1` certificate

The recurrence telescopes:

\[
\begin{aligned}
x_n={}&g_n+y_n g_{n-1}+y_ny_{n-1}g_{n-2}+\cdots\\
&+(y_n\cdots y_2)g_1+(y_n\cdots y_1)g_0.
\end{aligned}
\tag{20}
\]

Subtracting `g_{n+1}=x_n-1` gives

\[
\boxed{
1=g_n+y_n g_{n-1}+\cdots+(y_n\cdots y_1)g_0-g_{n+1}.
}
\tag{21}
\]

Every term has total degree at most `n+1`, and the final `g_0` term has degree exactly `n+1`. Thus `1 in V_{n+1}`. `□`

---

## 4. Exact complete-output attack on the false chain below the threshold

For every `D<=n`, the same public functional (18) is the separator from Theorem 2. If setup publishes

\[
C_K=K+R,\qquad R\in V_D,
\]

then

\[
\boxed{L(C_K)=K}
\tag{22}
\]

for **every** setup randomness.

This false statement has no source witness. Hence the candidate directly violates the required false-statement hiding and arbitrary early-recovery condition at every subcritical cutoff.

At `D=n+1`, equation (21) places `1` in the masking subspace, and the uniformly sampled full-subspace version has identical key-conditioned distributions. The issue is therefore no longer correctness or algebraic soundness; it is representation cost.

---

## 5. Resource consequence for the explicit monomial coefficient realization

The chain has

\[
N=2n+1
\]

variables. The explicit ambient coefficient vector for total degree `D=n+1` contains

\[
\boxed{
M(n)=\binom{N+D}{D}=\binom{3n+2}{n+1}
}
\tag{23}
\]

field coefficients.

Executed exact counts:

| `n` | variables `N` | minimum `D` | ambient monomials | `log2` ambient |
|---:|---:|---:|---:|---:|
| 8 | 17 | 9 | 3,124,550 | 21.5752 |
| 16 | 33 | 17 | 9,847,379,391,150 | 43.1629 |
| 32 | 65 | 33 | 131,629,284,070,068,266,150,382,462 | 86.7666 |
| 64 | 129 | 65 | 32,396,896,691,800,088,197,207,600,427,764,643,934,651,706,893,686,046 | 174.4361 |
| 128 | 257 | 129 | 2.7379717718646957e105 (exact integer in validation JSON) | 350.2556 |

Thus the direct **dense monomial coefficient** version is exponentially large on this sparse quadratic false family once `D` is raised enough to obtain exact false hiding.

### Scope

This does **not** prove that every possible representation of an ideal element needs this many bits. In particular it does not rule out:

- sparse or arithmetic-circuit encodings of high-degree ideal elements;
- computationally hidden encodings whose complete-view security reduces to an independent PQ assumption;
- changing the source compiler so that false instances have a different algebraic geometry;
- a source-aware nonlinear primitive outside this explicit coefficient-space model.

However, a sparse/circuit output cannot inherit Theorem 2's perfect-hiding conclusion merely by citing `1 in V_D`: the equality-of-cosets proof is about the full uniform subspace distribution. A compressed computational version needs a new complete-output reduction rather than treating compression as free.

---

## 6. Relation to Runs 42–44

Run 42/43 gave a useful standard-assumption **binding** interface: a supplied sufficiently short native preimage yields a source witness or an SIS solution. Run 44 showed that radial norm gates do not restrict the entire false affine preimage fiber.

Run 45 attacks a different direction: use the source equations themselves, anisotropically, so every genuine source point annihilates the mask. That succeeds perfectly for correctness. It also shows exactly what complete-output false hiding would require in this linear coefficient-space realization: a low-degree algebraic refutation of every false statement.

So this run does not re-use the radial attack. It identifies a different boundary:

- **source evaluation:** exact and efficient at a supplied witness if the capsule is represented;
- **false hiding:** exact iff the constant polynomial lies in the public truncated ideal span;
- **generic efficiency:** fails for the explicit monomial realization on the chain family because the minimum refutation degree is linear and the ambient coefficient space is exponential.

---

## 7. Implemented validation

`ideal_mask_run45_check.py` is standard-library-only and independently implements:

1. sparse multivariate polynomials over `F_101`;
2. truncated ideal generators;
3. sparse Gaussian-elimination membership tests;
4. the Laurent substitution and constant-term dual functional;
5. the telescoping certificate;
6. complete coefficient-output key extraction;
7. direct honest source evaluation;
8. exact resource counts.

Fresh executed checks:

- exact `1 in V_D` threshold by independent finite-field span computation for `n=1,2,3,4`; in every case the first accepting degree is exactly `n+1`;
- **1,753,578** allowed monomial-generator products checked against the Laurent dual for all `n<=8`, zero failures;
- telescoping certificate identity checked for every `n=1..64`, zero failures;
- **500/500** complete-view false-key extractions at `D=n` for `n=2..6`;
- **500/500** honest decapsulations on an independent true quadratic fixture;
- full-subspace shift-invariance membership controls at `D=n+1` for `n=1..4`;
- exact combinatorial resource counts through `n=128`.

The checker was executed twice and produced byte-identical captured JSON.

These tests validate the stated algebra and implementation. They are not used as evidence for cryptographic security.

---

## 8. What is proved and what remains open

### Proved in this run

1. Exact honest correctness of bounded-degree ideal masking.
2. Exact complete-output hiding/public-recovery dichotomy for the full coefficient-space distribution.
3. A public key extractor whenever `1 notin V_D`.
4. A sparse quadratic unsatisfiable family with exact minimum ideal-refutation degree `n+1`.
5. Exponential ambient monomial growth for the direct coefficient realization at that minimum degree.

### Not proved

- No impossibility theorem for sparse/circuit encodings of ideal masks.
- No computational hiding reduction for a compressed ideal encoding.
- No reduction from arbitrary QPT key recovery in a surviving efficient construction to a source witness or independent PQ break.
- No claim that the Run-45 chain is hard to *decide*; it is intentionally easy and is used only to prove the degree/resource property of this release architecture.
- No malicious-secure setup ceremony composition or final concrete parameters.
- No complete efficient generic-NP WKEM.

The stopping condition is therefore not met.

---

## 9. Next handoff

The next constructive target should preserve Run 45's good feature—an anisotropic source equation mask that every genuine witness annihilates—without publishing the full ideal coefficient vector.

A credible next step has to answer **both** questions, not only one:

1. Can a high-degree ideal element be represented/evaluated from a source witness in polynomial size without exposing a public separator analogous to `L`?
2. Can the complete compressed output be reduced to an independently justified PQ assumption rather than assuming that "compressed ideal membership" itself is hard?

If the compression is just a public linear sketch, the same dual-space audit should be applied first. If it is computational/nonlinear, the reduction must include all auxiliary statement-dependent outputs and cannot assume a WE-equivalent evaluator.
