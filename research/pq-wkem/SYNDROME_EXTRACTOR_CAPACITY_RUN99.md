# Run 99 — syndrome-extractor equivalence and entropy/capacity barrier for the Hamming release

Starting verified PR head: `0f8c44db5f1d11e1a7fea7fa8b92f42dcfc0e230` on branch `research/pq-wkem-validation-20260918`. The latest verified repository checkpoint is Run 97. Run 98's random-direction release is a local research checkpoint from the immediately preceding run; its GitHub write was explicitly blocked, so this run does not retry or republish that denied payload.

This run does **not** complete the practical generic-NP PQ witness KEM. It identifies the exact information-theoretic object that controls false-statement hiding in the Run-96/98 q-ary-symmetric release: the syndrome of the product noise modulo the mask subspace. It also proves an actual Shannon-entropy rate barrier for statistical hiding, an exact MacWilliams/Renyi-2 barrier for the chi-square certificate, a random-linear extractor benchmark that essentially attains the Renyi-2 threshold, and invariance results ruling out simple padding/isometric-expansion repairs. The arbitrary-QPT true-instance source-extraction problem remains open.

## 1. Setup and notation

Let

\[
C\subseteq \mathbb F_q^m
\]

be the source relation code, with `dim(C)=k`. In Runs 96/98, `C=ker(P)` for a public source matrix `P`. Let

\[
V=C^\perp,
\qquad \dim(V)=r=m-k.
\]

The mask `P^T s` for uniform `s` is uniform over `V` (redundant rows of `P` do not matter because a uniform linear preimage induces the uniform image distribution).

Choose any full-row-rank generator matrix

\[
H\in \mathbb F_q^{k\times m}
\]

for `C`, so

\[
\operatorname{rowspan}(H)=C,
\qquad \ker(H)=V.
\]

Let `E=(E_1,...,E_m)` have independent q-ary symmetric coordinates with bias `beta`:

\[
\Pr[E_i=0]=\frac{1+(q-1)\beta}{q},
\qquad
\Pr[E_i=a]=\frac{1-\beta}{q}\quad(a\ne0).
\]

Write

\[
D=U_V+E
\]

for the base masked/noisy capsule distribution, and define the **noise syndrome**

\[
Z=HE\in\mathbb F_q^k.
\]

The central result is that `Z`, not the ambient capsule, contains exactly all nonuniform information left after the public mask.

## 2. Exact syndrome-lift theorem

For every `x in F_q^m`,

\[
\boxed{
\Pr[D=x]
=
q^{-r}\Pr[Z=Hx].
}
\tag{1}
\]

Proof: `D=x` iff `E=x-v` for the uniformly sampled `v in V`. Equivalently `HE=Hx`. Every syndrome coset contains exactly `q^r` points, and conditioned on a fixed `E`, there is exactly one corresponding `v=x-E` when the syndrome condition holds.

Thus `D` is uniform **inside each coset of `V`**. Its likelihood ratio relative to uniform depends only on the syndrome `Hx`.

Consequently,

\[
\boxed{
\operatorname{TV}(D,U_{q^m})
=
\operatorname{TV}(Z,U_{q^k})
}
\tag{2}
\]

and

\[
\boxed{
\chi^2(D\|U_{q^m})
=
\chi^2(Z\|U_{q^k}).
}
\tag{3}
\]

These are exact finite-distribution identities, not asymptotic bounds and not cryptographic assumptions.

The same uniform-lift argument also preserves any divergence that depends only on the likelihood ratio and is additive over points in a coset; Runs 99's checker explicitly validates (2) and (3), which are the quantities used below.

## 3. Exact random-direction key-leakage equivalence

For one Run-98 bit capsule, after the mask is absorbed into `D`, the two public distributions are

\[
J_0(h,c)=U(h)D(c),
\qquad
J_1(h,c)=U(h)D(c-h),
\]

with public `h <- F_q^m`.

Put `a=Hh`. Because `H` has full row rank, uniform `h` makes `a` uniform in `F_q^k`. By (1), shifting the ambient capsule by `h` is exactly shifting its syndrome by `a`. Therefore

\[
\boxed{
\operatorname{TV}(J_0,J_1)
=
\mathbb E_{a\leftarrow\mathbb F_q^k}
\operatorname{TV}(Z,Z+a).
}
\tag{4}
\]

Let

\[
\delta_{\rm syn}=\operatorname{TV}(Z,U_{q^k}).
\]

Since `U = E_a[Z+a]`, convexity of total variation gives the lower bound, and the triangle inequality plus shift-invariance gives the upper bound:

\[
\boxed{
\delta_{\rm syn}
\le
\operatorname{TV}(J_0,J_1)
\le
2\delta_{\rm syn}.
}
\tag{5}
\]

This is stronger than the previous chi-square sufficient proof. It says that **for the random-direction release itself, false-statement one-capsule hiding is negligible if and only if the q-symmetric noise syndrome is negligible-distance from uniform**, up to a factor of two. For any polynomial number of independent repetitions, negligible syndrome distance is sufficient by the product/union bound, and negligible complete-view distance implies negligible one-capsule distance by marginalization.

So the exact false-mode target is now:

\[
\boxed{
HE_\beta^m\approx_{\rm stat} U_{q^k}.
}
\tag{6}
\]

Minimum distance is only an indirect way of trying to prove (6).

## 4. The Run-96/98 spectral sum is exactly syndrome chi-square

For each additive character indexed by `a in F_q^k`, the corresponding source-code frequency is

\[
y=a^T H\in C.
\]

Every nontrivial q-ary-symmetric coordinate character has expectation `beta`, so

\[
\widehat Z(a)=\beta^{\operatorname{wt}(a^TH)}.
\]

Parseval therefore gives

\[
\boxed{
\chi^2(Z\|U_{q^k})
=
\sum_{0\ne y\in C}\beta^{2\operatorname{wt}(y)}
=:S_C(\beta).
}
\tag{7}
\]

Thus the spectral sum from Runs 96/98 is not merely a convenient upper-bound device. It is the **exact collision/Renyi-2 nonuniformity of the noise syndrome**.

Large `S_C(beta)` alone does not imply large total variation; this is why the next section derives a separate Shannon-entropy barrier for actual TV hiding.

## 5. Exact MacWilliams dual expression and Renyi-2 rate barrier

Put

\[
z=\beta^2,
\qquad
A=1+(q-1)z.
\]

The q-ary MacWilliams identity for the linear code `C` and its dual `V=C^perp` gives

\[
\boxed{
1+S_C(\beta)
=
q^{-r}
\sum_{v\in V}
A^{m-\operatorname{wt}(v)}(1-z)^{\operatorname{wt}(v)}.
}
\tag{8}
\]

All terms are nonnegative for `0<=beta<=1`. Keeping only `v=0` yields

\[
1+S_C(\beta)
\ge
q^{-r}A^m.
\tag{9}
\]

Therefore a **small-chi-square certificate** `S_C(beta)<=eps_chi` requires

\[
\boxed{
\frac{k}{m}
\le
1-\log_q(1+(q-1)\beta^2)
+
\frac{\ln(1+\varepsilon_\chi)}{m\ln q}.
}
\tag{10}
\]

Since

\[
1+(q-1)\beta^2\ge q\beta^2,
\]

we also get the coarser necessary condition

\[
\frac{k}{m}
\le
\frac{2\ln(1/\beta)}{\ln q}
+
\frac{\ln(1+\varepsilon_\chi)}{m\ln q}.
\tag{11}
\]

Writing the worst honest signal as `t=beta^d`,

\[
\boxed{
\frac{k}{m}
\lesssim
\frac{2\ln(1/t)}{d\ln q}
}
\tag{12}
\]

is necessary for the **chi-square proof route** to be strong. This does **not** by itself prove a total-variation impossibility when (12) fails, because chi-square may be large while TV is small.

MacWilliams' original 1963 result is precisely the dual-weight-distribution identity used here; Run 99 applies it only to the q-ary linear relation code and q-symmetric spectral weight.

## 6. Actual total-variation entropy/capacity barrier

The syndrome equivalence (5) permits a stronger barrier that applies to actual key hiding, not only to the chi-square certificate.

Let

\[
\eta=(1-1/q)(1-\beta).
\]

A q-ary symmetric noise coordinate has probability `1-eta` at zero and spreads total mass `eta` uniformly over the `q-1` nonzero symbols. Its Shannon entropy in nats is

\[
\boxed{
H(E_\beta)=h_2(\eta)+\eta\ln(q-1).
}
\tag{13}
\]

Let `n_act` be the number of nonzero columns of `H`. Zero columns do not affect `Z`. Since `Z` is a deterministic linear function of those independent noise coordinates,

\[
H(Z)\le n_{\rm act}H(E_\beta).
\tag{14}
\]

Suppose

\[
\delta_{\rm syn}=\operatorname{TV}(Z,U_{q^k})=\varepsilon.
\]

The sharp Fannes-Audenaert entropy-continuity bound, specialized to a classical distribution on `q^k` points, gives

\[
k\ln q-H(Z)
\le
\varepsilon\ln(q^k-1)+h_2(\varepsilon).
\tag{15}
\]

Combining (14) and (15), any statistically hiding false-instance source must satisfy

\[
\boxed{
k\ln q-n_{\rm act}H(E_\beta)
\le
\varepsilon k\ln q+h_2(\varepsilon).
}
\tag{16}
\]

Equivalently,

\[
\boxed{
\frac{k}{n_{\rm act}}
\le
\frac{H(E_\beta)+h_2(\varepsilon)/n_{\rm act}}
{(1-\varepsilon)\ln q}.
}
\tag{17}
\]

For negligible `epsilon` and polynomial dimensions,

\[
\boxed{
R_{\rm act}:=\frac{k}{n_{\rm act}}
\le
\frac{H(E_\beta)}{\ln q}+o(1).
}
\tag{18}
\]

This is an **actual information-theoretic hiding barrier** because (5) lower-bounds the key-distribution TV by the syndrome TV. It applies against unbounded adversaries and hence arbitrary QPT adversaries.

The active-column formulation is necessary: adding public coordinates on which every relation is zero cannot create entropy in the syndrome and cannot evade (18).

For an honest signal target `t=beta^d`, substitute `beta=t^(1/d)` into (13). If polynomial-time honest decoding requires `t` to be at least inverse-polynomial, then as `d` grows much faster than `ln(lambda)`, `beta` approaches one, the per-active-coordinate noise entropy shrinks, and false instances require correspondingly vanishing active rate. Exact viability depends on the real source dimensions; no claim about Jin's reduction is made without those parameters.

## 7. Random linear maps attain the Renyi-2 threshold in expectation

Run 99 also checks that the Renyi-2 barrier is not merely an artifact of a loose proof. Consider a completely independent uniform random linear map

\[
H\leftarrow\mathbb F_q^{k\times m}.
\]

For iid q-symmetric `E`, let `CP(E)` be the collision probability of the full vector. For independent `E,E'`, a uniform `H` satisfies

\[
\Pr_H[H(E-E')=0]
=
\begin{cases}
1,&E=E',\\
q^{-k},&E\ne E'.
\end{cases}
\]

Therefore

\[
\boxed{
\mathbb E_H\chi^2(HE\|U_{q^k})
=(q^k-1)\,CP(E).
}
\tag{19}
\]

For the product q-symmetric source,

\[
CP(E)
=
\left(\frac{1+(q-1)\beta^2}{q}\right)^m,
\tag{20}
\]

so

\[
\boxed{
\mathbb E_H\chi^2(HE\|U)
=(q^k-1)
\left(\frac{1+(q-1)\beta^2}{q}\right)^m.
}
\tag{21}
\]

Thus below the rate threshold in (10), a random linear syndrome map is a good Renyi-2 extractor on average; Markov gives the corresponding high-probability statement whenever the expectation is negligible.

This is a **benchmark, not a construction for WKEM**. Our `H_x` is statement-derived and its rowspace must contain the witness relation on true statements. Replacing it by an independent random matrix destroys that source semantics.

The target is therefore sharper than “large false minimum distance”:

> Construct a generic-NP statement map whose true instances contain source-extractable low-weight row combinations, while false-instance rowspaces act as extractor-quality linear maps for the q-symmetric product source.

That is a planted-low-weight-relation versus extractor-quality-false-syndrome compiler requirement.

## 8. Simple geometry-preserving randomizations do not help

Several tempting ways to make the false map “look more random” provably leave the relevant distribution unchanged.

### 8.1 Row-basis changes

For `R in GL_k(F_q)`, replacing `H` by `RH` maps `Z` to `RZ`. This is a bijection of syndrome space, so TV, chi-square and entropy distance to uniform are unchanged.

### 8.2 Monomial coordinate transformations

If `M` is a coordinate permutation followed by nonzero coordinate scalings, then iid q-symmetric noise satisfies

\[
ME\overset d=E.
\]

Therefore `HM E` has exactly the same syndrome law as `HE`. These are precisely the elementary Hamming isometries that preserve witness support.

### 8.3 Zero-coordinate padding

Appending columns that are zero in every source relation changes `H` to `[H|0]`. The added noise coordinates disappear from the syndrome, while the mask is uniform on the added coordinates. The syndrome law and hence actual key leakage are exactly unchanged. This is why the entropy barrier uses `n_act`, not raw ambient length.

### 8.4 Coordinate repetition at matched honest signal

Repeat each source coordinate `ell` times in the generator. If each new noise coordinate uses bias `beta_in`, then the sum of the `ell` repeated noises is q-symmetric with bias

\[
beta_{\rm out}=beta_{\rm in}^{\ell}.
\]

The expanded syndrome distribution is therefore **exactly** the original syndrome distribution at `beta_out`. At fixed per-source-coordinate honest signal, repetition does not improve hiding at all.

These invariances rule out padding, basis randomization, Hamming-isometric scrambling, or pure repetition as ways to turn an arbitrary source code into the random-extractor benchmark while keeping the same witness geometry.

## 9. Implication for the Jin/GapMDP route

Current public metadata for Zhengzhong Jin's ePrint 2026/2063 states that the construction uses a Karp-Levin reduction from satisfiability of `polylog(lambda)`-size circuits to GapMDP over a prime field of size `lambda^{omega(1)}`, with approximation factor `omega(log lambda)`, before feeding that source into generic-group extractable witness encryption.

Run 99 does **not** claim the full manuscript's source code satisfies or violates (17), (18), or the random-extractor benchmark. The full current proof was still not retrievable through the available primary-source path in this run. In particular, the exact `m,k,d,D`, active-column count, complete/bounded weight enumerator, and every-low-support ORIGINAL-witness extraction theorem remain unverified.

The new audit question for that source is stronger and more useful than “what is its minimum distance?”:

1. What is the exact dimension/rate of the false relation code after preprocessing?
2. What is the distribution of `H_x E_beta` for the `beta` forced by honest low-weight decoding?
3. Can its false-instance syndrome be shown statistically close to uniform, or at least computationally QPT-pseudorandom under an independently justified assumption?
4. Does every relation in the true-instance low-support range extract the ORIGINAL NP witness?

Worst-case MDP hardness, including randomized-reduction hardness results, does not answer the extractor-quality distribution question. A code may have large minimum distance while its noise syndrome remains far from uniform.

## 10. Quantum-security ledger

**Honest algorithm model.** The Run-96/98 capsule, syndrome evaluation, and witness projection are classical PPT whenever the source dimensions and repetitions are polynomial.

**Adversary model.** Equations (1)–(6), the entropy barrier, and the MacWilliams identities are information-theoretic. When they establish negligible distance, they hold against unbounded distinguishers and therefore arbitrary QPT adversaries, including adversaries with quantum auxiliary information about other independent public data.

**Hardness distribution.** None is invoked for the new false-hiding identities/barriers. The random-linear benchmark is an information-theoretic average over random matrices, not a cryptographic assumption and not a statement that the actual source map is random.

**Reduction model.** No rewinding, extraction, random oracle, QROM programming, or superposition-query simulation is used in Run 99.

**Exact conclusion.** False-statement statistical hiding for the random-direction Hamming release is equivalent, up to factor two per capsule, to q-symmetric **syndrome extraction**. Small chi-square is exactly the code spectral sum. Actual negligible TV imposes the Shannon-capacity condition (16)/(18). Random linear maps attain the Renyi-2 benchmark in expectation, but the statement-derived source map is not shown to do so.

**Still UNPROVED.** Arbitrary-QPT early FINAL-key recovery on true statements -> ORIGINAL source witness or independently justified QPT-hardness break; a concrete generic-NP source compiler satisfying both low-weight source extraction and false-syndrome extraction; the exact Jin source parameters; full auxiliary-input composition; practical final resource estimates; and malicious-secure setup/abort if future layers introduce a setup secret.

## 11. Literature provenance

- F. J. MacWilliams, **A Theorem on the Distribution of Weights in a Systematic Code**, Bell System Technical Journal 42(1), 79–94 (1963), DOI `10.1002/j.1538-7305.1963.tb04003.x`. This is the classical source for the dual weight-enumerator identity used in (8).
- K. M. R. Audenaert, **A sharp continuity estimate for the von Neumann entropy**, Journal of Physics A 40(28), 8127–8136 (2007), DOI `10.1088/1751-8113/40/28/S18`, arXiv `quant-ph/0610146`. Its sharp continuity inequality specializes to the classical entropy bound in (15).
- Zhengzhong Jin, **Witness Encryption for NP from SNARGs and Groups**, ePrint 2026/2063. Only current public metadata/abstract-level claims were available in this run; no full-proof audit is claimed.

## 12. Fresh deterministic validation

`syndrome_extractor_capacity_run99_check.py` is standard-library-only and deterministic. Two finalized executions were byte-identical. It validates:

1. four complete tiny-code enumerations proving the exact uniform-coset lift, TV equality, chi-square equality, random-direction shift identity, and entropy-continuity inequality;
2. the exact identity `S_C(beta)=chi^2(HE||U)` and the MacWilliams dual expression;
3. 16 q-symmetric entropy-formula controls;
4. three exhaustive random-linear extractor benchmarks, checking (19)–(21) by enumerating every tiny matrix;
5. exact monomial-isometry, zero-padding and matched-signal coordinate-repetition invariances;
6. four illustrative rate calculations comparing the actual-TV Shannon ceiling with the stronger small-chi-square/Renyi-2 ceiling.

The representative arithmetic includes:

- `q=3,m=3,k=2,beta=1/2`: syndrome TV `7/36`, random-direction one-bit TV `1/4`, and `S=chi2=13/32`;
- `q=5,m=3,k=2,beta=2/3`: syndrome TV `16/45`, random-direction TV `592/1125`, and `S=832/243`;
- illustrative `q=65537,d=64,t=lambda^-2` at `lambda=2^20`: active-rate Shannon ceiling about `0.4100`, while the small-chi-square ceiling is about `0.07812`;
- illustrative `q=1,000,000,007,d=1024,t=lambda^-2`: active-rate Shannon ceiling about `0.03265`, while the small-chi-square ceiling is about `0.002613`.

These numbers are **not deployment parameters** and do not certify Jin's source. The checker validates finite-field probability/algebra and parameter arithmetic only.

## 13. Next handoff

The strongest next constructive target is no longer another capsule wrapper. It is the source compiler itself:

1. obtain the full exact Jin GapMDP source construction if accessible and compute its `m,k,d,D,n_act` and weight enumerator/syndrome spectrum;
2. test whether its false syndrome `H_x E_beta` is extractor-quality at the `beta` required by honest witness decoding;
3. if not, search for a source-preserving **non-isometric** transformation that improves noise extraction without densifying every true low-weight witness; Run 99 proves that basis changes, monomial scrambling, zero padding and pure repetition cannot do this;
4. keep the Run-97/98 counterfamilies as mandatory tests for any claimed arbitrary-decoder true-instance extractor;
5. independently continue the arbitrary-QPT key-recovery -> ORIGINAL-witness/hardness-break proof, because false statistical hiding alone does not satisfy the WKEM stopping condition.

The stopping condition remains unmet.
