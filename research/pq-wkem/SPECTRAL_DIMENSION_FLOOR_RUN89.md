# Run 89 — source-dimension / common-support floor kills the Run-88 additive-share spectral contraction on an actual Hair–Sahai false family

**Status:** new exact algebraic barrier for the Run-88 additive-share spectral amplifier.  On the explicit Hair–Sahai false family `sum_i b_i-(N+1)=0`, with the paper's standard `R=floor(log_2 N)`, the fixed-key-frequency squared Fourier bucket used by Run 88 is **strictly larger than one for every correctness-compatible `2r<t` parameter choice once `N>=5`**.  Thus the sufficient contraction condition `rho_x<1` from Run 88 cannot hold on this family.  This does **not** prove that the underlying capsule is statistically insecure, and it does not provide QPT source extraction.  The complete practical generic-NP PQ WKEM remains open.

**Starting verified PR head:** `52b5cc0d3650ed6c29dbf2225ecbfc9c08208503` on `research/pq-wkem-validation-20260918`.

Production code is unchanged.  This note uses the published Run-82 finite-difference source family, the published Hair–Sahai source compiler, and the local Run-88 spectral formula as the immediate handoff.  It does not retry or republish earlier denied Runs 86--88.

## 1. Run-88 target

For a prime field `F_q`, let `B_1,...,B_k` be a public basis of the statement-derived source space and let `ell_i=ell(B_i)` be the public anchor coordinates.  Run 88 uses, for one additive key share, the capsule

```
C_i = <R, J_t tensor B_i>_t + K_h ell_i I_t,
```

where `R` is a sum of `r` independent uniform rank-one matrices and correctness uses

```
2r < t.
```

For a complete-output additive character `Lambda=(Lambda_1,...,Lambda_k)`, `Lambda_i in F_q^(t x t)`, define the `t x t` block matrix `N_Lambda` by

```
(N_Lambda)_[p,q] = B(a^{pq}),
(a^{pq})_i = (Lambda_i)_[p,q],
```

and key frequency

```
sigma(Lambda) = sum_i ell_i tr(Lambda_i).
```

Run 88's exact one-share coefficient magnitude is

```
|hat P(Lambda)| = q^(-r rank(N_Lambda)).
```

Its fixed-frequency squared Fourier bucket is therefore

```
A_sigma = sum_{Lambda: sigma(Lambda)=sigma}
          q^(-2r rank(N_Lambda)).                       (1)
```

The proposed additive sharing proof needs

```
rho_x = max_{sigma != 0} A_sigma < 1.                   (2)
```

If (2) held with a quantitative gap, the same nonzero frequency being forced through every share would make the Run-88 Parseval upper bound contract exponentially in the number of shares.

This run proves that (2) is impossible for an explicit actual Hair--Sahai false family in the standard logarithmic-gap regime.

## 2. Primary-source structural fact: every Hair–Sahai source matrix has only `N+1` active columns

Hair and Sahai's Section 4.3 stacks weighted Boolean tables

```
A(b) = ( h_1(b) v(b)v(b)^T ; h_2(b) v(b)v(b)^T ; ... ),
```

where the weight list contains the constant polynomial `1` and

```
v(b)=(1,b_1,...,b_N)^T.
```

Section 4.4 then states that the resulting matrices have `m` rows and exactly `N+1` columns before zero padding, and appends `m-(N+1)` zero columns to make them square.  Thus every matrix in the final source space has the same public right-coordinate support of dimension

```
c = N+1.                                                (3)
```

This is not a rank lower bound or a statistical statement.  It is a literal support identity inherited by every linear combination in the source space.

Primary source: Hair–Sahai, *Witness Encryption via Prime-Order Generic Groups*, arXiv:2609.18275v1, Sections 4.3--4.4, especially equations (5)--(7) and Proposition 4.3.  The paper's WE theorem is in the **classical generic-group model**; that security theorem is not used here.

## 3. Theorem 1 — every Run-88 blow-up has rank at most `t(N+1)`

Let `c=N+1`.  Each source block

```
B(a^{pq}) = sum_i (Lambda_i)_[p,q] B_i
```

has zero columns outside the same `c` source coordinates.  Therefore the full `tm x tm` block matrix `N_Lambda` has nonzero columns only in `c` coordinates inside each of its `t` block columns.  At most `tc` columns can be nonzero.

Hence, for **every** complete-output character,

```
boxed{ rank(N_Lambda) <= t c = t(N+1). }                (4)
```

The same conclusion survives any common invertible right-coordinate change: what matters is the dimension `c` of the common right support, not the literal location of the zero columns.

This ceiling is independent of the false-instance MinRank distance and independent of the detailed rank enumerator.

## 4. Theorem 2 — exact fixed-frequency bucket floor from source dimension

Assume the anchor functional is nonzero on the false source space.  The explicit Run-82 family supplies such a nonzero-anchor source matrix, so this condition holds for the false family studied below.

The character space has dimension

```
k t^2
```

over `F_q`.  Because `sigma(Lambda)` is then a nonzero linear functional, each fixed frequency fiber contains exactly

```
q^(k t^2 - 1)                                          (5)
```

characters.

By (4), every term in (1) is at least

```
q^(-2 r t c).
```

Therefore, for **every** `sigma in F_q`,

```
boxed{
A_sigma >= q^(k t^2 - 1 - 2 r t c).
}                                                        (6)
```

Under Run 88 correctness, `2r<t`; since the parameters are integers,

```
2r <= t-1.
```

Substituting into (6),

```
A_sigma
 >= q^(k t^2 - 1 - (t-1)t c)
 =  q^((k-c)t^2 + c t - 1).                             (7)
```

Consequently,

```
boxed{
k >= c  ==>  A_sigma > 1 for every sigma.
}                                                        (8)
```

In particular, if an actual false source has basis dimension at least its common right-support dimension, Run 88's required `rho_x<1` is impossible for **every** correctness-compatible `2r<t` choice of `q,t,r`.

### Scope of (8)

`A_sigma>1` is a statement about the squared Fourier mass used in the Run-88 Parseval/Cauchy upper bound.  It means that this proposed additive-sharing **contraction proof cannot work**.  It is **not** by itself a lower bound on total variation and does not prove that some different analysis, different release layer, or computational assumption cannot hide the key.

That distinction is important: many individually tiny Fourier coefficients can have squared mass above one while a single efficiently exploitable statistic is still unclear.

## 5. Theorem 3 — the actual Hair–Sahai false source has `k >= binom(N-R+1,2)`

We now prove the source-dimension condition needed by (8) for the actual false family used in Run 82, without assuming that the Hair–Sahai weight list spans every low-degree polynomial.

Consider the false Boolean equation

```
f_N(b)=sum_{i=1}^N b_i-(N+1)=0.                        (9)
```

Let

```
s=R+1.
```

Run 82 proved that for any `s`-element free-coordinate set `T`, with all outside bits fixed to zero, the coefficients

```
lambda_x = (-1)^|x| / (|x|-(N+1)),  x in {0,1}^s,     (10)
```

produce a genuine matrix `A_T` in the **actual** Hair–Sahai false source space.  The proof uses only the actual fact that every listed weight has Boolean degree at most `R`; multiplying by the violated relation cancels the denominator and leaves an `(R+1)`-fold alternating finite difference.

Project `A_T` to the constant-weight block.  The primary source explicitly includes the constant weight `1`.  This block is

```
C_T = sum_x lambda_x v(b(x))v(b(x))^T.                 (11)
```

Fix a core set `C` of size

```
s-2 = R-1,
```

and let

```
U = [N] \ C,
|U| = N-R+1.                                            (12)
```

For every unordered pair `{i,j} subset U`, let

```
T_{ij}=C union {i,j}.
```

### Unique pair coordinate

The `(i,j)` Boolean-coordinate entry of `C_{T_{ij}}` equals

```
S_2 = sum_x lambda_x x_i x_j.                           (13)
```

For any different pair `{k,l}`, at least one of `i,j` is outside `T_{kl}` and is fixed to zero, so the same `(i,j)` entry of `C_{T_{kl}}` is zero.

It remains only to show `S_2 != 0`.

Define, for `0<=j<=s`,

```
S_j = sum_x lambda_x product_{h=1}^j x_h.               (14)
```

Let `a=N+1`.  Since

```
lambda_x (|x|-a)=(-1)^|x|,
```

the full alternating sum of every monomial of degree `j<s` gives

```
0 = (j-a) S_j + (s-j) S_{j+1},
```

or

```
S_{j+1} = (a-j)/(s-j) S_j.                              (15)
```

The standard partial-fraction identity gives

```
S_0 = - s!/[a(a-1)...(a-s)] != 0                       (16)
```

(up to the equivalent sign convention used in Run 82).  Hair–Sahai's supplied prime satisfies `p>2^N`, so all displayed factors are nonzero.  Applying (15) twice,

```
S_2 = a(a-1)/(s(s-1)) S_0 != 0.                        (17)
```

Thus each projected matrix `C_{T_{ij}}` has a coordinate at `(i,j)` that is nonzero and is zero in every other member of this pair-indexed family.  The projected matrices are linearly independent, hence so are the full source matrices `A_{T_{ij}}`.

Therefore the actual false source-space dimension satisfies

```
boxed{
k >= binom(N-R+1,2).
}                                                        (18)
```

This is a dimension theorem about the genuine statement-derived Hair–Sahai source space, not a count of merely distinct codewords.

## 6. Corollary — Run-88 contraction is impossible for the standard Hair–Sahai logarithmic-gap choice

Hair–Sahai choose

```
R=floor(log_2 N).
```

For every `N>=5`, the elementary inequality

```
floor(log_2 N) <= (N-1)/2
```

gives

```
N-R+1 >= (N+3)/2.
```

Hence

```
binom(N-R+1,2)
 >= (N+3)(N+1)/8
 >= N+1 = c.                                            (19)
```

Combining (18), (19), and (8):

```
boxed{
For the false family (9), N>=5, R=floor(log_2 N),
and every q,t,r with 2r<t,

    A_sigma > 1 for every sigma in F_q.
}
                                                               (20)
```

So the central Run-88 handoff question has a negative answer for this actual family:

```
max_{sigma != 0} A_sigma < 1
```

cannot hold, regardless of the detailed low-rank spectrum.

### Stronger `r<t` dimension warning

If a related one-capsule field construction uses only `r<t`, then `r<=t-1` gives the weaker universal floor

```
A_sigma >= q^((k-2c)t^2 + 2ct - 1).                    (21)
```

Thus `k>=2c` also rules out the same bucket-contraction strategy even at maximal `r=t-1`.  For `R=floor(log_2 N)`, (18) gives `k>=2c` for every `N>=9` (using `floor(log_2 N)<=(N-3)/2`).

This is a warning about the Fourier-bucket proof strategy, **not** a new break of Run 81's common-eigenvalue decoder.

## 7. Why this is stronger than the Run-82 low-rank-tail bound

Run 82 already gave exponentially many efficiently constructible nonzero-anchor matrices of rank at most `R+2`, yielding

```
A_1 >= t 2^(N-R-1) q^(-2r(R+2)).                       (22)
```

That lower bound can fall below one at sufficiently large `r` and `q`; this is why Run 88 still had an apparent parameter window.

Run 89 does not count only the low-rank tail.  It combines:

1. the **full character-fiber cardinality** `q^(k t^2-1)`, and
2. the **global common-support rank ceiling** `rank(N_Lambda)<=tc`.

Once `k>=c`, every character in the fixed-frequency fiber is too rank-limited, in aggregate, for the Run-88 squared-mass bucket to contract.  No detailed rank enumerator can repair that specific proof.

## 8. QPT/security classification

### Honest algorithm model

The underlying candidate setup/encapsulation and witness decapsulation remain classical probabilistic polynomial time where previously specified.  This run changes no honest algorithm.

### Adversary model

The new result is unconditional finite-field linear algebra.  No adversary, oracle, or hardness assumption is needed to prove the obstruction.  All explicit finite-difference source matrices used in the dimension proof are classically constructible in polynomial time for `R=O(log N)`.

### Exact hardness distribution / QPT assumption

None.  This run does **not** assume LWE, SIS, MinRank hardness, a generic group, or a random oracle.

### Reduction model

Direct algebra/counting only.  There is no rewinding, extraction, quantum auxiliary information, superposition-query access, random oracle, or QROM step.

### Conclusion

* Run-88's proposed sufficient **statistical/QPT hiding proof** is falsified on an actual false Hair–Sahai family because its required spectral contraction cannot occur.
* This does **not** prove the capsule distribution is distinguishable with nonnegligible advantage by an efficient classical or QPT adversary.
* Arbitrary-QPT final-key recovery `=>` ORIGINAL source witness or an independently justified PQ-hardness break remains **UNPROVED**.

Hair–Sahai's own WE theorem remains explicitly a **classical prime-order generic-group** theorem.  Its source-space algebra and exact matrix support are reusable here; its security theorem is not a concrete PQ reduction.

## 9. Literature consequence and constructive handoff

The dimension obstruction identifies a more precise design constraint than “increase the MinRank gap”:

> a spectral release of this block-randomizer type needs the effective number of key-sensitive source degrees of freedom to stay below the effective rank-support capacity of the public encoding.

The literal Hair–Sahai source violates that condition badly: already the explicit pair family gives quadratic source dimension while every matrix has only `N+1` active right coordinates.

This makes **compression of the statement-derived source degrees of freedom** more important than adding more scalar checks or increasing the feature degree.  Jin's ePrint 2026/2063 abstract is therefore relevant because it advertises a Karp–Levin reduction from polylogarithmic circuit SAT to GapMDP and extractable WE for those circuits in the generic-group model.  However, only the primary/archival abstract was accessible in this pass; the full proof chain `key recovery -> small-circuit witness -> accepting SNARG proof -> ORIGINAL NP witness` was not independently audited.  It remains a generic-group result, not a concrete QPT release layer.

A useful next test is therefore:

1. isolate whether Jin's code-space reduction has an effective **rate/dimension-versus-support** profile that avoids (6)--(8);
2. preserve source-witness extraction through the SNARG/Karp–Levin chain;
3. then seek a complete-public-output release under an independently justified **QPT-hard** assumption rather than importing the generic-group encryption layer.

Run 72 remains only standard-LWE local directional transport after a parent capability exists.  Run 76 remains only ideal-oracle arbitrary-QPT extraction.  Neither closes this source-release gap.

## 10. Validation actually executed

`run89_spectral_dimension_floor_check.py` is deterministic and standard-library-only apart from importing the already-published `research/pq-wkem/literature-20260924/rank_field_extensions.py` for tiny exact source-space controls.

The finalized checker was executed twice from a repository-shaped directory and produced byte-identical JSON.  It validates:

* exact pair-indexed finite-difference independence controls for `N=3,4,5,6,8,10`;
* the nonzero `S_0` / `S_2` identity (17);
* finite all-`N` checks through `N=128` that the Hair–Sahai choice satisfies `k_lower>=c` from `N=5` and `k_lower>=2c` from `N=9`;
* representative bucket-floor exponents for `N=5,8,16,32` and correctness-compatible `(t,r)=(3,1),(5,2),(9,4)`;
* tiny exact actual false-source dimensions from the published compiler dependency:
  * `N=2,R=1,p=7`: `k=1`, `c=3`;
  * `N=3,R=1,p=7`: `k=4`, `c=4`;
  * `N=4,R=2,p=19`: `k=5`, `c=5`;
  * `N=5,R=2,p=23`: `k=15`, `c=6`;
* 120 random common-right-support block blow-ups, all satisfying `rank<=tc`.

Representative `log_q` bucket floors using only the proved dimension lower bound include:

* `N=5,R=2,k_lower=6,c=6`: `17,29,53` for the three `(t,r)` pairs above;
* `N=8,R=3,k_lower=15,c=9`: `80,194,566`;
* `N=16,R=4,k_lower=78,c=17`: `599,1609,5093`;
* `N=32,R=5,k_lower=378,c=33`: `3203,8789,28241`.

These executions validate finite algebra and the implementation only.  They are not cryptographic security evidence.

Checker SHA-256 and captured-validation SHA-256 are recorded in the accompanying provenance file.

## 11. Result / precise next handoff

**New proved result:** the Run-88 additive-share spectral amplifier's required fixed-frequency contraction is impossible on an explicit actual Hair–Sahai false family in the standard `R=floor(log_2 N)` regime for every `N>=5` and every correctness-compatible `2r<t` choice.

**What genuinely helped from the literature:** Hair–Sahai's exact common `N+1`-column support and public polynomial-time source basis make the dimension/rank-ceiling argument possible.  This is reusable algebra, not their classical generic-group security theorem.

**Exact quantum-security status:** no new QPT hiding or QPT source-extraction theorem is obtained.  Instead, one candidate route to statistical/QPT hiding is ruled out.  The target remains a classical public/offline implementation secure against arbitrary QPT adversaries under independently justified assumptions.

**Next handoff:** stop trying to rescue this particular block-randomizer by more additive shares.  Audit a source compressor/code reduction whose effective public source dimension is below its effective rank-support capacity and whose extraction chain reaches the ORIGINAL NP witness; then require a separate concrete QPT-valid release reduction.  Jin's GapMDP route is the highest-priority literature lead, but its full theorem chain still needs primary-source verification.

The full stopping condition is **not met**.
