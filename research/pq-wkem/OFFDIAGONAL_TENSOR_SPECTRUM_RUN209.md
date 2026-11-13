# Run 209 — exact off-diagonal tensor rank spectrum for the characteristic-two cube code

**Status:** bounded algebraic/statistical checkpoint. This is not a completed PQ witness-KEM and not a claim about the fixed Syscoin bridge relation. The result is for the legitimate generic-NP constant-contradiction false source used by Run 198. It characterizes the *entire* off-diagonal `t x t` character array for that source code and shows that the global chi-square route from Run 152 can be dramatically looser than conditional-image total-variation mixing.

## 1. Verified live starting point

Connected GitHub reads at the start of this run verified `syscoin/PVUGC#1`:

- branch `research/pq-wkem-validation-20260918`;
- exact head `10ef85d5e34186b5c7bb8bf144804925604021ea`;
- open, draft, unmerged;
- latest substantive ordinary PR comment remains `5913974235` (Run 196).

Exact current-head inputs read before the derivation:

- `CMV_MINRANK_LACONIC_QPT_SOURCE_BRIDGE_RUN152.md`, blob `398b93af491d0b11cc486e86c89295a05b714804`;
- `CONDITIONAL_IMAGE_MIXING_RUN196.md`, blob `99a0538f9823bfd562b34570d7aa68dd079fa446`;
- `JOINT_LOWRANK_PROJECTION_RUN197.md` (current-head exact file; its one-direction `AB^T` theorem is used only as a consistency check);
- `CHAR2_FINITE_DIFFERENCE_REPAIR_RUN198.md`, blob `958854318ddc22c78f1910d4f63a0db65e44c0e9`;
- `char2_finite_difference_run198_check.py`, blob `b62467189f9a23c2d673c87614bd9bcf8c6dbc6e`.

The immediately preceding Run-208 checkpoint was local-only after a safety-blocked publication attempt. This run does not retry any denied Run-208 payload. The new checker independently rebuilds the Run-198 characteristic-two compiler fixtures from the current-head source.

## 2. Source code and notation

Use Run 198's characteristic-two false source over `GF(2^h)` and vertical binary scalar descent. Put

` s = R+1 `

and fix the `s` free cube coordinates `T`. Let the remaining `m=N-s` outside coordinates vary. The affine cube family is

` A_z = A_0 + sum_(j=1)^m z_j Delta_j `.

After binary descent define

` B_0 = D(A_0),  B_j = D(Delta_j) `

and

` W_T = { M(c)=sum_(a=0)^m c_a B_a : c in F_2^d }, `

where

` d=m+1=N-R. `

The result below is stated in the regime `d>=3`, which covers the growing-codimension family of interest and matches the private-row proof used here.

Partition source columns into:

- the `s` free-coordinate columns;
- `d` tag columns: column zero plus the `m` outside-coordinate columns.

## 3. New Lemma 1 — simultaneous canonical form

There are **fixed**, coefficient-independent invertible binary row/column operations which transform every `M(c)` to the same zero-padded canonical form

```
Phi(c) =
 [ c_0 I_s ]
 [ c_1 I_s ]
 [    ...  ]    | 0
 [ c_(d-1) I_s]
 ---------------------
 [      0       ]    | c^T
```

Equivalently, ignoring all-zero rows after the common transformation, the free-column part is `c tensor I_s` and the tag-column part is one row `c^T`.

### Proof

Run 198's cube construction gives the required identities directly.

1. **Tag columns.** The cube-summed column zero is a fixed nonzero vector `w`, independent of the outside assignment. An outside column `j` equals `z_j w`. Therefore, in the affine basis `(B_0,B_1,...,B_m)`, the tag-column block of `M(c)` is exactly

   ` w c^T. `

2. **Private free-column row groups.** Let `Q` be the free-column matrix in assignment-row group `i=0`. The cube sum extracts the degree-`s` coefficient of `h(b)b_k`; since `deg(h)<=R=s-1`, this is independent of the outside assignment. For outside assignment-row group `j`, the same entries equal `z_j Q`. Thus `B_0` contains `Q` in the `i=0` private row group, `B_j` contains `Q` in outside private row group `j`, and every other affine basis matrix is zero in that private group.

3. **`Q` has binary rank `s`.** Choose the listed degree-`R` weight used in Run 198 and `s` distinct nonzero compiler sample values. The extracted free-column minor is, up to nonzero row/column factors, a Vandermonde matrix on the distinct `gamma^i`. It has field rank `s`. Vertical scalar descent cannot reduce that rank and there are only `s` free columns, hence its binary rank is exactly `s`.

4. **Eliminate the remaining free-column rows.** Every other free-column row depends linearly on `c`. Since `Q` has full column rank `s`, its row span is all of `F_2^s`. Fixed row combinations of the private `Q` groups therefore remove those rows simultaneously for every `c`, without changing the tag columns because the private groups are tag-zero.

5. Reduce each private `Q` group to `I_s` and reduce the nonzero tag vector `w` to one pivot row. These are fixed transformations, independent of `c`.

This proves the simultaneous form. In particular every nonzero `M(c)` has exact rank `s+1`, recovering the one-word rank statement as a corollary rather than an assumption.

## 4. New Theorem 2 — exact arbitrary off-diagonal array rank

Let `c_(p,q) in F_2^d` be an arbitrary `u x v` array of public coefficient vectors, and assemble the source block matrix

` N(C) = [ M(c_(p,q)) ]_(p=1..u,q=1..v). `

Define the two ordinary binary unfoldings of the coefficient tensor:

` H(C) in F_2^(u x vd), `

whose row `p` is the concatenation of `c_(p,1),...,c_(p,v)`, and

` G(C) in F_2^(ud x v), `

whose column `q` is the vertical concatenation of `c_(1,q),...,c_(u,q)`.

Write

` alpha = rank H(C),   beta = rank G(C). `

Then

` boxed( rank N(C) = alpha + s beta ). `

### Proof

Apply the simultaneous canonical transformations blockwise. The transformed assembled matrix splits into two disjoint row/column parts.

- On the free columns, rows are indexed by `(p,a,k)` and columns by `(q,k')`; the entry is

  ` c_(p,q,a) delta_(k,k'). `

  After a fixed permutation this is `I_s tensor G(C)`, hence has rank `s beta`.

- On the tag columns, rows are indexed by `p` and columns by `(q,a)`; the entry is exactly `c_(p,q,a)`, i.e. `H(C)`, with rank `alpha`.

There are no cross terms in the canonical form, so the ranks add.

### Two required consistency checks

1. **Run-197 one-direction slice.** If `c_(p,q)=lambda_(p,q)c` for one fixed nonzero source direction `c`, then

   `alpha=beta=rank(lambda)`

   and therefore

   `rank N = (s+1) rank(lambda).`

   This is exactly the character-rank law behind the `AB^T` channel with inner width `r(s+1)`.

2. **Independent rectangular directions.** If all `uv` coefficient vectors are linearly independent, then `alpha=u`, `beta=v`, giving

   `rank N = u+s v`,

   which recovers the earlier independent-array blow-up formula.

The theorem therefore interpolates between the two previously separate cases and covers **every dependent or off-diagonal coefficient array**.

## 5. New Theorem 3 — exact joint rank enumerator

Now take the full square Run-152 character array: `u=v=t`. A character is a tensor

` C in F_2^(t x t x d). `

The exact Fourier coefficient of the structured branch is

` P_hat(C)=2^(-r(alpha+s beta)), `

where `(alpha,beta)` are the two unfolding ranks above.

The number of tensors having exactly those ranks has a closed form.

Let `[n choose k]_2` be the Gaussian binomial coefficient and

` mu_k = (-1)^k 2^(k(k-1)/2). `

Define the number of tensors in `F_2^(alpha x beta x d)` which are concise in their first two modes by

` K_(alpha,beta,d)
   = sum_(i=0)^alpha sum_(j=0)^beta
       [alpha choose i]_2 [beta choose j]_2
       mu_(alpha-i) mu_(beta-j) 2^(i j d). `

Then the number of ambient `t x t x d` tensors with mode ranks exactly `(alpha,beta)` is

` boxed(
  N_(alpha,beta)
  = [t choose alpha]_2 [t choose beta]_2 K_(alpha,beta,d).
 ) `

### Proof

Choose the minimal mode-1 support `U <= F_2^t` of dimension `alpha` and mode-2 support `V <= F_2^t` of dimension `beta`. After choosing `U,V`, the tensor lies in `U tensor V tensor F_2^d` and must be concise in the first two modes. The displayed `K` is exactly two-dimensional Möbius inversion on the two subspace lattices, since

` 2^(alpha beta d)
  = sum_(i<=alpha,j<=beta)
      [alpha choose i]_2 [beta choose j]_2 K_(i,j,d). `

Multiplying by the choices of `U,V` gives the ambient count.

## 6. Exact collapse of Run-152's full chi-square spectrum

For this cube source the Run-152 false-source Fourier sum no longer requires enumeration of `2^(d t^2)` characters. It is exactly

` boxed(
 chi^2(P_struct || U)
 = sum_(alpha=1)^t sum_(beta=1)^t
     N_(alpha,beta)
     2^(-2r(alpha+s beta)).
 ) `

This is a deterministic `t^2`-term rank enumerator once `(t,d,s,r)` are fixed.

The exact probability ratio at the all-zero transcript is similarly

` P_struct(0)/U(0)
  = 1 + sum_(alpha,beta>=1)
      N_(alpha,beta) 2^(-r(alpha+s beta)). `

These are exact identities, not union bounds and not minimum-rank estimates.

## 7. New consequence — the global chi-square criterion can fail catastrophically even when TV mixing is small

The `(alpha,beta)=(t,t)` term already gives a useful lower bound. For a uniformly random `t x t x d` binary tensor, each unfolding is a uniform `t x td` matrix. Therefore

` Pr[one unfolding is not full rank] < 2^(-(d-1)t). `

By the union bound,

` K_(t,t,d)
  >= 2^(t^2 d) (1-2^(1-(d-1)t)). `

Hence

` boxed(
 chi^2(P_struct||U)
 >= (1-2^(1-(d-1)t))
    2^(t^2 d - 2 r t(s+1)).
 ) `

whenever the parenthesis is positive.

So Run 152's **sufficient** route `chi^2 negligible => TV negligible` cannot certify this source unless, roughly,

` 2 r(s+1) >= t d `

with additional security margin.

But that does **not** mean the actual statistical distance is large.

The same canonical form gives the full basis-output law

` C_a = X_a Y^T + Z W_a^T `

with shared uniform `Y in F_2^(t x rs)` and `Z in F_2^(t x r)` and independent uniform `X_a,W_a`. If `Y` has full row rank `t`, each `X_a Y^T` is independently uniform over `F_2^(t x t)`, so the entire `d`-matrix transcript is exactly uniform even after adding the correlated `Z W_a^T` terms. Therefore

` boxed(
 TV(P_struct,U)
 <= Pr[rank(Y)<t]
 = 1 - product_(i=0)^(t-1)(1-2^(i-rs)).
 ) `

and if `rs=t+kappa`,

` TV(P_struct,U) < 2^(-kappa). `

The two statements are simultaneously true. For example, take

` t=128, s=3, r=50, d=100. `

Then `rs=150=t+22`, so

` TV < 2^-22, `

while the full-mode term alone gives approximately

` chi^2 >= 2^1,587,200 `

(up to the negligible multiplicative full-unfolding correction).

This is a rigorous warning about proof technique: the high-dimensional cube channel can be statistically close to uniform in total variation while having an astronomical chi-square divergence because rare bad hidden-image events carry enormous likelihood ratios.

### Consequence for the research program

For this source, **do not use negligibility of the global Run-152 chi-square sum as a necessary security target.** It is only a sufficient L2 certificate and becomes useless in exactly the growing-codimension regime of interest. Conditional-image coupling is strictly more informative for hiding here.

The Fourier/rank spectrum remains valuable for extraction questions and for identifying efficient low-rank projections, but its total L2 mass should not be conflated with total-variation insecurity.

## 8. What is and is not resolved

### Resolved here

- exact simultaneous normal form of the characteristic-two cube code;
- exact rank of **every** off-diagonal/dependent coefficient array;
- exact count of characters by the two relevant unfolding ranks;
- exact full chi-square spectrum as a double sum;
- a proof that the global chi-square hiding route can be exponentially looser than conditional-image TV mixing.

### Not resolved

- full practical witness-KEM security;
- a relation-specific analogue for the fixed Syscoin bridge relation;
- arbitrary-QPT premature final-key recovery -> ORIGINAL witness for the complete wrapper;
- malicious one-honest N-of-N setup/abort and auxiliary-input composition;
- an efficient distinguisher matching the huge chi-square value in the parameter regime where the conditional-image TV bound is already small. No such distinguisher is inferred from large chi-square alone.

All statistical identities in this note are information-theoretic and therefore apply against arbitrary QPT distinguishers. The remaining true-instance extraction statements are not upgraded by this result.

## 9. Deterministic validation actually executed

`offdiag_tensor_spectrum_run209_check.py` is Python-standard-library-only and independently rebuilds the current-head Run-198 compiler fixtures.

The finalized checker passed syntax validation and two byte-identical executions. It performs **8,284 assertions**.

For two independent actual compiler fixtures,

- `N=4,R=1,GF(16)`, hence `s=2,d=3`;
- `N=5,R=2,GF(32)`, hence `s=3,d=3`;

and `t=2`, it exhaustively enumerates all `2^(t^2 d)-1 = 4095` nonzero coefficient tensors. For every tensor it:

1. assembles the real descended weighted-table block matrix from the compiler;
2. computes its binary rank directly;
3. computes the two unfolding ranks `(alpha,beta)`;
4. verifies exactly

   `rank N = alpha+s beta`;

5. verifies the complete `(alpha,beta)` histogram against the Gaussian/Möbius formula;
6. verifies the exact chi-square sum against direct character enumeration;
7. verifies every fixed-direction `lambda tensor c` slice reduces to `(s+1)rank(lambda)`.

For `d=3,t=2` the exact joint mode-rank histogram is

- `(1,1): 63`;
- `(1,2): 126`;
- `(2,1): 126`;
- `(2,2): 3780`.

The resulting exact `r=1` chi-square values are

- `2583/1024` for `s=2`;
- `7119/16384` for `s=3`.

The checker validates the finite algebra/counting identities. It does not prove lattice hardness, QPT extraction, or the fixed Syscoin relation.

## 10. Precise handoff

The Run-208 question “characterize the off-diagonal full `t x t` Fourier/rank spectrum for an arbitrary coefficient array” is now closed for this characteristic-two cube source:

` rank N(C)=rank H(C)+s rank G(C). `

The next useful shared-factor question should **not** be another rank recount. The remaining high-value direction is to use this canonical channel to analyze either:

1. an efficient statistic that detects the rare bad-image mixture more sharply than the existing span/rank tests; or
2. the true-instance one-copy source-extraction game directly under conditional-image mixing, avoiding the globally huge chi-square mass.

The generic WE-like stopping condition remains unmet.
