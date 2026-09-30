# Run 197 — a full shared-factor `t x t` projection has the exact `A B^T` law and gives a public rank-event distinguisher

**Status:** new exact distribution theorem and a classical polynomial-time false-instance distinguisher/necessary parameter condition for the Run-152 CMV-form capsule. This is **not** a completed PQ witness-KEM, does not prove full-transcript hiding, and does not replace the missing arbitrary-QPT ORIGINAL-witness extraction theorem.

## 1. Verified live starting point

Connected GitHub reads at the start of this scheduled research iteration verified `syscoin/PVUGC#1`:

- branch `research/pq-wkem-validation-20260918`;
- exact head `bed393e8a4f83a5e4aaa266b7942b1ef3a45eb9a`;
- open, draft, unmerged;
- latest substantive ordinary PR comment read: `5913974235` (Run 196 publication).

Exact-version files used:

- Run 196, `CONDITIONAL_IMAGE_MIXING_RUN196.md`, blob `99a0538f9823bfd562b34570d7aa68dd079fa446`;
- Run 152, `CMV_MINRANK_LACONIC_QPT_SOURCE_BRIDGE_RUN152.md`, blob `398b93af491d0b11cc486e86c89295a05b714804`;
- Run 82, `FINITE_DIFFERENCE_LOWRANK_RUN82.md`, blob `6430557fd1596308db029d17b48549f9ed9490c8`.

No denied historical payload was retried. No production/workflow file is touched.

Run 196 proved a dimension-free mixing bound for an entire **one-block projection** and explicitly left the shared-factor `t x t` channel open. This run takes one fixed public source direction and analyzes **all `t^2` block positions jointly**.

## 2. Run-152 structured transcript and one public source projection

Use the exact Run-152 binary setup. Let the public source-space basis be

`M_1,...,M_D`,

where in Run 152 these are `(K_1,...,K_d,U_x)`. The Kronecker lift is

`M_i' = J_t tensor M_i`.

The structured branch samples

`R = sum_(l=1)^r u_l v_l^T`

with independent uniform

`u_l in F_2^(t a)`, `v_l in F_2^(t b)`,

where each source matrix has dimensions `a x b`, and publishes

`C_i = <R, M_i'>_t in F_2^(t x t)`.

Choose **any public nonzero coefficient vector** `z in F_2^D` and form

`M(z) = sum_i z_i M_i`,
`rho = rank(M(z))`,

and the public ciphertext projection

`C(z) = sum_i z_i C_i`.

On the uniform branch of Run 152, `C(z)` is a uniform `t x t` binary matrix for every nonzero `z`.

The question is the exact law of `C(z)` on the structured branch when all `t^2` positions share the same rank-`r` factorization of `R`.

## 3. Theorem 1 — exact shared-factor product law

**Theorem.** Let `rho=rank(M(z))` and put

`m = r rho`.

Then on the structured branch

`boxed( C(z)  ==_dist  A B^T )`

for independent uniform matrices

`A,B <- F_2^(t x m)`.

Thus this full `t x t` public projection depends on the source direction only through its rank `rho`.

### Proof

Take a full-rank factorization

`M(z)=P Q^T`,

with `P in F_2^(a x rho)` and `Q in F_2^(b x rho)` both of column rank `rho`.

Split every outer-product factor into block coordinates

`u_l=(u_(l,1),...,u_(l,t))`, `u_(l,p) in F_2^a`,
`v_l=(v_(l,1),...,v_(l,t))`, `v_(l,q) in F_2^b`.

By the definition of the Run-152 blockwise inner product,

`C(z)_(p,q)
 = sum_l u_(l,p)^T M(z) v_(l,q)
 = sum_(l,d) (u_(l,p)^T P_d)(v_(l,q)^T Q_d)`.

Define the column index `(l,d)` of `A,B` by

`A_(p,(l,d)) = u_(l,p)^T P_d`,
`B_(q,(l,d)) = v_(l,q)^T Q_d`.

Because `P` and `Q` have full column rank, the linear maps

`u -> P^T u in F_2^rho`,
`v -> Q^T v in F_2^rho`

are surjective. The original block vectors are mutually independent uniform vectors, so all rows/chunks generated above are mutually independent uniform. Hence `A` and `B` are independent uniform `t x (r rho)` matrices and the displayed identity is exactly `C(z)=AB^T`. QED.

This is stronger than the generic assembled-block treatment in Run 196 for this particular projection: it uses the actual Kronecker repetition and shared factors rather than treating all block coefficients as an arbitrary matrix code.

## 4. Theorem 2 — exact efficient rank-event distinguishing advantage

Let

`p_t = Pr[U in F_2^(t x t) has rank t]
     = product_(j=0)^(t-1) (1-2^(j-t))`.

For `m>=t`, let

`p_(t,m) = Pr[B in F_2^(t x m) has rank t]
         = product_(j=0)^(t-1) (1-2^(j-m))`,

and put `p_(t,m)=0` for `m<t`.

Consider the public polynomial-time event

`E(C) := [rank(C)=t]`.

Under a uniform `t x t` matrix,

`Pr_U[E]=p_t`.

Under `C=AB^T`:

- if `rank(B)<t`, then `rank(AB^T)<t`;
- if `rank(B)=t`, the map from each uniform row of `A` to that row times `B^T` is surjective onto `F_2^t`, so conditional on such `B`, `AB^T` is **exactly uniform** in `F_2^(t x t)`.

Therefore

`boxed( Pr_structured[E] = p_(t,m) p_t )`

and the explicit classical distinguishing advantage of the rank event is

`boxed( Delta_rank(t,m) = p_t (1-p_(t,m)) ).`

This attack uses one ciphertext and ordinary Gaussian elimination. It is therefore automatically valid against any claimed QPT hiding notion.

### Consequence when `m<t`

Then `p_(t,m)=0`, so

`Delta_rank=p_t`.

The finite-field product `p_t` decreases to about `0.288788...`, so this is a constant distinguisher for every `t`.

This sharpens the earlier Run-82 pseudo-witness/rank boundary for the Run-152 **uniform-vs-structured** capsule: a public false source direction with `r rho<t` already breaks false-instance bit hiding by a simple rank test, without recovering the hidden key.

## 5. Theorem 3 — tight constant-factor statistical sandwich

Conditioning on `B` being full row rank makes `AB^T` exactly uniform. Thus the structured law is a mixture

`Q_(t,m) = p_(t,m) U_t + (1-p_(t,m)) Q_bad`

for some distribution `Q_bad` supported on rank-deficient matrices. Consequently

`boxed(
 p_t(1-p_(t,m))
 <= TV(Q_(t,m),U_t)
 <= 1-p_(t,m).
)`

The lower bound is exactly the public full-rank event from Section 4; the upper bound is the mixture coupling.

For `m=t+s`, `s>=0`,

`1-p_(t,t+s)
 = 1-product_(k=s+1)^(s+t)(1-2^(-k)).`

The largest failure term and the union bound give

`2^(-s-1)
 <= 1-p_(t,t+s)
 < 2^(-s).`

Hence the full shared-factor projection is close to uniform **iff the inner product width `m=r rho` exceeds `t` by a growing margin**. In particular,

`p_t 2^(-s-1)
 <= Delta_rank
 < p_t 2^(-s)`.

For a target rank-event advantage at most `2^-lambda`, the exact necessary condition is obtained by evaluating `Delta_rank(t,r rho)`. A convenient integer coarse condition is:

> if `r rho - t <= lambda-3`, the public rank-event advantage is still greater than `2^-lambda`.

Equivalently, this theorem rules out `2^-lambda` false-instance hiding for that public source direction unless

`r rho - t >= lambda-2`

up to the stated constant-factor boundary. This is a **necessary condition**, not a sufficient full-transcript security theorem.

## 6. Apply the exact law to Run 82's real false Hair–Sahai family

Run 82 proves that for the explicit false relation

`sum_i b_i - (N+1)=0`

and `R=floor(log_2 N)`, an attacker can construct, in polynomial time, source matrices

`A_(T,z) in S_false`

with

- nonzero public anchor;
- `rho=rank(A_(T,z)) in {R+1,R+2}`;
- support size at most `2N` assignment matrices for each member;
- at least `2^(N-R-1)` distinct such members.

The attack does **not** need the whole family. Pick one member, express it in the public source basis as Run 82 already does, and compute the Run-152 projection `C(z)`.

By Theorems 1-2 its exact structured law is `AB^T` with

`m = r rho <= r(R+2)`,

whereas the uniform branch gives a uniform `t x t` matrix.

Therefore a source-independent coarse necessary condition for `2^-lambda` hiding against this explicit public family is

`boxed( r(R+2)-t >= lambda-2 )`

in the sense that if the left side is at most `lambda-3`, the rank-event attack is already larger than `2^-lambda` for every possible `rho<=R+2` allowed by the theorem.

This is strictly stronger than Run 82's scalar-bias condition `r(R+2) >= lambda`: the shared-factor `t x t` channel costs an additional approximately `t` bits of rank-width margin.

It is also different from Run 196's one-block mixing result. Run 196 gave an upper bound for one projected block. Here a **joint all-`t^2` public projection** yields an explicit lower bound and a concrete PPT distinguisher.

## 7. What this does to the Run-152 route

This result does **not** prove the entire CMV-form route impossible. A parameter regime with

`r rho >= t + lambda + O(1)`

makes this particular projection statistically close to uniform, and the full transcript could still require additional analysis.

But any future parameter claim for the Run-152 candidate must now simultaneously satisfy:

1. honest witness decoding: a rank-one source witness produces structured rank at most `r` while the uniform branch is overwhelmingly above the decoder threshold;
2. false-source projection hiding: every efficiently constructible public low-rank false direction, in particular Run 82's family, must have `r rho - t` large enough that `Delta_rank` is negligible;
3. full-transcript hiding: passing every one-direction projection is only necessary, not sufficient;
4. arbitrary-QPT unauthorized recovery must still source-extract an ORIGINAL witness or break an independently justified QPT assumption.

No random-MinRank theorem or generic-group result supplies (2)-(4) automatically.

## 8. QPT / assumption ledger

- **Honest algorithms:** classical polynomial-time matrix operations and Run-152 sampling.
- **Adversary:** the new distinguisher is classical PPT, hence included in arbitrary QPT.
- **Assumptions:** none. The product-law proof is exact finite-field linear algebra.
- **Auxiliary advice:** irrelevant to the attack; no advice is needed.
- **Quantum reduction:** none; this is an unconditional attack/necessary condition, not an extractor.
- **False-statement hiding:** broken with advantage `Delta_rank(t,r rho)` whenever that quantity is non-negligible.
- **True-instance arbitrary recovery -> ORIGINAL witness:** unchanged from Run 152's conditional spectral theorem; still **UNPROVED without its stated spectrum conditions**.
- **Full practical PQ WKEM:** **UNPROVED**.

## 9. Validation actually executed

`joint_lowrank_projection_run197_check.py` is Python-standard-library-only.

The finalized checker passed syntax validation and two byte-identical executions. It performs:

- exact enumeration of `AB^T` for `t=2`, `m=0..5` and `t=3`, `m=1..3`;
- exact verification of
  `Pr[rank(AB^T)=t]=p_(t,m)p_t`;
- exact verification that the measured total variation lies between
  `p_t(1-p_(t,m))` and `1-p_(t,m)`;
- exact verification of the elementary `2^(-s-1)` / `2^(-s)` failure bounds when `m=t+s`;
- three independent direct CMV blockwise fixtures showing that rank-1/rank-2 source matrices with `(r,rho)=(1,1),(2,1),(1,2)` produce exactly the normalized `AB^T` distribution with `m=r rho`;
- three illustrative rows for the coarse Run-82 necessary condition.

Representative exact values:

- `t=2,m=1`: TV `3/8`, full-rank event advantage `3/8`;
- `t=2,m=2`: TV `15/64`, rank-event advantage `15/64`;
- `t=3,m=3`: TV `3759/16384`, rank-event advantage `903/4096`.

The finite checks validate implementation and small identities only. The general result follows from Sections 3-5.

## 10. Precise handoff

Do not spend the next pass trying to extend Run 196 by summing one-block marginal bounds. The shared-factor channel now has an exact public-direction law.

The highest-value next question is genuinely **joint across multiple source directions**:

> given several efficiently constructible Run-82 matrices `M_1,...,M_q` evaluated on the same hidden `u_l,v_l`, characterize the joint law of `(A_1B_1^T,...,A_qB_q^T)` through the row/column spaces of the combined source matrices, and determine whether the exponentially large finite-difference family yields a stronger polynomial-time distinguisher than the best single direction.

A positive joint attack would further narrow or kill the structured CMV route. A negative theorem with exact combined-rank conditions could instead identify viable parameters. The WE-like offline-release requirement and the full QPT/ORIGINAL-extraction stopping condition remain unchanged.
