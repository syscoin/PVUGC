# Coupled metric: exact closure of the *published joint-support linear recovery certificate*

**Date:** 2026-10-25. **Status:** constructive, scoped algebraic lemma and executable integration; **not a complete PQ witness-KEM, not a key-hiding proof**. Research-only; no Bitcoin endpoint or deployed key. This result is specific to the previously documented pivot–Schur SOURCE compiler and its NEW experimental coupled metric, not a generic reduction for NP witness encryption.

## Exact ancestry

1. `syscoin/PVUGC#1`, branch `research/pq-wkem-validation-20260918`, **read-only verified head** `aa814d446419d84babc294de00b0205d7fe3c636`, 2026-10-25. Relevant exact file: `research/pq-wkem/joint_view_reduction_20261024/README.md`, Git blob `bc2f71b4b2969132c4eb3c36ff93810de5f2bc21`. That checkpoint establishes a public-space exact-key attack for the ORIGINAL scalar-identity key shift; the attack constructs `SR, SL, H, Z` and a public projected matrix space `S` from **all** nonconstant original-coordinate slices and labeled quotient markers.
2. The **local-only** `offline-coupled-metric-20261025` candidate (not present on the verified PR): `COUPLED_METRIC_REPAIR.md` and its `check_coupled_metric.py` in the attached predecessor bundle. The new public metric `B=sum_e U_e T_e V_e` has independent uniform private `T_e` in the five-dimensional Schur gate space, with public invertibility abort. The previous local work showed only the older *separated-node rank determinant* fails and a restricted functional observation. It did **not** instantiate the exact latest public joint-support `S` or prove its complete image or conditional distribution. This record completes those particular steps without changing the release algorithm.

## Full Setup / Build / Encode / Recover and public output

Use an extension `E/F`, both fields of characteristic two, with `E=GF(2^256)` and `F=GF(2^128)` in the illustrative predecessor parameters. Choose a fixed public ORIGINAL relation `R_x(w)` (R1CS→QAP, boolean/Frobenius quotient), L off-domain verifier nodes, n original coordinates, dimension `N=2L+h`, and independently sampled two-sided secret factors `U_e∈E^(N×3)`, `V_e∈E^(3×N)` plus the predecessor's SL2/pivot/shear setup. The local verifier matrix is

```
G_e(y) = [[c_e(y), a_e(y), s_e(y)],
          [b_e(y), pi_e(y),       0],
          [s_e(y),      0, pi_e(y)]].
Hloc = {[[c,a,s],[b,pi,0],[s,0,pi]] : c,a,b,s,pi in E}.
Phi(T) = sum_e U_e T_e V_e.
```

**Build:** Draw independent uniform `T_e ← Hloc`, `K←E`; set `B=Phi(T)`. Compute public affine slices from `C(y)=z K B+Phi(G(y))`. The original-coordinate public matrices are `C_1,...,C_n`; the constant is `C_0=Phi(G(y0))+K B`; quotient matrices are the publicly recomputable `Q_j` (or lossless `Q_0,Q_1`). Publish **every** coefficient necessary for public evaluation, `B`, the bound x including relation ID/claim-UTXO/branch/anchors/window/context, and the intended verification/checking key derived from the protected credential. The source compiler, field/node labels and any normalization metric are also public. Abort *before funding* if `B` is singular. Setup computes and must protect/erase secret K and factor coins under the existing honest-erasure N-of-N premise; **no malicious-secure ceremony is claimed**. No extra online authority exists.

**Encode:** Given an ORIGINAL valid witness w, publicly interpolate its QAP source polynomials, divide `A_w B_w-C_w` by the vanishing polynomial, and use Frobenius inverse on quotient coefficients to obtain the normalized `F`-valued `y_w`. Distinct w need not agree on `y_w`.

**Recover:** Evaluate `C(y_w)` from the complete public slices; determine `λ∈E` with `rank(C(y_w)-λB)≤2L` by polynomial-time generalized characteristic polynomial factoring, or return failure. On valid ORIGINAL w, `C(y_w)-K B=Phi(G(y_w))` has rank ≤2L, so K is always a candidate; the predecessor's simultaneous wrong-scalar lemma gives uniqueness **only at its exact supplied-F-pair honest-setup scope**. All valid ORIGINAL w obtain the same designated K when uniqueness applies. No hard-true key-only extraction is claimed.

## Proved theorem: the **actual public joint-view attack space** is exactly the coupled-metric image

Suppose the public certificate of the pinned GitHub attack holds: `rank(Q_0)=2L`, the independently reconstructed nonconstant support spaces `SR,SL` satisfy `dim SR+dim SL=3L`, the observed per-node rank-two quotient marker `R_e` intersects the public spaces in one of the two certified patterns `(dim(row(R_e)∩SR),dim(col(R_e)∩SL))=(1,0)` or `(0,1)`, and the public space `S` is formed exactly as in the cited checkpoint:

```
H = any full-row-rank left annihilator of SL;
Z = any full-column-rank right annihilator of SR;
S = span_E { H R_e Z, H T'_e Z : e=1,...,L },
```

where each supplementary `T'_e` is obtained publicly from `R_e` and the certified intersection line, as in the pinned attack. Let `Psi((X_e))=H(sum_e U_e X_e V_e)Z`. **Then, for the exact current local gate space,**

```
                    Im_E(Psi | Hloc^L) = S.           (1)
```

**Proof, both inclusions.** For orientation 0, saturation gives `v1,v2∈SR`; hence `v1Z=v2Z=0`. For every local Schur matrix `X=[[c,a,s],[b,pi,0],[s,0,pi]]`, direct multiplication gives

```
H U_e X V_e Z = (s H u1 + pi H u3) (v3 Z).        (2)
```

For orientation 1, saturation gives `u1,u2∈SL`; hence `Hu1=Hu2=0`. Thus

```
H U_e X V_e Z = (H u3) (s v1 + pi v3) Z.        (3)
```

The two generators for each node lie in the span of the publicly constructed projected quotient marker `H R_e Z` and its supplementary `H T'_e Z`; this proves `Im(Psi)⊆S`. Conversely, `R_e` is an E-multiple of `U_e(E13+E31)V_e`; its projected image arises from choosing the `s` basis coordinate in Hloc. After the certified row/column intersection extension, the supplementary projected rank-one direction differs from the image of the `pi` basis `E22+E33` only by a multiple of the marker. Both are in `Im(Psi)`. This proves `S⊆Im(Psi)`, hence (1). No SOURCE correctness, secret key, QPT assumption, or secret-factor recovery is used.

**Key consequence (latest attack's linear-functional family is neutralized):** Because both `G_e(y)` and the newly sampled `T_e` belong to Hloc, for every source y and key candidate λ,

```
H [ C(y) - z λ B ] Z ∈ S.
```

Any public linear functional `ell` that annihilates **the actual latest GitHub attack space S** must satisfy `ell(HBZ)=0` as well as `ell(H Phi(G(y0)) Z)=0`. It therefore cannot satisfy the original attack requirement `ell(HBZ)=1`. This is stronger than the predecessor's disjoint-node rank observation: it closes precisely the published joint ORIGINAL-coordinate-support **linear extraction certificate** for this candidate, on **every** honest output where that certificate is constructed. It does **not** rule out nonlinear or differently projected attacks on the complete tuple.

## Additional unconditional statistical lemma, exactly scoped

Before the invertibility-abort selection, conditional on all source-compiler/hidden factor randomness and all public slices `D=(C_1,...,C_n,Q_0,Q_1,relation,context)` (and any auxiliary information independent of the fresh T), equation (1) says the linear map from 5L independent uniform E-scalars to `H B Z` is surjective onto the **D-determined** space `S`. Therefore:

```
Pr[ H B Z = b | D, hidden baseline M0, other setup coins excluding T]
  = |S|^(-1) for each b in S, and 0 otherwise.       (4)
```

This equality is information-theoretic and survives arbitrary QPT postprocessing of this *limited marginal* and independent classical/quantum advice. In particular, conditional on D, `HBZ` is independent of `H M0 Z`. It does **not** assert that the **pair** `(H C0 Z, H B Z)` hides K, because its value also contains M0, nor that `HBZ` remains independent of M0 after conditioning on the *full* public B, checking key or joint capsules. Under public abort on `rank(B)<N`, the exact uniformity is for the **unconditioned honest trial**; the accepted-trial joint law differs in total variation by at most its overall abort probability, not by a uniform per-D guarantee. The predecessor derives an abort upper bound; no new security level is claimed here.

## Executed reproducibility

`verify_joint_coupled_metric.py` imports the **verbatim included helper files** from the local coupled-metric predecessor. It recreates the *latest* 4-wire/7-row false/true ORIGINAL sources, 8 release nodes, `N=21`, actual GF(16)⊂GF(256) fields, full original-coordinate/quotient public slices and random metric. It runs the public joint-support certificate and S construction (not using hidden factors to construct S), then uses private factors only to independently check identity (1). 64 deterministic setups (32 false, 32 true) satisfied the latest public certificate. All 64 verified `HBZ∈S`, projected constant `HC0Z∈S`, and the stronger equality of the complete 5L-dimensional local basis image with S; all retained the old-identity outside-S control. Complete Boolean census finds three true witnesses; nine distinct honest-witness evaluations of the actual QAP pipeline preserve the same K. **1,866 checks** in one captured execution, repeated with byte-identical output. This is synthetic finite-field algebra, not arbitrary-QPT evidence, and neither unknown-key factoring nor Bitcoin signing was executed.

To reproduce locally: `python verify_joint_coupled_metric.py > check_output.json && cmp check_output.json validation_latest_joint.json`, Python 3 standard library only; see PROVENANCE.json for exact file hashes. No network call is made by the checker.

## Security boundary and handoff

**Proved:** honest same-capability correctness at the inherited scope; exact public joint-support image identity and full closure of the pinned *linear-functional certificate family*; unconditioned conditional-uniformity of the limited metric projection; no new key/plaintext/public witness coordinate or verifier assumption.

**Not proved:** false-instance security of `(D, B_full, C0_full, vk(K), aux, related capsules)`; arbitrary QPT key-only recovery or native signature forgery ⇒ ORIGINAL witness or QPT-LWE/SIS break; setup maliciousness/abort under adversarial selection; all-E-source acceptance; native Bitcoin graph; practicality. The current example remains ∼381 TB of public matrices and is not deployable. The proved projected marginal does not solve the required *joint* distribution.

**Next exact equation:** find a publicly instantiable, classical-PPT SOURCE-sensitive masking mechanism with a straight-line simulator for the **joint** distribution `D,B_full,C0_full,vk(K),aux,correlated capsules` when embedded with a QPT-LWE challenge. A simulator must preserve all SOURCE/metric dependencies **without knowing the challenge secret** while all valid ORIGINAL w obtain the same K; otherwise explicitly demonstrate a different independent QPT-hardness reduction. The existing Run-259 SOURCE extractor applies only after an accepted representation is available. Neither (1) nor (4) forces a bare K to provide one. Until that implication is proved, do not call this a secure PQ witness-KEM and leave PR #1 open/draft/unmerged.
