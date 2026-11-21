# R383 — Threshold polynomial share attempt from original work certificates (NONQUALIFYING)

## Continuity
The actual draft PVUGC PR #1 branch `research/pq-wkem-validation-20260918` was read at start SHA `8a2f649e337b6a20aabfff50725f6e35379088f5` (R382). The exact R382 screening note (blob `d1b8f44038205f4c4e01d6c5dc6f89507933a875`), R381 (blob `47cbfe93ed12577bc2e0c2ad960234d5f87eb7f8`), R380 (blob `05dd3308a8a9ed8cd65116b1c746562e824d63f8`) were read. New ordinary comments since 2026-11-19 13:40 UTC: none. No Core source or network tests. This is a **nonqualifying** screening/construction experiment, not the original source gate.

## Distinct candidate: interpolation shares from authentic source work
Instead of using a single future certificate digest as R381's nonconvergent terminal pad, try to require a qualifying alternative Syscoin history's **d distinct authenticated parent work certificates** to yield a *threshold of shares* of one fixed frozen capability. Modern activated contextual checks distinguish valid child identities and one authentic Bitcoin parent commitment can certify at most one distinct Syscoin child, subject to the supplied strict-PQ qualifications. This does not imply every original OR challenge contains d independently newly mined parents: the burn and tag-fault branches are different, and parent certificates may have been mined by others.

Take a finite field F_q, threshold d, K=S-D and polynomial
`P(X)=K + a_1 X+...+a_(d-1) X^(d-1)`.
For d *distinct nonzero* points `x_i=Map(H(parent_i))`, a proposed public share evaluator gives `y_i=P(x_i)`. The opener interpolates
`K=sum_i y_i * product_(j!=i)((-x_j)/(x_i-x_j))` and returns `S=D+K`.
Any d evaluated shares of the same polynomial converge to the identical K; there is no canonical witness requirement. But the **serialization and source-conditioned key delivery** are the missing cryptographic operations, not presumed.

- If Build publishes coefficients (classical PPT), the constant K is public and S is immediately known.
- If Build provides any public callable `g_C(x)=P(x)` and hides its coefficients, an arbitrary caller queries *d invented field points*, interpolates K and recovers S. No original header or work is needed.
- If Build restricts g to authentic source parents by a *protected* verifier, it must instantiate a non-bypassable, publicly serialized function that conceals K while computing the same polynomial. Calling this function FE, ZK, a Merkle commitment, a public verifier wrapper, or a private oracle does not implement it. An unfunded source-generated secret or independent hash puzzle is not permitted.
- If y is instead a public SHA-only function of the parent bytes, Build generally cannot arrange that unknown future source shares interpolate one precommitted private K without an additional secret-dependent correlation.

## Exact universal-subset convergence theorem (scope restricted)
Let X be a set of at least d+1 distinct **nonzero** field points. Suppose for *every d-subset of X*, the unique degree<d interpolant through (x,y(x)) has the same constant coefficient K. Then all points lie on **one degree<d polynomial P with P(0)=K**.

Proof: on any d+1 points let Q be the unique interpolant of degree<=d, with leading coefficient a_d. Omitting x_i gives Q_i(T)=Q(T)-a_d*product_(j!=i)(T-x_j), and hence
`Q_i(0)=Q(0)-a_d*(-1)^d*product_(j!=i)x_j`.
The omitted-point products are pairwise distinct because all x_i are distinct and nonzero: each equals `(product_j x_j)/x_i`. Equality of all Q_i(0)=K forces a_d=0. Fix d reference points. Every extra point with them lies on that same degree<d polynomial, proving the claim. If x=0 is eligible, its y-value immediately equals K.

**Boundary:** Original Syscoin witnesses require ordered, authenticated, hash-linked histories. Not every arbitrary d-subset of potential parent certificates qualifies. The theorem **does not apply** to arbitrary ordered-history policies and is NOT a generic impossibility of source-specific FE/WE. It rejects only an unqualified all-d-subsets Shamir-style release that treats work hashes as share coordinates without a cryptographic gate.

## Complete-public security experiment and executed check
For BOTH implemented public forms (coefficients visible or unrestricted public evaluation), adversary learns S on FALSE instances without original evidence, so no complete-public secret-hiding simulator exists and hard-TRUE source work is bypassed. The attack is classical and therefore available to QPT adversaries; no QROM or concrete SHA break is asserted. Even restricting the honest interface to valid parents does not stop arbitrary public-package processing.

A Python3 standard-library checker was invoked twice; each completed successfully and the output bytes were identical. In F_101 with d=3 it reconstructed K=47 from all 20 3-subsets of six source-shaped field values. Modifying one share violated convergence. It also queried an **unrestricted** polynomial evaluator at field images of three SHA256d hashes of **invalid synthetic parent strings** (none met a toy eight-leading-zero-bit check), and recovered K=47. These are interpolation/algebra controls, NOT Bitcoin/Syscoin certificate tests, FE implementation, real chainwork, native signing, or QPT experiments.

Committed `check.py` SHA256 `274b77f96543b38edcf21fd651c4da85a7ef0aa0babc50e45895c446601e9ab4`.
Both JSON output SHA256 `de4a7cf1981ceecd621c1a74c2e6e0b13bea897b0d1e677495279b9d831b2617`.
The checker and captured output are committed below, and a second byte-identical run was observed locally.

## Disposition
Rejected. This fixes a convergence issue ONLY at the abstract threshold-share interface, not source-conditioned secure release. Do not repeat threshold, field, coding, hash-placement or sampling variants without a new **implemented** protected original-source share operator. The real missing operation is still `Build_orig(x_W,sigma_cancel)->C` (classical practical PPT), `Open_orig(C,w)=sigma_cancel` for *every* original qualified witness of the three OR branches, with a full-public FALSE/hard-TRUE QPT unauthorized recovery or native-forgery reduction to an ACTUAL original certificate or independently justified hash/native break. Preserve claim/UTXO/amount/recipient/burn/baseline/anchors/window/LC depth/reset/deadline/native signing and capsule binding, one-honest malicious setup, correlated siblings and source coins. No progress comment, breakthrough notification, Core/production write, deployment or automation change.
