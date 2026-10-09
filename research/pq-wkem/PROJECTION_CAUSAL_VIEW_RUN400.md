# Run 400 — Source-hard full states, publicly samplable release projection

**Scope:** newly sharpened causal-view falsifier; NOT a generic local-mixing/RIO impossibility, not a WKEM, not concrete QPT security. Exact current PR branch parent `4d4ca3d1197c1b9e418cbb3dda70604e14dc34c8`; exact Run 259 source blob `c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2`. Run 396 previously assumed a simulator for the **complete joint** release input. Here only the **actual projected causal view** needs to be samplable, while the complete source representation can remain QPT hard to produce.

## Projected-view simulation lemma

Honest classical PPT setup gives public `V=(x,ctx,P,vk,aux)` and private branch capability K. An ORIGINAL witness `w` yields a complete representation/state `s_w` and the protected, separately callable classical-PPT release only receives `u=pi_P(s_w)`. Its output permits public native-signature authorization checking for exact claim/UTXO/branch/message. Assume there is a classical-PPT `Q(V)` with total-variation distance `TV((V,Q(V)),(V,pi_P(s_W)))<=eta` for an honest valid-witness distribution W. If the honest release authorization probability is `p`, invoking release on `Q(V)` authorizes with probability at least `p-eta`. **Proof:** apply the identical release/sign/verify test to the two joint distributions and use the definition of TV distance. A computationally indistinguishable projected view gives the same conclusion up to its exact arbitrary-QPT distinguishing advantage; any quantum advice must be included in the compared joint distributions or explicitly restricted.

This lemma is not a WE/WPRF hardness assumption: it describes an elementary, *insecure* interface when the projection is publicly sampleable. It does not assert that an actual protected source-to-release program admits such separation or sampling.

## Strictness relative to full-state sampling: conditional one-way example

Assume quantum-one-way permutations `f_i` (independently justified QPT hardness would be needed in any real application). On `x=f_i(w0)` for uniform `w0`, define ORIGINAL `R_i(x,(w,t))=[f_i(w)=x]` with arbitrary `t`. Complete states `s=(w,t,r)` accepted by `R_i` are QPT-hard to manufacture absent a witness: any valid output inverts f. Distinct valid t retain distinct intermediate states. Given an accepted COMPLETE state, the ORIGINAL extractor is trivial, illustrating Run 259's limited *downstream* scope.

Independently publish a full-row-rank binary matrix `H` (k by b, k<b), syndrome c, and generate `r` uniformly in `{r:Hr=c}`. The separately callable release sees **only r**, not (w,t), and yields the same K on all r with Hr=c. Anyone solves Hr=c via GF(2) elimination and invokes release once without the ORIGINAL witness. Even though the fraction of accepted *uniform* b-bit inputs is `2^-k`, there is a **polynomial-time exact sampler** for the accepting coset. For (b,k)=(256,128), density 2^-128 does **not** imply even 64-bit witness-search work here. This is a structured public sampler, not a contradiction of generic Grover-query upper bounds (Run 388). No canonicalization or shared source preimage is used.

The release is an **ideal callable interface** containing a hidden K; no practical white-box implementation is supplied. The reduction to f-inversion is conditional and excludes auxiliary advice already containing the hidden preimage. False-instance hiding, actual native signatures, and concrete QPT hardness were not proved.

## Attack taxonomy and exact boundaries

(1) local seam: w,t omitted from protected causal view; (2) public gauge does not remove Gaussian sampler; (3) high codimension/low density is not a security invariant; (4) one capsule suffices, related capsules unproved; (5) one chosen projected input suffices; (6) honestly sampled H already fails, malicious setup/erasure unproved; (7) branch-replay protections not modeled; (8) full public vk is part of success test; (9) classical PPT attack is QPT, but no separate coherent attack on a surviving mixer. An inseparable original-input protected program, or a view that cannot be simulated without ORIGINAL w, is **outside the theorem**.

## Exact finite verification

The attached JavaScript checker was *executed as published* in the JavaScript research runtime: 6,210 assertions over public systematic affine cosets of widths 8, 12, 64, 256 and ranks 3, 5, 24, 128 respectively, with exhaustive coset enumeration at small widths; all honest and source-free one-query checks pass. A separate extended Python checker, retained locally, passed 106,780 assertions including scrambled full-rank cosets at b=384,k=192. These finite checks do not test one-wayness, native SLH, obfuscation, N-of-N security, or concrete 128-bit hardness.

## Ledger and handoff

Run 259 source-binding gives accepted complete z -> ORIGINAL / conditional SIS break, not signature -> z. Run 393 supplies an ideal oracle query extractor only; it does not justify white-box-to-oracle simulation. A practical source-bound local mixer must authenticate the **complete causal view** of the release region with non-bypassable cryptographic dependence on accepted complete ORIGINAL representations, not only make complete source states hard. All-witness secure SAME-K release, full-public false-instance QPT hiding, pre-release true-instance arbitrary-QPT key/signature-to-ORIGINAL extraction, malicious one-honest N-of-N setup/abort/erasure, multiple-capsule auxiliary-input security, practical resources and hypothetical native Bitcoin P2MR/SLH remain **UNPROVED**. Production unchanged; draft PR remains unmerged. No completion claim.

Background: Canetti–Chamon–Mucciolo–Ruckenstein, ePrint 2024/006 https://eprint.iacr.org/2024/006 (RIO/iO and random-circuit assumptions not discharged); Ambainis–Hamburg–Unruh, CRYPTO 2019 O2H https://www.iacr.org/archive/crypto2019/116940359/116940359.pdf (ideal-oracle context only).
