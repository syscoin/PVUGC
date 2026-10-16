# Run 566 — exact affine-hyperplane criterion and Booleanization's narrow boundary

Date: 2026-10-17. Research-only at exact live PR #1 start 0a64be1e4d636a262422ef06493524cba78ddbf7, draft/unmerged, no production modifications.

## Model and theorem

Fix precisely bound ORIGINAL statement x and R(x,w), public source residual rho_x(w) in F_q^m, with rho=0 iff R=1. Honest classical-PPT setup **is granted an ideal encrypted capability state** c_w=(K_x,rho_x(w),x) for fixed public source evaluation. A hypothetical protected gate releases K_x only when the decrypted residual is 0 and context matches. Neither encrypted-state confidentiality nor the gate is constructed. Adversaries are arbitrary nonuniform QPT with every public key, auxiliary input, related capsule and coherent circuit evaluation. The attack below is already classical PPT.

Restrict public transformations to affine combinations of honestly source-evaluated states with coefficient sum 1, no independent offsets, and no authenticated execution-lineage check. Let S_x={rho_x(w):R(x,w)=0} subset F_q^m \ {0}.

**Exact linear-algebra criterion.** Zero belongs to Aff(S_x) iff no linear form ell:F_q^m -> F_q satisfies ell(s)=1 for every s in S_x. For the empty set affine release from invalid source states is impossible.

Proof: Fix s0 in S, V=span{s-s0:s in S}. Aff(S)=s0+V. The origin is outside iff s0 is outside V, iff there is a dual linear form annihilating V and mapping s0 to 1. Conversely any affine combination of invalid residuals has ell=1 and cannot be zero.

**Attack consequence.** If 0 is in Aff(S), at most m+1 invalid residuals admit public affine coefficients alpha_i with sum alpha=1 and sum alpha_i*rho(w_i)=0. A poly-time adversary finding these candidates solves the augmented linear system and mixes the corresponding ciphertexts into (K_x,0,x), which the hypothetical gate opens. Mere existential affine membership does not guarantee such candidates are efficiently findable for every relation.

**No-attack consequence.** If a separating ell exists, no finite sequence of permitted affine mixes of invalid source states makes an accepted residual. This is only a restricted algebraic fact, not IND security or real-source provenance.

## Explicit three-source attack — even on a false statement

For any prime q, give a false ORIGINAL instance three publicly named invalid candidates whose residuals are e1=(1,0), e2=(0,1), e3=(1,1). With coefficients (1,1,-1), their residual combination is 0 while the coefficient sum is 1. The capability and context survive unchanged. This also works over F_2. It is a false-instance key-hiding failure in the **stipulated ideal gate model**, not only a true-instance extraction concern. This generalizes the exact Run 565 barrier, whose chosen b=0 branch deliberately returned constant residual 1.

## A precise algebraic mitigation and its immediate failure outside scope

Instead use the public nonlinear reject scalar
 B_x(w) = 1 - product_j (1-rho_{x,j}(w)^(q-1)) mod q.
Every valid witness gives 0; every invalid candidate gives 1 (Fermat). Computing this flag is classical polynomial time in m and log(q), and does not canonicalize witnesses. Under the special source-affine-only grammar all invalid output states (K_x,1,x) stay at reject bit 1 after every allowed affine mix.

**But this is not a KEM or secure local mixer.** If the public transformation grammar also allows adding an independently encrypted known offset (0,-1,0), an invalid output (K_x,1,x) becomes (K_x,0,x) in one step and releases K_x. Standard unrestricted additive/homomorphic evaluation permits precisely this kind of constant injection. A release circuit using only the publicly known Boolean flag also collapses: anybody can present the accepting flag 0, as already warned by Run 259. To preserve security would require *actually instantiated and independently justified* cryptographic linkage among original source representation, hidden capability, and single-source execution lineage, excluding offsets and mixed-source forgeries. Such a linkage has NOT been constructed or assumed to exist.

## Source binding and required security

Run 259 is exact only for a supplied **complete accepted representation** meeting its residual/source/SIS conditions (source note Git blob c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2). A mixed encrypted state, booleanized flag, recovered K_x, or native signature is not automatically that representation. The upstream unauthorized early recovery / signature forgery -> accepted ORIGINAL representation or independent QPT break remains missing. Valid witnesses may have different s_w but the intended capability must be identical for all. On-chain authorization would only be an ordinary native signature under the explicitly conditional P2MR/SLH endpoint; no Bitcoin NP computation is proposed.

Attack taxonomy: (1) affine seam exposed; (2) no gauge needed; (3) distributions/labels not justified; (4) three same-capsule views defeat vector case; (5) chosen public inputs/constant offsets decisive; (6) malicious setup/retained K unaddressed; (7) relation/UTXO/branch reuse not prevented; (8) public checking key unnecessary to compromise; (9) classical attack lifts to QPT, while absence of the attack does not certify joint coherent security.

Exact finite checks: a separately authored checker exhausts 414 subsets over six small prime-field/dimension grids, verifies affine membership against independent brute-force dual forms, checks concrete attacks/affine-only countercase/offset failure, and 91 Fermat Booleanization vectors. The committed executed checker reports 1560 assertions. These are finite algebraic tests only, **not** LWE/SIS/QPT security proofs or a real ciphertext implementation.

Literature: inspected the exact-version Canetti–Luo–Zhang applicability note (blob c19d9d9cd515140e3ce62eac960cd548c0add622). Its actual controlled-transform language has **not** been shown to permit the affine operations or constant injection here. This is not a break of CLZ and no full merged-paper proof/errata/quantum-assumption audit was completed. The affine-hyperplane lemma is elementary linear algebra; its application here is the narrow research checkpoint.

Open obligations: independently justified practical classical-PPT release and arbitrary-QPT full-public-output false-instance hiding; true-instance unauthorized recovery and native-signature forgery to ORIGINAL evidence or independent hardness break; malicious N-of-N erasure/abort and pre-funded graph; multiple-capsule and auxiliary-input composition; concrete 128-bit resources. No completed WKEM.
