# Run 512 — Claim-local seed translations block the Run-511 transplant without fresh full loader frames

Research only, October 14, 2026. Verified starting draft head 7dd755e3429bacc8d5fd7e240facd658c6bd3be0; branch research/pq-wkem-validation-20260918. One bounded ideal-model compositional lemma, **not** a practical PQ witness-KEM.

## Construction and exact semantics

Let the semantic state be (u,z,t), where u is an h-bit seed coordinate, z an n-bit ORIGINAL witness, and t a marker. A **common** ideal hidden permutation P conjugates witness-only loader generators R,X. Since these leave u unchanged, the public A_R=P R P^-1 and A_X=P X P^-1 can be shared across claims.

For every claim c, sample a fresh independent **unpublished** uniform h-bit delta_c, and claim-specific signing seed K_c. Publish anchor a_c=P(K_c XOR delta_c,0,0). Publish claim-specific reversible actions A_{c,i}=P B^delta_{c,i} P^-1, where

    B^delta_{c,i}(u,z,t)=(u,z,t XOR ((u_i XOR delta_{c,i}) AND f_c(z))).

Here f_c is the genuine ORIGINAL relation or an exact complete accepted Run-259 source predicate. Every valid z loads the state P(K_c XOR delta_c,z,0), and A_{c,i} moves it iff K_{c,i}=1. Hence every valid ORIGINAL witness recovers **the same K_c** in at most 2n+h public actions; different z remain different states. These are semantic oracle algorithms, not compact circuits.

## Full false-target joint distribution theorem

For false target x, f_x is identically zero, so every target terminal is identity regardless of delta_x. Fix all other public/reference capsules and the shared P, conditioned on them being independent of delta_x. For any two seeds K0,K1, the bijection

    delta_x -> delta_x XOR K0 XOR K1

leaves the target anchor P(K XOR delta_x,0,0) unchanged. Therefore the *joint target/reference public action view* has identical distributions conditional on either target seed. This is exact full-view equality for the **ideal false target** and survives arbitrary coherent QPT processing of that view. Native VK(K_x) is independently correlated with K_x, so equality does NOT include swapping native checking keys; it establishes zero incremental target-action leakage conditional on native VK and auxiliary information independent of fresh delta_x.

Against the Run-511 true-reference attack, the observed bit on the target anchor becomes

    d_i=K_{x,i} XOR delta_{x,i} XOR delta_{r,i}

rather than K_{x,i}. The target mask delta_x is an information-theoretic one-time pad, even when delta_r is known. Crucial negative control: if delta_x=delta_r (or delta_x is exposed), the Run-511 leakage returns and d_i=K_{x,i}. Each claim must therefore have a genuinely fresh, secret, independently erased delta.

Equivalently the effective per-claim mixer is P_c=P o T_delta_c. T_delta translates u and commutes with the public loaders. Thus **fresh complete random frames are not mathematically necessary to defeat this particular false-target transplant**. This refines Run 511, but does not settle other attacks against correlated P_c or real white-box compilers.

## Exact checks and attack taxonomy

The committed JS checker executes all 40,320 permutations of 8 states for h=n=1 and 128 deterministic 16-state permutation samples for h=2,n=1. It verifies 330,752 transplant equations, 82,176 conditional public-view multiset equalities, and 163,328 mask-reuse leakage negative controls. An independent locally preserved standard-library Python checker passed the same headline counts and was executed twice byte-identically (SHA-256 557ee8dccb3d90375575ef452ff91dae0dfc340e1f3cce375e4495fafe22bc9c). No practical cryptography or quantum device was tested.

(1-2) seam/gauge: reference terminals return a masked u, not K; reused delta restores the attack. (3) statistical fingerprints: false target terminal tables are identities. (4) multi-capsule: theorem tolerates arbitrary other views independent of delta_x. (5) chosen-state queries: included for ideal black-box actions; cannot remove fresh delta_x on false target. (6) malicious setup/retained coins: revealing/biasing/reusing delta defeats this protection. (7) cross-UTXO/branch: independently scope seeds and masks. (8) VK: independent key-hiding assumption remains. (9) coherent quantum: equality of the entire ideal classical distribution survives quantum processing, **not** arbitrary compact white-box attacks for true targets.

## Noncompletion / core handoff

The common P and full conjugated terminal tables remain exponentially large: the complete construction is **not classical PPT**. A compact white-box program exposing delta_x, P inverse, or correlated structural invariants could defeat the intended secrecy. A setup ZK proof cannot make an insecure compiler safe. Even with secure false-target hiding, arbitrary true-instance unauthorized final-key or native-signature recovery -> accepted COMPLETE Run-259 representation / independent QPT break remains **unproved**; likewise arbitrary-QPT multi-capsule security with true targets, malicious N-of-N ceremony, abort/erasure, concrete 128-bit resources, and the claim/challenge/timeout graph with only conditional P2MR/native SLH. Bitcoin performs no NP verification here.

This result introduces no WE/RIO/iO-equivalent assumption. Relevant architectural background: Canetti–Chamon–Mucciolo–Ruckenstein, TCC 2024 / ePrint 2024/006. Its RIO assumptions and complete proofs have not been audited in this pass. Production unchanged. PR stays draft/unmerged; stopping condition unmet.
