# R65 — SINGLE-ROOT-CK: derive signature seed and checking key jointly from one LWE root

Run: R65-SINGLE-ROOT-CK-DERIVATION-20261104, offline 2026-11-04. syscoin/PVUGC PR #1, research/pq-wkem-validation-20260918. Verified prior head 09693fd05ba79d101f018d05132614bd5e622c28; latest substantive comment 6633750370. Read at that exact head: R64 RESEARCH.md blob 04b94721427013bca3af8b8268d5c70c6b71c5b9; R63 RESEARCH.md blob 25b55c74f1e72e94cb1a3f7e4f2f00e966696bec; R61 RESEARCH.md blob 9e82f7cda1120541cf0e0fbc0b3315fbd8c003b6. No external research.

## Actual constructive advance and explicit limitation

The surviving R62/R64 ORIGINAL relation is R_SIS(A,r)=1 precisely when r is binary, r0=1, and A^T r=0 mod q, with A independently uniformly sampled from Z_q^(m×n). This is **not** the arbitrary ORIGINAL SYS/BTC NP relation. R64 encrypts both a uniform k-bit common release root K and an independently sampled k-bit checking key Kbind; at k=256,b=16 this costs 32 source ciphertext vectors. R65 encrypts **only K**, and uses **one entire ordinary-LWE generator sample** G_A0(K) to derive *both* the signature-expansion seed S and the checking-key seed Kbind. This reduces the source from 32 to 16 vectors (6,144 to 3,072 source bytes at identical R64 illustrative q,m,n,error and Δ), and the source-hybrid loss from 32 to 16. One additional generator expansion and base-LWE hybrid are needed. This does **not** repair generic-NP source soundness, R58's public trace, R63's signed-kernel bypass, malicious setup or a real Bitcoin endpoint.

## Exact classical PPT release

For general λ let k=k(λ), κ≤k, source q=2^t, A←U(Z_q^(m×n)), independent uniform s_i∈Z_q^n and bounded coordinate errors e_i←χ^m with |e_i,j|≤E. Set u=e_0. The generator uses independently uniform A0∈Z_q0^(m0×n0), q0=2^t0, with k=n0*t0+m0*b0 and m0*t0=2k. A **uniform** seed of k bits parses into independent uniform s0∈Z_q0^n0 and e0∈S_b0^m0, S_b={−2^(b−1),…,2^(b−1)−1}; define the entire 2k-bit ordinary-LWE sample G_A0(seed)=Serialize(A0*s0+e0 mod q0). The generator is not a hidden witness-release primitive.

First bind the immutable ORIGINAL relation ID, claim/UTXO, branch, actual SYS/BTC burn/authorization/output, anchors and observation window, relevant authenticated tags, path-scoped challenge credentials and native verification key into m*. Under separately unproved one-honest N-of-N preauthorization/erasure and data-availability conditions, generate the **actual precommitted** native challenge-path signature σ* on m* before funding. m* excludes later capsules to avoid a signing cycle; the final complete ciphertext manifest must itself be authorized before irreversible funding.

Build samples K←U({0,1}^k) and computes the *same whole generator output*

    (S, Kbind) := G_A0(K) ∈ {0,1}^k × {0,1}^k.

If κ<k, take a fixed prefix of Kbind. Use R52/R61's explicit depth-d tree generator, whose output length L=2^d*k matches the fixed native-signature serialization length:

    Dsig := Encode(σ*) XOR TreeG_A0^d(S).

Parse K into B=ceil(k/b) b-bit little-endian μ_i, zero-padding only the last public word. Independently sample s_i,e_i, then publish only

    C_i := A*s_i + e_i + Δ*μ_i*u (mod q),       i=1,...,B.

Never publish the unmasked A*s_i+e_i. Form canonical Base from (version, ORIGINAL relation/statement/scope, claim/UTXO, branch/anchors/window/context, intended vk and message, A,A0,Dsig, all ordered C_i, manifest, related public capsules and permitted opening policy). Exclude CK/Aux from Base to avoid cycles. Set CK=F_Kbind("CK",Base), Aux=F_Kbind("AUX",CK,Base). Transcript mutation security requires **independently justified QPT binding/unforgeability** for F and graph authorization; the hybrid merely recomputes F using known keys. No public H(K) or H(σ*) is silently assumed: those separate target-secret-dependent tags would break the simulator unless separately handled. A final public commitment to ciphertext Base is simulatable.

Public OFF-CHAIN Open first checks an **actual** ORIGINAL-SIS witness r, fixed authenticated scope and CK/Aux. For every r∈{0,1}^m with r0=1 and A^T r=0,

    r^T C_i = Δ μ_i + r^T e_i (mod q),  |r^T e_i|≤mE.

The two exact conditions Δ>2mE and q−(2^b−1)Δ>2mE guarantee all cyclic codeword centers separate. Every valid distinct ORIGINAL-SIS witness uniquely decodes the *same* K, recomputes (S,Kbind) and CK/Aux, and unmasks **the identical** Build-precommitted σ*. Verify ordinary native Verify(vk,m*,σ*) and return the signature for the scoped challenge path. No intermediate witness state/preimage needs to be shared. Bitcoin runs no NP verifier, general proof, VM steps or dispute trace; the hypothesized SLH-like native signature/P2MR-like no-EC-key-path endpoint is not deployed or established here.

## Full-joint public view and exact ordinary-QPT-LWE hybrids

Honest output V includes statement/relation, vk, claim/scope, A/A0, Dsig, all source C_i, manifest, CK, Aux, related public capsules and independently opened related claims. Adversaries are arbitrary nonuniform QPT, including coherent quantum processing of this entire **classical** view, with quantum advice independent of target coins. Permitted related selective openings are adaptive **classical** responses on separately sampled independent roots and distinct native messages; exclude any sibling or target opening that legitimately discloses the common native signature. Exclude adversary-chosen malicious A, target-witness/target-root/secret-correlated advice, coherent target-opening oracle, arbitrary secret-dependent checking tags outside the displayed Base, and rebinding without independent QPT authentication. These restrictions are material; this is not an unconditional malicious-setup or arbitrary auxiliary-input claim.

1. For each of B source words, a **real ordinary decisional-LWE challenge** (A,Y) has Y=A*s+e with the specified χ, or Y uniform in Z_q^m. The classical PPT simulator knows K, samples other words and independently permitted related claims, sets C_i=Y+Δμ_i*u, then recomputes the **whole** Base/Dsig/CK/Aux. Real Y gives exactly Build's source distribution. Uniform Y makes C_i uniform independently of K by translation. No unknown s/e, SourceOpen oracle, representation volunteered by the attacker, quantum rewinding or QROM programming. After all B hybrids source C's are independent of K; CK remains genuinely correlated through Kbind and is *not* asserted marginally independent.

2. Now a **single entire** ordinary base-LWE challenge (A0,Y0) provides all 2k bits at once. The simulator parses S=Y0[0:k] and Kbind=Y0[k:2k] from the SAME sample, recomputes Dsig=σ* XOR TreeG_A0^d(S), then computes all Base, CK, Aux, and related public correlations. Since target C's are now uniform, it needs **no target K or SourceOpen secret**. Genuine Y0 has exactly distribution G_A0(K) for uniform K, while uniform Y0 yields **jointly independent uniform S and Kbind**. This is a whole-output DLWE reduction, not two assumed independent marginal PRGs. The publicly shared A0 is unchanged between the root and TreeG computations, which are deterministic functions of the challenge and A0.

3. With S uniform independent of A0,Kbind, use the explicit R52/R61 level-wise generator proof: one ordinary-LWE challenge per internal tree node, at most 2^d−1 base terms, with public A0 reused at every node and each challenged node fed a seed first made uniform by earlier hybrids. After *each* change of Dsig, regenerate Base and its secret-Kbind-dependent CK/Aux and related accessible data. All reductions are straight-line classical PPT or QPT-compatible black-box distinguishers without rewinding. If the base ordinary-QPT decisional-LWE premise applies to each exact distribution and the related opening simulator has the stated independence, all QPT distinguishers see computationally indistinguishable whole classical transcripts.

4. Finally Dsig is a uniform L-bit string and can be simulated without obtaining a target signature, so an accepted fresh target native signature gives a QPT EUF-CMA forgery. Exact target-root K is absent from the final view, giving 2^(−k) guessing success. Formally for an unopened target, fixed fresh authenticated m*, independent related openings and arbitrary QPT adversary:

    Pr[accepted unauthorized target native signature]
      ≤ B Adv_QPT-DLWE_source + 2^d Adv_QPT-DLWE_base
        + Adv_QPT-EUF-CMA_native + Adv_QPT-binding + sampling-error.

For exact K recovery use final-game 2^(−k) in place of native-EUF. This bound is **only for the restricted uniform-A SIS relation and the displayed access/advice model**, not generic ORIGINAL x. It needs independent QPT decisional-LWE for BOTH source and generator, independently justified QPT native unforgeability and binding. The old R64 term counts were 32 source + (2^d−1) base; R65 is 16 source + 2^d base at k=256,b=16. No automatic classical-to-quantum extraction, generic-group, SIS-hardness, or WE/iO assumption is made.

## Executed checks / exact provenance

The attached exact V8 CHECKER.js is **the source of the executed function itself**, as serialized by function.toString; the accompanying OUTPUT.json is its exact captured JSON result. It passed 262281 assertions including two distinct actual planted binary SIS-witness openings of the SAME root, derived CK and signature, two independent related TRUE openings on a distinct scoped message, 16 source real-challenge/CK-correlation identities, entire root G real and uniform challenge simulations, tree uniform replacement, final public-view simulation, and exhaustive 65,536 symbols at both ±64 cyclic error boundaries. All source C and related capsules are included in the hash input. V8 checker uses a deterministic toy PRNG, toy checking hash and toy synthetic signer; no security proof or 128-bit parameter claim. An independent local Python 3 + cryptography 46.0.4 checker passed **262,324 assertions twice identically**, including actual Ed25519 public signature verification and SHA256/HMAC correlated CK/Aux. Ed25519 is a **classical test endpoint**, explicitly NOT PQ. That Python checker, full extended derivation and captured output are preserved locally, distinct from published V8 source. Planted matrices for correctness are **not** uniform-A LWE challenge distribution. The exact genuine source-challenge substitution and full CK/Aux recomputation are checked separately.

Numerical illustration matches R64's toy source q=2^24,n=2,m=64,E=1,Δ=129,b=16: 32→16 vectors, 6144→3072 bytes, 50%; shared A unchanged, CK/Aux, tree, graph, actual evidence excluded. The V8 base generator q0=2^8,n0=8,m0=64,b0=3 gives k=256 bits and exact 2k-bit ordinary-LWE output; no 128-bit QPT security is claimed for these tiny settings. A deployed version needs quantitative real QPT parameters, practical full costs, and actual native PQ support.

## Critical unfinished ORIGINAL work

R63's 3CNF→structured-kernel source is **explicitly classically broken**: a publicly computable signed h obeys A_x^T h=0 and can decode the secret for false x; its structured LWE distribution is distinguishable. R58's TRUE quotient exposes a public multiplication trace. Neither is repaired by folding roots. A generic classical-PPT statement-dependent compiler must preserve every actual ORIGINAL witness and jointly simulate all source, checking-key, context, auxiliary and multiple-capsule outputs from a **real independently justified QPT challenge** while proving

    Pr[unauthorized capability recovery or native acceptance from V_x]
      ≤ Pr[R_ORIGINAL(x,Ext^A(V_x))=1]
         + Adv_independent_QPT_break + negligible(λ),

with efficient extraction of an ACTUAL ORIGINAL witness and no adversary-volunteered internal representation. This remains unconstructed. Arbitrary-FALSE security, malicious N-of-N ceremony/abort/erasure, keyless Build, reliable finite-window SYS/BTC evidence under DA/reorg/censorship constraints, actual quantum security, and native Bitcoin endpoint are also unfinished. This is a restricted, concrete efficiency/composition advance **not a practical generic witness-KEM**. Continue research; do not disable the existing automation.

Reproduction of exact published V8: node CHECKER.js > OUTPUT.json. Offline research only; publication confined to research/pq-wkem/ on existing PR #1 branch and ordinary top-level PR comment.
