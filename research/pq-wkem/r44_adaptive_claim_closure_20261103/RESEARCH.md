# R44 — ADAPTIVE-CLAIM-CLOSURE (offline, 2026-11-03)

**Restricted constructive theorem and repaired eligibility algorithm; NOT a generic NP/SYS-BTC witness-KEM.** Builds directly on R43's packed, OR-of-LWE-secret, SAME-capability per-claim source. PR #1 starting head: 713aa69ade3335912ba0e47fb8955d13b4eab5c4, open/draft/unmerged, branch research/pq-wkem-validation-20260918. R43 exact RESEARCH.md blob 710ba7d1e6de66af64d9a63dc50984bb7f644ff0; CHECKER.js blob 7b72e3c55c62d39bed92161be46dadcc68430a74; substantive comment 6611390598. No external literature/web research.

## Release algorithm and full public view

Register at most Q=poly(lambda) independent, honestly generated claim sources before funding. Each claim i has J_i independently generated Regev public keys (A_ij,b_ij=A_ij^T s_ij+e_ij), with A uniform over Z_q^(n x m), s uniform over Z_q^n, e independently sampled from explicitly bounded chi with magnitude <= E. In each claim, choose independent uniform kappa-bit K_bind,i and K_pad,i and ONE private pre-signed fixed-path native signature sigma_i. Every branch j encrypts BOTH SAME seeds via fresh binary r for every symbol, role, scope and branch. Symbol a in Z_p is encrypted as (Ar, b^T r+floor(qa/p)), modulo q. Require floor(q/p)>2mE; then ANY bounded decryption witness (s',e') for ANY valid branch deterministically recovers exactly the two claim-wide seeds, hence the same sigma_i = D_i XOR G(K_pad,i), for D_i=sigma_i XOR G(K_pad,i).

Checking key CK_i=F(canonical public relation/claim/UTXO/anchors/window/branch/context, all target capsules, native vk, exact challenge message, D_i, K_bind,i). The complete adversarial view contains relation identities, statements, public source keys, all target and related capsules, CKs, common native vk, all fixed signing messages, D_i, contexts and permitted auxiliary data. Only CK/aux classes for which the R42/R43 full-view simulator can reproduce exact correlations are permitted: no independent K_pad, target sigma, target source-secret or target encryption-coin leakage. All honest algorithms are classical PPT. Distinct valid internal witnesses need NOT have common intermediate states.

**Register distinct signed messages:** the pair (native verification key, EXACT native challenge message bytes) must be unique across independently exposed claims. If messages coincide, merge their exposure domains or abort pre-funding registration. One revealed signature on a repeated (vk,m) already authorizes all its labels. If native message identity is represented by a hash digest, QPT collision resistance is an ADDITIONAL unproved assumption; exact-byte equality alone cannot justify a hash-based binding. All fixed paths, pre-signatures and data required by the actual UTXO graph must be determined before irreversible funding; this note does not prove the N-of-N ceremony or Bitcoin endpoint.

**Claim-wide source-opening closure:** Opening a source witness of ANY branch of claim i exposes K_bind,i, K_pad,i, and the pre-signed native capability sigma_i. Mark the WHOLE claim i exposed, not only branch (i,j). Exclude all exposure-equivalent claims from later eligible challenge targets. The opening API itself cannot be used as a security perimeter: a witness holder can run the public decryption independently.

## Security game and QPT reductions

Arbitrary nonuniform QPT adversary A first obtains the entire joint public view of Q honest claims. It may make polynomially many adaptively chosen **classically indexed** pre-commit opening queries Open(i,j), revealing genuine source witness/seed/signature records for the requested branch and marking claim i exposed. Query labels are measured/classical at the oracle boundary; the adversary's other workspace remains quantum, entangled and unrestricted. After these queries A commits CLASSICALLY to an unopened target claim t. Afterwards it may use R43's full reversible/coherent opening oracle for every non-target claim, while target openings return bottom. It wins by outputting an accepted native signature on the fixed message m_t, or by outputting exact K_pad,t which yields sigma_t. Any previously exposed branch of target t makes the trial invalid.

**A fully coherent pre-commit opening-index oracle with a target selected later is NOT covered.** Without a measured exposure record there is no proven eligibility semantics, and no quantum oracle security is assumed. Advice may depend on exogenous context but not on hidden target source-generation coins; public correlated information is included in the game. Target LWE keys are honestly generated, never adversarially forged.

For each fixed target i, R43 establishes a conditional straight-line full-public-view bound, under separately specified QPT exact-distribution decisional LWE, QPT PRG, and QPT multi-message native EUF-CMA, with all reproducible checking-key and auxiliary correlations and permitted coherent non-target opening tables:

B_i = Adv_QPT-native-EUF,i + Adv_QPT-PRG,i + 2 J_i Adv_QPT-DLWE,i + 2 T_i delta_i,

where T_i counts independently randomized target branch/role/scope/packed-symbol ciphertexts and delta_i=(1/2)sqrt(q_i^(n_i+1)/2^(m_i)) is the strong leftover-hash term for binary r. This is the R43 prior conditional theorem, NOT a fresh quantum-hardness proof.

Define A_i as a QPT adversary against that fixed-target-i game. It runs A only once. For every classical pre-commit Open(j,b) with j != i it returns the EXACT record generated from the fixed-game non-target opening table. If A requests ANY branch of i, A_i aborts; if A later selects t != i, A_i aborts; otherwise it forwards all post-commit coherent non-target queries and outputs A's target signature.

On every REAL winning transcript with t=i, no earlier opening of any branch of i occurred. Therefore the real and fixed-target-i transcripts are exactly identical on this event, including public checking keys, private-key-correlated non-target openings, native vk and A's entangled quantum workspace. The branching history is classical at each pre-commit opening boundary, so no measurement of A's private quantum state or rewinding occurs. Consequently:

Pr_real[Win AND t=i] = Pr_fixed-i[A_i wins] <= B_i.

The target outcomes are disjoint, so

Pr_real[Win] <= SUM_(i=1)^Q B_i <= Q max_i B_i.

A *single* reduction may guess I uniformly BEFORE generating/receiving the joint public view, use the fixed-target-I simulator, and obtain success exactly Pr_real[Win]/Q from eligible winning target-match transcripts. This is a polynomial loss Q, at most log2(Q) bits in the conditional security-success bound, not an attack-cost estimate. For Q=1024, this is up to a 10-bit loss if all B_i equal. No adversary-supplied representation, SourceOpen oracle for target, QPT rewinding, native forgery extraction beyond the fixed R43 reduction, or extra LWE secrecy assumption is introduced.

When the adversary outputs exact K_pad,t, deriving sigma_t = D_t XOR G(K_pad,t) is deterministic straight-line postprocessing. Any arbitrary target sigma obtained by other means is covered by the same multi-message native EUF hybrid, PROVIDED messages (vk,m_i) are distinct and the fixed-target simulator can hide/reproduce the original target sigma in the complete CK/aux view. R37's one-time Lamport illustration cannot share one key across all Q claims without a separate multi-use security justification.

## Exact bounded execution

The published CHECKER.js was actually executed twice in a fresh V8 code-isolate with byte-identical output. It tests q=257, n=2, m=7, error bound E=1, p=16, 4 independently generated claims with 3 branches each, same two private seeds across each claim's branches, packed releases, exposure closing across siblings, duplicate native message negative control, and all target choices for 157 sequences of pre-commit classically indexed opening requests (length <=2). It checks exact bounded coupling of the opening records whenever the guessed target was not exposed. It is a toy algebra/transcript test, NOT a QPT experiment, lattice security estimate or proof of the asymptotic theorem. A separate longer LOCAL-ONLY Node checker with 7,288 assertions, 11,088 decodings and 364 eligible target couplings was also executed twice and retained in the local offline archive (not byte-identical to this published checker).

## Exact unresolved construction

This has NOT solved arbitrary ORIGINAL relations. Every R43/R44 witness remains an LWE decryption secret unrelated to genuine SYS/BTC fork, burn or authorization evidence; attaching an off-chain ORIGINAL verification routine to Open does not prevent direct decryption. The required equation is, for classical Compile(x) from an arbitrary ORIGINAL NP statement and arbitrary QPT adversary in the *entire correlated view*:

Pr[A obtains precommitted capability or accepted native target forgery]
<= Pr[B^A produces w with R_ORIGINAL(x,w)=1] + Adv_QPT[independently instantiated PQ break] + negl(lambda),

without assuming a supplied representation, SourceOpen oracle, canonical witness, online authority or public Bitcoin NP verifier. The compiled source must preserve SAME-capability correctness for every distinct valid ORIGINAL witness. Arbitrary FALSE full-public security, malicious one-honest N-of-N setup/abort/graph composition, target-source openings, keyless retained-build, quantitative 128-bit parameters, SYS/BTC continuous observation and qualified forks, and the hypothetical no-EC-key-path native PQ Bitcoin endpoint all remain unproved. No production, main, workflows, reviews, merges, other repos, deployment or funds were modified.

