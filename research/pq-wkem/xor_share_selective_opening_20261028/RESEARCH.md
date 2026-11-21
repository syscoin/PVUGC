# Selective-opening XOR-share composition for restricted SOURCE witness-KEM

Research record: xor-share-selective-opening-20261028-turn11. Offline only. Repository syscoin/PVUGC, open/draft/unmerged PR #1, branch research/pq-wkem-validation-20260918, verified starting SHA ab771d54683e1d82d09def4948b7cfd8b640d909; latest relevant issue comment 6473947498. The exact predecessor read at that SHA was research/pq-wkem/planted_source_spectral_extractor_20261028/RESEARCH.md (blob 3d708d2b9ceeb211299ab27a60d480f82739ddc4) and verify.js (blob 55ce7929e7f9e4fc460d4a5208dd690dd6fb502b).

VERDICT: A new full-public, share-level selective-opening composition with concrete classical Build and Release, exact false-source native-signature reduction and conditional planted hard-true ORIGINAL extraction. This improves the predecessor's inability to disclose even a single same-key target capsule by replacing full-key capsules with independent secret shares. No generic NP witness-KEM or independently established planted-QPT hardness.

## Exact ORIGINAL relation and setup

Let t >= 2. The ORIGINAL statement x includes relation identifiers and independently sampled component statements x_i, intended claim/UTXO, branch, anchors, observation window, and actual native verification-key/challenge-path identity. The ORIGINAL verifier is

    R_AND(x,(W_1,...,W_t)) = AND_i R_i(x_i,W_i).

This note instantiates each true R_i with the anchored binary short-kernel ORIGINAL relation R_i(G_i,w_i) = [w_i in {0,1}^{M_i}, w_{i,0}=1, weight(w_i)=h_i, G_i w_i=0 mod q_i]. The independently generated planted source for hard-true extraction knows w_i, whereas the challenger and adversary see only G_i. For false security, one may instead use a certified false G_i with e_0 in im(G_i^T), or a separately proved whole-vector statistically smooth false G_i. No witness-free compiler for arbitrary NP is claimed.

For each component fix q_i an odd prime, h_i, g_i=2h_i+1<q_i, radix b_i=floor(q_i/g_i)>=2, ell_i=ceil(kappa/log2(b_i)), public G_i in F_q^(r_i x M_i), and e_0 the anchor basis vector. Honest Build is a classical PPT algorithm. Sample the *actual* native deterministic-seed signing secret K in {0,1}^kappa and compute its genuine native public verification key pk(K). Sample mutually independent uniform U,Z_1,...,Z_t in {0,1}^kappa and publish

    D = U XOR Z_1 XOR ... XOR Z_t,
    V = K XOR U.

For each i encode Z_i into ell_i radix-b_i digits a_ij. For every j independently sample hidden uniform u_ij in F_{q_i}^{r_i} and hidden iid eps_ij in {-1,0,1}^{M_i}, and publish

    p_ij = G_i^T u_ij + eps_ij + g_i a_ij e_0 mod q_i.

The complete public transcript is (R_AND,x,all G_i, all p_ij,pk(K),D,V,context, checking-key and challenge-path bindings, admissible auxiliary inputs and eligible independently masked related capsules). Coins for different SOURCE capsules are independent; domain separation must prevent index, context and UTXO relabelling. K,U,Z_i,u_ij,eps_ij are not public unless deliberately released through the restricted opening operation.

Public off-chain Release first evaluates every actual ORIGINAL R_i. For each valid w_i, project w_i^T p_ij = g_i a_ij + w_i^T eps_ij mod q_i. The centered error has absolute value <= h_i, hence with g_i=2h_i+1 and the cyclic final radix gap >2h_i there is exactly one correct digit. Recover every Z_i and output

    K = V XOR D XOR Z_1 XOR ... XOR Z_t.

Thus EVERY valid ORIGINAL full witness, even if component witness states differ, recovers the SAME precommitted K. A real native signature is subsequently created OFF CHAIN for the intended challenge path; no Bitcoin NP verifier, VM, PCP, proof trace or online release authority is assumed.

Open(i), when independently authorized and when component i admits an opening, may reveal Z_i, W_i, and the complete source capsule coins u_ij/eps_ij. It NEVER reveals U, K, or shares for another index. This opening is a share, not the final key. The game permits adaptively opening at most t-1 shares, with only classical opening and signing-oracle interfaces. Revealing every share trivially reveals K. A target source cannot be expected secure if its own share is revealed and all remaining shares can be obtained by other means. Likewise, if W_i=W_j or their hidden witnesses are correlated, disclosure of W_i may enable opening j; the planted hard-true theorem explicitly requires independent source witnesses.

## Exact false-source full-public theorem

Fix target index I whose SOURCE is certified false, with G_I^T lambda=e_0, or has the already established *whole-public-vector* protected digit shift TV <= delta_I, conditional on its public G_I and all permitted independent auxiliaries. In NoOpen(I), the adversary may adaptively open other shares, see their ORIGINAL witnesses and all source coins, and perform any coherent QPT computation over all classical public inputs and replies; it may not open I. The native key and public checking key are genuine, not modelled as independent ideal variables.

Hybrid H_real to H_zero replaces only the ell_I protected shifts g_I a_Ij e_0 with zero, holding every real K/pk, D,V, all other real shares and their coin openings fixed. By the whole-vector source quotient theorem and independent coins, the complete joint distribution shifts in TV by at most ell_I delta_I. For a certified false I, uniform u_I can be shifted by g_I a_Ij lambda for each column, yielding EXACT equality (delta_I=0); no SourceOpen oracle or LWE challenge is required.

In H_zero all p_Ij are independent of Z_I. For any fixed K, all other Z_j, and native pk(K), the map

    (U,Z_I) -> (D=U XOR Z_I XOR XOR_{j != I} Z_j, V=K XOR U)

is a bijection. Therefore (D,V) are exactly uniform independent of K, even CONDITIONED on every other disclosed share Z_j and its source-opening coins, and on pk(K). A native EUF-CMA reduction given only the genuine checking-key challenge pk samples uniform D,V, generates all non-I shares/ciphertexts and opening replies exactly, and generates zero-shift p_I. Permitted native signing-oracle queries are forwarded without quantum rewinding. A recovered correct K can sign a fresh, unqueried intended-path message; a fresh accepted signature already is a forgery. Freshness, authentic key binding and proper seed-to-sign verification are mandatory.

Consequently, for arbitrary nonuniform QPT A with quantum advice independent of hidden target coins and with the above classical interfaces,

    Pr[win in NoOpen(I)] <= Adv_QPT_native_EUF-CMA + ell_I delta_I.

Auxiliaries must be publicly simulatable from (source statements, public checking key, context, independent coins, permitted sibling openings). The theorem does NOT tolerate source-secret-correlated quantum advice, unrestricted coherent opening or signing oracles, leaks of U or K, or unauthorized target share opening.

If ALL t independent potential surviving capsules separately meet the certified-false/smooth source assumption and the adversary adaptively opens at most t-1, choose a random I before the run, abort when it opens I. A fixed completed real transcript has >=1 unopened index, hence a random I survives with probability >=1/t. Apply the above full-public hybrid for each I (the success-and-not-open-I event is a data-processing event) to derive

    Pr[win] <= sum_i Adv_QPT_native_EUF-CMA(i) + sum_i ell_i delta_i
            <= t Adv_QPT_native_EUF-CMA + sum_i ell_i delta_i.

This *adaptive-survivor* result requires ALL possible survivors to be secure. For a mixed true/false conjunction with one false component, it is only valid when that false source remains unopened, unless every other possible survivor has an independently established hardness theorem. If an adversary is allowed to open the sole false share, and all true witnesses are publicly easy, there is an explicit full-key attack; no security for that game is claimed.

An optional LWE Build may substitute hidden y_ij=A_ij^T s_ij+eta_ij for uniform u_ij and publish A_ij. An ordinary QPT decisional-LWE challenge embeds directly into the exact p_ij formula without a SourceOpen oracle; a straight-line independent-column hybrid costs sum_i ell_i Adv_QPT_DecLWE_i, conditional on the exact LWE sampling parameters and independence. LWE is not used to *assume* source hardness and provides no generic-NP security.

## Restricted planted hard-true extraction with adaptive share openings

Consider t INDEPENDENT planted anchored-binary source distributions, each with hidden witness W_i, and the ORIGINAL conjunction R_AND above. A reduction to the planted short-kernel SEARCH problem is given one public planted G without its W. It chooses I uniformly and installs this G as the I-th source; it honestly samples other planted (G_j,W_j), knows the true K/U/Z shares, and can answer every opening j!=I with correct coins and witnesses, aborting on an I opening. Its initial public distribution is identically generated to the real t-fold planted Build.

For any completed real adversarial transcript with <=t-1 opened shares, random I remains unopened with probability >=1/t, even when A chooses openings adaptively based on public ciphertexts. In H_zero(I), all target-I ciphertext shifts are zero; the exact native checking-key simulator above handles the event win AND never-open-I. Therefore nonnegligible real final-K recovery or fresh intended-path forgery, beyond the native EUF baseline, forces a nonnegligible hybrid gap in at least one of the ell_I target ciphertext columns and some nonzero radix digit a.

Define a bounded CLASSICALLY QUERYABLE function of an arbitrary classical target ciphertext vector p by honestly generating the rest of that hybrid transcript (including real native K/pk/D/V, all other independent witnesses/opened coins), fixing the chosen digit a and forcing the target column equal to p, running a fresh QPT A once, and returning 1 iff A recovers correct K or fresh native signature AND never requests opening I. The reduction can evaluate this function as a classical Bernoulli oracle without knowing W_I, without quantum rewinding, and without an adversary-supplied internal representation.

The predecessor's proved Fourier-concentration lemma says, for GOOD planted G, whole-vector P_a is within sqrt(theta)/2 of a comparison distribution whose Fourier support lies in span(W_I). A surviving nonnegligible hybrid gap thus forces a nontrivial heavy Fourier coefficient c W_I of the above success function. Its explicit classical prefix-energy Fourier-list algorithm uses independent QPT invocations as a classical bounded oracle, identifies a heavy mode, normalizes its anchor, and checks the ACTUAL ORIGINAL predicate R_I(G_I,W_I). The reduction appends its own independently known W_j for j!=I, yielding a valid full ORIGINAL conjunction witness. The list extractor costs polynomial(M,q,1/tau) with large overhead and depends on the predecessor's GOOD-source and Fourier bounds.

This is a *restricted conditional composition theorem*: it DOES NOT prove independent QPT hardness of the planted short-kernel search problem, and the planted generator itself knows W. No witness-free generic NP compiler, arbitrary fixed-false guarantee, malicious setup, or practical 128-bit QPT parameter claim follows. Standard unplanted SIS cannot be silently substituted for planted search. Independent planted witnesses and publicly simulatable auxiliaries are essential.

## Executed finite checks and scope

The exact check.py recorded with this note was run TWICE offline, byte-identical: PASS 14,092 assertions. It samples 24 full 256-bit same-K triple-share releases with 46 radix-51 columns per component at q=257, confirms all actual ORIGINAL binary-kernel checks, verifies opened source coins for all seven share-opening subsets of sizes 0,1,2, exhaustively counts full (D,V,opened shares) conditional distributions for two distinct fixed toy K at 3-bit share size and every subset, and checks an EXACT full-vector certified-false shift bijection for G=I. SHA-256 is used only as an explicitly mocked checking-key consistency check, NOT a native SLH signature or QPT hardness experiment.

Unsolved: a generic witness-free ORIGINAL (R,x) -> SOURCE release compiler; full-public false security for every fixed false NP statement; arbitrary hard-true final-key/native forgery -> ORIGINAL W or independently justified QPT break without unverified planted-search hardness; malicious N-of-N preauthorization, one-honest erasure, abort/transaction-graph safety; actual SYS/BTC AuxPoW, coinbase tags, chain ancestry, work/fork/window/censorship/source authentication; real pre-funding native signature availability and a hypothetical no-EC-key-path P2MR-like native SLH endpoint. The original NP evidence stays off chain and no new Bitcoin opcode or proof verifier is assumed. Do NOT disable the continuing research task.
