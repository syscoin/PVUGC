# MINK-DENSE public-coin proof CRS: no real decryption keys

Run MINK-DENSE-2026-11-01-T19. Research-only continuation of MINK-ECZK, whose exact RESEARCH.md blob is 174a59f3d737a715b10ba8466d94c5efb313548e at PR #1 head adcdebcd491126b031a60ce19de5c64079bb5d77. No external research. Not a generic post-quantum witness-KEM or a safe funding recommendation.

## Constructive change

The predecessor's real setup needs two honestly generated LWE encryption keys, both private keys subsequently erased. Here **the real proof CRS is only public independent uniform randomness**: A uniform in Z_q^(m x n), and independent uniform vectors b_col,b_ch in Z_q^m. They share A. No decryption keys are generated, distributed, or erased in the real proof setup.

The soundness *analysis* separately changes b_col to a genuine LWE vector As_col+e_col and privately uses s_col to extract an assignment from any malicious classical commitment batch. The zero-knowledge *simulation* instead changes b_ch to As_ch+e_ch and privately uses s_ch to decrypt a malicious verifier's committed edge before it receives a coloring batch. The two modes need not coexist. Both transitions are decisional QPT-LWE hybrids. This materially reduces the ceremony from secret distributed key generation/erasure to public-coin generation, but DOES NOT yet solve one-honest public-coin generation or simulator-compatible ceremony transcripts.

For q=65537,n=256,m=4800 and eta=3, pure raw 3-byte field-element public-key storage falls from 7,401,600 bytes (two independent A matrices and b vectors) to 3,715,200 bytes (shared A, two b vectors). These are unassessed illustrative dimensions and NOT 128-bit security parameters. The repeated graph transcript is still very large.

## Exact distributions and protocol

q odd prime, dimension n, m rows, error e sampled coordinatewise from explicit distribution chi supported on [-eta,eta], with 4m eta < q-1. Honest algorithms are classical PPT. The independent required decisional QPT-LWE assumption distinguishes uniform (A,As+e) from (A,U_m) for s uniform in Z_q^n, e from chi, A uniform in Z_q^(m x n). Arbitrary polynomial-time quantum computation and independent polynomial quantum advice are permitted; advice cannot contain genuine private coins or secret keys correlated with the challenge.

Set g=(q-1)/2. Encrypt bit mu with fresh r uniform in {0,1}^m:
    Enc_(A,b)(mu;r)=(u=A^T r mod q, v=b^T r+g mu mod q).
A public opening is exactly (mu,r); verify canonical bits and recompute every coordinate. Encode each three-color vertex with two independently randomized bits under b_col; 11 is invalid. Encode an edge index among d edges with L=ceil(log2 d) independently randomized bits under b_ch.

The actual setup-consistency statement X binds the ORIGINAL relation identity, claim/UTXO/path, context, anchors/window, genuine native vk/capability, every related SOURCE capsule, source/evidence domain, permitted auxiliary public data, and exact native KeyGen/Build specification. Its NP language is reduced deterministically to graph G_X=(V,E), d=|E|. This run DOES NOT supply the full KeyGen/Build-to-3COL implementation. TRUE setup X has a coloring, FALSE setup X has no coloring.

For each unique (session,X,prover,verifier,round): verifier first encrypts its independent uniform edge under b_ch and authenticates the ciphertext; prover next freezes fresh vertex color ciphertexts under b_col; verifier next reveals the selected edge and ACTUAL encryption coins; prover validates that reveal exactly, then opens only its two edge endpoint colors and coins. Reject malformed challenge values, noncanonical coins, extra queries and reuse. No general NP verification runs on Bitcoin.

## Strong statistical ciphertext hiding for uniform public vectors

Let M=(A,b), uniform in Z_q^(m x (n+1)), and F_M(r)=(A^T r,b^T r). For any distinct r,r' in {0,1}^m, delta=r-r' has a nonzero +/-1 coordinate, invertible modulo q, hence F_M(r)-F_M(r') is uniform on Z_q^(n+1). This is a 2-universal family. The exact leftover-hash bound for the REAL uniformly generated key is
    Delta((M,F_M(r)),(M,U_(n+1))) <= eps_LO = (1/2)*sqrt(q^(n+1)/2^m).
The public message shift by g*mu preserves distance. Thus Enc(mu_0) and Enc(mu_1) have statistical distance at most 2 eps_LO averaged over fresh real CRS. For k independent unrevealed honest encryption coins under a reused public key, the complete classical transcript changes by at most 2k eps_LO under replacement of plaintext bits. Independent b_col,b_ch may SHARE A: conditional on A, the other b is independent of the b under consideration. All polynomial quantum postprocessing and independent entangled advice obey the same trace-distance bound. Do not expose the coins of unopened ciphertexts, and do not infer every-key security from an average-key bound.

For the illustrative q=65537,n=256,m=4800 tuple, log2(eps_LO) = -344.99717125094. THIS is a leftover-hash statistical estimate, not an LWE hardness estimate. In the checker, exhaustive tiny q=3,n=1,m=5 enumeration gives average TV 0.1907568290741867 <= 0.2651650429449553; worst-case key TV 0.8888888888888891 confirms that maliciously chosen keys need not be secure.

## Arbitrary-QPT malicious-prover soundness in the real public-coin model

Fix any FALSE setup graph. Since final acceptance is publicly efficiently computable, swapping the real uniform b_col with a properly generated LWE b_col changes QPT false-acceptance probability by at most Adv_QPT-DLWE; the distinguishing reduction runs the PUBLIC protocol and checks acceptance, without possessing the LWE challenge's private key. In the genuine LWE-key HYBRID, the mathematical analysis can privately retain s_col.

For an exact opening Enc(mu;r), decryption under s_col yields g*mu + e_col^T r, with absolute noise <=m eta < g/2. Therefore every accepted opening of any committed vertex gives the same extracted bit, even if a malicious QPT prover never volunteers a coloring or randomness until challenged. The proof referee locally decrypts all submitted vertex ciphertexts and marks invalid bit pairs as invalid. Every total coloring attempt of a FALSE graph fails at least one edge.

Before the adversary fixes a fresh color batch, the honest verifier's encrypted edge under independent uniform b_ch is statistically close to fresh independent pad data, even given the full prior classical transcript and arbitrary QPT internal processing. Evaluating whether the already-extracted colors are valid on the still-hidden edge is sufficient; do NOT try to fake a challenge ciphertext and later open it to a different real edge. With alpha=1-1/d, ell independently tagged rounds, and k_edge hidden challenge-bit ciphertexts:
    Pr[accepted FALSE] <= Adv_QPT-DLWE_col + alpha^ell + k_edge*eps_LO.
For T polynomially many authenticated attempts, count all hidden ciphertexts and union-bound the alpha^ell failures, with ONE LWE hybrid for the whole attack. All messages are classical; no classical rewinding is lifted to QPT.

## Arbitrary-QPT malicious-verifier zero knowledge in the real public-coin model

For TRUE X with witness independent of the sampled proof CRS, compare the REAL honest-prover interaction using uniform b_ch with the SAME honest-prover interaction using genuine LWE b_ch. This transition reduces to QPT decisional LWE and does not require the distinguisher to know s_ch; the honest witness can be supplied independently as auxiliary input.

In the second world the straight-line simulator generates genuine b_ch=As_ch+e_ch itself and retains s_ch privately (the REAL world still has uniform b_ch). On any malicious classical encrypted edge challenge, decrypt its bits to j BEFORE generating vertex ciphertexts. Select the two challenged endpoints' colors uniformly among the six ordered distinct pairs; assign arbitrary colors to the others; encrypt all under uniform b_col with fresh independent coins. Later check the verifier's full canonical challenge opening and reveal only its selected endpoints. An authentic challenge opening cannot disagree with decryption because the real LWE error is bounded for EVERY binary r. Malformed/no-opening challenges lead to the same abort behavior.

For every fixed real edge, a uniformly permuted genuine 3-coloring gives uniformly distributed ordered unequal endpoint colors. These and their disclosed coins match exactly. All unopened colors are statistically hidden by the uniform b_col leftover-hash lemma, even with the same A as the simulated LWE challenge key. For k_col unopened bit ciphertexts:
    Dist_QPT(Real,Sim) <= Adv_QPT-DLWE_ch + 2 k_col*eps_LO.
This requires only classical authenticated protocol messages, CRS-independent witness/advice or independent efficiently samplable auxiliary context, no leakage of unopened r, no quantum honest secret-challenge oracle and no leakage of simulator's private s_ch. Malicious-verifier adaptive aborts and extra requests follow the specified fail-closed transcript API. Source-dependent true/false capsule generation, all native vk/SOURCE correlations, and general related-capsule selective openings are NOT simulated here.

## The remaining exact one-honest ceremony obligation

Generating uniform proof CRS from an honest sampler is not a substitute for N-of-N malicious setup. A corrupt party could plant b_ch=As+e with retained s and immediately decrypt edge challenges, so unbiased public coins and robust abort handling remain necessary. The entire public ceremony transcript T must admit both distinct computationally indistinguishable programmed distributions, with private trapdoor known only to the reduction:
    (T,A,U_col,U_ch,aux) ~=_QPT (T_col,A,As_col+e_col,U_ch,aux),
    (T,A,U_col,U_ch,aux) ~=_QPT (T_ch,A,U_col,As_ch+e_ch,aux).
These are not proved by plain XOR/reveal when corrupt parties may adapt, cancel, selectively abort, or when the simulator must explain an earlier honest commitment without knowing their later contributions. No ideal coin-oracle, programmable random oracle, unproven quantum extractor, or trusted setup is silently inserted. This is the next *setup* equation.

## Larger unsolved release problem

The central Build/Lift for arbitrary ORIGINAL NP witnesses remains absent. AXLR signed-XOR is efficiently decidable and cannot provide generic hard-TRUE recovery security. An LWE pad hybrid without jointly simulating all SOURCE opening data, legitimate checking keys, capsule correlations, malicious setup, and related capsules is insufficient. Arbitrary unauthorized final-key recovery/native forgery must imply extraction of an ACTUAL ORIGINAL witness or an independent QPT break; no attacker-supplied representation is assumed. N-of-N no-bypass custody, pre-funding DA, actual qualified SYS/BTC fork/auxpow/ancestor/window/tags evidence, one-honest observer timely inclusion, and hypothetical native BTC SLH-like path remain separate unsolved obligations.

## Execution and provenance

Exact published JavaScript checker executed twice deterministically within the tool runtime. The larger local Node 22.16.0 reference checker passed 6,070 assertion/check events twice with byte-identical output, including 96 public-coin ciphertext openings, all 81 K4 false assignments with private HYBRID decryption, 96 simulated encrypted-edge rounds, and the full tiny leftover-hash public-key universe of 59,049 possibilities. Both checkers are toy algebra checks, NOT QPT security tests. Full local derivation/source/output/provenance are separately archived in WKEM_MINK_DENSE_CRS_20261101_OFFLINE.tar.gz. No external research, production change, approval, merge, or deployment.
