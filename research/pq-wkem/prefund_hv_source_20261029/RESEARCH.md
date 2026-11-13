# Pre-funding honest-verifier SOURCE certification: a jointly simulatable public transcript

**Restricted constructive component; NOT a complete witness-KEM, post-quantum implementation, or generic ORIGINAL-NP witness-release reduction.** This replaces the uninstantiated dual-mode NIZK suggestion in source_cert_joint_20261029 for an *honestly executed pre-funding interactive verifier*, not for arbitrary malicious verifiers. It removes a genuine full-public SOURCE-certificate correlation obstacle under the stated assumption. It does not solve the underlying witness-encryption problem.

## Provenance and exact earlier component

Current open/draft/unmerged syscoin/PVUGC PR #1, branch research/pq-wkem-validation-20260918, observed starting head a4ceb05b7e860cacd19eb99860f7e030320be528. Latest ordinary substantive PR comment inspected: 6510837176. Exact predecessor reads: unique_source_lift_20261029/RESEARCH_AND_CHECKER.md, blob 47e5ba4a8f4bf239ec5135c83a71e34a8e3b0041, and native_attested_joint_20261029/RESEARCH.md, blob fd092b3a343a97a413fa504b9b39d48f90956a83. No outside literature/web research, whole-PR diff, or unrelated repository changes.

The prior honest restricted SOURCE sampler takes A uniform over F_q^(n x m), s uniform over F_q^n, e from bounded independent chi^m, and b=A^T s+e (mod q), publishing H=(A,b). The honest dealer knows (s,e) at setup and erases it before irreversible funding. A separate genuine native signing key (pk,sk*) is selected; the existing N-contributor encrypted base-8 shares, same-scope related capsules, and domain-separated native-key-correlated setup authentication stay as in native_attested_joint_20261029. For any bounded restricted SOURCE opening, the honest release equation still is

    v_l - s'^T u_l = g*a_l + e'^T sum_i r_(i,l) (mod q),

and g>2NwB ensures the SAME native sk* for every valid restricted SOURCE opening. This does NOT give an ORIGINAL W the hidden source opening.

## Precisely instantiated source certificate

Define an NP relation R_SRC(H,(s,e)) which tests exact canonical modular equation b=A^T s+e, e entries in [-B,B], and correct base-q encoding. Compile this fixed polynomial-size Boolean verifier by the standard deterministic polynomial Cook/Karp reduction to a graph G_H=(V,E) that is 3-colorable iff R_SRC has an opening; a satisfying source (s,e) maps algorithmically to a coloring. The circuit-to-3COL implementation has NOT been implemented in this bounded checker and remains an engineering step; its polynomial reduction is unconditional, not a WE/iO assumption.

Use a classical polynomial-time G:{0,1}^kappa->{0,1}^t with independently stated **nonuniform QPT PRG security** on classical output (not a random oracle, not an unproved WE-like release assumption, and not a claim about the toy SHAKE implementation). The pre-funding honest verifier samples a fresh uniformly random public sigma of t bits, authenticated and scoped to one claim, graph, native pk and ceremony, with t >= 2*kappa + lambda + a safety margin. To commit to bit b, draw fresh uniform r in {0,1}^kappa and publish

    Com_sigma(b;r) = G(r) XOR (b*sigma).

A 3-color is independently committed as its two bits; 11 is invalid. The opening is both bits and both random seeds. All fields are canonically length-delimited and signed over exact values. There is no decryption secret or hidden commitment trapdoor.

For any fixed G, define D_G={G(r) XOR G(r') : r,r' in {0,1}^kappa}. Since |D_G| <= 2^(2*kappa), an honestly uniform sigma is outside D_G except with probability <= 2^(2*kappa-t). On this good-CRS event **no commitment can be opened to both bit values**, even by an unbounded or coherently quantum adversary; every vertex commitment determines at most one legal color. This is global binding over arbitrarily many commitments for this sigma, not a per-vertex union bound. QPT hiding follows by replacing fresh G(r) by uniform and then reversing, costing at most 2 Adv_QPT-PRG per changed bit commitment. For kappa=128,t=512, the bad-CRS probability is <=2^-256, with NO claim that any particular PRG implementation reaches 128-bit QPT security.

The honest dealer knows (s,e), derives a proper coloring of G_H, and for each of k independent rounds:
1. Randomly permute the 3 colors afresh, commit with new coins to ALL graph vertices, and send T_i bound to H, the claim/context, native pk and the fixed whole-capsule record. The honest verifier signs a receipt binding this first message.
2. Only AFTER receiving and signing T_i, the honest verifier chooses a fresh independent uniform edge index E_i and signs a challenge binding the receipt, graph, session and round.
3. The dealer opens the two color commitments at that edge; the verifier checks valid openings to distinct colors, verifies all context/sequence bindings, and signs acceptance or aborts the entire ceremony before funding.
4. Include the full public first-message/receipt/challenge/opening/acceptance transcript and all checking keys in D. The same genuine native sk* signs a distinct setup-authentication domain over the WHOLE D; actual native challenge-path sighashes are never signed. Every configured N-of-N preauthorization remains necessary, with one honest signer enforcing its own policy and excluding bypass edges. No online verifier or on-chain NP execution is added after funding.

**This requires one designated honest pre-funding verifier with a protected signing key, truly uniform sigma, receipt-before-unpredictable-challenge policy and an honest-erasure dealer.** A signed transcript cannot independently prove that the signer did not know or choose the challenge before the first message. An adversary with an unrestricted verifier signing oracle can counterfeit acceptable transcripts for FALSE instances. A N-of-N malicious-verifier protocol with one unknown honest signer, malicious setup, arbitrary challenge choice and a full joint simulator for those malicious verifiers is NOT proved by honest-verifier zero knowledge.

## Theorem A: QPT-independent honest-verifier FALSE-SOURCE rejection

For fixed FALSE H, G_H has no 3-coloring. Condition on good sigma. Whatever classical commitments T_i an arbitrary QPT prover fixes before an honest challenge, each vertex has at most one legal color across all possible future openings. Otherwise it would double-open one of the statistically binding bit commitments. If all edges could be answered, these fixed colors would constitute a proper graph coloring, contradiction. Therefore at least one of E graph edges is unanswerable for every fixed first message. Fresh honest uniform E_i after T_i gives

    Pr[all k honest rounds accept | FALSE H]
      <= (1-1/E)^k + 2^(2*kappa-t)
         + Adv_QPT-EUF-CMA(verifier signature for counterfeit protocol messages).

The bound remains valid for arbitrary QPT prover processing/entanglement and adaptively chosen classical first messages, as per-round conditional success is bounded without rewinding or extraction. The signature term is needed only if a fake completed transcript is submitted in place of authentic verifier participation. Soundness is **interactive ceremony soundness**, not soundness of an independently manufactured noninteractive transcript. This theorem assumes honestly generated verifier CRS, signing credentials, no signing-policy bypass, and abort before irreversible funding.

## Theorem B: witness-free straight-line full-public honest-verifier simulator

For any TRUE G_H and any valid coloring, an honest round selects a uniform random permutation of colors, so the opened endpoint colors for an independently uniform edge are uniform over the six distinct ordered pairs. A classical witness-free simulator instead selects E_i FIRST, selects two uniform distinct endpoint colors, generates honest color commitments for these and arbitrary fresh commitments for all unopened vertices, then obtains genuine signatures on the first-message receipt, E_i challenge and acceptance IN THE PUBLISHED ORDER. The endpoint openings have exactly their real distribution. All remaining color commitments are QPT-indistinguishable from real ones by the stated independent QPT PRG hiding, with cost at most 2 Q Adv_QPT-PRG over Q changed bit commitments (including all independent rounds). Signatures by the genuine same native signing key, or *legitimate classical nonchallenge signing-oracle queries*, are efficient processing of the changing transcript, not fake checking keys. This simulates the complete public proof for TRUE H without (s,e). The SAME straight-line simulator also makes passively accepting, genuinely signed proof records for a uniformly random, usually FALSE H, because the reduction controls the verifier; a real cheating dealer does not.

Hence the predecessor's ordinary decisional-QPT-LWE hybrid can now be run with *this restricted honest-verifier transcript present*. Given H=(A,b) from the LWE/uniform challenger, generate native keys or use the actual native checking pk and classical signing oracle in the native-EUF game, simulate the graph proof, generate all actual contributor-share ciphertexts and related capsules, and sign the full exact record. Reissue/re-sign the record when the protected contributor's ciphertext is replaced by zero during the existing leftover-hash hybrid. A SOURCE-opening oracle, planted challenge s/e, quantum rewinding, and adversary-volunteered representation are NOT needed. The full-public reduction retains source/claim/context, genuine native pk, off-chain certificate checking keys, all J pre-funded related capsules, admissible independently simulatable auxiliary inputs, and globally adaptive corruption of at most N-1 contributors as in the predecessor.

For the RESTRICTED honestly generated TRUE-LWE SOURCE and honest-verifier setup only, one resulting bound is

    Pr[unauthorized native key or fresh target forgery]
      <= epsilon_HVZK + Adv_QPT-DecLWE(SOURCE H)
         + N*(2 J L delta_T + Adv_QPT-native-EUF-CMA),

where epsilon_HVZK <=2 Q Adv_QPT-PRG for Q changed bit commitments, and
delta_T=1/2 sqrt((q^(n+1)-1)/(binom(m,w)*2^w)).
Assume independently nonuniform QPT decisional LWE for the EXACT source distribution, QPT PRG distinguishability security, QPT native signature EUF-CMA with **classical** legitimate setup-signature queries, and independent quantum advice not containing hidden SOURCE or native secret. No superposition signing/corruption oracle is provided. QPT coherent processing of classical public outputs is covered through these QPT assumptions, standard hybrids and statistical trace distance, not automatically lifted rewinding or knowledge extraction. The honest secret-bearing dealer erases sk*, s/e and complete shares/coins before funding; source-certifying interactive setup is completed before funding. Arbitrary adversarially secret-correlated auxiliary data, arbitrary related-capsule issuance after erasure, compromised verifier signing policy and malicious setup are excluded.

## Reproducible checks, scope, and efficiency

The exact standalone JS checker in this directory exhaustively enumerates all 3^4=81 colorings of false K4, with max 5 of 6 edges proper. For k=256, its honest-verifier false-acceptance upper bound is (5/6)^256 = 2^-67.33681. It also exhaustively checks a 5-bit-seed/20-bit-output toy commitment difference-set and exact opposite-bit binding for a good sigma, correct 3-colorable K3 endpoint proofs, and accepting simulated FALSE K4 local proofs. It explicitly labels these as *protocol logic tests*, not QPT proofs. The extended local Python checker separately passed 1,319 assertions twice byte-identically, including 16,384 tiny seed-pair checks, 36 signed real TRUE rounds, 36 simulator-generated FALSE rounds, all 81 K4 assignments, genuinely same-key Ed25519 signature correlation and context/challenge tamper rejection. SHAKE-256 and Ed25519 there are **functional mocks**, NOT a QPT PRG proof or PQ native signature. None of these small tests implements the arbitrary SOURCE-to-3COL reduction or native Bitcoin verification.

Per vertex per repetition the two 512-bit commitments require 128 bytes excluding openings/framing. Total size is Theta(k*V), and k=Theta(lambda*E) without a stronger gap-amplified verifier, so a large LWE-preimage relation would have astronomical off-chain cost. No practical runtime, native SLH params, or QPT hardness calibration was measured. This certificate is a mathematical proof opportunity and restricted composition, **not yet a practical source-certification implementation**.

## Exact unproved ORIGINAL-witness requirement

The native capsule still needs an independently justified classical-PPT, witness-free compiler Comp(R_original,x,claim,ctx,pk)->D and public off-chain Release(D,W)=the SAME precommitted native sk* for EVERY ORIGINAL W satisfying R_original(x,W). It must hide that secret in the full public view for EVERY fixed FALSE x and turn *arbitrary* unauthorized hard-TRUE key recovery or native forgery into an ACTUAL ORIGINAL W or independently justified QPT break, without demanding an internal representation. The planted-LWE unique-short-source obstruction is unchanged. Malicious N-of-N setup/abort/graph, original SYS/BTC qualification across windows, availability/censorship/reorg assumptions, and hypothetical no-EC native SLH-like Bitcoin path remain unresolved. This result DOES NOT meet completion conditions; leave the research automation enabled.