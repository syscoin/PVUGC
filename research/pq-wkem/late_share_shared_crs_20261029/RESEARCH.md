# Shared-real-CRS ternary source certificate with honest-last challenge programming

**RESTRICTED CONSTRUCTIVE PROOF COMPONENT; NOT an ORIGINAL-NP witness-KEM, secure malicious N-of-N protocol, or Bitcoin deployment.** This is an alternative to the stronger per-position triple-equivocal active-verifier certificate: it removes its fake-CRS requirement and compresses real-CRS data, but explicitly requires a designated globally uncorrupted verifier to provide the LAST challenge share. Do not describe it as unconditionally superior.

## Provenance / exact unfinished step

Run: late_share_shared_crs_20261029; repository syscoin/PVUGC, PR #1, branch research/pq-wkem-validation-20260918, starting verified head 6e7c2ee6e603e3d2c1ef21e8861502a1e26b8355. The latest relevant ordinary comment 6513871959 and exact predecessor blobs 47e5ba4a8f4bf239ec5135c83a71e34a8e3b0041 (unique_source_lift_20261029/RESEARCH_AND_CHECKER.md) and 3019c759045aa250b40866dfdde181841146dd34 (prefund_hv_source_20261029/RESEARCH.md) were inspected. No external literature or full PR diff. The selected subproblem is to instantiate signed, adaptive adversarial co-verifier challenge correlations jointly with a SOURCE-certificate transcript that an ordinary-QPT-LWE challenger can simulate without the planted SOURCE secret.

The existing honest SOURCE remains H=(A,b=A^T s+e mod q), with prime q, A uniform, s uniform, independent bounded e; the signed-ternary N-contributor encrypted three-bit native key and genuine same-native-key setup attestation are unchanged. The relation R_SRC(H,(s,e)) checks the canonical bounded preimage equation. Compile that classical circuit to a loopless, nonempty simple graph G_H=(V,E) such that a real source preimage yields a 3-coloring and a false source has none. The general circuit-to-3COL code is not executed in this checker. Do not promote R_SRC to ORIGINAL NP: an arbitrary ORIGINAL W still cannot compute (s,e).

## Classical PPT setup, verification and opening

Assume a classical PPT PRG G mapping kappa-bit uniform seeds to t-bit outputs and independently justified nonuniform-QPT output pseudorandomness, with advice independent of its fresh seeds. A designated honest verifier, whose transcript-signing secret survives no adversarial corruption, authenticates one pair (sigma1,sigma2) of independently uniform t-bit strings, scoped to exact relation/statement, claim/UTXO, branch, anchors/window, graph, native checking key, source and related-capsule identities. Alternatively an honest LAST uniformly random CRS XOR contribution after authenticated corrupt contributions gives the same completed-session distribution; selective abort must terminate before funding and cannot be used to grind indefinitely. No hidden CRS trapdoor or fake CRS is generated.

Define offsets Delta_0=0, Delta_1=sigma1, Delta_2=sigma2. Every vertex/color occurrence uses an independent fresh uniform kappa-bit seed r, and publishes ONE color commitment

    C=G(r) XOR Delta_color.

The same GLOBAL sigma pair is reused across all vertex positions, rounds and independently keyed related capsules, but no seed or commitment vector is reused. Opening (color,r) verifies by recomputing C; illegal color/seed encodings fail.

One signed sequential proof round:
1. Given a real R_SRC opening, the honest dealer computes a proper coloring, applies an independent uniform permutation of three colors, commits every vertex, and sends/signed-scopes first message T containing all commitments.
2. The designated honest verifier signs a receipt for T before challenge generation.
3. An arbitrary N−1 corrupt co-verifier coalition examines the ENTIRE public record, prior interactions and T, and sends a classical in-range aggregate c in Z_E, or aborts. Its quantum memory and adaptive choice of c are unrestricted except for classical authenticated interfaces.
4. Only after c is fixed, the honest verifier samples h uniformly in Z_E. It signs its h and e=(c+h) mod E, binding both to the first-message receipt.
5. Dealer opens the two endpoints of edge e, proving two valid distinct colors. The verifier checks the exact signed chronology/context and signs acceptance, else aborts before irreversible funding.

Repeat k rounds with fresh commitment seeds/first messages/h; include complete CRS, T, c, h, e, opened seeds, signatures and session records in the public off-chain joint view. Full source/claim/graph/native-pk/individual and aggregate LWE ciphertexts/auxiliary/related-capsule correlations follow the predecessor's honest-sampled distribution. Native sk signs an authenticated full-setup record in a separate domain; the simulator can use the **genuine** native checking key and a legitimate classical nonchallenge signing oracle. No native challenge-path signature is authorized by this proof transcript. Bitcoin does not verify the NP evidence, trace or proof.

## Lemma A — one globally shared REAL CRS is statistically binding

For fixed G define D_G={G(r) XOR G(r'): r,r' range over all kappa-bit seeds}. Its size is at most 2^(2kappa). An individual commitment with two different valid colors would imply that one of sigma1, sigma2, sigma1 XOR sigma2 is in D_G. Each offset is independently or marginally uniform over t bits, hence

    Pr[ANY commitment anywhere under this CRS double-opens across colors]
        <= 3*2^(2kappa-t).

This bound has **no multiplier for vertex count M**, because the same good-offset property simultaneously constrains every commitment in the ceremony. It is information-theoretic even against coherent or unbounded attackers and after arbitrarily many other seed openings. For unopened positions, honest sigma is independent of fresh PRG coins. Replacing G(r) by independent uniform and back proves QPT computational hiding of one chosen color versus another with at most 2 Adv_QPT-PRG. Sequential replacement of Q unopened independently seeded positions across classical, adaptive QPT postprocessing costs at most 2Q Adv_QPT-PRG. Never replace a seed which is later opened; the theorem expressly authorizes only one edge/opening per new commitment vector.

## Lemma B — honest-last share admits a straight-line full-view simulator

Let the corrupted coalition's classical output c be ANY QPT-computed function of its quantum memory, the whole public source/capsule/checking-key/auxiliary record and the first message T; it is delivered before h. Real honest h is uniform in Z_E after c, so real e=c+h is uniform even conditional on the coalition's complete then-current state.

For TRUE graph G_H, consider an EXACT reparameterization: before building the honest first message choose target e* uniformly in Z_E, but continue to build an honestly colored commitment vector INDEPENDENTLY of e*. Obtain adaptive c and define h=e*−c mod E. Conditional on the first message and c, this h is uniform; signed (h,e*) and opened endpoints have precisely the real true transcript law, including adaptive c and any quantum co-verifier state.

The witness-free simulator retains e* but makes first-message commitments only to a uniform ordered distinct pair of colors on its two target endpoints; it assigns arbitrary dummy colors elsewhere. It receives c by a single straight-line interaction, sets h=e*−c mod E, issues genuine chronological verifier signatures (or legitimately available classical signing-oracle responses), opens exactly the two target endpoint seeds and obtains genuine native setup-domain authentication. The real TRUE opening colors at any edge are already uniform over six ordered unequal pairs because of the freshly random permutation. Only **unopened** commitments differ. The QPT hiding hybrid of Lemma A changes them to dummy colors even when the corrupt co-verifier chooses c after seeing all commitments, and preserves the entire full public view and honest challenge/signature correlations. No SourceOpen, quantum rewinding, adversary-supplied representation, fake checking key or fake PRG CRS is used.

The very same simulator handles a uniform, usually FALSE, LWE-challenge SOURCE by choosing one target edge and locally distinct colors. The resulting transcript is genuinely signed in the reduction but would not be obtainable by a real false-source prover against the truly random honest h. This is a *hybrid simulator*, not a claim of actual false-source setup acceptance. The simulator controls its honest-verifier private coins and credential and, for native attestation under the EUF-CMA challenger, uses ONLY authorized classical setup-domain signing queries. Conditional aborts before funding are handled by simply preserving the adversary's abort distribution under the QPT hiding hybrid.

For k rounds, J related capsules and independent first-message seeds, carry the adversary's quantum state through the sequential hybrids; if Q commitments are changed the additive distinguishing term remains bounded by 2Q Adv_QPT-PRG. Related capsules may share one native key only inside one fixed claim/path scope. Globally adaptive corruptions may expose up to N−1 contributor shares and all their coins, but must leave the same honest survivor uncorrupted across ALL capsules. No superposition signing/corruption oracle, secret-correlated arbitrary advice or post-funding issuance is covered.

## Lemma C — soundness against QPT false-source provers

For fixed FALSE source H its loopless G_H is not 3-colorable. Condition on good global sigma. Each fixed classical commitment vector can open at most one color per vertex; therefore at least one of E edges cannot be correctly opened to distinct endpoint colors, irrespective of a malicious prover's retained coherent quantum state. Because c arrives before fresh uniform honest h, e is uniform over E even if c depends on the full commitment vector. Each fresh round succeeds with conditional probability <=1−1/E, hence

    Pr[completed counterfeit false-source certificate]
      <= (1−1/E)^k + 3*2^(2kappa-t)
         + Adv_QPT-EUF-CMA(honest verifier transcript credential).

Soundness needs real uniform, signed and chronologically delayed honest randomness, a global uncompromised designated verifier, mandatory source check before any funding, and no bypass of N-of-N preauthorization. Unbounded retries/aborts and adversarial Bitcoin censorship do not imply useful completeness.

## Joint restricted QPT native-key-security bound and precise limits

Under independently assumed nonuniform QPT decisional LWE for the EXACT honest H sampler, QPT PRG security, QPT native EUF-CMA security for the actual native checking key with legitimate classical setup-domain signing queries, the predecessor's full-public survivor-specific signed-ternary LWE hybrid can include the preceding simulated certificate:

    Pr[unauthorized native secret recovery or fresh native target forgery]
      <= 2Q*Adv_QPT-PRG + Adv_QPT-DecLWE
         + N*(2*J*L*delta_T + Adv_QPT-native-EUF-CMA)
         + verifier-credential forgery if counterfeit records are allowed,

where L=ceil(native key bits/3) and
    delta_T=0.5*sqrt((q^(n+1)−1)/(binom(m,w)*2^w)).

These terms are conditional on honest SOURCE sampling/erasure, globally bounded N−1 corruption, fresh independent contributor coins and ciphertexts, simulatable auxiliary inputs and the full native checking-key/context/related-capsule correlations from the predecessor. They are not a concrete 128-bit QPT calibration. The public proof is SOURCE membership certification for an honest pre-funding interaction only, NOT a generic-NP opening or a safe public noninteractive SRC membership certificate.

## Measured component cost / incomparable trust models

At illustrative, UNCALIBRATED kappa=256, t=898 and M=2048 vertex commitment positions, the prior stronger arbitrary-active-verifier, **per-position fake-CRS** ternary certificate exposed 3*M*t=5,517,312 CRS-plus-commitment bits. This honest-last, global-REAL-CRS alternative exposes (M+2)*t=1,840,900 bits, a 66.634115% reduction in precisely that component. Its global bad-offset log2 bound is −384.41504 versus −373.41504 for M independently sampled offset pairs. This is also more compact than the prior honest-verifier two-binary-commitment baseline. It does NOT dominate the active-verifier scheme: globally shared offsets cannot provide its independent multi-position fake-mode equivocations using the same PRG construction. The honest-last chronology is essential to this alternative, and designated-honest-last is weaker than the target arbitrary unknown one-honest N-of-N model.

A K4 example has E=6 and needs 487 independent honest challenges to bound (5/6)^k by 2^-128. A large SOURCE graph has much greater E and prohibitive off-chain size. Source-to-3COL implementation, realistic memory/cost and actual QPT hardness remain unvalidated.

## Exact bounded evidence

The exact standalone Python standard-library script check.py was executed locally twice with identical OUTPUT.json, 3,966 successful assertions. It checks 48 toy color openings with one global CRS for cross-color binding, every one of 81 K4 color assignments and every pair of 6 malicious/6 honest challenge shares, five adaptive corrupt c functions over 64 ideal-hiding first messages, 144 pairs of two-round adaptive-policy couplings, and the illustrative global bad-offset and size arithmetic. Its SHAKE-derived 4-bit-seed toy G is NOT a secure PQ PRG. Ideal hiding transcript coupling by enumeration is NOT a proof of QPT security; the actual full-view argument relies on the stated QPT PRG hybrids. Exact independent local artifact includes the longer derivation and this provenance.

## Remaining ORIGINAL obligation / handoff

Still need witness-free classical-PPT Comp(R_original,x,claim,branch,anchors/window,context,pk)->D and public Release(D,W)=sk_star for **every** valid ORIGINAL witness W, always the SAME precommitted native secret with PK(sk_star)=pk. Must show full-public QPT secrecy for each fixed FALSE ORIGINAL statement and reduce arbitrary unauthorized hard-TRUE final-key recovery or native forgery to an ACTUAL ORIGINAL W or independently justified QPT break, without asking the adversary for an internal representation. The planted ordinary-LWE unique-short-preimage obstruction and missing SOURCE-dependent, jointly simulated ORIGINAL Lift remain unchanged. Malicious unknown-one-honest N-of-N generation/abort/graph, real SYS/BTC authenticated window/fork evidence, DA/censorship constraints, and hypothetical no-EC PQ native Bitcoin endpoint remain unsolved. No merge/deployment or automation completion is justified.
