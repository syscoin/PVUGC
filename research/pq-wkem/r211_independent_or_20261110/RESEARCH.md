# R211 — Independent OR encapsulations for the three original challenges

**Scope:** Conditional constructive OR-composition theorem only. NOT an instantiated hash-only source-dependent KEM, PQ security result, practical bridge, or generic witness encryption. The missing actual leaf Encap/Decap and its original-source QPT extraction remain unsolved.

## Provenance

syscoin/PVUGC draft PR #1, branch research/pq-wkem-validation-20260918. Starting head 7fddc1c1414436ca1d2756ba2d6be1b9ca0a0c9f, R210 research blob fb145c68915094d63208869e4d4ea3200f8d5da6; narrowly related R209 Merkle-source note blob f3ad3b4f3f69c43f9a245cc204089fe29818d558. Latest ordinary PR comments since 2026-11-10 12:00 UTC: none. Intermediate CHECKPOINT_01.md was published BEFORE tests, commit 99b3239aec7841f90d82e188dd81451df8aabd32, non-force expected-head advancement from 7fddc1c. No internet/literature, unrelated repo, agents, real mining, native PQ signing or QPT experiments.

Full local checker.py actually executed twice with byte-identical outputs (264316 finite algebraic assertions); SHA256 source 024e54a4d87e176f7beec9fb79eb7fc232d9d76067fee871208672679643d290, captured.json SHA256 d7f74535b024224be061d601f6df386bd16838c9290225fe4b2e28eb7b3104a7. Full checker/output remain LOCAL ONLY. The accompanying short repro.py and repro_output.json were separately executed twice with byte-identical outputs and are published with this note; local SHA256 1393b6780acf3d16f6412006c59b6c502112c915e8a8ad1ba46a4eb039f4cbf9 and 457b107d0dcffe6b3ea7eaa3d9303beead72fe85f38c4068073453c4bbd5ccda respectively. All checker work is synthetic algebra, not source consensus/KEM validation.

## Exact original relation

For fixed x_W bind exact vault/claim UTXO, one-notary withdrawal assertion, actual burn ID/authorization/recipient/amount, source roots, BTC/SYS anchors/branch/height/window, deadline/DA/reset/fork-depth, exact native cancellation message M and VKs, N-of-N graph, capsule ID and context. ONE of the three conditions must admit permissionless cancellation: R1 authenticated contradictory greater-work Bitcoin history with difficulty/target verification and a common comparison anchor; R2 finite authenticated invalid/nonexistent bound burn (not failure to find a Merkle inclusion path); R3 qualified source-prefix-incompatible Syscoin histories or separately authenticated applicable tag fault, with genuine SHA/AuxPoW/coinbase, header ancestry, interval tag and child-height verification. Same child under two parent work certificates is not a fork. No winning Syscoin fork selection or online notary challenge approval. Source verification must be cryptographically necessary for release, not only an honest Open if-statement.

## Named composition algorithm: INDEPENDENT-OR-KEM

For honest N-of-N participant h, independently freeze native signature sigma_h of L bytes on EXACT M, known VK_h. For j in {1,2,3} choose fresh independent rho_hj and run hypothetical original-source-specific classical PPT Encap_j(x_W;rho_hj) producing public C_hj and secret K_hj in {0,1}^{8L}. Publish P_hj=(j,C_hj,D_hj) where D_hj=sigma_h XOR K_hj. To open with an ORIGINAL witness for branch j, compute k=Decap_j(x_W,C_hj,w), s=D_hj XOR k; return s if native Verify(VK_h,M,s), else reject. Exact necessary leaf completeness is Decap_j(C_hj,w)=K_hj for EVERY R_j(x_W,w)=1. Then every qualifying witness for any branch recovers precisely the SAME precommitted sigma_h. Repeat independently for each N-of-N participant. The Bitcoin cancellation needs all native signatures, no invented PQ aggregation; challenge grounds are OR within every participant, N-of-N applies only to graph/signatures.

This wrapper is a literal algorithm **conditional on the missing leaf algorithm**; it neither invents a source issuer nor treats an idealized release oracle as a solution. Its constructive simplification is that branch keys K_h1,K_h2,K_h3 NEED NOT equal one another. The exact same native capability emerges by independent XOR pads, so the cryptographic leaf obligation can be investigated separately for each ORIGINAL Rj without requiring an additional common-key correlation theorem across the three predicates.

## Conditional full-public QPT theorem, proof, scope

Assume fixed/pre-capsule x_W and an efficiently preparable setup/source/public view Z including arbitrary allowed nonuniform quantum advice, native VK, full claim/aux/checking/context/related capsules and retained malicious source coins; the honest signer SK and fresh encapsulation randomness must remain private. Source/auxiliary can be maliciously chosen before honest independent rho_hj, and later source strategies can adapt to published capsules. Other public graph fields, corrupt-party data and off-target signed messages must be simulatable without sigma_h; honest M-signature appears only in the protected D_hj. No replay or bypass native signature edge.

For EACH j, if independently proved for its ORIGINAL source relation, assume its full-public QPT real-or-random key game distinguishes (C_hj,K_hj) from (C_hj,U_hj) only negligibly on the relevant FALSE/hard-TRUE instance distribution, even with independent other capsules and all permitted auxiliary/oracle interfaces. U_hj is independent uniform of L bytes. TRUE with efficiently obtainable original witness is intentionally NOT covered: Decap would distinguish, and that is authorized. For hard-TRUE the required full-public QPT source-to-original-witness/independent-PQ-break reduction is still missing; no black-box classical extractor is presumed.

Define G_t for t=0..3 by replacing the first t pads D_hj=sigma_h XOR K_hj by sigma_h XOR independent uniform U_hj, keeping C_hj genuine. Each adjacent pair is simulated by a straight-line QPT reduction to the j-th real-or-random leaf game: locally create native SK/sigma_h and all other capsules, use challenge value T for D_hj=sigma_h XOR T, and invoke A exactly once with the same allowed quantum oracle interfaces. No rewinding, forced query trace, or internal representation. In G_3 all D_hj are uniform and independent of sigma_h, as are all C_hj. Hence G_3 can be simulated from VK_h alone, without any signature on M. If A outputs an accepted N-of-N cancellation, its honest-h component is a valid native signature on M never requested from a signing oracle: a native EUF-CMA forgery.

For any QPT A within these exact assumptions:

Pr[unauthorized accepted N-of-N cancellation in G_0]
 <= Adv_EUF-CMA_native(B_native)
   + sum over j=1..3 Adv_QPT_real-or-random_Leaf_j(B_j)
   + Pr[graph/setup binding failure].

To transform any nonnegligible leaf distinguishability into the user's required ORIGINAL-witness-or-independent-hash-break result, EACH such leaf needs an actual source-dependent QPT reduction, including malicious source coins, related capsules and auxiliary-input correlations. No such hash-only Encap_j/Decap_j has been instantiated. This is a conditional composition theorem, NOT bridge security.

## Two necessary restrictions

1. Public CK_j=H(K_hj) is incompatible with this standard raw-key real-or-random assumption: when handed candidate T, a QPT or classical distinguisher checks H(T)==CK_j and separates real from uniform almost surely. Likewise a public H(sigma_h) is not simulatable in the final native EUF-CMA game without signing M. Use the native public VK/M to check the reconstructed signature, or derive a DIFFERENT rigorous joint model if these hashes are indispensable. Merely invoking collision/preimage resistance does not fix the candidate-key comparison attack.
2. Merely preventing recovery of each full K_hj from each individual capsule is inadequate. Explicit 2n-bit counterexample: K1,K2 independent uniform, D1=sigma XOR K1, D2=sigma XOR K2; C1 publicly leaks upper n bits of K1, C2 lower n bits of K2. Each individual capsule leaves n unknown bits, but the two together recover ALL bits of sigma in polynomial time without any original witness. The executed toy reproductions implement this exact leak for 16-bit examples. Full public IND/pad secrecy, not marginal one-wayness, is the reason for the hybrid premise.

## Still-unsolved deployment and proof obligations

No actual source-dependent KEM leaf or QPT hard-TRUE source extraction. No automatic authentication from hash commitments, fabricated fork bytes or a post-hoc source verifier. Honest pre-funding audit of malformed capsules, setup abort/useful completeness, signature confidentiality/erasure, source DA and censorship/reorg, chosen-later one-notary assertion binding to frozen signatures/capsules, N-of-N graph constraints, and the conditional native no-EC-key-path SLH-like endpoint are not implemented or proved. No single generic NP construction is presumed. Do not resume R209 Merkle hidden rows, R210 public work prefixes or retained-source-label OTS as if repaired.

NEXT original-dependent work: construct a genuine hash-only Encap_3/Decap_3 tied to REAL source-certified R3 AuxPoW/Syscoin claim-prefix inconsistency, with every-valid-witness SAME hidden K and full joint-public QPT FALSE/hard-TRUE witness-or-PQ-break security. Wrapper correctness is NOT completion and the research task stays enabled.
