# R226 continuation — OR-pad QPT hybrid and checking-key correction

**Status: conditional composition only. NO instantiated original-SHA/AuxPoW release, no native PQ implementation, no QPT security proof, no generic NP WE.**

Continuity: syscoin/PVUGC PR #1, research/pq-wkem-validation-20260918. The observed run start was 303c47e72a2120c0d3938cc979bd2315956f606c (parent 5558a95813df36f49fe5e41e8a832875d4adb4aa). Existing R226 CHECKPOINT_01.md was read at blob a25db5095ea9606a350326a824decb24576e7ab1. This pass published intermediate CHECKPOINT_02.md in 25ccb188b1b141bae5bb80a601a383dfda69d749. No internet/literature, external agent, PR-wide diff or production writes. Python standard library checker was actually executed twice with byte-identical output. Checker SHA256 b0372675d77915eae42095719a02aa7f06fa8d783dc97a339efdc698cb48be2f; captured output SHA256 313a8a9019b78ac2f2483fb999a0fe2b423b37bfc559e9b9add5e5f3544801b3.

## Named construction hypothesis OR-SEAL (leaf remains MISSING)

For each honest N-of-N ceremony participant i, freeze one native cancellation message M_i and its authentic unpublished signature sigma_i, before encapsulation keys are chosen. x includes the exact withdraw/slot/claim, source anchors, three complete original challenge predicates, cancellation path, native VK and ceremony constraints. Independently for branch j in {1,2,3} sample K_ij uniform in {0,1}^lambda and fresh r_ij. Attempt

    C_ij = EncSource_ij(x,K_ij;r_ij)
    V_ij = H_check("CK",x,i,j,K_ij)          [optional; changes security game]
    P_ij = SHAKE256("PAD",x,i,j,K_ij,L_i)
    D_ij = sigma_i XOR P_ij.

OpenSource_ij(C_ij,w) MUST compute exact K_ij from EVERY fully authenticated, relevant ORIGINAL source witness for branch j, without an online issuer, invented signers, synthetic headers or private oracle. Then sigma_i = D_ij XOR SHAKE256("PAD",x,i,j,K_ij,L_i) verifies under actual native VK, and every valid branch produces the SAME frozen sigma_i. This is conditional functionality, not an implementation of EncSource/OpenSource. Using SHAKE here repairs a security-game issue, NOT size/PRG optimization. All off-chain capsules/claims must be frozen before irreversible funding; later one-notary activation remains a binding problem. Slot-global versus activation-specific native message portability remains the R225 caveat.

## FALSE-instance QPT hybrid (exact conditional theorem)

The standalone branch-j *pad* game samples K_j, C_j=EncSource_j(x,K_j;r_j), optional V_j=H_check(x,j,K_j); it gives (x,C_j,V_j,Z_j,Aux) where Z_j is either P_j=SHAKE256("PAD",x,j,K_j,L) or fresh uniform U_L. Aux must include the exact public checking/native VK, source commitments, adversarial nonuniform advice and quantum-oracle context, plus any related capsules whose distribution may depend on challenged K_j. The leaf pseudorandomness premise is NOT established by SHA preimage/collision resistance, and EncSource remains MISSING.

For an x where ALL original challenge predicates are FALSE, define H_t for t=0..3 by replacing the first t D_j with sigma XOR independent U_L. To reduce H_(j-1) versus H_j, a QPT reduction samples the native signature and all independent sibling keys and capsules, embeds its challenged (C_j,V_j,Z_j), sets D_j=sigma XOR Z_j, and runs A once, forwarding its quantum queries. Thus H_(j-1) and H_j differences are bounded by the branch-j pad game, PROVIDED the honest ceremony distribution (including public source x, native VK, manifests and auxiliary data) can be generated with challenged K_j independent of siblings and outside-signature information. No rewinding or query-log extraction is used.

At H_3, all D_j are independent uniforms conditioned on x, C_j,V_j and sigma, so they add no information about sigma. If the public view supplies no extra unmodeled sigma-dependent leakage, any adversary outputting a previously undisclosed native signature on the protected cancellation message would then contradict the appropriately scoped native signature EUF game. A public hash of sigma is additional leakage and breaks the straightforward native-EUF reduction simulation. This theorem is ONLY a conditional FALSE-instance secrecy projection, not hard-TRUE recovery-to-ORIGINAL-witness, malicious setup, selective opening or a finished hash-source gate.

## Material correction to the RAW-KEY ROR game

If V_j=H_check(x,j,K_j) is public, a challenge that gives candidate raw key Z_j=K_j or an independent U has a trivial distinguisher H_check(x,j,Z_j)==V_j. Real accepts with probability 1 and random with probability near 2^(-lambda). The exact 4096-key finite fixture (SHA256) has advantage 4095/4096; see captured.json. This falsifies the RAW-KEY real-or-random *definition when a public raw-key checker is included*, regardless of source structure or quantum resources. It is not a cryptographic break of a source KEM with a more appropriate leakage-aware definition.

Repair the security game by omitting V_j and checking only the native signature, OR by demanding pseudorandomness of the *derived pad* conditional on V_j (as above), rather than pseudorandomness of a raw candidate K_j. The latter still needs an independently justified full-public QPT game and actual source-dependent EncSource. Separate hash domains or SHA preimage resistance alone DO NOT establish it against a capsule C_j potentially leaking K_j.

With naive D_j=sigma XOR K_j, any legitimately revealed sigma yields ALL sibling K_j by D_j XOR sigma, even if a sibling source branch was false. That invalidates naive claims of individual hard-TRUE extraction for every sibling following authorized release. It is not an early break for the already legitimately cancellable slot. Fresh domain-separated keys per claim are mandatory; same native spending message means the same disclosure class regardless of differing wtxid, as in R225. A pad KDF avoids automatically disclosing the *raw K_j*, but this conditional protection has NOT been proved for a real source C_j.

## Actual original-SHA challenge attempt and remaining equation

The actual evidence includes authenticated Bitcoin work, parent coinbase, child ancestry, relevant AuxPoW tag schedule, source state and claim-prefix qualification. Direct H(tag_baseline,tag_alt) has different outputs for different valid qualifying alternatives, so cannot define the same precommitted pad. Normalizing every accepted incompatibility to Boolean TRUE yields a publicly computable value and no hidden key. Privately salting that Boolean removes public opening absent a genuinely source-derived label-transfer operation. Simply executing VerifySource(x,w) before returning an openly recoverable secret can be bypassed. Merely authenticating the capsule root does not instantiate secret transfer. This exact attempted leaf remains missing; no counterexample test is dressed up as progress.

The unresolved ORIGINAL obligation is actual classical-PPT BuildSource_hash and public OpenSource_hash for every qualifying actual source witness, SAME K_i per source relation, FALSE security and arbitrary hard-TRUE QPT native-signature recovery -> actual original authenticated source evidence or independent QPT hash break, under malformed source, source-secret retention, auxiliary related capsules, malicious ceremony and quantum oracle access.

## Exact executed finite tests (not security experiments)

checker.py exhausts 4-valued key/signature toy algebra across three independent pads: all final hybrid-pad distributions uniform; 16 shared-seed joint leakage cases despite perfect individual marginals; 768 authorized-release sibling raw-key exposures; 64 same-native-message portability cases; 64 cross-slot raw-key reuse leaks; and an exact 4096-key public raw-key checking-hash distinction. All are algebra/distribution checks. No actual SHA/AuxPoW source verifier, key-release leaf, quantum cryptanalysis, native signature or deployed endpoint was implemented.

Next genuinely constructive step: instantiate ONE source-dependent leaf jointly with its QPT simulator; do not optimize this wrapper before that. This checkpoint alone does not warrant an ordinary progress comment.