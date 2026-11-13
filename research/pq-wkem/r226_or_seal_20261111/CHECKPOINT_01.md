# R226 checkpoint — independent branch pads for one fixed native cancellation capability

**Intermediate research, NOT a source-dependent hash release construction.** Repo syscoin/PVUGC draft PR #1, branch research/pq-wkem-validation-20260918, observed starting head 5558a95813df36f49fe5e41e8a832875d4adb4aa. Relevant prior R225 blob b674a938d3c45a43499666ad0cb41e9de5014895 and R224 blob 5e864459e396c4f200137b6ced04600da9fc7527 were read. One recent PR comment, 6796383617, concerned the activation-scope portability correction. No external web or literature.

## Construction hypothesis

For one fixed slot-global (or strictly claim-scoped, native enforced) cancellation message and one frozen native signature sigma, compare a *single* three-way OR capsule with three independent original-source branch capsules.

For each j in {1,2,3}, choose independent uniform K_j in {0,1}^ell where ell=|sigma|. Proposed future leaf Enc_j(x_slot,K_j) must be buildable before the later activation, and ANY genuine ORIGINAL R_j witness must publicly recover K_j. Publish C_j=Enc_j(x_slot,K_j), D_j=sigma XOR K_j. Anyone with one original witness for R_j would compute sigma=D_j XOR Open_j(C_j,w). All branches recover byte-identical sigma even though K_j are different. Use full-length pads for now; no PRG/packing optimization.

The resulting OR composition is not itself an implementation of Enc_j/Open_j. We must prove each branch's actual source-dependent, false-instance/hard-TRUE full-public QPT key indistinguishability or witness extraction; no such premise is established. In particular neither source-coin retention, invented OTS labels, normalized public tags, nor source-independent hash puzzles may be treated as a leaf gate.

## Security hypothesis to test

A QPT hybrid may replace the independent K_j used in D_j with independent fresh uniform U_j while retaining C_j, one branch at a time. If each branch key remains pseudorandom against a QPT adversary given source context, arbitrary advice, native VK, jointly visible sibling capsules (and related activation data), the final D_j are independent uniform pads, so a native signature forgery is the only remaining route. This is conditional: any accessible R_j witness correctly defeats confidentiality; hard-TRUE security must extract ORIGINAL evidence rather than merely assume inaccessible witnesses. No quantum rewinding or lifting classical proofs is permitted.

Compare the correlated version with a shared K across all C_j: marginal security of each C_j need not yield joint security. Independent pads permit an ordinary hybrid *only if the leaf games themselves include the relevant adaptive source/public-auxiliary correlations*. Check all 3 branch truth assignments and N-of-N signatures, and explicitly identify the missing branch algorithms.

## Next action within this pass

Derive the exact simulator/hybrid games, execute a bounded symbolic/functional check, and record where the original-source compiler remains absent. If the theorem is only a conditional wrapper, do not report it as a secure witness-KEM, practical bridge or unconditional SHA result.