# R295 — Nonlinear two-input join after the affine moment failure (NONQUALIFYING)

## Provenance and unchanged source obligations

Continuation of R294 (blob \`3655bc2689f2224405a6d42e071b92595219752a\`). Starting syscoin/PVUGC PR #1 head \`bf22ecf712f966b6270ce6f7ad784da00031adb8\`, branch \`research/pq-wkem-validation-20260918\`, draft/open. Read-only Core #609 metadata still at \`c91539de3c34937e57d7f5fda47c7b0502ff33f6\`; latest ordinary issue comment remains R225 #6796383617 (no new date-scoped comments since 2026-11-14). The source contract has NOT been narrowed: exact claim/UTXO, amount/recipient/burn, baseline and BTC anchors/window/reset, relevant height and semantic ancestor at h_rel, modern contextual AuxPoW chain ID, canonical 41-byte SYS tag, precise claim-parent-wrapper identity for tag faults, all LC depth and proof obligations, deadline and exact native cancellation message/VK/capsule ID. A valid greater-work BTC competitor, finite particular-burn fault, or relevant authenticated SYS inconsistency/tag fault is sufficient (OR). N-of-N is preauthorization, not the challenge quorum. No real source validation, Core tests or network deployment was performed.

## A failed global-consistency claim even on a TREE

For a finite CSP tree-decomposition, sample independent uniform r_(edge,separator tuple) and frozen K. Publish at every local accepted bag tuple a

    T_(v,a) = [v=root] K XOR XOR_(edge e incident v) r_(e, a projected to separator e).

For one common satisfying witness, one token per bag cancels each edge pad twice and yields the same K. It is tempting to infer that a publicly recoverable K implies a global consistent witness, because shared edge marginals must match. That inference is FALSE, even for an acyclic factor tree: marginal equality here is over GF(2), not nonnegative probability distributions.

Let the root accept only (x,y)=(0,0),(0,1),(1,0); a left leaf requires x=1; a right leaf requires y=1. Their conjunction is unsatisfiable. With independent masks a_0,a_1,b_0,b_1, publish the three root tokens R_xy=K XOR a_x XOR b_y and the leaf tokens L_1=a_1, M_1=b_1. Then the complete public transcript contains

    R_00 XOR R_01 XOR R_10 XOR L_1 XOR M_1 = K.

This is an exact source-free FALSE extraction. Root parity combination (00)+(01)+(10) has leaf marginals x=1 and y=1 but has no supported joint (1,1) tuple. Therefore treewidth alone does not repair R294's affine moment attack. The checker reproduced this extraction on 32 synthetic setups.

A restricted full-tuple-separator star control does hide K perfectly on the all-forbidden n=2/3/4 instances: the full public token matrix has rank equal to the pad-only matrix (16/64/256 rows) and no K-extracting functional. This is a special property of those finite explicit tables, not a general tree theorem; their public tuple enumeration also offers no SHA/PoW hard-TRUE security.

## Bounded nonlinear SHA join repair attempt

Preserve the same unsatisfiable two-leaf case. Build chooses independent private 256-bit labels u_0,u_1,v_0,v_1 and frozen K. The toy leaf factors disclose only u_1 and v_1; root publishes

    C_xy = K XOR SHA256("JOIN" || x_W || capsule_id || u_x || v_y)

for its locally permitted tuples (0,0),(0,1),(1,0). A party with the two matching leaf labels and the corresponding permitted root row can compute K exactly. With (1,1) also permitted at root, publishing C_11 makes that particular TRUE witness open the SAME K. Unlike affine sharing, the previous three-row XOR combination does not cancel SHA outputs with independent hidden labels.

A restricted *classical ideal random-function* argument is available: assume u_0,v_0 independent fresh uniform λ-bit strings, u_1,v_1 public, and distinct oracle domains. Conditional on u_0 != u_1, v_0 != v_1 and no classical oracle query at the three hidden inputs (u_0,v_0),(u_0,v_1),(u_1,v_0), their independent uniform outputs make all three C values jointly independent of K, even for fixed K and a native VK independent of those pads. A deferred-decision query bound is on the order of (2q+2)/2^λ + q/2^(2λ) for q classical oracle queries, including elementary collisions. This is NOT a QROM statement, concrete-SHA reduction, or security against setup-correlated auxiliary state. It does not handle unknown ORIGINAL certificates.

In 32 reproducible SHA256-based synthetic setups, 96 obvious false row + public leaf guesses did not equal K, while 32 toy TRUE openings did. These mismatches are tests of the formula only, not a security proof.

## Multi-capsule and source-authentication failures

For sibling capsules that reuse a pad P at any common permitted tuple, C_A=K_A XOR P and C_B=K_B XOR P. If a legitimate opening reveals K_B, then C_A XOR C_B XOR K_B=K_A with NO qualifying evidence for A. The checker reproduced this exact extraction in 128 synthetic pairs. Independent capsule-scoped pads removed this particular algebraic equality in 128 comparisons, but do not prove broader malicious-setup, related-capsule or selective-opening security.

**The source-release foundation remains missing.** This entire repair uses setup-issued hidden labels, not labels obtainable only from authentic future Bitcoin/Syscoin evidence. Its finite root table is precomputed from known 2-bit assignments; the toy TRUE witness is already publicly obvious. Replacing a leaf label with a SHA256d(parent header) value creates a row-issuance impossibility for this static table: Build does not know every future qualifying original parent certificate. Publishing seed/row-generation keys permits fabricated-source extraction, while keeping them private demands an online or assumed source-dependent issuer. An after-check cannot retract released native bytes. The known R280/R288 reusable-label splice regressions are not defeated by a single good nonlinear join.

Exact unfinished obligation: construct actual classical-PPT \`Build_inc(x_W,sigma_cancel)\` and public \`Open_inc(C,w)\` returning the SAME frozen safe cancellation for EVERY qualifying ORIGINAL witness, with complete-public FALSE security and hard-TRUE recovery/accepted-native-forgery implying an ACTUAL qualifying ORIGINAL source certificate or independent hash/native break under arbitrary QPT coherent access, advice, sibling capsules, honest/malicious setup and source-secret retention. In particular a static polynomial-sized \`R_x\` must admit honest future source-derived \`L_x(w)\` but no mixed-source joint extraction. This is a missing equation, NOT a constructed component. No new online signer, invented OTS labels, hash puzzle, lattice/group fallback, oracle-programmed concrete SHA, or Bitcoin verifier is assumed.

## Executed checker/provenance (local-only archive)

Python standard library, SHA256-derived reproducible synthetic pads (not production randomness): \`checker.py\` reports 23 assertions in each byte-identical final run; \`tree_repair.py\` reports 32 affine FALSE extractions, 96 mismatching nonlinear false candidate openings and 32 true openings in each identical run; \`sibling_check.py\` reports 256 assertions in each identical run. No Bitcoin/Syscoin contextual consensus, real SHA gate verifier, native SLH signatures, formal QROM experiment, or independent security audit was run.

Checker SHA256s:
- checker.py \`05af1fd6d59cadab37e45d9e2269eff11036ab041498433c259d80832fba206d\`
- tree_repair.py \`bafe339db98445646136f0ccb96e0d8aa71bbe1854591ae02f2cb266bbc1a9c0\`
- sibling_check.py \`e7c8d1c01567a03307f9ae40ced8fd3dd2eafa5b417364c47724b6774eac9501\`
- run1/run2 \`8fcc319665fe694fa7aeee11b410b4a07ff487cdb84e4a095223e03ce9ba3bb8\`
- repair1/repair2 \`3ce5e7e3c5568a1e59cc70696298d23c31d4fe64ae59c574df9466035cfdce35\`
- sibling1/sibling2 \`1f584bde9f14d10e4649769072d302a2411a79bea6c98dc946d9cb45b0b0cceb\`

Local complete archive \`R295_nonlinear_join_20261115.tar.gz\`, SHA256 \`9784320ea419f61fbc7a1cabe189e7b81399a8d23c779dc26a7cc5f4124ae9ba\`; source code/output archive NOT written to GitHub. No ordinary PR comment, production edit, merge, deployment, QPT proof or automation stop. Routine nonqualifying iteration: no notification is warranted.
