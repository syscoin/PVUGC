# R204 / CHECKPOINT_01 — authenticated dynamic-claim carrier inside a fixed withdrawal slot

Status: genuinely unfinished bridge-source compiler investigation, **NOT** a witness-KEM, not a QPT security claim. The focus is the interface between R191's fixed txid / variable SegWit witness activation and the frozen Build(x,sigma) requirement.

Continuity: syscoin/PVUGC draft PR #1, actual branch research/pq-wkem-validation-20260918, starting head 3e1d2f507ff4dd797de713bf88d880572e74612e; the newest read R203 MASH note is research/pq-wkem/r203_source_normalizer_20261110/RESEARCH.md, exact Git blob 06c1da021ae998aa54544b468928d9fb32d247a5. The last read ordinary PR comment query since 2026-11-10T14:00Z returned no comments. No web/external literature, production changes, quantum simulator or independent agents.

Hypothesis: stop trying to precommit the eventual notary-selected claim A as part of Build's public input. Freeze instead the *withdrawal slot policy* x_slot and the same preauthorized cancellation message/signature, and make the Bitcoin-confirmed activation A a component of ORIGINAL evidence w. Source authentication of A must be cryptographic, not merely notary text. The verifier is not on Bitcoin.

Proposed fixed statement:
  x_slot=(vault outpoint, spend/activation txid, permitted claimant/notary keys,
          exact cancellation tx/message/VK, funding/anchor and source policy,
          challenge/timeout schedule, required fork depth, capsule id).

Witness:
  w=(activation tx with raw SegWit witness, block/header and coinbase witness
     commitment inclusion, signed assertion A, challenge selector j, challenge evidence e).

Semantic target:
  R_slot(x_slot,w) =
     AuthBitcoinActivation(x_slot, activation, inclusion) AND
     SigAndClaimScope(x_slot,A) AND
     [R1_qualified_more_BTC_work(A,e) OR R2_bound_burn_fault(A,e)
      OR R3_claim-prefix_SYS_fork_or_tag_fault(A,e)].

The cancellation native signature is fixed for the slot, **not** for any as-yet unknown A. The future claim A is nevertheless exact and authenticated in the ORIGINAL relation via the parent wtxid/coinbase witness commitment; different SegWit witnesses have the same txid but different wtxids with overwhelming collision-resistance qualification. An accepted witness for each valid challenge must identify the single claimed *canonical* activation and the source fault relative to it. Comparing two different activation witnesses from two forks without the prescribed BTC anchor/work rule must not silently count.

Potential benefit: this is a polynomial-size, fixed-statement compiler for any later one-notary A (as long as source data lengths/window are bounded), avoiding an online N-of-N capsule-update round or exponential table of claims. It is only a **relation compiler**, and its claim of static-policy usefulness is contingent on being able to bind activation through an authorized pre-signed graph. A post-hoc notary claim without Bitcoin witness inclusion must be inadmissible.

Tests to run in this pass:
  (1) same parent txid and cancel outpoint with altered A but distinct wtxid;
  (2) witness Merkle commitment binding to actual mined A and rejection of substituted A;
  (3) absence of arbitrary offchain A being able to trigger challenge;
  (4) cross-slot/cross-claim replay rejection;
  (5) same cancel signature target independent of claim;
  (6) source branch input must be qualified under R1/R2/R3, not free Boolean caller flags;
  (7) catch any circular manifest/capsule commitment or mutable source slot.

No Open_release was defined or proven: the exact unsolved equation is
  Build_hash(R_slot,x_slot,sigma_cancel) -> C
  Open_hash(C,w) = same sigma_cancel for EVERY ORIGINAL-valid w,
  and arbitrary full-public QPT recovery/forgery -> ORIGINAL w or independent
  PQ hash/native break.
A normal verifier that returns a public secret and a secret derived from H(wtxid) both fail. Source auth is *inside the relation* here but not yet inside a cryptographic release mechanism.
