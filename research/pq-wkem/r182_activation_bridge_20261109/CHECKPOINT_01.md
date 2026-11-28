# R182 — Activated-claim source binding and noninteractive release: first checkpoint

Observed syscoin/PVUGC PR #1 branch research/pq-wkem-validation-20260918 at head 426af96e65fa4e48313b2767b561caf16e7f34ee (draft/open). Read only current R181 source-slot release and R180 frozen-root relevant notes, and newest relevant ordinary PR comments. This is an intermediate hypothesis, not a security claim.

Candidate: Branch-Anchored Annex Claim (BAAC) with a frozen N-of-N vault-input signature, variable input-1 one-notary signature binding its own annex, and a publicly authenticated claim activation (block, index, wtxid) that scopes all original challenges. The source-dependent challenge-key release would then depend on actual activation, not a notary-signed hypothetical assertion.

Test the actual Bitcoin SHA256d stripped/witness encodings with two distinct annexes and one exact non-witness body. Investigate whether input-local signature and a subsequent native cancellation signature bind the actual annex or only the fixed txid. Check a reorg where a different annex variant of the same txid appears on another chain.

Attempt repair: bind original challenge witness to mined wtxid AND qualified Bitcoin block anchor, bind the cancellation graph to one fixed activation slot, require evidence and reorg/reset conditions for both variants. Ask whether fixed N-of-N preauthorization can accommodate this without online re-signing, and whether it solves OR-gated release. It does NOT by itself supply Build_hash or Open_hash.

Execution note: this is the initial plan recorded locally before the checker was executed. No runtime counts, native signatures or quantum proof are claimed by this checkpoint.