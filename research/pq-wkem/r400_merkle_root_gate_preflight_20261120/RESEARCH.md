# R400 — witness-selected Merkle-root binding preflight (NONQUALIFYING)

## Continuity and purpose

Read existing open/draft PVUGC PR #1, branch research/pq-wkem-validation-20260918, at \`c39dfb4a46cdc5664903fec3d6cac42649dcf93d\` (R399) with source note blob \`c0f4addb3d6bca1c12a51fdb5618659f484edb32\`. Read exact R398 note blob \`edc6bf78805accdd6757b218083d95205a08cea6\` and R397 note blob \`f1452084a76c34ccce422d448e333664b00b3509\`. Recent ordinary PR comments since 2026-11-19T00:00:00Z returned none. No Core source, native verification, source certificate, quantum experiment, or external source was used in this iteration.

Objective: attempt a *different* consistency boundary for a public source-release circuit, not another change of basis, masking polynomial or matrix conjugation. Earlier public local garbled-correction labels could be mixed from inconsistent partial assignments (R289); R397's publicly invertible global gauges also failed. The proposed change is to make every local observation attest one **single opener-chosen Merkle commitment** to the entire ORIGINAL certificate, instead of only locally permitted bits. The exact question is whether this makes an independently constructible hash-only release compiler possible rather than merely adding a public verification wrapper.

## Proposed witness-selected root and exact binding

Let \`R_x(w)\` be the unchanged ORIGINAL OR challenge relation, with contextual AuxPoW, relevant source ancestry/work, authenticated burns, claim/outpoint, deadline/reset and required LC depth. The builder knows \`x,S\`, not future qualifying \`w\`.

A later opener with a certificate \`w=(w_1,...,w_n)\` can choose a canonical length/index/domain-separated hash-Merkle commitment \`r=MerkleRoot(w)\`. For each source-verifier gate or clause \`j\`, include the needed leaf values and authenticated Merkle paths under this SAME root \`r\`. If an adversary opens an index \`i\` under \`r\` as both 0 and 1, accepted paths yield a collision in an underlying canonical tree hash (assuming fixed leaf count, index, exact paths and binding; this does not prove that a committed witness is valid).

That is a **genuine global witness-consistency check** at the level of a public verifier. It does not release any private share. The missing cryptographic operation is conditional release:

  \`Release_j(C_j,r,a_j,paths_j) = k_j\` only when the local assignment \`a_j\` is authenticated under \`r\` and satisfies clause \`j\`, while arbitrary processing of PUBLIC bytes \`C_j\` does not recover \`k_j\` otherwise.

For the complete circuit, all clause shares must belong to one common \`r\` and all ORIGINAL authenticated source checks must hold, with the same frozen capability S for every valid future r. This is not obtained just by publishing r or its hash.

## Precise build-time obstruction and adversarial execution

There are two ways to try inserting r into symmetric SHA masking:

1. **Build fixes a root \`r_0\`:** publish \`E_{j,a}=k_j XOR H("share"||r_0||j||a)\` for allowed local values, and require a Merkle path under r_0. This binds the public table to ONE prespecified certificate commitment. The builder cannot choose the commitment for ALL unrelated future ORIGINAL witnesses. Requiring every future certificate to have r_0 silently changes the relation.

2. **Open chooses r:** builder must serialize one public capsule that works for all future r, without knowing r or future Merkle paths. If the builder publishes per-allowed-local-value masks using only public \`H(r||j||a)\` derivations, the adversary itself chooses any r and any local a_j, computes all those public hashes, and combines locally permitted shares **without one committed witness**. If the publication keeps r-dependent secret keys private, it has not provided a public evaluator. Adding an ordinary external \`MerkleVerify\` check changes the honest invocation but not arbitrary processing of the public ciphertext/table.

Using a two-clause FALSE relation (\`w_0=0\` and \`w_0=1\`) makes the distinction exact. No single Merkle root admits correct openings of both different values at index 0 without hash collision. But local-public authorization tokens for \`(j=0,a=0)\` and \`(j=1,a=1)\` remain individually computable: public authentication is not a cryptographic restriction unless the share releases themselves enforce the common root. A verifier detecting inconsistency cannot revoke shares already recoverable from the public table. The argument does NOT claim that all possible root-gated cryptographic releases fail; it rejects the specific root-as-public-salt / root-as-wrapper construction.

The repair would have to create \`Release_j\` as a protected program verifying a membership relation for an *opener-selected* root while keeping the same fixed k_j hidden under arbitrary full-public processing. Nothing above gives its classical-PPT source-dependent compiler, joint public simulator, or hard-TRUE extractor. Assuming such a Release_j is precisely the missing conditional-disclosure/FE capability in narrower language, not an independent hash-only solution.

## Selection decision and next exact object

**Reject before implementation.** The global Merkle root really couples certificate bits *for an honest public verifier*, but it does not couple decryption from full public bytes. Known local-splicing applies unchanged unless cryptographic release is conditioned on the same root, and that conditioning has no independent construction here. Consequently no experiment of more Merkle sizes, circuit clauses or random salts is justified. No code/test execution or Core result is claimed. This prevents another misleading numbered 'success' from a public verification improvement.

The needed advance remains an ACTUAL classical polynomial-time serialized \`Build_orig(x,S)\` and unrestricted-public \`Open_orig(C,w)=S\` for every ORIGINAL authenticated qualifying witness, with source-conditioned enforcement inside recovery, independent complete-public FALSE and hard-TRUE QPT security, original-certificate extraction or justified hash/native break, one-honest malicious setup, all related capsules, and valid native cancellation binding. R399's claim-ticket endpoint remains a separately conditional component. No easier relation, source-generated hidden label, offline verifier-only gate, or signer availability assumption is promoted.

NONQUALIFYING: no original release operation constructed; no breakthrough/progress comment, no production/Core changes, no deployment or automation modification.
