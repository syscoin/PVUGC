# HPW-HSS-20261109 — Hash-sealed complete verifier states, intermediate checkpoint

Status: construction attempt in progress, not a breakthrough, not a secure generic witness-KEM. No lattice, group-based primitive, online authority, external literature or efficiency optimization.

## Exact continuity

Repository syscoin/PVUGC, PR #1, branch research/pq-wkem-validation-20260918. Observed starting head 21ef9abc289e40c02bb119121978d813d222c60a, open/draft/unmerged. Read the exact current R166 research delta and hpw_20261108/resumed_2353/CHECKPOINT_05_QROM_AND_PADDING.md. A since-2026-11-08T23:00Z ordinary-comment read returned no new comments. R166 supplies a necessary implication, not a working primitive. The previous complete-witness table has exponential Build, and the conventional per-wire garbling fails on inconsistent reuse of witness bits. Those limitations are not assumed repaired.

## Candidate: one token per complete verifier configuration

For the original deterministic verifier, a configuration must include the program location, computation registers and the remembered value of every witness bit whose later reuse must remain consistent. For a source verifier this also includes every still-live authenticated claim, anchor, interval, header and parsing dependency, not merely a child-outcome hash.

Give each distinct configuration s an independent secret lambda-bit label L_s. Publish a hash-addressed transition row for each permitted transition s --(read i,b)--> s':

    tag_s = H_tag(context,L_s)
    E_s,i,b = L_s' XOR H_edge(context,L_s,i,b).

Include the instruction i in the authenticated row and domain-separate every hash. Root label L_start is public. All accepting configurations transition to a common random terminal label L_accept; rejecting configurations do not. Publish a frozen native capability sigma masked by H_release(context,L_accept), plus an independent terminal check hash. Honest Open follows the original witness's read values and reaches the SAME terminal capability for every accepted witness. Different witnesses may pass through different configurations and labels. This is a concrete attempt to bind global consistency inside key flow, rather than attach a verifier that a raw attacker can ignore.

The key issue is the compiler, not token size. It must generate the necessary state-dependent rows in classical polynomial time without enumerating all witness histories. Hashing a complete state into lambda bits does not by itself bound how many such states exist.

## Construction tests and attempted repair in this pass

1. Implement complete-memory transitions for ORIGINAL CNF verification, and verify that raw public transition closure has an accepting path iff an ORIGINAL satisfying assignment exists. The raw attacker receives no private labels or privileged issue helper.
2. Test the proposed polynomial folding: merge configurations sharing program location and local clause accumulator while omitting witness memory. On the repeated-read contradiction x AND NOT x, check whether state-specific hashes actually prevent a path that reads x=1 first and x=0 later. This is not the earlier per-wire garbling; it uses whole local-state hash labels, and specifically tests whether those labels preserve source history across merges.
3. Repair by retaining all live witness assignments. Measure exact reachable-state counts for a family whose verifier must retain n first-pass bits until later rereads. Distinguish a lower bound for THIS verifier/read order from any claim about all possible generic constructions.
4. Test a full-evidence synthetic hash/PoW verifier whose statement binds claim, anchor and a baseline child outcome. A second parent-work certificate for the SAME child must not be treated as a fork. No claim of Bitcoin best-chain membership or deployed Syscoin parsing will be made.
5. Examine replacing stored transition rows with the public rule L_next=H(L_current,step,b). Determine whether distinct accepting paths still obtain the precommitted terminal label without one correction per accepting path, a hidden evaluation key, or an online secret holder.

## Security and publication boundaries

The graph-path invariant is not yet an arbitrary-QPT key-recovery theorem. Full-public commitments, native VK, auxiliary data, related capsules, setup corruption and selective openings must be covered before making one. A source chosen after Build cannot acquire precommitted labels by a post-hoc validity check. The source metadata must be bound before use; neither fake work nor public header hashes supply secret correlation automatically.

This checkpoint is written before the new checker has been executed. No counts, successful simulation, native deployment or completed proof are asserted. Tests and any failed repairs will be preserved with exact source/output and a precise handoff. No ordinary top-level PR progress comment is warranted for this checkpoint.
