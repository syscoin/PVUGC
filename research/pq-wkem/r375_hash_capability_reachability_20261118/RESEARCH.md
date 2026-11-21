# R375 — hash-capability reachability gate (NONQUALIFYING)

## Continuity and attempted repair
This execution started from open/draft syscoin/PVUGC#1 research/pq-wkem-validation-20260918 at head `52fdb1f0b078ef05843bc8b6258210cf92677a88` (R374). Ordinary PR comments since 2026-11-18T18:00:00Z were empty. The prior FE assessment was reread at blob `6cd435772422fdb740d36af25fd7a0f751f8737e`. No Core #609 source/tests, actual AuxPoW evidence, Bitcoin signature, FE compiler or QPT experiment was run.

R374's masked DFA published a final transition callable on arbitrary artificial predecessor states, leaking its acceptance label. **New operation tested:** replace public arbitrary-state transition calls with a SHA256-encrypted edge table requiring a reachable *secret predecessor capability*; the opening algorithm cannot inject an arbitrary intermediate token. Unlike R374's private reversible framing, this is an explicit public serialized finite-state Build/Open, and the direct suffix-injection interface is absent.

## Restricted Build/Open, fully specified

Consider a deterministic layered binary automaton with finite state sets S_0,...,S_L, transitions delta_i(s,b), a public initial state s0 and one canonical accepting terminal state yes. Build samples independent 256-bit labels k_(i,s) for each layer/state. It publishes initial capability (s0,k_(0,s0)), and for every actual edge (i,s,b) the pair

    ct_(i,s,b) = (encode(delta_i(s,b)) || k_(i+1,delta_i(s,b)))
                 XOR XOF_SHA256(k_(i,s), i,s,b)
    tag_(i,s,b) = SHA256("tag" || k_(i,s) || i,s,b || ct_(i,s,b)).

It also publishes

    h = SHA256("target" || k_(L,yes))
    D = S XOR SHA256("padsecret" || k_(L,yes)).

Public Open(C,w) starts at the published initial state/label and, for each input bit, verifies the edge tag and decrypts the next state/label. If the final label hashes to h, return D XOR SHA256("padsecret"||label), otherwise bottom. Every accepted whole word ends in the same terminal state/label, so same S is returned without requiring a shared witness/preimage. Runtime/storage are Theta(sum_i |S_i|). This is a small-width synthetically compiled automaton, **not the ORIGINAL SHA/AuxPoW relation**. The local deterministic checker includes the builder's fixture seed and is not evidence of cryptographic hiding.

## Full-public recovery defeats hard-TRUE source work

The initial capability permits a public breadth-first traversal. Maintain one authenticated reachable capability plus complete input-word representative for every reachable state at each layer. Expand each by both input bits using the published encrypted edges; deduplicate by next-state index. At most

    Q <= 2 * sum_(i=0)^(L-1) |S_i|

edge decryptions suffice to find any accepting state and an ACTUAL accepted whole word. If this table were polynomial-size for the ORIGINAL hard-TRUE source relation, it would make obtaining a corresponding original witness polynomial-time; it would not preserve the required Bitcoin/Syscoin proof-of-work budget. This applies to explicit canonical-state edge tables, **not to all hash-only witness encryption**.

The table does remove R374's *arbitrary unreached final-state probe*. But it replaces that failure with efficiently enumerable reachable state space. The test also has no complete-public FALSE, QPT, native-signature or sibling-capsule security argument. Any presumed honest-erasure setup does not make such a compilation secure.

## Attempted succinct repair and why it remains incomplete

Replace per-state tables with key evolution k_(i+1)=SHA256("step"||k_i||b). The table disappears, but distinct valid paths almost surely end with different labels and cannot decrypt one fixed D. Tested accepted paths 10101,10110,11001,11010 produced four distinct terminal SHA256 values. To regain witness-independent terminal convergence, the builder would need a correction for merging states that are not known at setup.

If the correction is a PUBLIC arbitrary-state transition, R374's invented-predecessor attack returns; if it depends on a PRIVATE state key, no public transition is implemented. Enumerating keyed transitions over unknown 256-bit source states is exponential. This was a concrete construction/repair iteration, not a generic impossibility claim, and none of these observations proves impossibility of a different compact hash-only compiler.

## Actual bounded execution and local-only artifacts

A Python3 standard-library checker in the local-only archive builds all SHA256-encrypted edges for a five-step maximum-width-16 machine, opens one common 256-bit synthetic payload for each of four accepted words, and opens nothing on an always-rejecting fixture. The public BFS recovered an accepting word after 62 edge traversals on the TRUE fixture; none existed for FALSE. The checker was executed once with exit code 0. There were no source-network tests or real FE/ZK/QPT/native Bitcoin signatures.

Checker SHA256: `7c22b2062be9d53bdf33be7936797a73a0958ff6a327dfa27e43e9c9f0ecb190`.
Captured JSON SHA256: `44b39cab7a471f66a7ab078ef026a084c40a21c62dd6e9c992ab2d0d98333c05`.
Complete local derivation+checker+output+provenance archive: `/mnt/data/R375_hash_capability_reachability_20261118.tar.gz`, SHA256 `30a28e5a50efc4fe7f64df74e62d6d9fc094fd18d8caf998552e4529767952f7`. These executable bytes are **not** committed in this research note.

## Remaining ORIGINAL-source operation, unchanged

Construct an ACTUAL practical classical-PPT globally consistent public compiler `C=Build_inc(x_W,S)` with `Open_inc(C,w)=S` for **every** qualifying authenticated ORIGINAL witness, returning the frozen safe signature, without local arbitrary-state injection, public polynomial work-avoiding search, witness-specific terminal labels, hidden online signer, source-generated secret or exponential state table. Prove the full-public joint FALSE/hard-TRUE QPT recovery/accepted-native-forgery -> actual qualifying original certificate or independent hash/native break under malicious setup, retained source coins, siblings, selective opening and nonuniform auxiliary input. Preserve all three independent ORIGINAL OR branches, strict modern contextual AuxPoW, maturity, anchors, claim/UTXO/burn/amount/recipient/deadline/reset/capsule/native-message binding; no greater Syscoin work is required for branch 3.

**NONQUALIFYING.** No PR progress comment, breakthrough notification, Core/production/main/workflow edit, deployment or automation change.
