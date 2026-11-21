# R357 — hard-TRUE source-path soundness and implicit-edge cutoff

**NONQUALIFYING checkpoint; no ORIGINAL WKEM, native signature, independent full-public QPT proof or user/PR progress update.**

## Read continuity and design change
Read actual open/draft syscoin/PVUGC PR #1 head 5d6c8fb73d854522cf8edc834e9549d2c7b0e588 on research/pq-wkem-validation-20260918; R356 note at research/pq-wkem/r356_hash_locked_dag_20261118/RESEARCH.md, blob 8e161fe26a554b8de6e0d82e100b8c102cefed0a; and PR comments since 2026-11-16 (none). The previously examined strict post-PQ Core rules are context, not newly fetched/tested code.

R356 correctly transports one independently random target label through EVERY path of a *listed* acyclic graph, with its restricted honest-label QROM FALSE simulator. Its exact missing operation is to represent every unknown future original authenticated source certificate with a publicly usable polynomial-size source-sound graph. This pass attempts an on-demand single-edge compiler rather than another SHA-chain/affine correction and checks both its complete public output and the hard-TRUE witness-search consequence.

## Source-relative graph extraction lemma (no PoW hardness claim)

Fix a claim x and the approved ORIGINAL three-branch OR relation R_orig(x,w). Suppose a polynomial-size graph G=(V,E,s,t) is listed in the honest pre-funding public capsule, together with a polynomial-time algorithm Decode(x,p), and satisfies:

1. If an ORIGINAL witness w exists, an s-to-t path p exists in G (except negligible honest setup failure).
2. EVERY s-to-t path p decodes to an ACTUAL R_orig-valid authenticated certificate, including claim relevance, exact contextual/source checks, LC maturity and time window; there are no fake certificate or splice shortcuts.
3. The graph's topology is public even if all transport rows/vertex labels are encrypted.

Then the adversary runs BFS on the public graph in O(|V|+|E|) and calls Decode on its resulting path. On TRUE honest capsules this algorithm obtains a real ORIGINAL certificate in classical polynomial time, without decrypting any encrypted edge labels. Thus this particular explicit-topology compiler cannot coexist with *capsule-relative hard-TRUE witness-search security* for a source distribution where qualified original witnesses exist but remain computationally hard to find given the public capsule. This statement is **conditional on such a distribution**; it does not establish Bitcoin/Syscoin PoW hardness, an NP-completeness claim, a hash-only WE impossibility or any unconditional lower bound on implicit cryptographic graphs. It is sharper than R356's general polynomial reachability remark: it directly addresses the original hard-TRUE extraction model and applies even to the special source relation.

This excludes treating a small, complete, source-sound explicit graph as hidden cryptographic access control. Hidden labels do not hide an already-public source-witness-producing route. R356 remains a valid restricted path-transport component but does not become a source compiler.

## Candidate I357: source-gated on-demand hidden-edge row

In the QROM *design formula*, choose uniform independent hidden K_t and public K_s, capsule ID cid, fixed safe native cancellation S, and independent domain-separated H_edge/H_end:

  Row_x(w) = K_t XOR H_edge("I357-edge" || cid || x || w || K_s)  if R_orig(x,w)=1; otherwise bottom.
  D        = S   XOR H_end("I357-end" || cid || x || K_t).

For any valid, complete ORIGINAL w, a public opener could obtain Row_x(w), remove H_edge to obtain the SAME K_t for all w, then decrypt D. This requires no shared future nonce, canonical certificate, equal SHA digest, or per-future-witness table. Unlike R354's linear flows, it has one atomic whole-certificate opening rather than independent local gate labels that can be mixed. The essential unresolved issue is NOT this correctness algebra; it is **actual classical-PPT public serialization of Row_x without exposing K_t**.

Attempt A: publish transparent code implementing if VerifyOriginal(x,w) then K_t XOR H_edge(...) else bottom. The code must contain K_t, and an adversary with the full public bytes reads it directly. API-only secrecy or a post-recovery honest verifier is insufficient.
Attempt B: expose a public row formula without the verification gate, to avoid a source-dependent table. Any invalid/unrelated w obtains K_t just as a valid witness does. This violates FALSE security.
Attempt C: publish a Merkle root of pre-enumerated gated rows or a public/secret PRF-seeded implicit row table. A root does not produce an undisclosed future row; enumerating unknown future source certificates is exponential in the proposed source window, a public seed permits unauthorized derivation if the gate is absent, and a secret seed requires a public functional evaluator that is itself unconstructed. Hashing source transcripts first does not cure this.

A compact secure whole-certificate Row_x would immediately solve the *same* missing source-release cryptography, rather than follow from R356 or from ordinary collision/preimage security. One cannot count that abstract gate as an independent premise. There is presently NO concrete public Build_inc/Open_inc for the original three OR branches, nor a joint-public FALSE/hard-TRUE QPT simulator, native forgery reduction or malicious-source/setup/sibling composition. Do not count this as security progress.

## Executed, bounded synthetic checker
CPython standard library script was executed twice with byte-identical JSON. It defined a toy SHA256 prefix predicate for a synthetic fixed claim (12 constrained bits over 65,536 nonces). Enumerating to BUILD the listed graph already solved that source search; a public BFS immediately decoded qualifying nonce 601 from one of the public paths. A private implicit gated row opened one fixed label on valid nonce, but literal program serialization exposed that label. Removing its source gate opened on an invalid nonce. This is regression evidence for the proof obligations, NOT Bitcoin/Syscoin source admission, native PQ signature verification, QROM security experiments or a real source witness.

LOCAL-ONLY exact checker: /mnt/data/r357_source_graph_hardtrue/check.py, SHA256 fc0a1d5af95a2730dde5f3f040cf071dd3dbf2ee4a94fa30f131f978c1f8cb57.
LOCAL-ONLY output1.json and output2.json, each SHA256 859387a3505790b56d78db71a980852df8a0b7b76b216a1c305b10a662a8e42a.
The full expanded local derivation is /mnt/data/r357_source_graph_hardtrue/RESEARCH.md (SHA256 711a748c046128e50c3e2d29fc0fbffe1c2c4b9f5fc315dcfaf4662a8d0d5507); no assumption of persistence across sessions. This GitHub note is the portable handoff; the checker/output are NOT claimed as GitHub-published.

## Decision and exact next operation
Do not devote further run cycles to merely enlarging the explicit graph, a publicly inspectable literal if-gate, Merkle roots without preimages, arbitrary public hashed source pads, direct unmerged SHA paths or another affine mask basis. The remaining constructive target is an actually instantiated polynomially serialized, publicly inspectable, hash-only, **whole-certificate source-gated label program** where every ORIGINAL-qualified w recovers exactly one frozen cancellation capability, invalid/unrelated and spliced certificates do not, and full-public QPT hard-TRUE/FALSE security reduces to the actual ORIGINAL certificate or independent genuine hash/native break. It must not contain an online source-label issuer, hidden evaluator, setup-known future certificate, source-generated retained secret or primitive assumption already asserting this release property.

The relation remains: qualified strictly greater same-anchor BTC work OR finite authenticated particular-withdrawal burn fault OR LC-depth-qualified relevant Syscoin inconsistency/independently authenticated tag fault, enforcing modern contextual AuxPoW chain ID, exact canonical tags, complete header/coinbase/history/ancestor linkage, actual claim-prefix ancestry and claim/UTXO/burn/amount/recipient/anchor/window/reset/deadline/capsule/native message/VK binding. No greater Syscoin work or winning-branch selection; different valid parent certificates for one child are not automatically forks. Preserve the corrected R316 tag-lag interpretation (same stale tags do not defeat full-history LC fork detection), R225 native fixed-outpoint activation portability, pre-funding N-of-N erasure and setup-bypass restrictions, sibling capsules and malicious-source retained coins.

No PR comment, Core/production edits, deployment, publishing of progress claims, or automation change.
