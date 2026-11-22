# SAI116 — Explicit authenticated-state graph screening for source-release (NONQUALIFYING)

## Continuity
Live draft syscoin/PVUGC#1 was read at head `8f654a4da740fad4198c69a53a5296433b5459ae` on `research/pq-wkem-validation-20260918`; tree `9f2eadacd436e4b8d11bb2e5d1106035af72ff24`. Read SAI115 note blob `039a72cc5caedb4be14b79a3d14291b83759940c` and SAI114 blob `b208a894a0d6df4221bc1b4be2d66a136f06aa5a`. PR issue comments since November 21 returned none. No new Core source review, authentic source certificate, Bitcoin signature, FE, ZK or QPT test.

## Exact attempted change
SAI115's public globally ordered matrix word permits contradictory local choices of a repeated witness bit. This attempt instead uses a single globally consistent explicit finite-state graph with hidden state keys: a node stores prior bit choices, so contradictory occurrences cannot reach an accepting node. That removes this *specific* local splicing mechanism. It tests whether the repair maintains original source-acquisition work.

## Concrete hash-only polynomial compiler for an EXPLICIT DAG (not ORIGINAL)
Let G=(V,E) be an explicitly listed directed acyclic graph, with start s, public directed labeled edges e=(u,v,label), and accepting states F. The builder samples independent random 256-bit k_v for all nodes and publishes k_s. For each edge publish

  X_e = k_v XOR SHA256("edge" || k_u || id_e || label_e).

For every accepting vertex f publish

  Y_f = S XOR SHA256("release" || k_f || f).

Public Open follows a path from s to an accepting f, decrypting k_v using each X_e and the preceding k_u, then outputs S=Y_f XOR SHA256("release"||k_f||f). Every accepted path recovers the SAME preselected S, including different paths. Honest Build/Open is classical polynomial-time in the EXPLICIT |V|+|E| representation. The graph can remember previous variable values, so a prescribed path cannot splice contradictory values of a repeated bit. This is a toy finite-path-language capsule, NOT a compiler of the approved Bitcoin/Syscoin relation. Production would need authenticated edge decryption and exact source typing; neither is instantiated here.

## Public exploration defeats hard-TRUE work
Because all edges and ciphertexts are public and k_s is public, any adversary runs BFS over the explicit graph in O(|V|+|E|), recording predecessors. If an accept node is reachable, BFS constructs a path and evaluates those ciphertexts to recover S, even without first obtaining a source witness independently.

Dichotomy: (1) if its labels already constitute actual ORIGINAL evidence, the evidence is available by public graph search rather than the intended hard source work; (2) if labels do not constitute ORIGINAL evidence but S opens anyway, the capsule violates release authorization; (3) if some edge needs an external ORIGINAL source object before decryption, a genuinely source-dependent protected transition remains unimplemented. A symbol SourceTransition or a public verifier followed by an edge decoder is not a repair. This is an explicit-state/public-transition limitation, NOT an impossibility theorem for nonblackbox hash-only witness encryption, succinct protected state machines or original SHA.

If no accepting state is reachable, the graph-walk algorithm does not reach any accepting key. A full public FALSE-instance QROM security theorem would require joint analysis of correlations across all hidden node keys, ciphertexts, native VK and sibling capsules. It is NOT established by the toy check.

An exponentially enumerated state graph is not practical PPT Build. Public master seeds for compressing node keys disclose accepting keys; secret seeds alone do not provide a public algorithm for arbitrary unseen future edges. Neither constitutes a protected source transition.

## Original relation and requirements unchanged
R_orig remains three independent OR grounds: qualified same-anchor greater Bitcoin work; specific finite authenticated burn invalidity/absence; qualified relevant Syscoin history inconsistency or independently authenticated tag fault at actual LC depth. Use strict post-PQ contextual modern child ID and exact canonical SYS tag, not a stale-tag inequality test. R316 does NOT prove the user's strict-PQ LC misses forks. The capsule must bind exact claim/outpoint/assertion/burn/recipient/amount, source anchors/window/height, deadline/reset, safe Bitcoin message/VK, capsule ID and one-honest N-of-N setup; these were NOT implemented here.

## Actual bounded checker and output
Ran `python check.py > output.json` (exit 0) using SHA256 and fresh `secrets.token_bytes(32)` keys. Synthetic FALSE graph has one bit remembered across two contradictory local requirements and no reachable accept. Synthetic TRUE graph has two accepting paths. Public BFS opens S through both TRUE paths, while no accept is reached in the FALSE graph. No authentic source evidence or quantum processing was tested. Test package keys themselves are NOT published as public protocol material.

LOCAL-only checker SHA256: `50f6cdafad72f50b6c870aa0f6a8471bec05f19c39bf6fb6ee654d9f99bd49bd`.
LOCAL-only output SHA256: `720ed78d19b672d0d81475924cfe655372b77454e2edb882575997d986a3378d`.
Local archive SHA256: `063fab73fcfe176cdac5909237623b068af8dd32686bc277ebc2667aa1b1fbfa`. The local files are not represented as committed if only this note is published.

## Next equation and status
Still missing actual serialized classical-PPT Build_inc(x_W,S)->C and public Open_inc(C,w)=S for EVERY original qualifying witness, together with complete-public FALSE and hard-TRUE QPT recovery/native-forgery -> actual original certificate or independently justified cryptographic break, including malicious setup/source coin retention/sibling capsules. The attempted explicit-graph consistency repair is not the missing advance. No progress comment, user breakthrough notification, production/Core changes, deployment or automation change. NONQUALIFYING.
