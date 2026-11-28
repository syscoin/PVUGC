# R342 — Serialized hash-labeled source traversal: explicit state merging, no ORIGINAL WKEM (NONQUALIFYING)

## Provenance / selection

2026-11-17 offline bounded iteration; PVUGC PR #1 on `research/pq-wkem-validation-20260918` began at `140582bb0e6366150950d4ef8ed03e1328ce6a1b`, R341 blob `9cc4bcfca8c0614895115423982e176c91979f1c`, R340 blob `7281ee8e92b1292bca2feb91ec80a4db2c392c56`, R327 blob `ab7602bfc54403bf68294034557206f62d69a5dc`. Core #609 PR metadata only, head `c91539de3c34937e57d7f5fda47c7b0502ff33f6`; no Core test or admission. Top-level PVUGC #1 issue comments since 2026-11-16 were empty. No web, literature or agents.

Attempted structural change: replace R337 spliceable independent wire labels and R341 unknown future source-tap addresses with **one sequential keyed state** that must pass through a complete graph representing witness admission. Give all accepted paths an identical terminal key by encrypted corrections on graph edges. The first question is whether such an *actual serialized* hash-only graph capsule composes, and the second is whether it can be generated in classical PPT for the ORIGINAL SHA/AuxPoW relation. This note does **not** claim either second-stage property.

## Exact restricted construction

For a publicly specified, finite directed acyclic graph G=(V,E), start s and accept t, let a witness be any directed path s->t with typed public edge IDs and input symbols. Build samples independent uniform lambda-bit labels L_v at every vertex, publishes L_s, and publishes for every edge e=(u,v):

```
E_e = L_v XOR SHAKE256("R342 edge" || x || L_u || edge_ID || input_symbol; lambda)
D   = sigma_cancel XOR SHAKE256("R342 release" || x || L_t; |sigma_cancel|)
C   = (x, G, L_s, {E_e}, D)
```

The hypothetical ORIGINAL instance x includes claim/outpoint, protocol/chain IDs, baseline/source commitment, withdrawal assertion and burn/amount/recipient, BTC anchors/window, relevant child height, LC depth, reset/deadline, capsule ID and frozen safe native cancel message/VK. These bindings are **not actually checked** in this synthetic G. The labels except L_s are protected/erased after honest Build.

Public Open follows one edge at a time from (s,L_s) and computes `key <- E_e XOR SHAKE256("R342 edge" || x || key || edge_ID || input_symbol; lambda)`. On arriving at t, it returns `D XOR SHAKE256("R342 release" || x || key; |sigma_cancel|)`. An absent/wrong edge or incomplete path rejects. For every genuine graph-path witness, induction gives `key=L_v` at each visited vertex. Consequently *every accepting path*, including divergent paths that merge at a state, yields the **same** precommitted sigma. Unlike a plain path-dependent hash chain, explicit E_e corrects labels on merging paths; no canonical witness is assumed. These are actual polynomial-time algorithms in the **explicit graph size**, not a private oracle or retained online authority.

## Serialization/completeness conflict for the ORIGINAL source

If G is explicitly polynomial sized, public breadth-first traversal starting with L_s decrypts every reachable edge label and constructs an s->t path whenever t is reachable. Thus **all TRUE explicit-graph instances have efficiently findable witnesses**. This is *not* an unauthorized recovery claim for the graph language: BFS produces its valid graph-path witness. It is proof that a polynomial explicit graph does not provide a hard-TRUE instance of the actual source relation unless qualifying Bitcoin/Syscoin certificates are already efficiently findable.

A SHA compression state fits a fixed number of bits but has exponentially many potential values; this does **not** make its reachable transition graph polynomially enumerated. The full authenticated-source verifier also requires contextual modern chain ID and exact canonical tags, child-Merkle and parent PoW, relevant ancestor ancestry, source anchors/maturity, and the typed outer-carrier authentication for a claimed tag fault. Discarding those tests to shrink G merely turns invented sources into graph paths; a plaintext VerifyOriginal after pad recovery cannot repair that.

Three precise attempted compression substitutions:

1. Set `L_v=H(x||v)`: the accept key is publicly computable from the public accepting state, and S is immediately recovered without a source witness.
2. Set `L_v=H(master||v)` with private master: merging is available to the builder, but there is no specified publicly serialized on-demand `E_(u,v)` for unanticipated states without the master or a different cryptographic primitive. A hash commitment to master does not supply it.
3. Set `L_next=H(L_current||input_symbol)` so anyone can derive transitions: distinct paths reaching the **same semantic state** ordinarily yield different labels, destroying common-capability correctness unless there is a hash collision or an explicit per-edge correction. The latter returns to graph expansion.

The unresolved operation is therefore a **compressed nonlinear public transition/merge encoding** that binds the entire original-source witness, derives labels for unforeseen SHA/AuxPoW states without secret setup service, and converges to the same frozen safe signature from every qualifying original certificate. This construction has **not** supplied it; it does not count as a material ORIGINAL advance.

## Security scope

In a FALSE explicit DAG, the accept vertex is unreachable from s. Informally, in an ideal random-oracle model, the accept pad remains hidden while L_t is not learned and secret keyed oracle points are not queried. This is NOT a complete QROM joint-public simulation, and no independent QPT reduction is claimed for the published edge ciphertexts, correlated native verification key, auxiliary source, malicious setup, pre-signature/DA, sibling capsules or selective openings. Concrete SHAKE256 does not inherit programmable-QROM claims from preimage resistance. A malformed malicious graph/capsule cannot be accepted before irreversible funding. R225 native signature activation-portability remains separate. No actual Bitcoin/Syscoin admission, network safety, native SLH-like signing or P2MR deployment was checked.

## Executed check / provenance

Locally executed Python 3 checker used SHAKE256 and a five-vertex TRUE DAG with two distinct accepting paths that merge into one state; both independently return exactly the same frozen 128-byte *synthetic* capability. Public BFS discovers one representative accepting path, exposing the restriction that graph-path search is easy. A FALSE DAG has no reachable accept; wrong-edge traversals are rejected; plain hash-chain state labels do not merge. Two independent executions produced byte-identical JSON.

Local-only `/mnt/data/pq_r342/check.py` SHA256 `e43502bf1f1957213911c13e7ba8c0d90969d31b993064ea3c3d4d50adca199b`; `result.json` and `result2.json` SHA256 `c315bb9396eb8ecaa84ebc87cb002b286797d99e16ee421e54f2f5cb6eea9e1b`. Local-only full archive `/mnt/data/R342_state_merge_graph_20261117.tar.gz` SHA256 `e7c6373d5ade210a3b982b3f2b304f8251248b2cae1766c6c3e21f2cf1415801`. These artifacts are not published with this note or assumed persistent across runs. No QPT, authenticated source or native signature tests took place.

## Handoff

Reject explicit graph traversal as ORIGINAL WKEM, not merely as an unfinished optimized implementation. The next candidate must give a **real serialized classical-PPT** common-value source-conditioned release operation with full-public FALSE/hard-TRUE QPT security and malicious N-of-N/sibling/native composition. Do not try another label-width, graph-size, public probe, private source tap, affine mask or synthetic witness count as a substitute. ORIGINAL challenge relation is unchanged: independently qualified greater-BTC-work OR specific burn fault OR source inconsistency/tag fault at required LC depth, with no greater Syscoin work or choice of winning fork. R316's equal delayed tags do not show a strict-LC detection failure.

**NONQUALIFYING.** No ORIGINAL breakthrough, no PR comment/user progress notice, no production/Core edits, no deployment or automation change.