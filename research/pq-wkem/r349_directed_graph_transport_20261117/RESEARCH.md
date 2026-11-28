# R349 — directed SHA edge transport for finite graph (RESTRICTED; no ORIGINAL witness-KEM)

## Provenance / selection

Read live open draft syscoin/PVUGC PR #1 at `3d1452e4861b2fdb89e7eee0d3698b50766644f3` on `research/pq-wkem-validation-20260918`; inspected R348 blob `f5c60d69cf235ecc408e3c405ddcd5c5e917a11d`, R347 blob `65acfd7c51d7efec1c669ffad10c340e17031b79`, and R327 blob `ab7602bfc54403bf68294034557206f62d69a5dc`; checked current PR comments. No new Core code claims, external sites, or source certificate execution. R316 stale tags are not an LC failure.

R348's fixed native Merkle root does not accept future un-enrolled source Merkle leaves. R289/R327's globally additive public masks splice across inconsistent witnesses. Test a structurally different *directed*, SHA-based transport that permits multiple distinct public paths to converge at one secret endpoint without a hash collision or XOR-backwards traversal. The candidate is complete for a polynomially enumerated graph, **not** for original source histories.

## Fully serialized classical-PPT Build/Open for explicit directed graphs

Let `G=(V,E)` be a public, explicitly listed, polynomial-size directed multigraph, with start `s`, terminal `t`, and distinct edge IDs. Let `x` bind protocol/capsule/message/native context, `S` be one frozen authorized safe cancellation capability of length L, `lambda=256`, and `H_e,H_o` be domain-separated hashes (SHA256 in the local checker; any quantum random oracle claims require explicit idealization). `Build_G(x,G,S)` samples *independent* uniform `K_v` for each vertex, publishes `K_s`, and for every *pre-enumerated* directed edge `e:u->v` publishes

```
  C_e  = K_v XOR H_e(x,e,u,v,K_u)                (1)
  C_0  = S   XOR Expand(H_o(x,K_t),L)            (2)
  capsule = (x,G,K_s,{C_e},C_0).
```

`Open_G(capsule,p)`, given any actual directed path `p:s->t`, starts with `K_s` and for each edge executes `K_v=C_e XOR H_e(x,e,u,v,K_u)` (3). It returns `C_0 XOR Expand(H_o(x,K_t),L)`. Induction over edges shows that **every** legitimate path derives exactly the builder's same `K_t` and same frozen `S`; distinct paths need not share other states. Serialized capsule size and Build work are `O(|V|+|E|+L)`. No private evaluator, source signer, generic witness-encryption oracle or lattice/group primitive is assumed for this graph-only construction.

Why it actually repairs one local issue: publishing `K_u XOR K_v` for each edge leaks keys along UNDIRECTED paths, including reverse edges not on an allowed path. With (1), knowing `K_v` and `C_e` does not directly yield `K_u` by XOR; it poses a domain-separated SHA preimage problem. This is not a proof against all QPT adversaries.

## Full public FALSE simulation boundary

When no directed path `s->t` exists, let `R` be all reachable vertices. Every edge from `R` terminates in `R`. In the **classical random-oracle lazy-sampling game** with independent uniform vertex keys, for each edge whose source is outside `R`, choose `C_e` uniformly and program `H_e(x,e,u,v,K_u)=C_e XOR K_v` at its hidden keyed input. Choose `C_0` uniformly and program `H_o(x,K_t)` to couple the actual `S`. This gives the correct joint classical public-output distribution until a hidden-key query is made. A loose classical hit bound is `O(q|V|/2^lambda)` for q adaptive queries under the stated fresh/independent key and auxiliary assumptions. In the *no-query public transcript*, even cycles among unreachable vertices are covered because each edge has an independent domain-separated RO output.

**Do not promote that argument to QPT:** coherent quantum queries to all these correlated, programmed RO inputs need a separate joint hidden-point/reprogramming proof. No QPT bound, concrete-SHA security theorem, arbitrary-auxiliary guarantee, malicious N-of-N setup or sibling selective-opening proof was obtained. An attacker pre-supplied `K_t` or an already released identical native signature is not covered.

## Exact ORIGINAL-source obstruction, not an abstract missing “API”

An ORIGINAL challenge is one of three OR grounds: (i) qualified BTC strictly-greater exact cumulative work from same relevant anchor; (ii) finite authenticated specific burn/authorization fault; (iii) qualified mature Syscoin inconsistency or independently authenticated tag fault. The original witness binds chain IDs, actual relevant ancestry, modern contextual AuxPoW/tag rules, claim/outpoint/burn/amount/recipient, source commitments, BTC anchor/window, LC depth, deadline/reset, exact safe message/VK and capsule. Different genuine parents for the SAME child alone are not forks. R316 is a delayed-tag reference regression, not inability of strict LC to detect history conflicts.

The explicit finite graph is insufficient. Modeling the actual SHA/AuxPoW verifier as a streaming state machine `q -> T(q,a)` over arbitrary future source certificate components `a`, the builder must serialize a polynomial-size public evaluator

```
  E_C(q,a) = K(T(q,a)) XOR H_e(x,q,a,K(q))         (4)
```

for *all unknown future authenticated source transitions*, while all accepted paths converge to the ONE hidden terminal key and fabricated/incompatible paths cannot open. Choosing `K(q)=H(secret||q)` makes (4) uncomputable without the secret; publishing the secret reveals `K_t` early. Choosing public `K(q)=H(q)` reveals the pad or loses fixed-secret convergence. Setting `K(T(q,a))=H(K(q)||a)` omits edge corrections but merging genuinely different SHA histories now requires a hash collision unless the hashed predecessor inputs coincide. Explicit per-edge corrections require enumerating exponentially many possible SHA states/edges for general source certificates. The public graph path is findable by BFS, so a graph-only hard-TRUE “extractor” has no significance for the ORIGINAL source. **Equation (4) remains UNSOLVED.** This is not a claimed generic hash-only WE impossibility.

No frozen-native R225 activation portability fix, original source-conditioned Build/Open, independent joint-public QPT reduction, full source/DA checks or malicious N-of-N setup was established. Large evidence must remain off chain; no generic NP verifier in Bitcoin. The original fixed native cancellation must not authorize unrelated theft; endpoint binding and slot-global veto vs activation-specific signatures remain separate.

## Executed reproducibility / exact scope

Local CPython standard-library `check.py` created one publicly serialized finite-graph capsule for a diamond with a loop, and another with no directed s->t path but a connected UNDIRECTED graph. Verified 4 distinct directed paths return one identical 32-byte S, invalid paths reject, classical XOR coboundary traverses a forbidden reverse edge, and naive reverse XOR cannot recover a SHA-directed edge's key. Enumerated 4,094 synthetic SHA prefix states as a source-state scaling illustration. **20 local functional assertions, two byte-identical executions; none is Bitcoin, Syscoin, native SLH, QPT, or security testing.**

Script SHA256 `14edf14a7904a624b540921cc98f64bf120be29b98bcc363779144875af8f3a6`.
Outputs SHA256 `634ef6b27822256df141221aeccb64e5e9bd6e2443db39cc04dee5dd7f7bb7f4` each.
Complete derivation + executable `check.py` and two outputs preserved in local-only `/mnt/data/pq_wkem_r349/`; self-contained extended note SHA256 `2d2a54e22a4841b2cd8a352dd367605a01d3671344e5f11af66dc3c8fcbea70e`. Checker is **not** GitHub-published.

**NONQUALIFYING.** This note is a restricted component/anti-splice checkpoint, NOT a new ORIGINAL-source release foundation or a progress announcement. No top-level PR comment, production edit, Core edit, deployment or automation change. Continue only with an actually independent, classical-PPT public implementation of (4) or a materially different source-dependent construction plus full-public QPT argument; do not return to mere table growth, root-depth changes, publicly keyed syndrome variants, or toy test counts.
