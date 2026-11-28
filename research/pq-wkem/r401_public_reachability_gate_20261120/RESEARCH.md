# R401 — Public source-state hash graph: constructive preflight and hard-TRUE obstruction (NONQUALIFYING)

## Exact continuity
Opened syscoin/PVUGC PR #1 on branch `research/pq-wkem-validation-20260918` at actual head `d0c189e9a875965ec91b93c8a912f3b6776acbf2` (R400; tree `3a5aa7008ddc87555219e35e36a8222b77aa81a2`), rather than assuming old R327. Read R400's exact one-file addition and R399's immediately preceding claim-ticket endpoint. Ordinary PR comments since 2026-11-18T19:24:00Z returned empty. This run did not inspect Core #609 source, use the web, execute Core tests, generate real source certificates or native Bitcoin signatures, or invoke quantum adversaries.

The exact unfinished step from R400 is a SERIALIZED hash-only public conditional release for opener-chosen original source certificates, not another external Merkle-root verifier. New candidate here changes the representation: instead of separate per-clause local pads, encode complete verifier history as a single state-machine walk with a shared accepting sink and hash-only edge-masked state labels. Evaluate the complete-public transcript, including the ciphertext, jointly. This is a new constructive preflight, not a claim of ORIGINAL release.

## Construction on an explicit finite directed source-state graph
Let G_x=(V,E,v0,a) be a directed acyclic graph whose paths purport to be complete histories of the *unchanged* ORIGINAL OR source relation (qualified greater BTC work OR authenticated specific burn fault OR qualified Syscoin history inconsistency/tag fault), with every claim, source, exact native message, deadline, reset and contextual AuxPoW constraint already bound. This graph is a SYNTHETIC abstraction. A compact graph accepting local transitions is not itself a validator for actual source certificates.

Builder samples independent uniform lambda-bit state labels L_v, an independent fixed cancellation payload S, and publishes for each directed edge e=(u,v,descriptor) the mask

  C_e = L_v XOR SHA256("edge" || u || v || descriptor || L_u).

It also publishes L_v0 and D=S XOR SHA256("sink" || L_a). A prescribed opener walks a path v0->a, peeling C_e to derive the final label L_a, and returns S. Different valid paths return the SAME S without a common witness prefix, common SHA preimage or canonical fork. Build is classical polynomial time only if |V|+|E| is polynomial and all explicit edges are available at setup. A source verifier and Bitcoin network are NOT implemented by this graph.

For a TRUE graph with a reachable sink, the public package gives all edge masks and the starting label. The prescribed algorithm works, but **the entire public graph is also freely traversable by every adversary**, with no source-work admission. This is a concrete full-public hard-TRUE failure: adversary performs ordinary graph search, decrypts the labels of every reachable state, reaches the accepting label and decrypts S without any actual ORIGINAL source witness.

For the deliberately disconnected FALSE toy graph, the accepting label has no incident reachable edges. In a simplified ideal random-hash model, independent L_a makes D appear independent of S until L_a is found, but no complete-public QROM theorem is claimed here. This contrast demonstrates that ordinary FALSE hiding alone cannot establish hard-TRUE source-work security.

## General traversability lemma (scope precisely limited)
Consider a public finite graph with start token, each outgoing edge and edge descriptor visibly enumerable, and each edge transition computable in polynomial time using its source token and public bytes. Then a BFS/DFS finds a reachable accepting sink and its corresponding token in time O((|V|+|E|)*poly(lambda)), if one exists. This is an elementary unconditional property of the SPECIFIED PUBLIC TRANSITION REPRESENTATION, independent of SHA inversion.

Consequently, if G_x has polynomial size, its accepting paths are soundly and efficiently convertible to authentic ORIGINAL Bitcoin/Syscoin evidence, and a reachable accepting path exists, this representation also gives a polynomial-time extractor of that evidence. It cannot preserve a superpolynomial source-work barrier for hard-TRUE instances. If the graph accepts mere local descriptor paths instead, its public acceptance is not authenticated ORIGINAL release (as in the synthetic checker). This is NOT a general impossibility of hash-only WE/FE, not a proof about arbitrary implicit/exponential graphs, and not an attack on correctly admitted post-PQ AuxPoW.

## Attempted repair: make each edge require authentic future source evidence
A tempting repair asks an edge to carry an as-yet-unknown source certificate portion c and tries the single static pad
  C_e = L_v XOR SHA256("edge"||L_u||c).
For two distinct qualifying future portions c1,c2 that must traverse the SAME edge and lead to the SAME L_v, one static C_e requires
  SHA256("edge"||L_u||c1) = SHA256("edge"||L_u||c2).
Under hash collision resistance this does not hold except negligible coincidence. If Build freezes one c, it silently restricts the original every-witness relation. If Build instead exposes C_e(c) that anyone can compute for arbitrary chosen c without a protected source check, the public graph search/splice problem returns. If it privately computes C_e(c) only for authenticated original c, it is an online authority or inaccessible secret program, not a public capsule.

A source-gated public transition
  AuthNext(C_e,L_u,c)=L_v iff c is a REAL, relevant ORIGINAL source extension
would remove the explicit public-BFS attack **only if** arbitrary processing of the serialized public bytes cannot bypass that condition. No such algorithm or simulator was constructed. Naming AuthNext, calling Merkle verification outside it, or hypothesizing a protected FE evaluator would merely restate the missing witness-dependent release operation. Do not count this as a reduction to an independently instantiated smaller primitive.

Crucially, the canonical parent SYS tag can be equal on two genuine source histories until its reference height advances; it is a PUBLIC ancestor commitment, not a secret source-derived edge token. Strict post-PQ contextual chain IDs, exact OP_RETURN PUSH39 tag formats, and the distinct AuxPoW child Merkle commitment remain mandatory. The R316 stale-tag comparison is not a defect in a history-consistency LC and is NOT reused as an invalid source attack here.

## Executed bounded checker; exact reproducibility
A Python 3 standard-library checker was executed twice against a six-vertex, six-edge public DAG with two different accepting paths. Both prescribed paths recover an identical fixed synthetic 256-bit payload. A separate PUBLIC breadth-first search, given only public graph bytes and start label, recovers that payload by traversing the first path WITHOUT being supplied any source certificate. In a disconnected four-edge FALSE graph it finds no accepted path. Neither graph validates real original evidence; the toy fixture exists solely to test algebra and the full-public path bypass.

Both program executions succeeded with byte-identical JSON. Exact script SHA256:
  62dd7cea3531ce08dc054a4bd95692332ba6b0beeaf4e87037214ef11b47f9b2
Each JSON output SHA256:
  725aabcefde513a9d9858e24830413e46d58482bda5c570b3d20574754bedce8
Reproducibility archive SHA256:
  8ebde39c9ab693d6181a023f056bc67299c3c5bde3d3c6eeface774016a8cf84

The archive is committed as base64 ASCII in `reproduction.tar.gz.b64`. Reproduce by decoding it and executing `python3 r401_source_gate_reachability_20261120/check.py`; compare emitted JSON with the archived outputs. The archive contains script/output only; all full mathematical derivations are in this note. Public test seeds and payloads are not private keys. This is NOT a Core test, quantum security test, Bitcoin native signing test or original source witness admission.

## Handoff and status
NONQUALIFYING, not an ORIGINAL foundation advance. The bound destroys the public-edge graph *representation*, not hash-only witness encryption in general. An actually serialized classical-PPT Build_inc(x_W,S)->C and public Open_inc(C,w)=S for EVERY qualifying ORIGINAL authenticated witness, with full-public FALSE and hard-TRUE QPT recovery/native forgery -> an ACTUAL ORIGINAL source certificate or independently grounded hash/native break, remain missing. No accepted same-message signature substitution, malicious setup proof, correlated sibling capsule theorem or first-release EC native security claim follows from the graph.

Do not continue by enlarging the graph, changing hash domain, adding only public proof/root checks, or treating a hypothetical AuthNext as implemented. Pursue a genuinely protected source-conditioned hash-only transition with a concrete independent security simulator, or a distinct construction that bypasses this public-state traversal family. No ordinary PR comment, Core/production modifications, deployments, fund movement, automations modification, or user breakthrough notification was made.
