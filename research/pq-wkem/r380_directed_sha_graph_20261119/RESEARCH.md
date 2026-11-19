# R380 — directed SHA edge locks as global witness gate (NONQUALIFYING)

## Continuity / specific missing operation

PVUGC draft PR #1 on research/pq-wkem-validation-20260918 began at 0a3e16f001fc7724a78118d79845ba5b9c7e6ed5 (R379; note blob 137b210e947b31652cc3507ed861b2ae985dfeff). The latest top-level comments since November 18 19:24 UTC returned none. No Core source or tests were reread. R379's exact blocker is the exponential public SHA differential correction table; the restricted independent-leaf FALSE coupling cannot be lifted to its deterministic SHA-GGM roots.

This iteration changes the algorithm rather than changing SHA correction basis or sampling: try a single shared public directed graph with **one-way SHA edge locks**, avoiding reversible XOR differences and their immediate backward-splice. It constructs and tests a completely serialized Build/Open for the **synthetic graph-path relation only**. It neither implements nor weakens the three original Bitcoin/Syscoin challenge branches.

## Direct public algorithms

For an explicit directed graph G=(V,E) with s,t and a path-to-witness decoder, the builder samples independent uniform node keys k_v of lambda bits. It publishes the complete labelled graph, k_s, for each directed edge (u,v) the 256-bit SHA pad:

    c_(u,v) = k_v XOR SHA256("R380:edge" || encode(u,v) || k_u),

and D = S XOR k_t. A public opener starts with k_s and applies

    k_v = c_(u,v) XOR SHA256("R380:edge" || encode(u,v) || k_u)

on each edge of an s-to-t path, then recovers S = D XOR k_t. The SAME k_t is assigned to the terminal for every valid graph path, hence all different paths yield the same frozen S. Build and Open are classical PPT in the *explicit graph size*. SHA is genuinely evaluated rather than idealized in the checker. No source-authentication or Bitcoin work is performed by this construction.

The one-way directional pad removes the need for a publicly computable XOR-difference transition U(H(a) XOR H(b)) studied in R379, but does not generate any source-specific edge authorization. A Merkle root over the graph would authenticate bytes, not fix this gap.

## Concrete FALSE distribution, and why this is insufficient

Use edges s->a, b->a, b->t. There is NO directed s-to-t path, although the undirected graph connects s-a-b-t. In an older reversible XOR edge label c_uv=k_u XOR k_v, one can traverse the undirected path backwards and obtain k_t and S immediately. The directed SHA pad prevents this *algebraic* reversal. From s->a one learns k_a and from b->a one learns y=SHA256(domain||b,a||k_b), but b->t requires the unknown k_b.

For this precise isolated gadget with k_b uniform and domain-separated ideal independent random-oracle evaluations, conditioning on no oracle query at the hidden input k_b makes y and SHA256(domain||b,t||k_b) independent uniform oracle outputs. The full published pair y and D XOR c_(b,t)= S XOR SHA256(domain||b,t||k_b) is then exactly independent of S. A classical lazy-sampling argument bounds the chance of encountering this one unknown input by O(q/2^lambda) for q oracle guesses; the 12-bit brute-force experiment demonstrates recovery when that independent key is small. This is only a classically idealized *two-edge* argument: NOT a QROM theorem, NOT concrete-SHA or general-DAG security, and NOT source-bound security. The obstacle is an **independent setup hash puzzle**, explicitly prohibited as a substitute for real ORIGINAL source work.

## Exact route-closure: public graph paths make TRUE witnesses easy

For any classical PPT compiler B(x) outputting a polynomial-size **publicly navigable explicit graph** with:
  (i) every s-to-t path efficiently decodable to a qualifying ORIGINAL witness w with R_orig(x,w)=1;
  (ii) every TRUE instance having at least one such path;

the algorithm E(x) = BFS(B(x)) followed by path decoding obtains an ACTUAL ORIGINAL witness in polynomial time, with T_E = T_B + O(|V|+|E|) + T_decode. This is a direct deterministic reduction, with no cryptographic assumption and no need to volunteer a representation. Hence under the intended hard-TRUE source-work distribution, a correct polynomial Build for such a *fully visible graph* would already violate the hypothesized original search hardness. It must instead fail polynomial size, soundness/completeness or public traversability. The result is restricted to this graph syntax; it says nothing about generic FE, hidden-edge graphs, other WE constructions or a generic SHA impossibility.

If all possible witness edges are published without actual source authentication, invented fake paths open. If only authentic future source edges are published, the setup builder must already possess the future certificate (or update online, forbidden). A source-dependent cryptographic gate that reveals an edge only upon its ORIGINAL certificate would repair this—but no concrete polynomial public Build/Eval or joint full-public simulation for that gate exists here. Replacing the missing step with a source-verifier if-statement is not a repair.

## Executed bounded control and provenance

A Python standard-library script was executed twice; outputs were byte-identical and both completed successfully. The script builds a TRUE graph with two directed s-to-t paths yielding the exact same S; a FALSE directed graph with an undirected path leaking S under reversible XOR; and a 12-bit secret-key recovery from the directed SHA edge through exhaustive preimage search without a valid graph path. The public TRUE graph is also traversed by BFS without SHA mining. These are synthetic graph fixtures, not real AuxPoW or contextual light-client history, native signatures, real FE, ZK or QPT tests.

Local executable checker SHA256: 207c31264747db1b0d367a8a9c360c4b4555611e3a5419871e66dfe5d39d5b62.
Two captured output JSON SHA256: 555f251951db0d8cf63d994c74c49de029e3c270115d1665c7b3590bb5812fe1.
The full local archive, including expanded derivation, checker, paired outputs, has SHA256 8a40dcb3d31b5f5dd16ae27d7b50bd522fc205c4404c2ef5f0bd6fa715edcb93 and path /mnt/data/R380_directed_sha_graph_20261119.tar.gz. The run is local-only unless the exact checker bytes and output are separately read back from the committed code below. No unknown elapsed duration is claimed.

## Disposition

NONQUALIFYING. This directed edge syntax can remove an immediate reversible FALSE leak in a restricted graph but does not implement a source-conditioned original certificate gate or protect the resource bound. Do not extend this family with additional graph compression/packing/parameters/independent puzzles without a *new instantiated* edge-release mechanism. The original work continues to require classical-PPT serialized Build_orig(x_W,S)->C and public Open_orig(C,w)=S on EVERY qualifying original Bitcoin/Syscoin witness, plus full-public FALSE/hard-TRUE QPT recovery/native-forgery reduction, malicious setup, one-honest multi-capsule composition, all original claim/anchor/source and R225 binding. No progress comment, user breakthrough notification, production change or automation change.
