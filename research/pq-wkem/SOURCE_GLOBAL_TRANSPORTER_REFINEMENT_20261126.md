# Global-transporter source response trial — 2026-11-26 UTC

Status: rejected candidate, not a qualifying ORIGINAL release advance. Static construction and attack; no claimed checker or security theorem.

Continuity: syscoin/PVUGC PR #1, open/draft/unmerged, branch research/pq-wkem-validation-20260918. Start head 088b5a2d38a5b3858c895224d2cc4f6459c5a1a6. Read PR metadata, five latest substantive discussion entries ending with R225, latest commit filename, and exact SOURCE_SPECIAL_SOUNDNESS_RESPONSE_20261126.md, blob cac38e235014d0ee4b05d8ae269639f941edbe70. Re-read the same head before preservation; this path did not exist (NOT_FOUND/404).

## Selection and actual missing operation

The last special-soundness trial could generate a source response but extracted the wrong witness, or could extract the native capability but could not generate the requisite opening. Try a different global carrier: a hidden relabeling of an entire source-derived graph, not a set of locally selectable secret wire labels or two independent proof responses. A complete original certificate would give a resolving order for recovering ONE globally consistent transporter. The native contribution would be masked by an invariant of the transporter, not by a source witness hash. This is the explicit change intended to avoid the local cross-witness splice and the previous response-extracts-wrong-witness obstruction. No graph-isomorphism, group-action, lattice or discrete-log hardness assumption is permitted; the proposed graph algorithms must stand on source and hash hardness alone.

The missing operation tested is: from ANY qualifying original w, publicly reconstruct the same hidden image of a designated vertex v*, under a single setup-generated global relabeling. Build must be polynomial without w, and recovery by an unauthorized algorithm must imply an ORIGINAL certificate or independently justified break. All three original OR grounds remain in R(x,w); no change to authentic/relevant admission, maturity, work comparison or burn refutation. Grant for this local trial a witness-preserving polynomial graph encoding of R; no actual source circuit implementation is claimed.

## 1. Serialized candidate

Let G=(V,E) be a public graph derived from x, with n vertices. A graph reduction can, for illustration, encode witnesses as Hamiltonian cycles. Build is allowed to add polynomially many public graph gadgets depending on x but not on an unknown w. Let A be a public subset of anchored vertices. Choose n distinct random lambda-bit names, uniformly without replacement, and an independent bijection pi from V to those names. Publish the relabeled graph G'=pi(G), including any public vertex colors, and the true partial mapping M0=pi|A. If randomized names are used, choose lambda large enough for efficient sampling; no security claim is based on name collisions.

Choose a designated public vertex v* not initially anchored. For a block of native contribution S, output P=S XOR H("transporter-pad",ctx,pi(v*)). For longer contributions use a domain-separated counter stream with injective encodings. The serialized capsule is (x,ctx,G,G',M0,v*,P), plus the stipulated public native checking information. Build knows the full pi and erases it after creating P. This is an actual polynomial Build for a given graph; it does not rely on generating every future witness.

Define Cand_M(v) for an unmapped v as all unused names y in G' with the correct public color and with both adjacency and nonadjacency to every mapped vertex preserved:
    
    y in Cand_M(v) iff y not in range(M)
        and color_G(v)=color_G'(y)
        and for all u in dom(M):
            E_G(u,v)=E_G'(M(u),y).

For directed/edge-colored graphs replace the last equality by equality of all directed/colored edge relations, including absence. The real pi(v) is always a member when M is a restriction of pi.

Proposed Open: use the full original witness w to produce an order v1,...,vt (e.g. order along its encoded Hamiltonian cycle), after validating R(x,w). Follow the order, assigning each vi its unique member of Cand_M(vi); abort on a nonsingleton. Once v* is mapped, return P XOR H("transporter-pad",ctx,M(v*)). Every such successful order gives exactly S since it recovers restrictions of the same pi. The required compiler property would be that EVERY qualifying w yields such an order reaching v*, for EVERY supported setup randomness. This property is not supplied by an ordinary graph reduction; try to obtain it by graph gadgets or public anchors before appealing to any hardness. The source check here is not accepted as a security mechanism by itself.

## 2. Eliminate witness order from the proposed operation

The key question before implementing graph gadgets is whether an order-dependent resolving property can enforce source authorization. It cannot for the candidate above, regardless of graph encoding.

For M subset M' subset pi, Cand_M'(v) subset Cand_M(v) whenever v remains unmapped: unused-name and adjacency requirements only become stricter. Both sets contain pi(v). Thus a singleton assignment persists unless that vertex has already been assigned. This property uses global consistency and includes all nonedge constraints.

Public attack Greedy(C):

    M = M0
    while v* not in dom(M):
        find any unmapped v with |Cand_M(v)| == 1
        if none exists: return FAIL
        M[v] = the unique candidate
    return P XOR H("transporter-pad",ctx,M(v*))

All assignments are correct by induction; scanning all vertex/name pairs and comparing at most n mapped vertices takes O(n^4) total naive time, polynomial in the serialized capsule. The adversary never invokes R, has no w, and supplies no internal state to a reduction. It is a classical PPT algorithm, hence also an allowed QPT adversary.

Proof of exact completeness transfer: suppose any witness-guided order v1,...,vt reaches v*. Let Mbar be the greedy closure (run to a fixed point if necessary). Induct on the witness order. Its prior assignments belong to Mbar by induction. If vi is not already mapped by Mbar, monotonicity and nonemptiness imply Cand_Mbar(vi) is the same singleton as at the ith honest step. This contradicts fixed-point termination. Therefore all vi, in particular v*, belong to Mbar. Greedy can stop as soon as v* is mapped. This is pointwise for each capsule; no averaging, rewinding, query-log extraction or independent auxiliary-input assumption. The success probability of Greedy on valid instances is at least the honest completeness probability for any qualifying w. Erasing the original pi, choosing fresh names, or hashing its image does not help: Greedy makes precisely the intended pad query, with no collision or preimage search.

This is not a generic graph-isomorphism algorithm. It proves the proposed resolving-order compiler property cannot serve as the security barrier. If a compiler somehow made the greedy closure itself efficiently decode an ORIGINAL certificate for every successful instance, the combination would be a public original-witness finder on every complete hard-TRUE instance. That alternative requires an actual original-witness-finding construction and would contradict the hard-TRUE premise on any applicable hard instance. Merely decoding the order as a Hamiltonian cycle is not valid: greedy order need not be a cycle or even follow edges. On false inputs the carrier alone likewise supplies no implication from resolving a vertex to R being satisfiable. Example: a path on three vertices with one endpoint anchored resolves all vertices by singleton propagation, despite having no Hamiltonian cycle. This is a carrier example only, not an actual BTC/SYS counterexample or a claim about the images of a specific graph compiler.

If native S is an exact fixed cancellation signature contribution, successful Greedy obtains that exact value, not just a possibly different accepted signature. The attack does not need any assumption on native VK, public source commitments, auxiliary advice or sibling capsules; these can be ignored. It therefore defeats a full-public security argument whenever the above completeness is achieved on a genuinely hard-TRUE input and source recovery remains hard. No concrete SHA claim is required.

## 3. Repair trial: coupled moves instead of singleton moves

To try preserving witness-order utility without local splicing, let the witness supply a sequence of coupled blocks of at most k still-unmapped vertices. A candidate block image is an injective assignment of unused names preserving all edges/nonedges within the block and to all of M (and colors). Assign a block only if there is exactly one such tuple. It contains the restriction of pi; uniqueness again persists under correct extension of M, after dropping any already-mapped block vertices. To see the latter, any alternative tuple on the remaining vertices could be extended with the true already-mapped block vertices; it would give an alternative to the original unique tuple, since consistency with M' includes consistency with those vertices. This contradicts uniqueness.

For any FIXED k, Greedy scans all blocks of size <=k and all candidate tuples (O(n^(2k)) combinations per round, plus polynomial checks). The same induction on honest blocks proves witness-free recovery whenever the honest algorithm succeeds. Consequently a fixed-size coupled-move gadget does not repair this specific source gate. No larger fixtures or arity sweep warranted. Allowing k to grow changes the attack's complexity, but does not furnish a classical PPT honest operation: if the witness only specifies the domain block, the public evaluator must still find its unique image. If the witness also specifies the target tuple, it needs an actual correlation with independently sampled setup names or hidden pi. The ordinary source witness-to-cycle encoder depends on x,w, not on those hidden names. A polynomial global search algorithm using w remains unconstructed; its security cannot be replaced by an independent graph-search hardness assumption. This identifies the next missing constructive equation rather than assuming it.

## 4. Handoff

Reject the global-transporter resolving-order candidate before implementing a source graph compiler. It is distinct from R327 private additive coefficients, R289 local splice and the immediately previous fixed-transcript response conversion. The new global consistency does remove the need to align independently released local labels, but here it gives monotonicity and a deterministic public closure that makes the intended release unconditional on possession of source evidence on every complete instance. Do not retry with graph colors, extra public anchors, another name encoding, fixed-size lookahead or a witness-dependent hash pad. No claim against general globally correlated encodings is made.

A future transporter candidate would need a classical PPT algorithm that uses an original witness to resolve a genuinely nonlocal ambiguity tied to setup-secret data, with every qualifying witness yielding an invariant same capability and a public adversary obtaining it only via an original certificate or an independently justified hash/native break. That algorithm and joint simulator would have to be supplied, not an abstract transporter oracle. Graph-isomorphism hardness is not an allowed substitute.

No actual original source compiler, full-public QPT security theorem, native signature instance, malicious setup, related-capsule proof, Core source reinspection, execution/test, or external literature. R316 maturity and R225 endpoint scope unchanged. Static derivation only; no ordinary PR progress comment. Notification gate not met.
