# SAI103 — hash-locked explicit state-path capsule (restricted; NOT ORIGINAL WKEM)

## Continuity
Verified live open/draft syscoin/PVUGC#1 at `f17e714dd7d772abc3a2bb15c12f768d06340a33` on `research/pq-wkem-validation-20260918`, SAI102. No issue comments since November 18 19:24 UTC. No Core source/tests or network inputs were read or run.

SAI102's per-certificate SHA stream gives incompatible pads. This new candidate changes the operation: independently keyed graph states, with publicly hashed edge transfers, so *any* accepted whole path reaches the same frozen secret. It is not another source-hash pad or local affine constraint mask. Security and succinct source compilation are tested jointly rather than inferred from honest opening.

## Exact restricted public Build/Open
Given explicit directed acyclic G=(V,E), start s and terminal t (t has no outgoing edges), choose independent n-bit state keys k_v for v != t, let k_t=S. Publish G, domain/capsule ID, k_s and for every edge e=(u,v) the ciphertext

    c_e = k_v XOR H(domain || capsuleID || edgeID(e) || k_u).

The full public token vector and start key are the capsule. Open on a path p=(s,...,t), after verifying adjacency and endpoints, iterates

    z_0=k_s,
    z_(j+1)=c_(v_j,v_(j+1)) XOR H(domain || capsuleID || edgeID || z_j).

Induction gives z_j=k_(v_j); thus EVERY s-to-t path returns exactly S, regardless of internal states, length, or route. Build is classical polynomial time in **the explicit graph size**, O(n|E|) bytes, with no online release service.

This does NOT claim authenticated Bitcoin/Syscoin witnesses are equivalent to these paths. A qualifying ORIGINAL witness must map to a path and EVERY accepted path must decode to an actual relevant, authenticated ORIGINAL certificate, including contextual AuxPoW, strict canonical active tag, actual claim-prefix ancestry/maturity, source anchors, and the three independent OR branches.

## Full-public marginal and ideal-RO false-capsule coupling
Since edgeID is unique, each ideal random-oracle query at (edgeID,k_u) is distinct, even if vertices repeat. Conditional on keys, the independent RO outputs make all c_e independently uniform. Consequently the *standalone capsule-token marginal* is exactly independent of S. This is NOT full-public security in the presence of RO access.

For an unreachable terminal t, couple S0 and S1 by keeping all other state keys fixed, replacing k_t=S0 with S1 and reprogramming the RO value at each secret input (edgeID(u,t),k_u) by Delta=S0 XOR S1. Then the public incoming ciphertexts remain equal:

    S1 XOR (H(edgeID,k_u) XOR Delta) = S0 XOR H(edgeID,k_u).

No u with an edge to t is reachable from s, so an honest start-following evaluator never queries a changed oracle point. The executed checker verifies identical whole public capsules in the coupled ideal-RO worlds and disjointness of changed points from reachable traversal points. Arbitrary adversaries are not restricted to honest traversal: they may invert hashes, query coherently, exploit related capsules or retained source coins. A QROM hidden-point programming theorem for the **joint** view was NOT constructed. This ideal coupling is NOT a security statement for concrete SHA256.

## Decisive original-source obstruction
This gadget has a structural gap separate from encryption. If a polynomial-time `Graph(x)` outputs an enumerated polynomial-size graph and `Decode(x,p)` turns ANY s-to-t path into a genuine ORIGINAL source certificate, then BFS on that public graph yields a path in polynomial time whenever one exists, and Decode yields the certificate in polynomial time. This destroys the desired hard-TRUE source-work condition for such a representation. This is a combinatorial implication, not an impossibility theorem for arbitrary hash-only witness encryption.

The original SHA/AuxPoW verifier has a 256-bit SHA chaining state and additional contextual history; explicitly listing all possible future states/transitions grows exponentially. To avoid that, a practical compiler would need a **serialized public keyed transition-token generator**

    EdgeToken_x(u,v,e) = k_v XOR H(edgeID(e) || k_u)

that covers every authenticated future source transition without an exponential table, while not revealing private state keys or allowing arbitrary unverified edge queries. Publishing a master key reveals S; a Merkle root authenticates bytes but does not supply tokens; a private online generator is forbidden. That source-dependent compiler and its full-public FALSE/hard-TRUE QPT reduction remain MISSING. Do not label this FE, WE or an available primitive.

Even a graph generated from syntactically valid child headers must distinguish two different parent certificates for the same Syscoin child (NOT a fork) from actual incompatible child ancestries. Raw parent PoW is not BTC best-chain membership. Any proposed mapping must enforce source relevance and the user's full ORIGINAL relation, not invented edges.

## Reproducibility and disposition
Attached `check.py` uses concrete SHA256 for all-path correctness on two accepted synthetic DAG paths, and an explicit programmable random-oracle map solely for the FALSE coupling. It verifies exact public-token equality across different S and that changed RO points are not queried along any reachable path. It also shows BFS immediately recovers the TRUE path, demonstrating that this is NOT a practical source-work barrier. Two invoked executions were byte-identical.

- `check.py` SHA256 `0d1bec670871487f0d20677fa5b0b17b77711be6e8eb92cdf7180bbe3f3bb743`.
- Captured `output.json` SHA256 `cc97d800401d5fb48506141fbcfcfcd1e27d0f5814d2dbc08ea536593604e244` (two executions identical).
- No Core tests, native signatures, actual Bitcoin/Syscoin work certificates, source verifier, ZK or quantum computation executed.

This is an indispensable construction screen, NOT an ORIGINAL foundation advance. No full-public false/hard-TRUE extraction, actual source authentication, native forgery/one-honest malicious setup, or multi-capsule security exists. The next equation is not a different hash mask but a *real* practical public `EdgeToken` over authenticated future states with a joint security reduction; if impossible without a hidden program, record that rather than assuming FE. No PR progress comment or user breakthrough notification is warranted.
