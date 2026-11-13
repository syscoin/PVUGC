# R240 — attempted hash-only source-transition telescope

**NONQUALIFYING research checkpoint. No secure ORIGINAL-source Build/Open, public QPT simulator/extractor, or deployed BTC/SYS verifier.** This is a concrete construction-and-repair investigation, not a claim of practical witness encryption.

## Provenance and scope

syscoin/PVUGC PR #1, branch research/pq-wkem-validation-20260918, initial head **7fc2c7c093245477bb313380dea192c420e5c3f0** (R239, parent c9ee0c11). Read R239 research at Git blob f5a37d2d7d18ce225cdb301c9db7beb367ad694e; checked latest substantive ordinary PR comments, most recent relevant R225. No external websites or literature, and no other repository writes. Intermediate checkpoints were written before/within the local experiment; two separate runs of each local checker were byte-identical.

The **ORIGINAL** withdrawal relation remains an OR of (1) qualified heavier conflicting Bitcoin history, (2) finite authenticated missing/incorrect burn authorization, and (3) qualified AuxPoW/Syscoin claim-prefix fork or carefully scoped tag fault. One notary can initiate; any qualified observer can challenge; N-of-N preauthorization is a separate setup, and Bitcoin receives only native cancellation signatures. Exact claim/UTXO, source baseline, chain IDs, BTC anchors and observation window, source reference height and depth, deadline/reset, activation, native message/VK, and capsule ID are bound. This investigation did not implement or change those admission rules.

Core #609 post-PQ conditions (previously inspected, not tested anew): one exact 41-byte recognized SYS ancestor tag OP_RETURN PUSH39(marker,ancestor hash,height) and mandatory modern child chain ID, plus original AuxPoW root and deterministic index constraints. A Bitcoin parent commitment can support at most one valid activated Syscoin child under normal hash binding, but distinct parent certificates may support distinct children or the same child. Its local tag ancestor depth 6–15 is not the full authenticated source proof or LC fork depth. Public activation remains release-disabled; no deployed claim.

## Candidate: explicit public graph of SHA/AuxPoW verification transitions

Let G=(V,E,s,t) be a public directed graph whose **s-to-t paths would have to encode complete ORIGINAL source-qualified witnesses**. Freeze a safe native signature/capability sigma; builder samples uniform independent node keys K_v (lambda-bit in the model). For each directed edge (u,v), publish XOR mask:

    D_uv = K_u XOR K_v.
    C = sigma XOR K_s XOR K_t.

Given ANY directed accepting path p, the intended opening computes:

    sigma = C XOR XOR_{e in p} D_e

because the intermediate keys cancel. Every accepted path yields precisely the SAME sigma, even with different source witnesses. This is a literal public encoder/opening calculation for the toy explicit graph; it is NOT a source-secure release.

### Full-public FALSE attack, even if graph paths are faithful

Choose vertices s,q,t and **only** directed edges s->q and t->q. There is no directed s-to-t path, hence no graph witness. Nevertheless:

    D_sq XOR D_tq = K_s XOR K_t.
    C XOR D_sq XOR D_tq = sigma.

This straight-line classical attacker does not call honest Open, does not have a source certificate and does not break a hash. It invalidates FALSE secrecy independently of exact-source authentication and therefore defeats any claim to QPT secrecy. The checker reproduces the attack.

### Repair A — directional hash-locked transitions

Publish K_s and:

    E_uv = K_v XOR SHA256("edge" || encode(u,v) || K_u),
    C = sigma XOR SHA256("payload" || K_t).

Any directed s-to-t path can propagate its key and recover the same sigma. The false S->Q<-T graph no longer admits the same easy backwards XOR decoding: E_tq and known K_q expose only a hash of unknown K_t. This is a **toy equation repair**, NOT a quantum-random-oracle or standard SHA theorem; public native VK/checking correlations, auxiliary advice, malicious setup, related capsules, multiple openings, source coins, and final-signature forgeries are not analyzed.

Because K_s and all edge encodings are public, however, a graph with polynomially many explicit states can be explored using normal BFS, deriving every reachable node key. Therefore either every accepting path corresponds to a quickly constructible qualifying source certificate (unlikely for a genuinely hard future Bitcoin-work/source problem), or the graph is not faithfully representing the ORIGINAL source relation. A polynomial-size explicit graph cannot simply substitute for a succinct SHA verifier circuit.

### Repair B — enforce global occurrence consistency

A local graph that treats repeated input occurrences as independent admits a false trace for the unsatisfiable relation [x=0 AND x=1]. It chooses 0 at its first source occurrence and 1 at the second, follows the otherwise valid-looking edge sequence, and releases sigma.

A fixed authenticated Merkle root for all source input bits, with consistent per-occurrence openings and hash collision resistance, prevents this *specific* inconsistent-bit trace. Letting the purported root vary between edges restores the bypass. Real alternative Bitcoin/Syscoin histories produce unknown, possibly differing roots at setup: a source-root commitment is a consistency proof, not a new hidden signing secret.

**Exact explicit-state lower bound.** For EQ_n = {x||y : x,y in {0,1}^n and x=y}, any layered nondeterministic graph consuming x then y and accepting precisely EQ_n needs at least 2^n midpoint states. For each x choose an accepting path for x||x and its midpoint q_x. If q_x=q_y for x!=y, splice the first half of x||x with the last half of y||y; it would accept x||y, contradiction. Hence all 2^n midpoints are distinct. This rules out a polynomial **explicit-state path graph** for that repeated-variable consistency representation; it is not an impossibility theorem for compact circuits, obfuscation, or hash-based WE.

### Attempt to bind the released edge key to actual future source evidence

Let c be the full witness/source fingerprint (for the real challenge it must be SHA/AuxPoW/Bitcoin anchored and not a synthetic, attacker-chosen label). To bind the edge mask itself, try:

    E_uv(c) = K_v XOR SHA256("source-edge" || K_u || c).

With frozen K_u,K_v, one fixed preauthorization E_uv works for one c. For any two genuine distinct c0,c1 it cannot open the SAME K_v unless the hash outputs coincide. The checker tests the two-root failure. Ideal independent random-function outputs collide with probability 2^-lambda for fixed c0!=c1; this is idealization, not a SHA or QPT reduction. Publishing a succinct *public function* E_uv(c) that works for every future authenticated c, conceals K_v from fabricated c, and prevents mixed root paths would be a **source-conditioned protected-function compiler**, which this candidate does not build. Publishing the secret predecessor key or a public constant source pad permits raw bypass; enumerating all future c is exponential.

## Actually executed checks and limits

Local research.py (SHA256 937ddc17f5a8c7a091715a4fd290bc983cecf505db14f53bad1dc05ac75a0e4e) was executed twice with identical first.json SHA256 c947a9645a22d6400eb65dc70e85df8f41979a9c06ee4249c03c1bb36326dd83. It checks false directed graph XOR leakage, two correct accepting paths converging to one sigma, directional repair on the false three-node fixture, an inconsistent occurrence path that opens, public BFS and EQ_n counts for n=1..12. Local fingerprint_repair.py SHA256 cd19073228c30e840f208b65653263d77f88218e670c1c6587bcd48b70974d95 ran twice with identical captured SHA256 d0a654b105215074b4bf66e69018ebf35bd42678dd33012b2895a41883e725de, testing global-root reuse/substitution and the frozen edge mask against two distinct roots.

The smaller independently run checker_min.py and captured_min.json reproduced the key algebra; its exact Git blobs are published alongside this note. NO actual contextual Bitcoin/Syscoin consensus verification, real mined source, native PQ signing or quantum security experiment was performed.

## Precise unbuilt equation

We still require classical PPT Build_inc(x_W,sigma_cancel) -> C and public Open_inc(C,w) -> the **same frozen claim-scoped native cancellation capability** for **every ORIGINAL qualified evidence** w. Unauthorized arbitrary QPT recovery or an accepted native forgery in the *complete* public, correlated multi-capsule view must produce an ACTUAL ORIGINAL evidence certificate or independently justified PQ hash/native break, without requesting a volunteered representation, post-hoc verifier, trusted signer, hidden issuer, exponential state graph or online release. No such guarantee follows from this run.

This is a rejected construction family plus a small directionality correction. Continue source-driven release work; do not prioritize packing or performance. R225's slot-global versus activation-specific native endpoint issue remains a separate unresolved policy choice. No ordinary PR progress comment is warranted.
