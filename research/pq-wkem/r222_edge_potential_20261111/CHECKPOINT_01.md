# R222 — hash-only authenticated-path potential release, intermediate hypothesis

Repo: syscoin/PVUGC PR #1, observed head 76d5218cb7a630104808a702300fd41f7fa001f3, branch research/pq-wkem-validation-20260918, draft/open. R221 exact RESEARCH.md read at blob 3e517f440c0e88da2cfb3308b2f874cd561d32a1. Recent top-level PR comments since 2026-11-10 22:00Z returned none. No web or other repository reads.

Candidate for this pass: EPR (edge-potential release), a public finite graph whose edges are actual authenticated SHA256d/coinbase/AuxPoW source relation steps, and whose path labels telescope to a single frozen cancellation capability. The possible advantage over source Merkle-leaf preimage R221: it tries to use an *entire qualified path/fork cut* rather than claim one Merkle opening yields a secret preimage.

At setup choose K and fixed native cancellation sigma, publish D=sigma XOR Hpad(K,context). For an authorized path P composed of edges e and attached public masks M_e, seek potential differences that permit reconstruction of K from every qualified P but not from arbitrary synthetic edges. Explore (a) direct edge weights P(u) XOR P(v), (b) public response functions for future source edges, and (c) policy-checked release using public evaluator. Test global witness mixing, source spoofing, and source-independent coefficient recovery. Need avoid proof-derived K dependence and avoid pre-enumerating future certificates.

This is a genuine untested hypothesis, NOT an instantiated Build/Open or claimed advance. Preserve exact executed tests and repair analysis at run end. No routine PR comment unless an actual constructive delta is proved.
