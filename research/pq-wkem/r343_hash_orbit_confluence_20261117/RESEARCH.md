# R343 — Public SHA-orbit confluence does not give source-gated release (NONQUALIFYING)

## Exact continuity
Open draft syscoin/PVUGC#1 on research/pq-wkem-validation-20260918; start head 8af52962286fb91b6a4a972166e03ceb80a48481 (R342). Read R342 note blob b7a31929a597ffac7bf64e317a982fffb7e8e3f5 and the relevant R341 hidden-source-tap note. Issue comments since 2026-11-16 returned empty. No external web/literature, actual Bitcoin/Syscoin/Core tests, live signatures or QPT experiment. This run selected one *specific* improvement to R342's explicit edge table: a public, one-way forward SHA orbit whose seed preimage is secret at setup. It is **not** a viable successor construction.

## Attempt 1: path-confluent public hash orbit

Build samples hidden r, computes public start label L_0 = H("seed"||r) and lets
    L_d = H_step^d(L_0)
    D = sigma_cancel XOR H_release(x||L_d)
with d the fixed source path length. Intended Open first verifies one ORIGINAL authenticated source witness with d steps, then performs the d public hash steps and returns sigma.

The result is path-confluent but is insecure even on a FALSE relation instance. Any outsider, without executing VerifyOriginal or having a source witness, hashes the public L_0 forward d times and returns D XOR H_release(x||L_d). For fixed distinct native signatures sigma_0 and sigma_1, the distributions C_b=(L_0,D_b) are perfectly distinguishable by this public algorithm. This holds regardless of source commitment, authenticated PoW or public native verification key. The honest Open conditional is not cryptographic source gating.

## Attempt 2: source-dependent hashing and confluence

Try L_(i+1) = H_step(x||L_i||encode(e_i)), with e_i a fully authenticated typed source transition. It must include postactivation *contextual* modern AuxPoW child ID, exact canonical SYS tag/parent coinbase, correct child Merkle/PoW/contextual targets, BTC anchors and claim-relevant actual ancestry/LC maturity as applicable; a validator after release is insufficient. Distinct accepted histories may use distinct independently authenticated Bitcoin parents; different parent certificates for one child do not alone constitute a Syscoin fork.

For two accepted witness paths P and Q with different source transitions, a random-function model (conditioned on distinct last oracle inputs and no earlier collisions) yields unequal terminal labels except with probability 2^-lambda. Consequently a single D prepared for P does not recover the SAME frozen sigma using Q. Strict canonical tags do not make independently valid future parent certificates identical; R316's delayed equal reference tags were not a strict-LC failure.

## Explicit correction and the true missing equation

For anticipated edges (u,e,v), Build can choose hidden vertex labels and publish:
    E_(u,e,v) = L_v XOR H_step(x||L_u||encode(e)).
This makes all known paths merge to the same vertex label and recovers one sigma. It is R342's actual finite-graph Build/Open, not a new ORIGINAL WKEM. A polynomial explicit graph permits public path search; a true SHA/AuxPoW verifier has unanticipated exponentially many reachable source states/edges. Merkle-root authentication of absent entries cannot compute those entries.

Any actual repair must instantiate a polynomial-size, publicly executable source-gated state corrector
    Corr_C(x, authenticated_prefix, e, L_u) = L_v XOR H_step(x||L_u||encode(e))
for ALL qualified future ORIGINAL source edges, without exposing the underlying secret labels or accepting unauthorized/spliced prefixes, and prove the complete-public FALSE and hard-TRUE QPT security bound with native VK, siblings, malicious setup and retained-source-coin auxiliary input. Calling this an ideal primitive does NOT solve it. Its independent instantiation is the missing advance, so **none is claimed**.

## Actual local execution and provenance

Python 3 SHA256/SHAKE256 synthetic checker executed twice with identical results: 7-step public orbit leaks the whole synthetic 224-byte capability without a witness; two different source-salted paths do not yield the same terminal capability; a four-entry explicit corrected DAG recovers one frozen capability on two known paths. This is algebra only, not source authentication, native signing, QPT simulation or bridge security.

Local-only check.py SHA256 5bd4ef1888c0d0e10fe37194e1e686843e09371475aa04d84f1ddaf32d521916. Each captured JSON SHA256 654459210e32506944fcd69b84c7a5ac1dfc08dcea403cf0d42bcf886b5cb608. Full local derivation and checker were saved at /mnt/data/pq_r343/RESEARCH.md, check.py, result1.json, result2.json; archive R343_hash_orbit_regression_20261117.tar.gz SHA256 a8e35a58be87852ea0a40d2941f979dea62c915a34c5da9a36f84f0632936219. Do not infer local files persist into a later execution or that checker files are published by this note.

## Disposition

NONQUALIFYING, NO ORIGINAL foundation progress, no PR comment/user progress notice. Reject this hash-orbit family without further variant/parameter sweeps: public source-independent iteration leaks the key, source-dependent iteration fails multi-witness convergence, and enumerated corrections are not compact future-source release. Keep the three original OR challenge branches unchanged and the existing research automation enabled; no changes to Core, production code, workflows, activation, approvals, merging or funds.
