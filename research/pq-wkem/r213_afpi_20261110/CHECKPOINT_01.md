# R213 — Authenticated-fork pair interpolator: source-domain completeness test

Status: intermediate research hypothesis/checkpoint, NOT a secure WKEM, QPT theorem, or source compiler.

Scope: hash-only, original bridge R3 claim-prefix inconsistency with N-of-N setup / one-notary activation unchanged. Start PR #1 branch research/pq-wkem-validation-20260918 at c4f6b7cce2790370575c08a438f57298959586dc; prior R212 PUBLIC residual gate was read at exact SHA. No external literature or other repositories.

### Named candidate — AFPI
Let x_W fix a fully authenticated claim baseline. A future qualified conflicting AuxPoW/Syscoin history yields a semantic prefix digest z = U_claim(P), extracted only after complete work, child, tag and anchoring validation. Source-cert identities and semantic child identities are distinct.

Attempt Build_inc(x_W, sigma) -> public polynomial coefficients (c_0,...,c_d), sealed capability E, native VK and context, with Open recovering sigma from a public gate F_C(z) on ANY qualified, relevant future conflicting history. Distinct future z must produce the SAME precommitted opening. No false certificate, synthetic header or fabricated z may release it.

Hypothesis: a publicly evaluable low-degree F_C cannot produce a secret common release value across an unrestricted set of unknown future authenticated fork digests while rejecting arbitrary fabricated digest input. Proof obligation: for fixed baseline and capsule, if more than d possible distinct qualifying z values exist in the same future-source-admissibility universe and F_C(z)=K for each, then polynomial root counting forces F_C = K identically on the entire field. In that case an adversary evaluates F_C(0), without any original evidence, to recover K. This is a conditional claim about public polynomial factorization, NOT a theorem against arbitrary nonblackbox hash/SHA WE.

Candidate repair A: interpolate F_C(z)=K+Delta * product_{i=1..t}(z-z_i) for t setup-known authentic source digests; reject arbitrary z. It only covers the enumerated points, so test any later qualified z outside that set for failure of universal completeness. If future z_i are unknown, Build cannot create those factors. Candidate repair B: replace semantic digest z with H(complete_authenticated_source_certificate); this changes input distribution but does not protect public evaluation if output is forced constant on all qualifying unknown future points; test boundary without claiming a QROM result.

The next checker will use field F_257 with exact arithmetic, demonstrate multi-witness functional correctness, public early-opening collapse for d+1 distinct points, and failure of finite-point interpolation outside the chosen set. It is NOT a Bitcoin/Syscoin or security model; absence of a functional gate is NOT a solved ORIGINAL bridge.

Precise missing target remains classical-PPT Build_inc/Open_inc from original authenticated source evidence, SAME frozen claim-scoped native signature for every R3 witness, full-public arbitrary-QPT false/hard-TRUE security, malicious setup and multi-capsule composition. No online issuer, source-retained signing labels or general-NP prerequisite.
