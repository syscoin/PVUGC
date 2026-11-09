# Intermediate checkpoint: full-public opaque hash-correction span test

Research-only. A substantive bounded hash-only iteration, **not** a secure KEM, generic source compiler, QPT theorem, or breakthrough. Do not send a routine PR comment or user notification.

Continuity: syscoin/PVUGC PR #1 open/draft/unmerged, research/pq-wkem-validation-20260918, observed start 10fdd6d545be26e05302cc6a2a94fb7a2128b452 (tree 83728b71d6f8a137e6febed5e4952da6a414126b). Read the exact clause-occurrence-masks_20261109/RESEARCH.md (blob 4d75cf96bf78b58584b7204c20e41a612bc596be) and hash_sealed_states_20261109/RESEARCH.md (blob fd6576b982733e9ff7065f34b2a6cfe20f2e4820). Bounded ordinary PR comments since 2026-11-09T02:25:00Z were empty. No web, external literature, unrelated repository, or independent agent. No lattice/groups were used.

## New test direction: truly arbitrary nonlinear local SHA outputs

The preceding two-point attack concerned a specific degree-three clause correction. We instead test completely arbitrary independent 128-bit SHA256-derived words U[j,a] indexed by local clause j and each three-bit tuple a. Let S_j be secret shares and R[j,k,b] secret per-occurrence-bit masks. Define K=XOR_j S_j. Build can issue public seven allowed local rows
    A_j(a)=S_j XOR U[j,a] XOR XOR_{k=1}^3 R[j,k,a_k]
for a different from the forbidden local clause tuple, and public bit-cancellation rows
    B_i(b)=XOR_{j,k:variable(j,k)=i} R[j,k,b].

Propose an unrestricted public correction D(z)=XOR_j U[j,z|clause_j]. Then for every SAT-valid ORIGINAL assignment w, XOR_j A_j(w|clause_j) XOR_i B_i(w_i) XOR D(w)=K, the SAME precommitted key. The O(m+n) Build of A/B is concrete, but **a public D evaluator is NOT constructed**: the research checker uses a private simulator for D to challenge the strongest apparent repair. Simply exposing SHA seeds would reveal secrets; a black-box public secret-key evaluator is not allowed as an independent assumption.

## Exact affine-public-feature theorem (restricted scope)

Suppose all publicly readable row values Y_j (including any publicly callable D responses) are XOR-affine in hidden setup words t_1,...,t_M and precommitted K, with a PUBLIC, efficiently computable binary coefficient matrix A and K-column b:
    Y=A t XOR b K.
Suppose a valid witness w induces a public XOR-linear reconstruction vector c(w) such that c(w)^T Y=K for **all** independent t,K. Then c(w)^T A=0 and c(w)^T b=1. Even without w, a public Gaussian eliminator can solve A^T c=0,b^T c=1 whenever such c exists and recover K from c^T Y. For TRUE x, correctness guarantees such c; this is unconditional algebra, NOT an NP witness extractor. Hash-generation of t_j does not help if the public incidence is known: one may treat each SHA output as an independent formal variable. The theorem does NOT apply to non-affine hidden correlations or a source-dependent evaluator whose *coefficient incidence* is not public, and it does not prove no hash-based WKEM exists.

Because each D(z) is a Boolean function of degree at most three, its values at all inputs of Hamming weight <=3 span D(z) for every z through Moebius interpolation. The number of public D queries is 1+n+n(n-1)/2+n(n-1)(n-2)/6, polynomial; no witness, private label, source certificate, or quantum attack is supplied to the public row-space solver.

## Executed checks, bounded and synthetic

A local standard-library checker.py was run on 144 TRUE/FALSE sampled CNFs with 1,846 asserted equalities: 120 planted TRUE and 24 known FALSE, 1,558 honest Open evaluations, 144/144 key recoveries using public symbolic coefficients and public table/correction rows, no witness provided to the attacker. Source SHA256 bfd6b21d29764acf13c754602dce390c42f84b6e591d84cf29c69d7ab64a8a9f; output SHA256 5ec519e9b8f469bcf151d951bd5e4234f26436274eb00bf9a1fdf53663a1d39c. Neither count proves cryptographic security.

An independently formulated arbitrary-local-SHA correction checker, opaque_correction_checker.py, was run twice with byte-identical captured output: 120 TRUE and 24 FALSE, 1,179 honest openings and 1,299 assertions. All 120 TRUE keys were linearly extractable without a witness. For the 24 simple 3-variable all-pattern UNSAT cases, no row-span leakage was found, showing this particular local nonlinear mask appears to hide K on those easy false cases; this does NOT establish FALSE security. Source SHA256 188bf8ab0b1cd98f10481648bf854607da28740cb4c39c3360ce0220ed27fb0e; captured SHA256 ea60bd4ae997235d40b43f6275ae85bf3c99d86877055499e4c521b404b09a74. These are synthetic coefficients and a hypothetical public D query interface, not a real deployed public capsule.

Further SAT-unsat sampling of this class across n=4..9, 400 formulas each, found UNSAT false-key row-span leaks increasing with n. For n=4, 8 of 206 UNSAT samples had leaks; n=9, 298 of 298 UNSAT samples leaked. This is empirical on a particular random generator, not a universal theorem. A 9-clause/4-variable UNSAT leakage counterexample was minimized; all 16 assignments were verified invalid, and the public row eliminator nevertheless recovered K. Its complete fixture and exact minimal checker/output will be preserved in the final checkpoint. This distinguishes computationally sound original-witness release from an algebraic *pseudo-witness* within local public corrections.

## Current precise open task

Construct a **polynomial-time** hash-only correlation mechanism not representable as a publicly indexed XOR-affine system and not predicated on an uninstantiated secret-key public D oracle. It must be computable by EVERY actual ORIGINAL evidence witness while producing the SAME frozen signature. Full-public arbitrary-QPT key recovery and target native forgery must imply the ACTUAL ORIGINAL witness or a separately justified PQ hash break. PoW/source authenticity must be bound to release itself, not a post-hoc API check. Source WorkID and child OutcomeID remain distinct; genuine Bitcoin canonical-chain inclusion, ancestor, coinbase, tag, window and reorg assumptions are NOT implemented in these SAT fixtures. Ceremony/erasure, pre-funding DA and native PQ endpoint remain separate requirements.

No ordinary PR comment, positive claim, parameter optimization or automation stop.
