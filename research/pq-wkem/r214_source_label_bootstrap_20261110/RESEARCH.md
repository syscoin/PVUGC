# R214 — one-sided source-label bootstrap, exact attempted source-label interface

**Status: negative construction/repair checkpoint only.** No secure hash-only Build/Open, no original-source witness compiler, no QPT theorem and no user progress notification. Preserves a concrete attempt, functional checks and correct model boundaries rather than repeating it in future passes.

## Continuity and provenance
syscoin/PVUGC PR #1, draft/open, branch research/pq-wkem-validation-20260918. Observed starting SHA cca3912e367765d1c97a6285e060419f32995fde (R213); exact R213 and R212 notes read, no full PR diff. Latest ordinary comments since 2026-11-10T16:00Z: none. Intermediate hypothesis committed BEFORE test execution at 7246d0bde6d32a15cf1a068a915eba5a233175b0, parent cca3912e. No web/literature, independent agent, real mining, current deployment verification, native PQ signature or quantum experiment. Only synthetic SHA256 fixtures executed locally, twice with byte-identical JSON output.

## Exact original target
One N-of-N preauthorized safe graph, one notary initiates a withdrawal and ANYONE with one qualifying ORIGINAL R1 (relevant contradictory greater Bitcoin work), R2 (finite authenticated invalid/missing bound PoB) or R3 (fully authenticated incompatible Syscoin claim-prefix with required depth or separately admitted tag fault) witness must release the SAME frozen UTXO/claim/path-scoped cancellation capability off chain, without an online signer/issuer. Bitcoin sees only the intended native cancellation signature. Each witness must bind actual BTC anchor/work, exact source/burn/window, AuxPoW/coinbase/Merkle/pure-child ancestry, relevant tags, parsed height, claim/recipient and native VK. Synthetic hashes in this run are NOT authentic evidence. Different work certificates of one child are not forks.

## Candidate: one-sided source-label bootstrap (SLB)
Fix authenticated baseline claim-prefix digest u0=U_claim(P0) in xW. Future qualified alternate source proof P has a digest u=U_claim(P) != u0. Build must finish BEFORE the unknown future alternate u exists. Try labels

    L0=SHA256("baseline",xW,u0);
    L1(u)=SHA256("alternate",xW,u);
    M(u)=SHA256("pair",xW,L0,L1(u));
    E(u)=sigma_cancel XOR M(u).

An individual source proof P may let honest Open compute u, but is not automatically able to produce a hidden builder-chosen label or any *same* private mask for every P.

Attempt A (known alternate). Build freezes E(u1) against one hypothesized qualifying u1. For a different qualifying u2, M(u2) typically differs; one common frozen sigma is not recovered. In the 96 synthetic contexts tested, each of two different future digests produced different pads. A direct nonce/hash-of-certificate version is similarly witness-dependent; this is not a statement about hard-to-find real future histories.

Attempt B (normalize). Replace L1(u) with a fixed public baseline-derived label, or a universally known source root. Every honest P can then evaluate the same mask. Any outsider evaluates the exact same mask without a source witness and extracts sigma from E, independent of SHA security.

Attempt C (secret labels). Honest Build samples private s0,s1, commits to H(s0),H(s1), publishes E=sigma XOR H(s0,s1). Neither ordinary Syscoin tag nor actual AuxPoW carries these invented preimages. Keeping s1 private blocks permissionless Open even when P is genuine; publishing both enables immediate disclosure. If source signers originate and retain both labels, R173 retained-secret attack applies; if an honest party supplies later s1, it becomes a prohibited online authority.

Attempt D (public bit labels). Make labels public functions of xW and u0 for both sides of a source conflict. Every outsider can compute both and open even before a fork. A post-hoc source-verifier if-check cannot protect the raw pad. Having a pair of *semantic* conflicting slot values is not a hash collision or OTS double-opening.

Attempt E (full certificate or root). A future-certificate label H(serialize(P)) varies for each valid P, invalidating every-witness common-capability correctness. A fixed public baseline-root label restores convergence but enables immediate extraction. A builder-secret salt would require a new actual source-to-salt interface; it cannot be inferred from authenticated work alone.

## Limited structural claim; not a general impossibility
In this narrow gate family, a **public, fixed, source-independent mask** is computable by an unauthorized evaluator; a mask of an UNKNOWN future digest cannot be precomputed for every future source under one frozen E; a *private* source label is unavailable from normal original evidence absent an instantiated interface. This follows from the equations above and does not exclude a non-factorized, genuinely source-coupled full SHA/AuxPoW circuit encoding. There is no proof that all hash-only witness encryption is impossible, or any QPT extraction from original hard-TRUE recovery.

## Actual executed checks
Local checker.py was executed twice as standard-library Python and stdout matched byte-for-byte, 1,440 functional assertions in 15 groups for 96 synthetic contexts. The tests include distinct future witnesses, fabricated alternate digest, public-label extraction, hidden-label liveness, early disclosure on publication and fixed-root normalization. They do NOT test a mining distribution, actual verifier, native signatures, quantum security or malicious graph. Executed checker SHA-256 02e20aa3198f6706a0fb42ec808f1c14ccd480ed3b1a646421b4c12b432da94c, captured stdout SHA-256 a16301e2c053e91c871a764b775212dc79538b80f8cef6bd34429a381bc9b2ea. Files below are the exact checker and stdout read back separately.

## Exact missing algorithm
A new candidate must supply a classical-PPT public capsule whose *actual* original SHA/AuxPoW and source-history constraint computation jointly enables a common hidden value from ANY qualifying source witness, without making this value evaluable on fabricated source, accepting inconsistent mixed traces or having an issuer label preimage. Its full-public arbitrary-QPT simulator must handle malicious builder/source coins, related capsules, native VK/checking context and one-honest N-of-N ceremony. Any candidate with only a public source-check guard, private label not derivable from source, independent PoW puzzle or a canonicalized publicly computable hash pad is not a solution. Do not optimize this rejected class. No routine PR comment, and task remains enabled.
