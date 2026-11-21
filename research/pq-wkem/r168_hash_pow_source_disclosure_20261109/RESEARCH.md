# R168 — Hash-authenticated source-share disclosure (research-only, rejected as WKEM)
**STATUS:** No generic secure witness-KEM or new source-to-capability compiler. This is a substantive test of a Syscoin/PQ hash-authenticated source-signature route, documenting its exact early-release/completeness obstacle rather than an optimization or a reportable breakthrough.

**Continuity:** syscoin/PVUGC PR #1, research/pq-wkem-validation-20260918, start HEAD 3151fd04792e818292ade52a2c37439d4f392775, open/draft/unmerged. Read exact prior hash-sealed-state research file at Git blob fd6576b982733e9ff7065f34b2a6cfe20f2e4820. No internet, no independent agents, no lattice/discrete-log primitives and no production changes.

## Explicit attempted Build and release

Take F_q with odd prime q and a pre-funded authenticated source signing group of N nodes. The source message m encodes the ORIGINAL relation/claim, source slot, child hash, parent/ancestor/anchor data and complete context; its field coordinate x(m) must be nonzero and domain-separated per capsule and source slot. Each participant j samples a_j,b_j <- U(F_q), retains a source polynomial f_j(X)=a_j+b_j X, and has its own hash-based signing key to authenticate messages. Before funding the N-of-N ceremony *conceptually* computes the sum K=Σ_j a_j without revealing it to a corrupt subset and masks an already frozen native signature sigma by an independent domain-separated hash of K. A public check hash is supplied.

An authentic attestation of m would carry signed z_j(m)=f_j(x(m)) from every required j. Given two distinct m1,m2 with x1!=x2, interpolate:
    K = Σ_j (x2*z_j(m1) - x1*z_j(m2)) / (x2-x1) mod q.
This is an exact SAME-K identity for any distinct pair and does not require the pairs to share an internal witness state. With just one source message, for an honest j unknown a_j,b_j, the posterior a_j conditioned on z_j(m1) is *uniform*; thus K is hidden from a corrupt N-1 subset except for its public key-check hash. This is a scoped information-theoretic lemma; the checking hash permits generic quantum preimage search, so it is not a full QPT game proof.

## Fatal original-use-case restrictions

1. These authenticated z_j are not produced by ordinary PoW headers, Bitcoin merged mining, ChainLocks or the ORIGINAL fork evidence. Adding them would require future source signers/issuers with retained private polynomial state. They are an *online release authority*, forbidden by the user, and N-of-N setup erasure would prevent producing future attestations.
2. For the natural two-conflicting-source-attestations-in-one-slot predicate, the required one honest N-of-N source signer refuses to authenticate an equivocation. Thus the full two-source witness cannot arise. If a threshold excluding that honest party can complete the second certificate, it cannot reveal the honest j's second polynomial point, so cannot recover K. This is a completeness/safety conflict under precisely these assumptions, not a general impossibility theorem for other evidence relations.
3. Reusing the same polynomial for normal source blocks at different slots releases K on any two normal messages prematurely. Distinct slot-scoped polynomials avoid that but reinstate (2). A malicious signer retaining coefficients learns its own shares early; N-1 retained coefficients alone do not reveal K until the honest j shares twice. No automatic conversion of ordinary source signatures into these shares exists.
4. There is no generic arbitrary-NP statement-only compiler and no joint full-public QPT simulator for x, capsule, CK, Aux, related capsules and selective opening. Authentic source post-checking cannot prevent raw key recovery once the shares are leaked.

## Actual executed algebraic checker

An independently executed offline Python standard-library checker (local-only implementation, not claimed published in this note) passed 17,024 assertions on 64 deterministic F_257 fixtures with 4 participants: two-message K interpolation, all 257 possible honest constant coefficients under one given signed point, and the absence of the second honest attestation under no-equivocation policy. Its exact source SHA256 is 85c0fe1bcaa91c22e56b9ce167e70af268eecbc0c85756022e2c280d6dfd7075 and stdout SHA256 b912bf8dcd1b44c9a2794b8eb6f431bbdfb3b5139e9c893147c876385982b153. This is finite mathematics, not QPT/hardness testing or real Bitcoin/Syscoin implementation. The local source and output are preserved in /mnt/data/HPW_R168_HASH_POW_SOURCE_DISCLOSURE_20261109/.

## Next actual construction target

Seek a NONINTERACTIVE source-dependent correlation built by classical-PPT honest setup *before* future authenticated AuxPoW witnesses exist, using hash-only operations and source semantics. Every valid ORIGINAL witness must recover one frozen K/sigma without online signers, but arbitrary invalid/raw private-PoW strings must not. A root/tag commitment only authenticates data; it cannot prearrange unknown secret preimages for all future witness strings. All prior SHA-prefix PoW and pre-enumerated tables fail this interface. Keep semantic outcome identity distinct from work-certificate ID. For generic-NP retain arbitrary witness correctness and extraction; do not promote this restricted source-signature scheme to the user's required WKEM.

**No ordinary top-level PR comment**, no security breakthrough, no native SLH/P2MR deployment, no optimization.