# Run 519 — atomic reversible commutator at the release frontier

Research-only checkpoint, 2026-10-15. Draft syscoin/PVUGC#1, verified starting SHA e7a8a1e1dda86bd6ea8efd3c5e516314966481d9. Exact predecessor notes: Run 518 blob f5c6f40cce0b31da6dec3d1221270d89b73374d0; Run 517 blob fb0acb35eae848e7fa3b19a5486085d126fcf41f; Run 516 blob fe183bf7b53eb5087e3496d7ae2cdeeef525b979; Run 259 blob c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2.

## Exact new algebraic factorization

Take a complete ORIGINAL-source predicate f_x(z), immutable claim sector d, hidden signing-seed bit k_i, untrusted admission bit b, and release marker t. Define reversible involutions
E_x: b <- b XOR ([d=x] AND f_x(z));
B_i: t <- t XOR ([d=x] AND k_i AND b).
All other registers remain unchanged. Their commutator, with rightmost action applied first,
C_i = E_x B_i E_x B_i
is EXACTLY
t <- t XOR ([d=x] AND k_i AND f_x(z)).
The initial value of b cancels for EVERY input (not just honest trajectories). Arbitrarily different accepted z produce the SAME K_x, with witness-dependent states retained. A complete Run-259 representation is usable only if its actual residual and SrcExt or stated SIS conditions hold. A short public admission flag is insufficient.

For any hidden permutation P, the atomically exposed composite A_i=P C_i P^-1 is identity over the ENTIRE space when f_x is identically zero, even when an arbitrary public editor changes b. Thus it has no off-source accepting support of the Run 517 kind and does not admit Run 518's bad-mark search on this defined atomic action. Any nonfixed query under A_i decodes (with simulator-only P^-1) to a complete accepted z. Run 509's straight-line coherent hybrid then has its required source-support premise: if the real-vs-null authorization advantage gap is Delta after q coherent terminal calls, random-query extraction probability is at least Delta^2/(4q^2), in that ideal-oracle experiment with all auxiliary interfaces otherwise identical. This does NOT prove arbitrary native-signature -> ORIGINAL extraction, real-world QPT hiding, or a practical classical-PPT simulator; null-world bypasses and auxiliary checking keys remain separate.

## Exact attack on transparent factor exposure

If the public evaluator can invoke the hidden-frame B_i factor individually AND edit the admission bit from the anchor, then from a_x=P(K_x,x,0,0,0) compute y=P(K_x,x,0,1,0), and read K_x,i as [P B_i P^-1(y) != y]. Repeating requires h+1 actions and recovers the entire key even when f_x is false everywhere. Exposing identifiable intermediate E/B subcircuits or an interpretable reversible gate trace in a literal implementation of E B E B recreates this seam. The positive lemma assumes C ONLY is published as an atomic operation; it is not a construction of an inspectable public circuit concealing B. If P acts only on hidden k,t while d,z,b remain public, E is an ordinary public checker and the cryptographically sensitive region is a tiny k*b gate, but simply publishing its two occurrences allows the attack. If P mixes z also, producing the encoded E can require obfuscating the full verifier. No independently justified compact solution to this splice was obtained.

## Security/attack ledger

(1) Local seam: exposed B+bit-editor extracts K; atomic C blocks the exact seam. (2) Frame/gauge: no compact construction or resistance to synchronization is proved. (3) Terminal still involutory/fingerprintable, not a PRP (Runs 514-515). (4) Related capsules: require actual claim-sector isolation and independent auxiliary scope; not proved for public white-box instances. (5) Chosen-input: arbitrary b does not bypass atomic C, but does bypass B. (6) Malicious setup/retained P/K, erasure, abort unresolved. (7) Cross-UTXO/branch/relation aliases and sector switching must be excluded. (8) Native VK(K) and pre-signatures remain in adversary's view. (9) The atomic ideal model supports coherent quantum queries and source-support hybrid only; white-box arbitrary-QPT extraction unproved.

The factorization is an elementary identity, NOT an added hardness assumption or a local-mixing compiler. This establishes a narrower *functional seam* between public ORIGINAL checking and hidden-key release, but no efficient, secure, atomic program representation. The hidden ideal permutation remains exponentially large. No live Bitcoin change: only conditional P2MR-like no-EC-key-path plus native SLH-DSA-like verification, not CAT, proof execution, on-chain NP, or a completed payout graph. N-of-N honest erasure setup and one-of-N watchers remain separate.

## Executed exact checker

The accompanying Python stdlib checker was executed TWICE and the JSON outputs compared byte for byte. It exhausts all 40,320 hidden permutations on eight states, checks 645,120 commutator cases, and checks deterministic 32-state fixtures covering witness z, source predicates, sector guards, off-orbit b, reference claims, and transparent-B bypass. Finite tests corroborate the identity, NOT security.

Literature: Canetti–Chamon–Mucciolo–Ruckenstein (TCC 2024, ePrint 2024/006) concerns local mixing of reversible circuits and conditional stronger obfuscation; its random-circuit statements do not instantiate this atomic splice. Canetti–Luo–Zhang (CRYPTO 2026) uses iO/PPRP in its encryption approach; controlled homomorphism does not automatically admit late external ORIGINAL witnesses. Recent arXiv:2609.40289 discusses a quantum obfuscation extension under qiO assumptions, not a concrete classical-source guarded capability-release construction. No full new paper proof was audited.

Handoff: construct and falsify a succinct public atomic composite that cannot be decomposed into callable/inspectable B, with independently justified full-public-output QPT security, arbitrary native authorization -> ORIGINAL extraction, multiple capsule/setup composition, and concrete 128-bit classical-PPT resources. These remain UNPROVED. Production unchanged, draft/unmerged, stop condition unmet.
