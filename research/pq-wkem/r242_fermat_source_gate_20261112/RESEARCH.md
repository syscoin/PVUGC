# R242 — Fermat source-trace indicator and vanishing-mask repair

STATUS: NONQUALIFYING. No original-source hash-only key release, SHA256/AuxPoW circuit, QPT security, native signing, or production changes. Routine negative work: no PR progress comment.

## Continuity
PVUGC PR #1 on research/pq-wkem-validation-20260918, observed head fb28fd2b1408d0ac92945e0cd50ae8e83d64aa18 (R241), file research/pq-wkem/r241_public_sha_garbling_20261112/RESEARCH.md, blob 57ff8b927e0639419a8d2a712f1795abf9cb9584. Latest issue comments since 2026-11-12T00:00Z were empty. R241's public input-label and root-conditioned repair both failed. Here the release attempt is algebraic rather than garbled. Checkpoint recorded BEFORE testing, locally SHA256 0673799b795ca326bee0a1261a8da1145a777f077c991275d400c4ea90d7978a. No external literature or web search.

## Original source target (not replaced)
One notary initiates and any watcher with qualifying authenticated evidence challenges. The relation is the OR of relevant strictly heavier Bitcoin work, authenticated finite burn fault, and sufficiently deep authenticated Syscoin claim-prefix/tag inconsistency or explicitly applicable tag fault. Bound x_W to exact claim/outpoint, baseline and claim-relevant height, source anchors/windows, modern chain-ID/exact post-PQ tag, authenticated original Bitcoin AuxPoW/Merkle/parent context, interval ancestry, native cancel message and VK, deadlines/reset and capsule ID. A different parent-work certificate for the same child is not a Syscoin fork. N-of-N preauthorization is separate; only native cancellation authorization reaches Bitcoin. This experiment implements NONE of the full source verifier.

## Proposed arithmetic carrier
Over F_q, q prime, suppose actual ORIGINAL source constraints are c_1(z)=...=c_m(z)=0, including Boolean SHA gates, parent PoW/coinbase/child commitment, canonical tags, height/ancestry, relevance and Bitcoin anchoring; no fabricated validation flags. Define

 Z(c)=1-c^(q-1)
 V_x(z)=Product_j Z(c_j(z))
 D_x(z)=(H_alt(z)-H_base)^(q-1)
 F_x(z)=V_x(z)*D_x(z)
 P_sigma(z)=sigma*F_x(z).

Fermat's theorem makes Z(c)=1 exactly on zero constraints, and D=1 on unequal semantic child hashes. Therefore if a fully qualified original witness can be encoded correctly, P_sigma(w)=the SAME sigma for every such witness. A field arithmetic circuit can evaluate this identity with O(log q) operations per zero-test (relative to the cost of the actual source constraints). This is only functional correctness. The public straight-line program literally contains sigma and is not a secure Build/Open.

## Explicit hash-only repair attempt, and its exact limit
Try a random constraint-ideal mask:
 Q(z)=sigma F_x(z) + Sum_j R_j(z)*c_j(z).
At a valid original witness, c_j=0 and Q(w)=sigma. But publishing arithmetic program literals exposes sigma. Hash-committing coefficients hides the values without enabling public field evaluation, since SHA commitments supply no homomorphic evaluation of the required sums/products. Revealing coefficients restores access to the encoding.

A concrete digest-only vanishing-mask subfamily is broken even when coefficients are flattened and R is nonlinear/random. In F_17 take c(t)=(t-1)(t-2), F(t)=1-c(t)^16 and Q(t)=sigma F(t)+c(t)R(t). Since F(t)=1 (mod c), public Euclidean polynomial division gives Q(t) mod c(t)=sigma, independent of R. No qualifying authenticated original source is needed. The included checker executed 12 distinct random-mask instances and verified every recovered remainder. This proof is exact for this subfamily, NOT evidence that quotient computation for full multivariate SHA trace is efficient or that all hash-based WE is impossible.

## Exact bounded executions
Local checker.py, SHA256 7914467f23c18503ce093f70041f0373811dcad885f0f7a54a5ac044f9addf7e, twice enumerated F_17^3 = 4913 input triples. Toy NONCRYPTO source h(n)=n^2+3n+1 (mod17), n in {0,1,2,3}, d=h(n), t=d, d in {1,2}, t!=baseline 11. The finite-field indicator matched exact accepting tuples (0,1,1) and (3,2,2), each opening the identical toy sigma=13. False target {9,10} accepted none. Direct public sigma literal and a complete 4913-entry evaluation table each disclosed sigma without requiring a supplied original witness. The full table would be exponential at real source width. Local captured.json SHA256 36de51877f84da18928d9933c8aaaf2d2852cc1dd8a72b59f9f2a7bfa0332173.

The separate quotient_repair.py checker (source SHA256 0a69474dc77ed8ae75e04ecaae241abc382c2fa7dda19f0fbbf6c862248b5b53, Python + SymPy 1.14.0) ran twice with byte-identical output showing 12 masked polynomial encodings and sigma=13 recovered from each. Its output SHA256 d7a9f3db28af3e775ad548694c59d7c577adf0374cebdf5eb7ccf82880a97b27. All checks are algebra only; no real SHA/AuxPoW source check, QROM proof, full-public native signer, malicious-source experiment or N-of-N ceremony was performed.

## Unfinished ORIGINAL bridge equation
Still missing an actual classical-PPT Build_inc(x_W,sigma_cancel)->C before unknown future source, and public Open_inc(C,w)=SAME sigma_cancel for EVERY fully qualified ORIGINAL relevant challenge witness, without leaking the secret via literals, polynomial coefficients, nonBoolean tests, or forged source evidence. For arbitrary QPT attackers given all public keys, checking correlations, sibling capsules, selective openings and malicious source coins, recovery of the final native signature must imply an ACTUAL original challenge certificate or independent justified hash/native break. The hash-only protected evaluation of an original SHA/AuxPoW trace is not instantiated here. An oracle or hidden arithmetic evaluator providing it by definition would just rename the unsolved witness-encryption task.

No genuine reduction of the original source-conditioned secret-release obligation was obtained.