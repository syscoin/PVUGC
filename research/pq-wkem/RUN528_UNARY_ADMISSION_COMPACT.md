# Run 528 — one fixed unary map versus two selectable reversible witness writers

Research-only continuation of syscoin/PVUGC#1. Starting head: 6e4a92587a7256bb920f82679233742ac86fd080, branch research/pq-wkem-validation-20260918, open/draft/unmerged. Exact inputs read: Run 519 commutator (f44a4d4486fdbb396f5456eebc240fb4661e4060), Run 520 WE implication (e01829de622de185c64ecde602c8560329fb0d9e), Run 526 sparse loader (5ecc680e4409e55cebab4318fa3a61ece574fe1d), Run 259 source-binding (c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2), CLZ assessment (c19d9d9cd515140e3ce62eac960cd548c0add622).

## Exact fixed-unary orbit bound

Suppose classical setup provides m capability-bearing ciphertext anchors and a watcher can apply a SINGLE fixed deterministic unary plaintext function g at most T times to any anchor, copy it, or rerandomize it without changing the plaintext. Fresh encryption of known witnesses produces independent ciphertexts but no allowed binary join of their plaintext with hidden K. The watcher MAY choose the anchor and repetition count depending on later witness w. All *sanctioned* capability-bearing plaintexts belong to {g^t(s_j):1<=j<=m,0<=t<=T}, so there are at most m(T+1) distinct states. If a proposed faithful-input architecture requires distinct protected states for all 2^k witness strings, m(T+1)>=2^k. This is tight for a reversible counter g(K,z)=(K,z+1 mod 2^k) with appropriately spaced anchors.

Proof: induction on the unary/copy/rerandomize construction tree. A descendant of anchor j at unary depth t has plaintext g^t(s_j). Rerandomization does not affect it. Count the possible (j,t) pairs. Crucially, w-dependent selection of t is permitted. No claim is made about unsanctioned malformed ciphertexts, a second selectable unary action, a plaintext-controlled function, a binary join, or schemes that do not faithfully encode every w into distinct states. This is NOT an impossibility theorem for WE or CLZ.

## Exact reversible two-action functional repair

Let protected semantic state include (K,x,z,t,marker), z a k-bit witness slot and t mod(k+1). Define two publicly SELECTABLE reversible permutations indexed by b in {0,1}:

U_b(K,x,z,t,marker)=(K,x,z XOR (b*2^t if t<k else 0),(t+1) mod(k+1),marker).

The inverse determines old t from new t and undoes the XOR. Starting z=t=0, applying U_{w_0},...,U_{w_{k-1}} yields (K,x,w,k,marker) for every later w, in exactly k updates, and does not require learning K. This is a FUNCTIONAL interface, not a cryptographic construction. Publishing jointly secure compact programs for P U_0 P^-1, P U_1 P^-1 and an atomic source-guarded terminal remains entirely open. The fixed-unary controlled-homomorphism result stated for one g must NOT be silently extended to two selectable maps.

The semantic protected terminal must depend on the complete ORIGINAL source predicate R_x(z), not a writable admission bit: marker XOR=([claim=x] AND K_i AND R_x(z)). Merely exposing a separate B_i gate or untrusted b recreates Run 519's false-instance credential recovery. Valid w may retain distinct z but all recover the same K; only the *semantic identity* is established. No ordinary transparent gate list securely protects K.

## Falsification and model ledger

(1) Exposed local protected gate/cancellation seam leaks K. (2) Shared-frame synchronization of Runs 521-525 remains relevant. (3) The structured conjugated loaders are not independently PRPs; Run 526's fingerprint may apply to sparse circuits. (4) m anchors and related capsules are explicitly counted but no joint crypto security is proved. (5) Chosen iteration counts are included; selection of U_0/U_1 is the additional expressiveness. (6) N-of-N erasure/malicious setup not handled. (7) Claim/UTXO/branch data remain immutable only in the ideal semantic description. (8) Native checking key and pre-signatures must be included in a real public-view game. (9) Honest semantic counting applies to classical PPT evaluation, not arbitrary-QPT public white-box attackers; coherent evaluation, quantum advice and QROM extraction are UNPROVED.

Run 259 applies only after obtaining an accepted complete representation satisfying rho_x(z)=0 and SrcExt(x,z), or the exact stated folded-residual / QPT-SIS conditions. This pass does not establish unauthorized native signature or capability recovery -> accepted z. Run 520 shows universal general-NP release with false-instance full-seed one-wayness is already WE-capable; no disguised new release assumption is made here.

Executed checker's deterministic validation includes 980 orbit bounds, 589 tight orbit cases, 8,192 inverse-permutation checks, 2,040 witness admissions, 3,780 source-guarded identities and 945 untrusted-admission counterexamples. These are finite tests, not a QPT or resource proof.

Literature: Canetti–Luo–Zhang CRYPTO 2026, https://simons.berkeley.edu/talks/ji-luo-mit-csail-2026-07-13 and DOI 10.1007/978-3-032-35367-2_18; their published description covers iteration of one fixed unary g. Complete conference proof, quantum-security assumptions, and joint selectable-input extension were NOT audited. CCMR local mixing ePrint 2024/006 remains only architectural evidence here.

Handoff: seek and directly attack jointly secure selectable public witness loading with an atomic source-verifying terminal. Classical-PPT practicality, complete-public arbitrary-QPT false-instance hiding, arbitrary true-instance native-authorization-to-ORIGINAL extraction, malicious N-of-N setup, multiple capsules, and concrete 128-bit resources are all UNPROVED. Native P2MR/SLH is conditional; no Bitcoin proof execution, no production change, PR draft/unmerged, automation stays enabled.
