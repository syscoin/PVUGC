# Run 502 — two-path local-frame holonomy defeats a minimal reversible bit-release gadget

**14 October 2026; research-only; draft syscoin/PVUGC#1; starting SHA `904455a97bddfe597094db99608be43d3fe365f4`.** This is a focused falsifier, not a practical witness-KEM, a result about CCMR's actual RIO distribution, or a generic impossibility theorem.

## Candidate and explicit model

Let a native signing-seed bit `k` control a 2-bit reversible source/release gate `B_k(b,z)=(b,z XOR (b AND k))`: `B_0=identity`, `B_1=CNOT`. Public setup has independent uniform local frames `P_v` from `S_4` on the four `(b,z)` states. Each exposed gate table for an edge `u -> v` is `E_{u,v}=P_v G_{u,v} P_u^{-1}`. A proposed tiny protected release region publishes two **readable** paths with the same input and output frames: one path implements `B_k`, the other implements identity transport. No restriction on later ORIGINAL witness states is required for the attack. Honest setup and evaluation are classical PPT. Adversary sees the complete public tables, full context and checking key, auxiliary inputs and arbitrarily many capsules; it may be QPT, but the attack below is already deterministic classical PPT.

## Exact theorem (all masks independent; single-edge marginals perfectly hiding)

For independent uniform frames `P_s,P_t` expose `A=P_t B_k P_s^{-1}` and `B=P_t P_s^{-1}`. Both `A` and `B` **individually** are exactly uniform in `S_4` for either `k`. But the *relative public holonomy*

`H=A B^{-1}=P_t B_k P_t^{-1}`

is identity if `k=0` (four fixed points), and is a transposition if `k=1` (two fixed points). Hence `k=[#fixed(H)=2]` is recovered with probability one without knowing a frame.

Exact pair law: for `k=0`, there are 24 equally likely ordered `(A,B)` pairs, each of probability `1/24`. For `k=1`, there are 144 equally likely ordered pairs (the 24 choices of `B` times six conjugate transpositions), each of probability `1/144`. The supports are disjoint, so joint statistical distance is **1**, despite both single-edge marginals being identical uniform distributions.

A separate random intermediate frame does not help: if `A_1=P_m B_k P_s^{-1}`, `A_2=P_t P_m^{-1}` and `B=P_t P_s^{-1}`, then `(A_2 A_1)B^{-1}=P_t B_k P_t^{-1}`. The intermediate gauge cancels. More generally, pairs of publicly traversable paths with identical source/sink frames reveal conjugacy invariants of their unmasked relative permutation. This says **nothing** about designs that do not publicly expose such paired paths, hide gate truth tables, or use unrelated endpoint frames.

## Release/security consequence and sharp boundary

If 256 signing seed bits are represented by such publicly paired local gates, an adversary independently computes 256 fixed-point counts and reconstructs the whole seed. An honest opener may check the ORIGINAL relation first and then return that same seed for every valid ORIGINAL witness, satisfying *honest* SAME-capability correctness. An attacker ignores the local validity check and recovers the credential even when the ORIGINAL relation has no valid witness. This violates false-instance secret hiding and can yield fresh same-claim authorization without an accepted COMPLETE source representation. Neither setup-ZK certifying faithful construction nor honest N-of-N random frame generation repairs this specific public algebraic leak. Run 259 only starts after an accepted COMPLETE representation and therefore does not apply.

**Nine-family falsification ledger:** (1) local seam cancellation across the paths; (2) conjugacy/holonomy is a gauge invariant, no global frame reconstruction; (3) fixed-point/cycle-type gate fingerprint; (4) correlated path views leak despite individually uniform gate distributions; (5) no adaptive public evaluation required; (6) fully honest independent masks already fail; (7) context binding rejects replay but not a fresh signature from the recovered secret; (8) public native checking key does not prevent extraction and can validate signatures; (9) classical attack is included in QPT, with no separate coherent quantum breakthrough.

## Exact validation / literature / outstanding obligations

Published `run502_compact_holonomy_check.js` is the exact executed deterministic JavaScript checker. It exhausts 1,152 independently framed edge pairs and 27,648 three-frame/two-path cases; the recorded JSON reports the exact support frequencies and total assertions. A separate **local-only** independent Python checker `run502_holonomy_check.py` executed 57,922 assertions and 24 classical Ed25519 signing demonstrations across 24 source contexts, including 12 false contexts; byte-identical rerun and Python syntax validation passed. This is finite algebra, not a quantum or cryptographic security proof.

Reference: Canetti–Chamon–Mucciolo–Ruckenstein, *Towards General-Purpose Program Obfuscation via Local Mixing* (TCC 2024, ePrint 2024/006). Their actual obfuscator does **not** thereby inherit this attack; its paper-level QPT assumptions and seam exposure remain unverified in this run.

**Unproved and unchanged:** an actual protected release algorithm with all-valid-ORIGINAL SAME native capability; full-public-output false-instance arbitrary-QPT hiding; arbitrary unauthorized true-instance native signing -> ORIGINAL witness or independent QPT break; malicious N-of-N setup/abort/erasure; multiple-capsule composition; concrete 128-bit resource estimates; conditional P2MR/native SLH-DSA endpoint and complete covenant graph. No new security assumption. Production untouched, draft/unmerged, no stopping condition met. **Handoff:** when testing the next local mixer, calculate all publicly composable reconvergent-path holonomies; merely making each individual local gate distribution uniform is insufficient.
