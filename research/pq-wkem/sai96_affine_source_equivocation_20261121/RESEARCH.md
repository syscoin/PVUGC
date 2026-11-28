# SAI96 — Two-opening affine equivocation carrier screened against ORIGINAL source (NONQUALIFYING)

## Continuity and candidate selection
Live draft syscoin/PVUGC PR #1: branch research/pq-wkem-validation-20260918, initial head f7cefb2497ca4e325c3d7ae8130e9dd5b9725ab1; latest SAI95 note blob 732b8b2730571ea55e4247eb442201cad875ecb7. Targeted issue comments since 2026-11-19T00:00:00Z returned none. No current Core source read, Core test, original Bitcoin/Syscoin source certificate, or native signing run.

SAI95 tried extracting a setup secret from two sigma-OR proofs with a fixed first commitment. The source witness can rewrite the B response but not the A response; only B's already supplied witness is extracted. Here we test a different algebraic mechanism: two independently verifiable future *source* attestations that share one setup secret polynomial could reveal one common cancellation pad, without requiring common future header bytes. This must be checked against the ACTUAL ORIGINAL source relation before optimization.

## Algebraic construction for a DIFFERENT, signed-evidence relation
Over F_p choose uniform independent setup secrets K,a. For nonzero signed source-message encoding m, define response y_m = a*m + K (mod p). For fixed m != 0 and uniform a, y_m is uniformly distributed independently of K. For any two distinct nonzero m1,m2 attested using precisely the SAME pair (a,K), interpolate:

    K = (m2*y_m1 - m1*y_m2) / (m2-m1)  mod p.

D = S XOR KDF(K,claim_id) could then conceal a fixed cancellation authorization S until two such genuine evaluations appear. This algebra would return the SAME K across every pair of distinct messages using that one polynomial, and avoids using a variable future block digest as the pad. A hash commitment to (a,K) and a transparent proof that each response corresponds to the same commitment could conceptually certify consistency, but no such ZK circuit is constructed or tested here. Nor is any actual native signature from it constructed.

## Why it cannot open for all ORIGINAL witnesses
The ORIGINAL policy remains OR of qualified strictly-greater exact Bitcoin-chain work, finite authenticated withdrawal-specific burn fault, and qualified strict-post-PQ Syscoin history inconsistency/tag fault at required LC depth. An ordinary authenticated Bitcoin parent header, coinbase SYS ancestor tag, AuxPoW merged-mining child commitment, and child ancestry contain NO evaluation y_m produced using a setup-secret affine polynomial (a,K). Coinbase hashes and PoW nonces are public and independently chosen. Legitimate conflicting child histories may use distinct parent certificates from independent miners; strict one-parent/one-child commitment does not imply two uses of one hidden signing secret. Different valid parent certificates for the same child alone are NOT a fork.

Mapping y_m to public SHA(parent_certificate) does not yield the fixed hidden K that setup needs to mask S: the setup cannot know future headers or tie every one to the same secret affine coefficient pair. Enforcing an added affine relation on such SHA values would exclude otherwise valid ORIGINAL challenges. Adding new miner-carried polynomial evaluations/commitment proofs would require source protocol changes and miners knowing setup secrets, or a forbidden post-setup signing authority. Bitcoin greater-work and burn-fault certificates do not require two distinct source messages at all. Consequently, even a perfect hash-only proof system for the polynomial responses fails universal ORIGINAL correctness.

Attempted repair: let anyone publicly compute y_m from authenticated original witness w, but not from unrelated m. That is exactly the still-missing source-conditioned non-black-box secret evaluation mechanism, not an operation implemented by public SHA/AuxPoW or by the affine interpolation. Publishing an arbitrary-message response oracle would permit an adversary to request any two different m and immediately extract K, before a qualified challenge. A setup participant cannot precompute evaluations for exponentially many unpredictable future headers in classical polynomial time.

## Bounded execution and limitations
Executed Python3 finite-field checker at p=7 once, success. Across 294 one-response assignments each (m,K,y) has exactly one choice of a, demonstrating the stipulated uniformity. All 1,470 distinct-message pairs sharing one (a,K) recover K. When instead crossing responses with independent (a,K) and (b,L), extraction fails to recover the desired K in 2,058 of 2,401 ordered cases. These assertions concern only finite algebra; no actual SHA PoW, source verifier, ZK commitments, FE, setup, QPT adversary or Bitcoin native VM was tested.

Local-only checker: /mnt/data/pq_research_run/equivocation_check.py, SHA256 142ac99899abc74080e462ca20b54339ac7b0b2956fc5e87e1386756b14a635b.
Local-only captured output: /mnt/data/pq_research_run/output.json, SHA256 0f060e4124a33624acd36d9f97b444c970ab00f3e6ac68c0e2ea0ed09a3576c6.
These executable bytes are NOT claimed to be included in this GitHub note.

## Decision and exact uncompleted obligation
**REJECT for ORIGINAL.** Two-use secret-bearing signatures are a different, source-strengthened relation. The actual Bitcoin/Syscoin work certificates have no such signer or polynomial evaluation. This does not establish a generic hash-only impossibility or a completed source-specific release scheme. Do not misinterpret two different authenticated parent PoW certificates as hidden-key equivocation.

Still needed, without adjusting the approved challenge grounds:

    C = Build_ORIGINAL(x_W, sigma_cancel; rho)
    Open_ORIGINAL(C,w) = sigma_cancel   for EVERY qualified ORIGINAL witness w.

The serialized classical-PPT public compiler must cryptographically tie SHA/AuxPoW authenticated evidence to release of the SAME frozen native safe capability; complete-public FALSE and hard-TRUE QPT recovery/accepted forgery must reduce to an ACTUAL qualified ORIGINAL source certificate or independently justified hash/native break under full native VK, setup proof, malicious source coins, sibling capsules, selective openings and one-honest distributed setup. This candidate does not supply that compiler or simulator.

NONQUALIFYING research-only assessment. No PR progress comment, Core/production write, deployment, automation change, or funds transfer.
