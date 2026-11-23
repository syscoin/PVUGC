# SPU: Trapdoor-simulated unique-proof release — screened, NONQUALIFYING

## Continuity and source
On the actual open draft syscoin/PVUGC PR #1 branch research/pq-wkem-validation-20260918, the inspected starting head was 567f25d0d55788936c013478ce882c4f5bcd6802. Read the immediately preceding public group-program consistency note at blob 3c70c26f6babdf3e5e6be68f12f470ec2b7b47ce and hidden-reject-matrix note at blob 1dfbc9719c827c2e4cbdf6bde419e9924c7b0823. Top-level PR comments since 2026-11-18T19:24Z returned []. No Core reread, external research, network certificate, native signing or quantum experiment was conducted. The full companion local derivation is also available in this execution as /mnt/data/pq_unique_proof_screen_20261123.md (SHA256 68a3c7e02ca28b1e995c71175de504d476219026962dc5f6abd0858d091f8717).

## One named mathematical candidate
Rather than per-occurrence public matrix transitions that allow inconsistent source-bit selection, hypothesize a globally proof-based key. Let R_x(w) be the unchanged ORIGINAL three-branch OR predicate for (1) same-anchor strictly greater Bitcoin work, (2) finite authenticated claim-specific burn fault, or (3) qualified actual Syscoin history inconsistency or independently authenticated tag fault at the required LC depth. It binds exact protocol/chain, claim/outpoint, assertion/amount/recipient/reserve/replay, baseline, strict post-PQ modern AuxPoW contextual checks, ancestor heights and paths, BTC anchors/windows, reset/deadline, native safe cancellation and VK, and capsule/session ID.

Suppose a hash-only NIZK-like primitive had all three STRONG properties:
  (U) any qualifying ORIGINAL witness w permits classical PPT Prove(crs,x,w) with one identical proof byte string pi_x, even when different valid future histories exist;
  (S) the honest setup has a trapdoor td permitting Sim(td,x)=pi_x before any source witness is known;
  (E) arbitrary full-public QPT recovery of a proof-dependent key or native signature extracts an ACTUAL qualifying ORIGINAL certificate or yields an independent justified hash/native break.

A proposed fixed-message release is:
  (crs,td) <- Setup(lambda)
  pi_x <- Sim(td,x)
  k <- KDF("SYS-PVUGC/SPU",x,session_id,native_VK,safe_msg,pi_x)
  D <- sigma_cancel XOR k
  C <- (crs,D,x,session_id,native_VK,safe_msg,verifiable-setup transcript)
  Open(C,w): return D XOR KDF(...,Prove(crs,x,w))

Under (U)+(S), every valid witness obtains the SAME frozen signature; the source witnesses themselves need no common preimage. Independent participant setup could protect N precomputed native signatures and require an N-of-N native Bitcoin spend while a single watcher evaluates all capsules. Honest erasure/protection and no native bypass remain required. This is a conditional interface, not implemented FE or WE.

## Joint public simulation and early screening result
A FALSE simulator must account for (crs,D,original instance, native VK and exact message, setup proofs, auxiliary/sibling capsules and malicious retained setup/source randomness). A unique accepted proof plus ordinary hash collision resistance does NOT imply that KDF(pi_x) is pseudorandom given that joint view. Simulation trapdoors and correlated public setup proofs are particularly dangerous. A hard-TRUE knowledge theorem about an adversary that voluntarily outputs pi_x does NOT control an attacker that directly computes k or produces an accepted native signature from the published bytes without outputting a proof. Property (E) is already substantially the requested original release security; assuming it is circular rather than an independent source/hash reduction.

Deterministic hash/Fiat-Shamir proof generation does NOT supply (U): different qualified future AuxPoW histories, ancestor hashes and burn proofs yield different witness traces and proof commitments. Canonicalizing the ORIGINAL witness is prohibited and can require the same hard search. If the proof-independent key is instead a public hash of (x,accepted), it is computable before any evidence and the frozen capability leaks. A trapdoor-simulated UNIQUE proof satisfying (U),(S),(E) is essentially a witness pseudorandom function/WE under another name, and no hash-only compiler was built.

## Repair screened
Allow differing proof bytes pi_1,pi_2 but demand a single Key(crs,x,pi) for every accepted proof. A public Key with a publicly synthesizable accept input leaks. An unimplemented source-conditioned protected Key simply restores FE. The missing, independently instantiated operation remains:

  Build_orig(x_W,sigma_cancel;rho) -> actual publicly serialized C
  Open_orig(C,w) = same safe frozen sigma_cancel for EVERY R_orig(x_W,w)=1
  any arbitrary QPT unauthorized recovery / accepted native forgery
      -> an actual original certified challenge or independent justified break

The output must be native claim/UTXO-safe, not general unrestricted signing. Fixed pre-signing requires an actually fixed native message or explicit slot-global veto; dynamic future activation needs restricted signing with no signature/txid self-reference. Ordinary Bitcoin ECDSA is an accepted classical first-release endpoint, not QPT security.

## Outcome
NONQUALIFYING. This is one bounded construction-and-joint-simulation screen of a different proof-centric route, rejected BEFORE implementing an assumed primitive. No public source-dependent Build/Open, QPT theorem, real authenticated certificate or tested native cancellation. No breakthrough announcement, PR comment, production edit, scheduler change, deployment, or external web use. The next valid candidate must instantiate a protected source-conditioned public release algorithm rather than assume proof uniqueness, source labels, simulator access or a hidden-signature oracle.
