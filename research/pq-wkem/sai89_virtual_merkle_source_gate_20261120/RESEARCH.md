# SAI89 — virtual Merkle-edge source gate (NONQUALIFYING)

## Continuity and unfinished operation

The open draft syscoin/PVUGC PR #1 was read at 7d6bdfb7ddeb118db1c638ea2fdd9c3cbe763f57 on research/pq-wkem-validation-20260918. Latest substantive SAI88 blob 2e40f22299579e38b27c3a0c1ab7d662572d7f3c, SAI87 blob 8c48de7132aa4b2587fe6c64956d6ab6e8a91c0d, and exact SAI86 source-state candidate blob b507add2b1fef6720fc0d3c96c0a9a7a51a8c4df were read. Ordinary comments since 2026-11-18 19:24 UTC were empty. Core #609 source/tests and actual source certificates were NOT checked in this run.

SAI86 has a correct classical hash-only explicit finite-state builder/evaluator: independent secret label L_(i,q) per global verifier state, encrypted edge table E_(i,q,b) = L_(i+1,delta_x(q,b)) XOR H_pad(L_(i,q),i,b), and accepting terminal D_q = S XOR H_out(L_(n,q)). Multiple distinct original-valid paths merging into q acquire the same successor label. The cryptographic acceptance test is on the path, not a post-secret if-check. Its exact missing piece is a polynomial-time public succinct merge/update over the enormous authenticated SHA/AuxPoW state set, with one frozen S and QPT whole-public security.

## Candidate: commit to a virtual encrypted transition table

Change the storage semantics rather than the secret-sharing algebra. Generate labels by the keyed hash L_(i,q) = H_label(s,i,q) and define the same edge ciphertext E_(i,q,b) above. Attempt to replace an explicit table with one ordinary SHA-Merkle root M_s over all encrypted edge entries. A challenger carrying an original witness follows the verifier state path and obtains Merkle openings for its required edges. The builder would precommit root and fixed cancellation capability before any future Bitcoin/Syscoin challenge appears.

This attempt has three distinct public/private interfaces:

1. Publishing all entries and paths gives honest per-witness opening but requires enumerating every global source-verifier state, exponential for actual SHA/AuxPoW and future history. Merkle authentication reduces proof size, not the cost of constructing the standard Merkle root over arbitrary keyed leaves.
2. Publishing the keyed-hash seed s lets anybody regenerate labels and edges. An adversary then directly calculates L_(n,q*) for a known accepting terminal q* and decrypts D_q* even when that state is unreachable from the initial state. FALSE security fails without a relevant original certificate.
3. Keeping s private and publishing only M_s gives no public way to obtain an unanticipated future edge ciphertext/Merkle proof. An ordinary proof of a correctly computed keyed leaf still requires a prover with s or the already materialized table. A short public generator for keyed edges would need to evaluate hidden-key label functions without exposing s. That generator is the unconstructed protected computation, not a consequence of Merkle hashes, STARK proof soundness or one-honest erasure.

An arbitrary Merkle opening of an encrypted edge does NOT automatically reveal its destination token: decryption also needs the authenticated predecessor label. The failure of route 3 is missing honest PUBLIC evaluation, not an alleged universal state-injection attack. Route 2 is specifically broken by exposed seed and accepting-output ciphertext. A sparse tree with only currently seen evidence omits unknown future valid witnesses; untrusted off-chain root changes cannot alter the frozen capsule without an authenticated release mechanism.

## Joint-public simulation and exact missing equation

In an EXPLICIT FALSE graph with inaccessible accepting states and fresh independent secret labels, the restricted classical ideal-hash argument masks accepting D_q and prevents obtaining their labels from reachable edges. It does not extend to a public seed (which directly reveals every label), or to a private unimplemented virtual-edge generator (which does not open honestly). No true source-dependent public joint distribution was built to simulate; no QPT/coherent, sibling, selective-opening, malicious-source-coin or correlated native-VK theorem is claimed.

The necessary new mechanism, still NOT built, is:

    PublicAuthenticUpdate(C, token_(i,q), b, genuine_source_prefix)
      = token_(i+1, delta_x(i,q,b)),

where tokens merge at equal semantic states, no unrelated or counterfeit prefix supplies a token for an unreachable accepting state, and every complete approved ORIGINAL witness recovers the same precommitted safe Bitcoin cancellation capability. The serialized implementation must simultaneously provide FALSE full-public security and hard-TRUE arbitrary-QPT recovery/accepted-forgery => actual qualifying original evidence or an independent hash/native break. The original relation remains the OR of strictly-greater relevant Bitcoin work, finite authenticated particular burn fault, and qualified strict-post-PQ Syscoin history inconsistency/tag fault (without greater Syscoin work). No source is replaced by target prefix, invented label, optional soft verification, another signer or an uninstantiated FE/obfuscation interface.

## Bounded executed regression (synthetic ONLY)

A Python 3 standard-library checker was invoked twice with byte-identical output, exit 0. It uses eight steps and seven states; two distinct TRUE words open one synthetic secret, all 256 FALSE words fail, and a public virtual-table seed allows unauthorized terminal-state opening for a FALSE graph. Mutating each of the 56 toy encrypted edge records changes its SHA-Merkle root. These observations do NOT establish a general Merkle lower bound, real AuxPoW authentication, native Bitcoin execution, source work hardness or any QPT result.

Local executed checker SHA256 a4f0c51799bd44e85cbd85d3f970d4afff6fb6b18e888424fd48fcde158d7a51; two outputs SHA256 1ea0eb2fe033fe4998b7959c355d3cb70325bef732c276b4482d17968e20f4a0. Full local-only source, derivation and paired outputs archived as /mnt/data/pq_virtual_merkle_20261120.tar.gz, SHA256 286ced98b7a508649268fa0e17680f20e21b943ab2fc89446acc2c8977d4e40a. This research note is the durable handoff; archive presence is not assumed across future executions.

NONQUALIFYING. No original public Build/Open, no joint-public QPT security, no progress comment, user alert, production/deployment edit or automation change. The next candidate must change the cryptographic publicly updatable transition, not repackage an exponential table or publish its master secret.
