# R216 — Two-time source admission for universal-slot challenge release

**Status: source/instance binding and conditional hash commitment lemma ONLY. No hash-based witness-KEM Build/Open, full public simulator or QPT witness-recovery security achieved.**

## Actual continuity and provenance

syscoin/PVUGC PR #1, draft/open/unmerged, branch research/pq-wkem-validation-20260918. Observed initial head 5a05916758906ec097689e9ddc3f716187772c00, its parent tree 43f6c8e572adbc5204f0f0786e47aee92a7ce3a0, and the R215 exact SHA256d-midstate research note at blob e4ab8e84b261083f98ab412516df62a1f6b4dbb1. Recent top-level PR comments since 2026-11-10T12:00Z: []. Intermediate R216 hypothesis checkpoint published on this same branch at e82d367fe2c03c747cc5d9f6368e36da108bde5e, before executing these local tests. No external web/literature, independent agents, mining, deployed signatures, other repository writes or QPT experiment.

## Named proposal SLOT-UNIVERSAL: the missing quantifier at pre-funding

At t0, the N-of-N setup freezes a Bitcoin vault/activation slot v, exact safe cancellation message M_v, participant public native keys and honest-erased contributions. At later t1 ONE notary chooses assertion a and activates the preauthorized transaction graph. At t2 ANY watcher with one genuine R1 (contradictory greater Bitcoin work), R2 (authenticated exact PoB fault), or R3 (qualified Syscoin fork/tag fault) witness must be able to recover the SAME frozen cancellation package off chain with no live notary/setup participant approval. A fixed preauthorized Bitcoin txid and a later witness-dependent wtxid (explored in R191) can support fixed cancellation outpoints, but do not alone authenticate which withdrawal assertion was mined.

**Quantifier/timing lemma (unconditional):** If setup capsule C is immutable at t0 and one notary can select ANY allowed a at later t1, all-valid-activation completeness without trusted new setup requires
  forall allowed a, forall full ORIGINAL witness w for a:
      Open_slot(C, a, w) = the same precommitted sigma_cancel.
A per-claim Build(x_a,sigma) cannot have been executed at t0 for an unknown future a. The design must either restrict allowed claims at t0, trust a later release-capsule issuer (disallowed), or compile a universal slot relation with a included in the future witness. This is logical architecture, not the missing crypto.

The exact ORIGINAL target is
  R_slot(v; a,auth,j,e) =
     AuthBTCActivation(v,a,auth)
     AND NotaryAuthorized(v,a)
     AND ((j=1 AND QualifiedGreaterBTCWork(v,a,e))
       OR (j=2 AND AuthenticatedBoundBurnFault(v,a,e))
       OR (j=3 AND QualifiedSysPrefixOrTagFault(v,a,e))).
All claim/slot identity, real burn/amount/recipient, source anchors/window, chainwork, Syscoin Ancestor(P,h_rel), AuxPoW/tag rules, cancel path, deadline, native VK and capsule data must be explicitly bound. Distinct parent-work certificates for the same Syscoin child do not imply a fork. The fault subrelation must authenticate the outer coinbase/parent/child without first requiring the disputed tag to pass.

## Concrete malicious-notary early-open defect, and repair

Naive R2 = ValidNotarySignature(a) AND BurnAbsent(authenticatedStateRoot,burn_id(a)) is TRUE if the malicious single notary invents a fresh absent burn identifier, signs an **unmined** withdrawal assertion and supplies its genuine absence proof. Even a hypothetically perfect witness encryption for that naive relation would open early; the underlying claimed ORIGINAL instance was wrong. This is not rescued by N-of-N setup or by stronger secrecy of hash pads.

Repair: R2 must also authenticate that the exact notary-signed assertion was actually admitted in the relevant Bitcoin activation witness, including its full wtxid against the consensus-authenticated witness Merkle root/coinbase commitment, slot/txid, anchor window and source confirmation policy. Signed mempool data, untrusted roots, forged standalone PoW headers and unrelated source observations do not suffice. If a legitimate protocol intentionally recognizes a pre-confirmation event instead, it needs a separately specified authenticated admission condition and finality/censorship model. A public verifier that checks before exposing a plainly embedded signature is still insecure: this is the source relation specification, not the cryptographic release gate.

## Local conditional SHA binding lemma

Under a genuine consensus-authenticated Bitcoin block with a canonical witness Merkle root and positions, if an adversary supplies a **different serialized transaction witness** at the **same authenticated leaf index** yet passes the same root, comparing that leaf/path with the actual accepted transaction's leaf/path yields a first SHA256d collision (including possible transaction-hash collision), assuming correctly encoded commitments. This reduction can use the QPT adversary's final *classical* submitted evidence straight-line; its security is conditional on an independently justified QPT collision-resistance assumption and authentic Bitcoin source data. It is NOT a claim about recovering a witness from arbitrary recovered K, nor source best-chain selection from any submitted header. Correct full Bitcoin coinbase, header/PoW, Merkle, height, reorg and source-admission verification are premises, not implemented by a mock root table.

## Actual tests and capture

Full LOCAL checker (not published in this commit): /mnt/data/r216_slot_universal_20261111/checker.py. Python stdlib, Bitcoin-like base/witness SHA256d, two-leaf witness commitment and 4-leaf domain-separated authenticated burn tree. Executed twice with identical results: 20 functional assertions. Exact local source SHA256 f05b0b0b3b767216a9d478696d99f729f09403a975bad6fc9c08752a1849dfa1, JSON output SHA256 c0eaab5bdb15e01ed26aa5624436558922c5a442830d4218793b78ae49d79a54. Local source and outputs are local-only and not falsely attributed to GitHub publication.

Small reproducible Node.js source repro.js **is published alongside this note**. Executed twice with byte-identical output, 8 source-binding checks; exact source SHA256 866f558dc2b7d34afd68571e49f1cab266373309e240d975bea4e78238e3bef2 and output SHA256 5abe30deede0ca0fd4ecb114c70d5ab400da85d363751d5bc10b84894fb93d55. The small checker further abstracts transaction serialization and burn-state roots. Both test runners demonstrate that a malicious notary-signed unmined absent-burn assertion passes naive R2 but not anchored R2. Also check witness mutation vs fixed base txid, no accepted-root substitution, signature mismatch and existing burn status. The notary HMAC and accepted-commitment lookup table are synthetic and NOT production signature, Bitcoin best-chain membership or full Syscoin evidence. None of these tests is a key-release or quantum test.

## Uninstantiated security-critical Build/Open operation

  Build_hash(slot, frozen_sigma_cancel; t0 setup coins) -> C_slot
  Open_hash(C_slot,(a,auth,j,e)) -> the SAME frozen_sigma_cancel
        for EVERY full ORIGINAL R_slot witness.
For any arbitrary QPT unauthorized final-key recovery or valid native forgery, show an ACTUAL relevant authenticated full ORIGINAL witness or an independently justified PQ SHA/native break. Include malicious notary choices after setup, one honest N-of-N source erasure, full public statement/native VK/source roots, related capsules, auxiliary dependence, selective openings and coherent attacks. The source verifier's success is not a key-release mechanism; two different future source witnesses need a cryptographically hidden common output, not H(w) or an unprotected public constant. Earlier R215 public SHA midpoint/target-prefix and variable hash-label failures remain in force.

Next constructive experiment is an actual **non-factorized hash/SHA/AuxPoW source-dependent release encoding** for the universal-slot relation, with its public simulator and exactly these forged-unmined/anchored witness cases. No claim of completed WE or practical bridge.
