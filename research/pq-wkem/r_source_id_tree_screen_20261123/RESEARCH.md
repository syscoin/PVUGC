# Source-ID hash-tree input-label proposal — screened, NONQUALIFYING (2026-11-23)

## Provenance

Opened actual draft syscoin/PVUGC PR #1 at research/pq-wkem-validation-20260918, SHA 120c33b575bf0d651ab45c033b2a7c8aa0c03f0d (immediate unique-proof screen). Read the preceding public group-program note and hidden-reject-matrix note, verified latter blob 1dfbc9719c827c2e4cbdf6bde419e9924c7b0823. Top-level comments since 2026-11-18T19:24:28Z were empty. No web, Core tests, network certificates, native signing or quantum experiments.

The ORIGINAL relation remains the exact claim/UTXO/amount/burn/recipient/anchors/source/window/depth/reset/deadline/capsule/message/VK-bound three-way OR: same-anchor strictly greater Bitcoin chainwork, specific finite authenticated burn fault, or qualified relevant Syscoin history inconsistency/tag fault without greater Syscoin-work condition. The post-PQ canonical tag and modern ID are contextual checks; actual relevant child ancestry, not tag equality alone, establishes history incompatibility. Multiple valid parent certificates for one child do not make a fork.

## Named candidate: source-ID-indexed SHA tree

We screened a different source-label representation than the prior per-occurrence group program: index a public SHA256 GGM tree globally by the complete source certificate ID t=ID(w), rather than presenting independent transitions for local witness occurrences. An excluded baseline ID a has a compact, size-lambda prefix cover of all other lambda-bit strings: publish sibling subtree seeds along the a path. A holder can derive GGM(k,t) for any syntactic t distinct from a, entirely in classical polynomial time with public SHA256 calls. This does bind all input-label derivations to ONE chosen global t at the API level and avoids the prior per-occurrence mixing syntax.

The missing operation remains a cryptographically enforced mapping from authentic source witnesses w to the SAME hidden setup capability S, with no access from forged IDs. A source-ID tree does not implement it:

1. Public subtree seeds allow arbitrary syntactic t != a to derive a leaf key without a genuine authenticated Bitcoin/Syscoin certificate. A public wrapper checking VerifyOriginal(w) is bypassed by directly computing the leaf key from C. This is an unauthorized public-key access, not a SHA break. If a public key-to-secret uniformizer uses those keys, its capability is exposed before any challenge.
2. Leaf values GGM(k,ID(w)) differ for different valid future w. A single frozen D=S xor H(GGM(k,ID(w))) cannot decrypt to the same S for arbitrary different ORIGINAL witnesses. Publishing a separate D_t for every accepted t is exponential and would not solve the publicly accessible prefix-seed problem.
3. A shared pad keyed solely to the known baseline ancestor/tag is already public at setup, so D=S xor K leaks S. Hiding the common seed makes it inaccessible to public Open given an ordinary future source certificate, unless a newly implemented source-conditioned release primitive supplies it.
4. Independently encrypted N-of-N participant signatures do not repair the honest participant's public-cover leak or missing access. Malicious source coins, selective openings and source authentication must be analyzed inside the protected operation; attaching only a ZK proof of correct setup is insufficient.

This specifically rejects a syntactic global-input-label shortcut, NOT a theorem that hash-only source WE/FE or arbitrary structured public programs are impossible. The public-ID cover and honest-witness convergence do not compose. The required new mathematical step is an actually serialized, globally source-authenticated protected derivation whose full public representation has FALSE/hard-TRUE QPT source-extraction/native-forgery security; a secret PRF seed, source signer, obfuscator or oracle cannot be assumed.

## Executed bounded local regression

A standard-library Python SHA256 toy GGM checker ran and was independently rerun, with matching JSON results. For 8-bit IDs, eight public sibling-subtree seeds cover all 255 IDs except baseline 165. Exhaustively, every allowed syntactic ID derives its leaf, including one deliberately fabricated noncertificate ID. Two distinct possible future source IDs derive unequal pads. A pad from an already-known baseline tag unmasks a synthetic 256-bit S before any evidence. No real source evidence, FE implementation, proof of work, native signature or QPT experiment. This is only an explicit regression for the public-cover algebra.

Local-only checker: /mnt/data/pq_source_label_probe_20261123/check.py (SHA256 5945141ffc906f3c8a2c985eaa5993b9617301feca8a284fe7a93cd99c5c8a43).
Local-only captured output: /mnt/data/pq_source_label_probe_20261123/output.json (SHA256 e014a65ea105dce4a14c6d7fc59023c0864077c05154e5fb027f078c7300a1a1).
The note is the durable handoff; these local paths are NOT claims of permanent availability or GitHub-published checker bytes.

## Disposition

NONQUALIFYING. No classical-PPT public Build/Open for every ORIGINAL witness, no complete-public QPT reduction, no malicious N-of-N setup proof, no native forgery/work-budget bridge theorem. Do not revisit GGM covers, merely hashed source-ID pads or per-identifier ciphertext lists without a new source-credential-to-secret mechanism. No user notification, PR progress comment, production edit, Core modification, deployment or automation change.
