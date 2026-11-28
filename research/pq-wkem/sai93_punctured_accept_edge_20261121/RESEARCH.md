# SAI93: punctured hash-tree semantic-edge update (NONQUALIFYING)

## Exact continuity
Actual live open/draft PVUGC PR #1 branch research/pq-wkem-validation-20260918 was read at 9a8ef2e8cf3dedf861fc7645fc78d1646b54e80a (SAI92); exact note blob 7510cacbf69a858195fc46b64e01206ae76715c4. Targeted top-level comments since 2026-11-18 19:24:41 UTC returned none. No Core #609 source or tests were used. This run addresses SAI92's unfinished publicly serialized, authenticated source-state transition, NOT another digest terminal interpolation or low-degree Boolean mask.

## Mathematical change and actual candidate
Replace a publicly exposed terminal digest with a **hash-tree PRF label punctured at a frozen accepting semantic state**. A source witness is intended to carry a token through valid semantic transitions to that state, yielding one common cancellation capability independent of which future source history was used.

For n-bit semantic-state indices, sample private root seed s_empty. Define child seeds s_(v||b)=H("GGM"||s_v||b), and leaf labels L(q)=s_q. Fix the accepting state a, key K=L(a), and D=S XOR H("FINAL"||K), where S is the setup-frozen safe cancellation payload. Publish the n GGM sibling seeds on the path to a, a punctured public key PK_a. These permit *random-access* public derivation of L(q) for all q != a without directly publishing L(a).

To connect any permitted semantic predecessor p to a, Build publishes

    E_p = K XOR H("EDGE"||p||a||L(p)).

The proposed Open, after authenticating original evidence w as a semantic predecessor p(w), computes L(p(w)) from PK_a, then removes the edge pad and D to get S. Every *listed* accepting predecessor gives the **same K and S**, with no canonical witness imposed.

This is a genuinely serialized hash-only Build/Open for a tiny listed-edge state graph, not a general FE, witness encryption, or actual ORIGINAL source scheme.

## Public-byte attack and repair attempts
The public punctured key itself supplies the predecessor label for ANY p != a. The full-public adversary therefore computes

    K = E_p XOR H("EDGE"||p||a||Eval(PK_a,p))

from a single published edge, without producing w, a header, an AuxPoW certificate, a burn refutation, or valid chainwork. Then S=D XOR H("FINAL"||K). An external source verifier or ZK proof of correct capsule construction does not prevent direct use of these exact bytes; no cryptographic hash assumption is broken.

Repair 1: puncture accepting predecessors too. The legitimate witness now cannot obtain L(p) from its ordinary source bytes. It needs an actually public SourceLabel(C,w) bound cryptographically to ORIGINAL authenticated evidence, not a script that checks R_original and then calls an unprotected label decoder. Such SourceLabel is exactly the missing functionality, not a new assumption we may silently adopt.

Repair 2: puncture a low-target SHA digest interval rather than one leaf. A GGM prefix cover may represent that interval compactly, but knowing a valid header whose digest lies inside it does NOT reveal its independently keyed GGM label. Publishing the corresponding subtrees lets anyone choose an arbitrary target digest and recover the pad without a header, as in SAI92. Keeping them hidden prevents honest opening. An unspecified secret program or online key generator does not resolve this.

Repair 3: Publish edge patches for only the known predecessors. The tiny fixture opens consistently for each published predecessor, but future ORIGINAL witnesses are not enumerated at setup. An exact all-witness compiler must provide an efficient protected function producing the edge operation for every source-valid predecessor; listing exponentially many valid future histories or proof roots is not PPT.

## Executed source and precise limitations
The included standard-library Python checker was executed twice locally; two output files were byte-identical using cmp. It builds a SHA256-based 8-level GGM-style tree, punctures leaf 255, derives all other 255 leaves from eight public sibling seeds, publishes two synthetic accept-edge patches (states 5 and 78), verifies both nominally converge to the same K, and extracts K and a synthetic S directly from one patch without source evidence.

Local checker SHA256 cceab8ddf8b9f8019de9c36616590bd8e52511792e2c43be4d1367ad994979a9; each local output SHA256 0b782f95d47681d1472fb76c940e0d469efb29d0e613f1c0e1c4b023534f28a0. The explicit seed is public and deterministic for reproducibility; it is NOT a cryptographic security experiment. The executable fixture is NOT an actual original Bitcoin/Syscoin header, ChainLock, native signature, malicious setup, GGM security or quantum proof test.

## Full public simulation and next equation
The desired FALSE simulator would replace hidden K with an independent random value while preserving the joint distribution of the punctured key, all edge patches, D, native VK and verification context, sibling capsules and selective openings. It fails immediately when any published E_p allows a public derivation of K. Punctured-key GGM security cannot justify the correlated patches. Ordinary SHA preimage resistance does not supply a QPT puncturing theorem.

What still must be constructed, not postulated, is a practical classical-PPT serialized pair:

    PublicSourceLabel(C,w) -> L(p(w))
    PublicAcceptMerge(C,L(p(w)),w) -> K

for **every** qualifying ORIGINAL witness, with a public adversary unable to select unrelated p or splice partial tokens and with independent joint-public FALSE/hard-TRUE QPT unauthorized-recovery/native-forgery -> actual qualifying ORIGINAL certificate or justified hash/native break.

Keep the original three OR grounds (strictly greater relevant Bitcoin chainwork, finite authenticated claim-specific burn fault, qualified strict-post-PQ Syscoin history inconsistency/tag fault at required LC depth), exact claim/UTXO/amount/recipient/source anchors/windows/reset/native message/VK/capsule binding, one-honest N-of-N setup, and no greater Syscoin work or second notary. No new evidence predicate was substituted.

**NONQUALIFYING.** This excludes one precise punctured-state repair; it neither constructs original source-dependent release nor proves an impossibility for hash-only WE/FE. Do not notify as a breakthrough, post a PR progress comment, or modify production. No Core tests or deployment were performed.
