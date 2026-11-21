# HPW checkpoint 04 — full-evidence indexed hash release reference (UNSOLVED)
Status: actual ORIGINAL-dependent hash-only reference algorithm, but exponential Build; not generic PPT witness encryption, no independent QPT full-public theorem, no deployment.

## Continuity and scope
On syscoin/PVUGC PR #1, branch research/pq-wkem-validation-20260918, start/parent a0fdd00181c5e4ed27ae1de2ba40254104ce56e5 (open/draft/unmerged). Earlier CHECKPOINT_03_POW_AND_SOURCE_TOKENS.md at Git blob 4cac0bc119283ec8a1cd6010c89f937b5566e71d was read and remains unchanged. Latest substantive ordinary PR comment R153 ID 6718361572. No web/external literature, independent agent, or LWE work. This experiment does not justify user notification as a security breakthrough.

## The explicit release algorithm
Take an ORIGINAL classical-PPT relation R(x,w) with exact fixed-length l-bit witnesses and public source context ctx fixing relation identity, claim/UTXO, branch, anchor/window, native VK and challenge message. During honest pre-funding Build, choose one uniformly random k-bit K; freeze exact already-authorized native signature sigma. Use independent domain-separated ideal hash functions T,F,C,P with T a tag, F a k-bit pad, C a checking digest and P a signature-length pad.
Build enumerates all w in {0,1}^l. If and only if the ACTUAL R(x,w)=1, append the record
    ( T(ctx,w), K XOR F(ctx,w) ).
Publish those records, ctx, CK=C(ctx,K), Dsig=sigma XOR P(ctx,K), checking/public manifest and distinct sibling capsules.
Open with any valid ORIGINAL witness w finds its T entry, unmasks K using F(ctx,w), checks CK, unmasks sigma and verifies its native signature on the originally intended message. Different ORIGINAL witnesses need no shared state or canonical preimage; all yield the same precommitted sigma. FALSE x has no records. This is a concrete source-dependent distribution: there is no SourceOpen oracle. Build is EXPONENTIAL in l and therefore NOT the required practical classical PPT algorithm.
On tag collisions, test all corresponding record decryptions against CK; do not silently choose one. This reference assumes complete witness encoding and authenticated x; future actual best-chain membership is NOT implemented as a static predicate merely by PoW target checks.

## Executed toy checks
A local Python standard-library implementation source_indexed_reference.py was actually executed twice; outputs were byte-identical. It exhaustively builds for two synthetic child outcomes, 14 nonce bits each and a SHA256 prefix-8 parent work predicate with an exact toy anchor. It emitted 104 qualifying COMPLETE witnesses, and each recovered the same frozen 96-byte fixture capability. Eight false certificates (wrong anchor/wrong child) did not open. A deliberately UNSAFE alternative folded records to child outcome and leaked K to a fabricated invalid certificate sharing the child. Its 124 assertions passed. Exact output manifest SHA256: 82c9d8057cd95b7848aa8109cec71252b6f0c3a4ba6aa534eb981ea374b11dab. Fixture signature SHA256: c45a3ec20fa7eb96355f053d1c2414c471e7fc55fbcf0f7e393e696405be1711. Checker/output are preserved in the local archive, not claimed GitHub-published with this note.

An independent locally executed prefix_gate_checker.py reproduced the prior checkpoint-2 finding with 12 SHA256 fixtures and 60 assertions. Wrong-anchor invalid evidence still recovers a precommitted prefix puzzle K by directly mining raw hash input, despite honest API rejection. Source SHA256 0c8e5105212cba2bde4d77dc4a29f320ad45628f58ea9fcdc51f99b04071a0c9; exact captured output SHA256 996021b20c64565cf2f90c8fca0f03209630d958cd86b425b68412f07391e09f. This is a reproduction, not new construction progress.

## Quantum recovery implication being evaluated, NOT proved here
In a QROM reference for this EXPONENTIAL Build, program witness-domain F(ctx,w) for each accepting w so the selected public record decrypts to the same K. Program C(ctx,K) and P(ctx,K) consistently. In a reference oracle replace these values with independently uniform outputs. Under standard quantum-query hybrid reasoning, distinguishability requires query amplitude on some ACCEPTED ORIGINAL w or the actual secret K; measuring a random query position gives a candidate w without the adversary volunteering a representation. BUT the simulator that builds or even lists the records currently enumerates all witnesses, so it is not a PPT reduction. A classical log of queries cannot replace a quantum extractor. Conditioning on auxiliary and sibling capsules must be explicit before any theorem. No claim of standard-model SHA or actual 128-bit QPT security.

## PoW/source authenticity and temporal gap
The toy parent-work predicate is STATIC and can be privately mined before an actual network event. A prefix target alone is not authenticated Bitcoin best-chain membership. Syscoin child semantic outcome ID must remain distinct from its complete AuxPoW/parent-work certificate ID. Folding full certificates by outcome is unsafe unless the opened public data still entails a COMPLETE admissible ORIGINAL evidence item, with correct ancestor/coinbase tags/window/inclusion.
Committing a root in the coinbase authenticates claimed bytes but does not produce secret token preimages or prevent direct hash calculations on invalid work. No SourceOpen/oracle or online committee is assumed.

## Exact next attempt (fundamental compiler, not compression cosmetics)
Find a CLASSICAL-PPT compact representation of the accepting-witness-specific keyed mask records that:
(a) can be generated from x and frozen sigma without witnessing future events,
(b) supplies the SAME precommitted K for every ORIGINAL valid w,
(c) does not expose a K-recovery path for invalid/cross-witness splices or fake PoW,
(d) supports straight-line QPT joint-public simulation and arbitrary recovery -> a FULL ORIGINAL witness or independent PQ hash break.
An unprotected public circuit implementing if R(x,w) then K trivially leaks embedded K. A conventional hash garbling with BOTH input labels published permits local two-label closure and invalid global splicing. Do not rename obfuscation/WE as the missing compact representation. This checkpoint deliberately records a mathematical reference with an OPEN polynomial-build gap.
