# R291 — GGM-constrained full-witness shares and static-row compression (NONQUALIFYING)

## Continuation
Existing PVUGC PR #1, research/pq-wkem-validation-20260918, starting head aab716891b7d6ca31e6ffbbbed39dcd3852124e2; continues R290 serialized state (blob d9f30c65c58f83e6e3dbf70bf97b986813182ba6) and R289 joint masks (blob b68a3104900ba2c0fb0c544d567f00aca0622e40). Last relevant ordinary PR comment R225 #6796383617. Core #609 observed metadata head c91539de3c34937e57d7f5fda47c7b0502ff33f6; no Core tests. Offline local Python and connected GitHub only.

## Actual Build/Open attempt
For two literal finite-domain local constraints A(w), B(w) on a complete n-bit witness, choose independent hidden binary GGM SHA256 roots s,t and a frozen lambda-bit key K. Publish restricted subtree keys for F_s on D_A and F_t on D_B, plus ALL corrections for w in D_B:

    Delta(w) = K XOR F_s(w) XOR F_t(w).

Public Open on w in both permitted domains computes K = Delta(w) XOR F_s(w) XOR F_t(w). Every member of the intersection recovers the SAME K, no selected canonical witness. The public interface consists of complete per-witness values rather than cut labels from R289, but this only gives an ideal finite-domain evaluator, not a secure general-source compiler.

For D_A intersect D_B empty, when unknown F_s evaluations on D_B are independently uniform conditioned on all published F_s values on D_A, the entire classical public table is statistically independent of K, including under coherent access to that fixed table. This is a deliberately restricted independent-random-function model, NOT a QROM proof for SHA256-GGM, native signatures, malicious setup, auxiliary states or siblings.

## Exact obstruction: full-public static correction rows
The algorithm enumerates all |D_B| future witnesses in Build, generally exponential. An attempted compression selects a fresh lambda-bit GGM seed r such that F_r(w)=Delta(w) for ALL w in D_B. For ell specified inputs and an independent-uniform correction vector, there are at most 2^lambda candidate r-vectors: probability at most 2^[-lambda(ell-1)]. An additional arbitrary lambda-bit XOR offset increases the family to at most 2^(2lambda): probability at most 2^[-lambda(ell-2)]. These union bounds rule out ONLY that seed(+offset) correction family in an ideal-independent-output experiment, not all hash-only constructions. No compressed RowEval was instantiated.

Source validity is also missing independently of size. GGM keys on arbitrary bit-string prefixes do not restrict outputs to authenticated ORIGINAL Bitcoin/Syscoin evidence. Using the public SHA256d digest or its target prefix as the index allows source-free candidate inputs; checking AuxPoW only after key recovery is unsafe. Replacing it with full certificate bytes does not magically make SHA/consensus validity a prefix language. Actual mandatory active modern chain ID, 41-byte canonical SYS ancestor tag, distinct parent carrier/semantic hash, actual h_rel and LC depth, same-anchor greater Bitcoin work, burn authorization, claim and native transaction/VK binding remain outside the candidate.

## Reproduced counterchecks
Two identical runs of a Python 3 standard-library SHA256 checker on four deterministic seeds with n=8: A is bit 0=0; TRUE B is bit 1=0 and has 64 correct identical-K openings per tape; FALSE B is bit 0=1 and has zero openings; each B has 128 published correction entries. If a sibling exposes the complementary subtree from the SAME s, each FALSE tape immediately yields K at all 128 rows: 512 sibling-assisted public-only recoveries over four tapes. Thus independent per-claim seed separation is mandatory even in this finite control.

An exhaustive 8-bit seeded SHA control over 256 target tapes and all 256 candidate seeds found direct matching seed vectors for ell=1,2,3,4 in 145,1,0,0 tapes respectively; seed-plus-global-offset matches at ell=2,3,4 in 172,0,0 tapes. These numbers are tiny controls, not parameter estimates or a SHA/quantum theorem.

Full local research archive has checker source and both byte-identical output captures. Exact SHA256: checker 49941b78ab9de645172ea7fcfc41743ac28d8c63e16e6073e18d627747aaf33a; run1.json and run2.json a9bb1940349ac91dc479abba17f49534e2b2add44843ac5cfb2ac7595908e06d. No genuine ORIGINAL-source Build/Open, QPT joint-public extraction, native PQ authorization, actual AuxPoW verifier, or bridge safety is established.

## Unfinished equation
Replace the explicit Delta(w) table with a classical-PPT public source-authenticated correlated evaluator for EVERY future qualifying ORIGINAL witness, while resisting full-public cut splicing (R289), repeated-bit inconsistency (R290), sibling selective opening and native replay; prove unauthorized hard-TRUE recovery/accepted native forgery straight-line implies an actual qualified ORIGINAL source certificate or independently justified PQ native/hash break. An assumed secret future-row issuer, exposed source signer, digest-prefix hashlock, generic WE/iO or after-the-fact source check is not a repair. No ordinary PR comment, milestone announcement or automation stop warranted.
