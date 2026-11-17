# R340 — semantic affine conflict latch, exact source-delivery gap (NONQUALIFYING)

## Provenance and candidate selection

2026-11-17. Read open/draft syscoin/PVUGC PR #1 on research/pq-wkem-validation-20260918 at head 6d1324e79633332889f98459f75ecba6ee38e0fc, and exact R339 blob f4fa4fd371c432039ddcd0a7a655f63b14b90018; checked R338 commit 79734d931f9f49f055b2215ddc58a1e6033d4656 and R327 blob ab7602bfc54403bf68294034557206f62d69a5dc. No web, no original Core admission, native signing, source certificates or QPT testing.

R339's unsolved operation is an issuerless classical-PPT public translator from arbitrary FUTURE authenticated source observations to a setup-frozen secret. Here the *join* is changed to a single semantic affine share, not a multiwire garbling, avoiding the direct R337 splice of inconsistent intermediate circuit labels. The source-delivery problem is NOT repaired; this note is not a candidate for an ORIGINAL completion claim.

## Mathematical construction with explicit unimplemented primitive

Fix x_W, a claim-prefix relevant height h_rel, and one legitimately authenticated baseline source history B. Let u0=EncodeNonzero(x_W,h_rel,ActualAncestorHash(B,h_rel)) in a field F of roughly 2^lambda elements, with u0 != 0. For an independently admitted, mature, claim-relevant source observation R define u(R) analogously from its *actual* authenticated child ancestor. Hash-to-field collisions are independent hash breaks, not equal source history by definition. Different Bitcoin parent certificates for the SAME Syscoin child are the SAME semantic class; R316 equal delayed tags are not equal actual semantic ancestors. For distinct reference heights prove predecessor path; never substitute the rounded h_ref tag for h_rel.

Build freezes the exact safe native cancellation signature sigma, independently samples K,a uniformly in F and sets

    b = K + a*u0
    D = sigma XOR SHAKE256("pvugc-r340-cancel" || x_W || capsule_ID || encode(K), len(sigma)).

The proposed *still unbuilt* issuerless source-certified delivery interface is

    Deliver_C(R) = K + a*u(R)   only if R is an admissible mature original-source observation
                    within the precise claim/anchor/height/window/depth and baseline scope.

Given a second observation R that really conflicts with B and u(R) != u0, public Open would calculate

    a' = (b - Deliver_C(R))/(u0 - u(R))
    K' = b - a'*u0
    sigma' = D XOR SHAKE256("pvugc-r340-cancel" || x_W || capsule_ID || encode(K'), len(sigma)).

These identities yield exactly K'=K and sigma'=sigma for EVERY such qualifying R, without selecting a Syscoin winning fork or greater Syscoin work. The affine join uses no per-gate labels, so the R337 partial-label splicing mechanism is absent *at this join*. Alternative parent work certificates for the same child, or extensions of the same claim-relevant ancestor, yield only the existing b; they are not forks.

This is NOT a serialized Build/Open: Deliver_C is a hypothetical secret-output interface, not a source-generated hash invariant. The source observations contain public SHA/AuxPoW information, not K or a. Do not promote it to a release primitive.

## Security / composition calculation

Restricted one-share law: for fixed K and nonzero u0, uniformly random a makes b uniformly random independent of K. Thus (b,K) is exactly jointly uniform in F x F. This is only a restricted distribution law for published b, not a complete-public capsule simulator. D includes a real native signature and a KDF; proving its QPT joint pseudorandomness relative to native VK, malicious auxiliary information and coherent random-oracle queries is independent unfinished work. QROM idealization cannot be silently carried over to concrete SHAKE.

Complete-public fatal alternative: if a serialized public program permits the challenger to compute y(t)=K+a*t for any invented t != u0, with no authentic original source observation, then the same formula above recovers K and sigma immediately. Embedding K,a as literal constants in a publicly inspectable "if VerifyOriginal(R) then return y" circuit also exposes them. Hiding them in an evaluator with no published implementation is not a hash-only solution. A capsule hash/root authenticates bytes but cannot supply source-dependent hidden shares.

Pairwise scope: for a two-history design that issues shares individually, the necessary semantic condition is

    Eligible_x(R) & Eligible_x(R') & u(R) != u(R')
          ==> ORIGINAL_inc(x,(R,R')).

Merely having individually valid headers is insufficient: they may differ in source anchors, BTC membership, observation windows, relevant height, LC maturity, claim scope or authenticated predecessor relations. For the narrowly claim-prefix fixed-baseline policy used above, require instead

    Eligible_x(R) & u(R) != u0  ==>  ORIGINAL_inc(x,(B,R)).

This implication must be instantiated by real contextual source certificates and actual LC maturity. Later-fork policies needing two later observations are not covered by silently reusing fixed B. A malformed claimed-wrapper fault requires independently authenticated outer carrier and is not admitted by merely assigning it a different u.

Sibling selective-opening failure: if independent capsules j reuse the same hidden a while publishing b_j=K_j+a*u0_j, one legitimately opened capsule reveals its K_j through the public opening computation; then a=(b_j-K_j)/u0_j, and K_i=b_i-a*u0_i decrypts every sibling i even without its ORIGINAL challenge. Fresh independent (K_j,a_j) per capsule, claim and participant is mandatory. This is not a complete malicious N-of-N/multi-capsule security proof.

The original three grounds remain separate OR options. Strictly greater same-anchor Bitcoin work can be a history extension, and a finite missing/invalid specific burn authorization need not provide a second source ancestor; neither is covered by this branch-3 affine latch. Exact tag faults, historical missing tags, native activation-bound signature/slot-global veto, deadline/reset and one-honest-N-of-N setup are still independent necessary components. No new signers or online release authority may be introduced to implement Deliver.

## Bounded local checker (not ORIGINAL source security)

A Python3 standard-library arithmetic checker was executed twice. Its results were byte-identical: 160 seeded trials in field p=65537 checked equal-class share reuse, recovery from two distinct semantic classes, unauthorized recovery if shares for invented classes are available, and illicit recovery of sibling K when the slope is reused. An exhaustive (K,a) census in field p=17 checked exact one-share uniformity for nonzero u0. Total recorded assertions: 1,889.

Checker SHA256: c45482096c63f59a739e7950616824b9fc7e7d66d9147d26f56e476ee57d16c1
Captured JSON SHA256 (each run): cf07961241681f685ea83a105854ed6d4d0aa891c69b5226f6b4848ba84f73f2

The exact local checker source was saved as r340_affine_latch_check.py in the execution container, with captured JSON r340_affine_latch_result.json and a full local derivation R340_RESEARCH.md; these local files are NOT represented as GitHub-published or persistent cross-run artifacts. The arithmetic fixture is not real Bitcoin/Syscoin authentication, native PQ signature/KDF checking or a quantum experiment.

## Handoff / no progress claim

The affine join has a clear same-output equation and a restricted single-share simulator, but still relies on the very missing secret source-certified Deliver interface; rebranding it as an OR of certificates would be assuming the desired release. Do NOT iterate on field choice, number of shares, SHA domain or toy assertion counts without first constructing issuerless, serialized, public, classical-PPT source-dependent share delivery and an independent full-public QPT reduction. Source authentication must control release cryptographically, not merely be a plaintext if-check after leaked shares. Need actual Build_inc(x_W,sigma_cancel) and public Open_inc(C,w)=sigma_cancel for all three approved ORIGINAL branches, FALSE/hard-TRUE recovery and accepted native forgery, arbitrary auxiliary/siblings, and malicious setup/source coins.

NONQUALIFYING. No original bridge WKEM, no PR comment or user notification, no production/Core modification, no automation change.
