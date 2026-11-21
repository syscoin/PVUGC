# R387 — Sender-unknown source opening as public-key transport (NONQUALIFYING)

## Continuity and purpose

Read live open/draft syscoin/PVUGC PR #1 on branch \`research/pq-wkem-validation-20260918\` at start commit \`8401b3a4ef007038f6bdf33d474d2b78d47bbd38\` (R386), exact note blob \`a116f3c0ae679ab6ceaf3f23b90ae0c46dda7483\`. Read its specific precursor R385 \`f7b5af5ad60c529b00344d0dc794ac068b8d2b3a\`. Recent issue comments since November 18 were empty. No Core reread was needed for this mathematical subproblem. No external literature or web searches. No executions of protocol code, SHA implementation checks or native Bitcoin tests are claimed.

**Candidate name:** preimage-key ciphertext for fixed, authentic source Merkle root. R386 left the exact unknown-opening transport step unfinished. This run changes its hypothesis from a symmetric hash pad to **asymmetric public encryption keyed by a *source* Merkle commitment**, rather than repeating another root-pad variant. It evaluates the release and full-public simulation together, including the separate ORIGINAL relevance qualification. This does not use lattices or groups as a fallback.

## 1. The new interface and exact reduction to a recipient-generated primitive

Let \`F_\lambda(z)=y\` be the context-serialized Merkle-root computation for one fixed Bitcoin parent's unknown, canonical child leaf and branch path. The authenticated parent's coinbase gives \`y\`, branch depth and modern slot, but *not* \`z\`. R386 supplies binding (one child per parent, absent SHA collision), not extractability.

The proposed new primitive is:

    RootKeyGen(1^lambda): z <- source-consistent opening distribution; y=F_lambda(z); output (pk=y, sk=z)
    RootEnc(pk=y, M; r) -> c                    [NO z available to sender]
    RootDec(sk=z, c) -> M  when F_lambda(z)=y  [publicly verifiable match]

For arbitrary valid alternative openings \`z'\` of the same \`y\`, correctness must return the same \`M\`. Authenticated SHA binding means efficient distinct openings are collision-hard; do not assume the root identifies a known preimage. The public encryption operation must work for the *actual source-generated* \`y\` without installing an encryption authority or receiving a preimage.

**Formal implication (only for this narrowed artificial relation).** If classical-PPT \`Build_y(y,M)\` and \`Open_y(C,z)\` were available for the language \`R_y(z):F(z)=y\`, with correctness for the real \`RootKeyGen\` distribution and complete-public hard-TRUE indistinguishability when z is unknown, then

    PKE.KeyGen := RootKeyGen,
    PKE.Enc(y,M) := Build_y(y,M),
    PKE.Dec(z,C) := Open_y(C,z)

is a public-key encryption scheme in precisely that distributional security game. This is a direct syntax-preserving reduction, not a claim that general hash-only PKE is impossible or an independently established security theorem. A candidate that instead needs z *to encrypt* has not built the required public-key operation.

For the ORIGINAL bridge, the harder relation has additional claim, ancestry, burn, anchor, LC depth and relevance checks, and is an OR across three grounds. Consequently **an ORIGINAL scheme would not automatically instantiate this simpler PKE**: its accept set is not all hash preimages. Conversely, even a secure \`RootEnc\` for the simpler subrelation is **not sufficient for the bridge**: a valid Merkle opening alone is not a qualified fork, burn fault or greater-BTC-work certificate. Treat this implication as a candidate-selection test for a proposed source-root *transport subcomponent*, not a general reduction or result for ORIGINAL witness encryption.

## 2. Two concrete SHA-based attempts and joint-public views

**Attempt A — native hash output as encryption key.**

    Enc_y(y,S) = S XOR SHA256("pad" || sid || y)
    Dec_z(z,C) = C XOR SHA256("pad" || sid || F(z)).

Build and every correct opening converge, but the attacker computes the same pad from published y. For any two candidate messages \`S0,S1\`, the complete public view \`(y,C,context)\` perfectly distinguishes: \`C XOR pad(y)\` reveals S. There is no FALSE or hard-TRUE hiding, regardless of SHA preimage security or exact AuxPoW admission. This rejection does not depend on R386's exact ciphertext implementation; it applies to **any public function of the root used directly as a secret pad**.

**Attempt B — decryption under an opening-dependent private key.**

    Dec_z(C,z) = C XOR HMAC_z("pad" || sid || y).

Unlike A, the decryption pad is not syntactically computable from y alone. But the sender given only y cannot compute the ciphertext \`S XOR HMAC_z(...)\`. Asking the source miner for z at Build changes the original future-source distribution; source miners need not participate in setup, and malicious ones may retain source-opening coins. An opaque encrypted program which holds z or a generated source key is not a classical public encoder. There is no specified \`RootEnc\`; therefore no complete-public joint simulator/security claim.

**SHA-specific continuation attempt.** A tempting way for the sender to compute an opening-dependent pad from a *single* SHA256 digest y of an unknown z is the Merkle–Damgård length extension: with known message length, continuing the exposed SHA256 chaining state after its deterministic glue padding gives \`SHA256(z || MDpadding(z) || suffix)\`. But that continuation is computable by everyone holding y, not just Build, and therefore reduces to A. In contrast, \`SHA256(z || suffix)\` without the glue padding and HMAC keyed by z do not follow from y; Build remains unable to compute its needed mask. This observation is specific to exposed *single-SHA256* states; it does **not** assert a length-extension attack on a SHA256d Bitcoin Merkle root. No concrete SHA computations were executed in this pass.

## 3. Source authentication and hard-TRUE are additional gates

Even if \`RootEnc\` somehow existed and transported a fixed secret to holders of a valid opening, it would *not* enforce the ORIGINAL bridge relation. An ordinary miner holding a parent/child Merkle opening is not thereby entitled to cancel an unrelated claim. The missing interface must additionally cryptographically enforce the entire claim-bound original OR predicate *inside* the public release computation, not in a user-supplied boolean or wrapper:

    Build_orig(x_W, sigma_cancel; rho) -> C
    Open_orig(C, w) = sigma_cancel for every R_orig(x_W,w)=1.

At least one eligible ORIGINAL certificate can be obtained after mining; different ones may use different parent roots and different Merkle openings. Prefix knowledge of a root, a single valid child, or a distinct parent work certificate for the same child is not by itself a fork. The activated contextual modern ID, exact canonical SYS ancestor tag, deterministic child-slot chain root, actual claim-prefix ancestry, finite burn refutation, BTC greater-work comparison, LC depth, reset/deadline, outpoint/message/VK/capsule all remain binding. Source validation may not run solely as an optional check after a raw pad has already been extracted.

A stronger candidate must specify concrete public bytes so that a joint simulator can handle malicious source generation and retained opening secrets, sister capsules, native public keys and checking context. For TRUE instances the security target is not absence of a mathematical witness; it is resistance before a qualifying ORIGINAL witness is *obtained*. A reduction needs an **actual ORIGINAL certificate**, not an arbitrary hash preimage or a disclosed internal representation. QPT processing is joint/coherent and cannot automatically be extracted through classical oracle logging.

## 4. Result / next equation

This was a **candidate-selection iteration**, not a source-release construction. The root-as-key idea changes R386's symmetric transport to an asymmetric sender-unknown opening interface, and the exact public-key-encryption implication distinguishes two different missing obligations: (i) encrypt to the externally sampled parent root without knowing its opening, then (ii) cryptographically gate the **original qualified conflict relation**. Neither operation is instantiated. Even solving (i) would not complete (ii). No concrete original source-dependent Build/Open, complete-public FALSE/hard-TRUE QPT reduction, setup security, native cancellation signing or work bound was produced. Do not prioritize another root-pad encoding, HMAC suffix or public SHA continuation as a repair.

**Next decisive constructive step** must instantiate an independently secure **joint-source predicate gate**, not a root-only PKE substitute:

    C <- Build_orig(x_W,S;rho),    Open_orig(C,w)=S for every ORIGINAL w,
    Adv_cancel(C,context,siblings) <= Adv_original_certificate(extractor)
       + independently bounded hash/native/setup terms.

In particular its publisher must not know future source certificate w, its public bytes must prevent cross-witness splicing, and the extractor must output qualifying authenticated claim-relevant original evidence. This remains unsolved. This run contains an exact mathematical implication and comparison of explicit candidate algorithms; no toy tests or negative-run progress metrics are claimed.

**NONQUALIFYING; NO USER NOTIFICATION.** No production/Core edit, PR progress comment, deployment, funds transfer or automation change.
