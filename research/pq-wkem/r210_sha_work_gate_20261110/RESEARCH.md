# R210 — SHA256d work-prefix common-pad test and attempted source-preimage repair

**Nonconstructive research checkpoint. The original hash-only challenge-conditioned Build/Open remains missing. This is NOT a native Bitcoin/Syscoin implementation, quantum security argument, or qualifying progress report.**

## Exact continuity and actions

Observed syscoin/PVUGC PR #1 open/draft on research/pq-wkem-validation-20260918, starting head 52ecc5682f670303dec3a2e900060432426fbb67 (R209 publication receipt). Read exact R209 source-Merkle release research and narrowly relevant R208 expanded-sparse mask research. Ordinary PR comments since 2026-11-10T19:00Z: none. No external web, unrelated sources, independent agents, Bitcoin mining, source-consensus validation, or native postquantum signature operation. Wrote CHECKPOINT_01.md **before** running the experiment and published the intermediate checkpoint at dbc306a0d4bc700c361987da2bf5b92f59743a7c, a non-force advance from the observed start head. No PR progress comment.

The exact full standard-library Python checker.py and captured.json in this folder were executed locally twice with byte-identical outputs: 24,547 functional checks; three synthetic Bitcoin-format source contexts containing 2,130, 2,010 and 1,993 double-SHA256-work-qualified candidate headers. The separately executed small repro.py and repro_output.json were also byte-reproducible. Full-run source SHA256 4a7554e222db77036dbc50648b734dacae4fc80bddba185e1152206b97c99e08 and output SHA256 f1e05c444c17bcb6cb92773684c9c9cee95d94bf09323d13b14390aae9822521; small repro SHA256 e62611d2f10c610598e67466bfda24a0c0d679edeea967e4165ceaaa7b67b164 and output SHA256 6286367f46f05d9c4edaedea73015f39f46a6d8de307cd4cf2ea3c40174a52d2. All four exact tested files and captured outputs are included in the current research commit. These checks are NOT a QPT experiment.

## Target

The actual withdrawal x_W is bound to the exact claim/UTXO, burn authorization, BTC/SYS anchors and interval, light-client fork policy, cancellation native message and verification key, N-of-N preauthorization graph, context and related capsules. One notary initiates; anybody with genuine R1 contradictory greater Bitcoin work, R2 absent/invalid authorized PoB or R3 qualified source-prefix inconsistency/tag fault must obtain the SAME frozen claim-scoped cancellation capability off chain. No source authority or Bitcoin on-chain NP verifier is permitted.

This pass studies only a *necessary original-source PoW subproblem*. The SHA256d function is genuinely executed on syntactically 80-byte parent headers; the anchor/coinbase Merkle fields are synthetic, nBits is not contextually validated, and the target is an artificial leading-5-zero-bit toy condition, not Bitcoin DAA, AuxPoW, actual mining, or Bitcoin best-chain membership. Never turn the synthetic work fixture into original authenticated evidence.

## Candidate with exact all-work-witness identity

Let D(h)=SHA256(SHA256(serialize80(h))), with the work integer interpreted little-endian from digest bytes. Let p_d(h) be its d highest work-integer bits. For the toy work predicate p_d(h)=0^d, a builder selects a fixed random 256-bit key K and publishes:

    P(c,t)=SHA256(typed('work-prefix-pad',c,d,t))
    E=K XOR P(c,0^d)
    CK=H_check(c,K)
    D_cancel=sigma_cancel XOR H_sigpad(c,K).

After honest source validation, Open evaluates K'=E XOR P(c,p_d(h)) and verifies CK before unmasking the frozen synthetic signature. For EVERY accepted toy-work header p_d(h)=0^d, so K'=K. This is a genuine algebraic equality for work-valid headers, not just a test-count correlation. The three runs tested every accepted nonce in 65,536 candidates per context.

## Full-public break: work-prefix convergence exposes the key

A malicious caller does not need any Bitcoin header, Syscoin child, nonce or source certificate. From public E and the known work rule it computes K=E XOR P(c,0^d). It also directly recovers the frozen native-shaped capability from D_cancel. This is a deterministic straight-line classical attack, therefore also available to arbitrary quantum polynomial-time adversaries. Adding a hash/nonlinear function of the publicly known invariant 0^d cannot hide it: f(0^d) remains publicly evaluable. A post-hoc honest Open work check cannot protect the raw public capsule.

This theorem applies to a precise family: the mask factors solely through a publicly forced work digest prefix, and its evaluator and ciphertext are public. It is **not** an impossibility theorem for all hash-only SHA-internal witness encryption, and it does not disprove source-entangled encodings whose evaluator is not factorizable through that public digest boundary.

## Attempted actual-preimage repair fails every-witness completeness

Instead bind pad to full work input:

    Q(c,h)=SHA256(typed('full-sha-preimage',c,serialize80(h),D(h)))
    E_full=K XOR Q(c,h0)
    Open_full(E_full,h)=E_full XOR Q(c,h).

The chosen source header h0 recovers K, but different accepted full headers have different Q values; all 6,130 alternate qualifying fixture headers returned a different key. In a genuine pre-funding ceremony, the future h0 is also unavailable. This does not meet every-ORIGINAL-witness common-output correctness. Using only a shared publicly known pre-fork Bitcoin anchor as pad restores convergence but immediately permits early recovery, also checked in the fixture. Keeping a private salt would make public Open unable to evaluate the pad; revealing the salt recovers the early attack. An uninstantiated obfuscation/online issuer cannot be credited as a repair.

The degree<=2 Boolean polynomial basis on ten unconstrained suffix bits of the work digest had rank 56 among the accepted samples in all three contexts. This is a finite fixture observation about suffix diversity, not a theorem for 256-bit SHA, not a hardness proof, and not an optimization result. Earlier public sparse polynomial constraint masking and source-Merkle-row commitment failures remain un-repaired; do not restart them from this test.

## Exact remaining construction interface

Construct an actual classical-PPT, BEFORE FUTURE AUTHENTICATED WORK EXISTS:

    Build_inc(R_original,x_W,sigma_cancel) -> (capsule,CK)
    PublicOpen_inc(capsule,w) = SAME frozen sigma_cancel
       for every qualifying ORIGINAL R1 OR R2 OR R3 challenge witness.

The source SHA256/AuxPoW/coinbase, work, Bitcoin anchor, entire relevant Syscoin history, tag-fault and PoB-authentication constraints must be cryptographically inseparable from secret release. Any arbitrary QPT unauthorized final-key recovery or accepted native forgery must produce genuine ORIGINAL evidence or break independently justified PQ hash/native assumptions, without supplying an internal trace, representation or oracle-query log. The full public view includes CK, native VK, context, sibling capsules, auxiliary inputs and malicious source coins; malicious setup and N-of-N honest erasure must compose. This is not currently instantiated. The next experiment must propose a concrete nontrivial *source preimage-to-common-secret* encoding and its full-public simulation, rather than a public digest-only secret pad or a proof that honest Open checks work.

No user notification or ordinary PR comment is warranted. Keep the research task enabled.
