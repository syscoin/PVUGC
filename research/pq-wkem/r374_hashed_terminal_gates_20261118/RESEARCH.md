# R374 — Hashed terminal-state release after R373 (NONQUALIFYING)

## Continuity and precise proposed change

At research start, live open/draft syscoin/PVUGC PR #1 on research/pq-wkem-validation-20260918 was f6f0d104a89bf421fbda75ea0932460c7aedf93a (R373), note blob 5c5898d0c7ece43e365d95d430cf48abb793e2c2. Relevant ordinary comments since 2026-11-18T19:24:00Z were empty. Core #609 was not reread or tested; its activated modern-ID and exact tag rules are retained, with claim-relevant fork checks based on authenticated histories, not just tag inequality. R373's public terminal vector enabled a prefix-span witness search. This iteration removes that vector rather than resampling the old same construction.

## Candidate A: hide terminal target using independent SHA256 hash locks

For a deterministic binary-input DFA of length L with d one-hot states, all accepting words end in e_yes, while all rejected words end in other basis rows. Each public A_i^0,A_i^1 maps basis rows to basis rows. Build selects independent R_i in GL_d(F_q) and publishes

    u=e_start R_0
    B_i^b=R_(i-1)^(-1) A_i^b R_i
    t_yes=e_yes R_L                         [PRIVATE]
    h=SHA256("target"||enc(t_yes))           [PUBLIC]
    D=S XOR SHA256("pad"||enc(t_yes))       [PUBLIC].

Open publicly evaluates z=u product B_i^(w_i), checks SHA256("target"||enc(z))==h, and if equal returns D XOR SHA256("pad"||enc(z)). Telescoping proves SAME S for all accepting words. Rejected words end in a distinct one-hot R_L row and cannot pass except via hash collision. Build/Open are finite-width explicit classical algorithms; they are not an efficiently compiled ORIGINAL SHA/AuxPoW predicate.

**Attacker without a terminal vector.** At each layer maintain at most d actual reachable-prefix row representatives forming a basis of their public span; expand each by B_i^0 and B_i^1 and eliminate dependent rows. Every rejecting terminal row is in span{e_j R_L:j!=yes}; the accepting row e_yes R_L is linearly independent of that span because R_L is invertible. Therefore, if there exists ANY accepting full word, any basis made of actual terminal representatives must contain one accepting word, or it could not span all reachable rows. Comparing the public h against hashes of at most d final basis rows detects this representative, yielding an ACTUAL accepted word and S in polynomial time O(L d^4) (naive bound). This does NOT directly recover S on a FALSE instance; it invalidates the required hard-TRUE original-source work bound when an original relation is claimed to fit polynomial d. R373's explicit terminal-vector test has been removed, but reachable-prefix linearity remains fatal even under a hash-lock.

## Candidate B: nonlinear secret coordinate changes on source-processing state

Replace the R_i by arbitrary secret bijections of the n-bit state and publish callable T_i^b(z)=R_i(F_i^b(R_(i-1)^(-1)(z))). Keep SHA256 commitment to the hidden accepting terminal label t_yes=R_L(s_yes), plus ciphertext D=S XOR SHA256("pad"||t_yes). This eliminates the basis-search argument for general nonlinear F, but does NOT authenticate the origin of an arbitrary intermediate argument z.

Exact **local-image lemma**: For a public callable final T_L, if its original unmasked final gate F_L maps fraction alpha of all n-bit predecessor states to s_yes, then for uniform z, Pr[T_L(z)=R_L(s_yes)]=alpha, because R_(L-1) is a bijection. A public hash check on the resulting output recovers the hidden terminal label and S after expected 1/alpha public suffix evaluations, even when none of those artificial states is reachable from the statement's actual initialization. This is a FALSE-instance leak for a globally impossible source predicate whose local last-gate acceptance density is appreciable. It is independent of inversion/deobfuscation of nonlinear coordinate gauges and of the R373 prefix-span algorithm. A public last-stage validity bit permits alpha=1/2; adding k independent local bits gives alpha ~2^-k but does not itself bind the state to an actual relevant Bitcoin/Syscoin history.

A proposed repair must cryptographically ensure intermediate-state reachability from the fixed statement's authenticated origin while permitting only full, consistent source-evidence evaluation. A public authenticity/hash key permits arbitrary artificial state credentials; a private key makes the public update operation unavailable absent another protected compiler. Authenticating capsule bytes or checking a wrapper after raw label recovery is not a repair. Concealing all substages in one truly source-dependent public evaluator merely restates the missing functionality unless its exact polynomial-size serialized construction and joint public security are supplied.

## Executed bounded computation (local-only code/output)

Python3 standard-library source ran twice to exit zero with byte-identical output, no real Core, Bitcoin, native ECDSA, FE, or quantum tests.

1. 19-bit exact-match DFA, d=2, field F_65537, random invertible private gauges, published u/B/h/D but NOT terminal vector: 74 public prefix transition expansions, two final basis rows, recovered the real unique accepting word and same synthetic S.
2. FALSE fixture: reachable original predecessor has bit0=0; last local gate outputs YES exactly for bit0=1 and bits1..3=0. Secret 5-round Feistel permutations before and after it make the public transition nonlinear in the unmasked input. A public 256-entry table of T_L in this **8-bit only** fixture has 16 accepting preimages; randomized last-stage sampling recovered t_yes and S after 17 probes although no complete witness was valid. This table grows exponentially with n and is NOT claimed as a practical implementation. The image-density lemma applies to any compact public T_L if one exists.

Exact local checker /mnt/data/pq_r374/check.py SHA256 5e4b8e7918467ebbff54f7127553a7fe6c4f47497d61898267ab550d35bf12b6.
Captured out1.json and out2.json SHA256 38e486a0539591e4a6e3c0ed6723075c4b740d0420b5697319f7bfdff5163100.
Archive /mnt/data/R374_hashed_terminal_gates_20261118.tar.gz SHA256 3cdc48c2a4349a29de15991c9accf3ce8a0164c272d5ce503408b86a39aa5156.
Checker/outputs are local-only, not falsely represented as part of this commit.

## Exact remaining ORIGINAL-source obligation

Still absent: practical hash-only classical-PPT Build_inc(x_W,S)->C and public Open_inc(C,w)=S for EVERY authenticated, qualifying ORIGINAL witness in the approved three-branch OR relation, with no artificial state/label leak, actual relevant AuxPoW/Syscoin consistency, native safe cancellation, full FALSE/hard-TRUE QPT recovery/native-forgery reduction to an original certificate or an independently justified break, and one-honest verifiable setup/multi-capsule composition. The necessary next equation is a public globally consistent source-dependent evaluator with a JOINT public simulator, not an oracle, reversible frame, label proof, isolated source verifier or independent puzzle.

**NONQUALIFYING.** No user breakthrough notification or PR progress comment. No Core/production/workflow/main/automation change.
