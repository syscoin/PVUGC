# One-honest planted-secret / transparent OR-proof release screen (NONQUALIFYING)

## Exact continuity / scope
Read open/draft syscoin/PVUGC#1 branch \`research/pq-wkem-validation-20260918\`, head \`705379caf1848e897fe69891acab11a373b78b3f\`; exact latest adaptive activation note blob \`b36ceabc6a6f59d5e7e6ad84a693b3a487597956\` and relevant public frontier note blob \`82755666b0573e7d04400c1062f73735ba1040fb\`. The ordinary PR issue-comment query since 2026-11-21 UTC was empty. No Core source/network verification, benchmark or actual FE was run. This screen concerns a **new planted-witness setup route**, not a repetition of the GGM/polynomial/tensor parameter sweeps.

## Candidate and the missing source operation
To exploit the permitted one-honest N-of-N initial setup, let participant i generate a fresh, source-independent setup secret r_i and publish
  t_i=H0(sid||r_i), K_i=H1(sid||r_i), D_i=sigma_i XOR K_i.
The setup can prove in transparent ZK that sigma_i is a valid frozen *safe cancellation* signature and that its encrypted commitment was formed from the same r_i; it then erases r_i. One can offer a transparent proof of the relation
  R'_x(w,r') = R_ORIGINAL(x,w) OR [H0(sid||r')=t_i].
R_ORIGINAL remains the exact approved OR of authenticated strictly-greater-BTC-work, specific finite burn refutation, and qualified Syscoin history conflict/tag fault at LC depth; no added Syscoin-work/winner requirement. The statement and native authorization still bind claim, outpoint, burn, amount/recipient, baseline, anchors, window, reset, deadline and the strict post-PQ contextual rules.

A watcher with any ORIGINAL w can prove the *left* branch. The hope is that this proof or its transcript somehow unlocks K_i, without learning r_i, contacting the participant, enumerating future forks, or requiring a shared preimage across witnesses.

## Exact proof-only independence claim
Let P be the public relation, source policy, verifier code and setup commitments that are not secret-bearing release machinery. Let V include all published setup data (including t_i, D_i and the native VK). Sample the honest r_i independently of future source-mining/source-evidence coins. An adaptive adversary/source process is allowed to see the **entire V** and choose an ORIGINAL W and transparent proof Pi using V, its own coins and public hash evaluations, but no auxiliary channel to r_i other than V. In the *proof-only* construction, no secret-dependent evaluator or decryption token is published.

The sampling graph then factors as
  p(r_i,K_i,V,W,Pi) = p(r_i,K_i,V) * p(W,Pi | V),
hence, whenever defined,
  p(K_i=k | V,W,Pi) = p(K_i=k | V),
and I(K_i ; W,Pi | V) = 0.

This is an **exact data-processing fact under its conditional-sampling assumption**, not a QROM hardness result or general impossibility of hash-only witness encryption. Including H as an explicit sampled public oracle is allowed only if the honest r_i remains independent of the source process conditional on its whole public view; if malicious source generation learns r_i via an independent retained/setup secret, the premise fails. The native VK and D_i may themselves computationally correlate with K_i, but W/Pi generated solely from V add no further correlation. A secret-dependent compiled gate C* would break this factorization and is **precisely** what must be newly built.

Thus neither proof of the disjunction, nor proof of correct setup, nor N separate planted hash witnesses turns an unrelated ORIGINAL certificate into a decryption preimage. Building a public extractor
  Transfer(C*, w, Pi) = H1(sid||r_i) for *every* qualified ORIGINAL w
without revealing K_i on arbitrary proof-invalid/public inputs is the missing FE/WKEM problem, not a ZK-protocol side effect. A public external accept-bit can be forged; proof verification must control release within the actual cryptographic program. Honest erasure is a setup premise, not publicly provable.

## Selection verdict / next equation
Do **not** implement the planted-OR proof wrapper, claim extra source-work hardness from it, or count it as a positive release advance. It does not change the user's allowed evidence, source correlations, or missing cryptographic foundation.

Only an **actually serialized classical-PPT source-dependent** C*=Compile(x,sigma;rho) with PublicOpen(C*,w)=the same frozen safe sigma for all original authentic w, and a complete-public FALSE/hard-TRUE arbitrary-QPT recovery/accepted-native-forgery reduction to ORIGINAL certificate or independently grounded cryptographic break, would qualify. Universal future activations further require the adaptively bounded program in the latest continuity note or an explicitly safe slot-global fixed-message alternative. No such compiler, joint simulator, native issuance security, or source-work theorem was constructed.

This is a narrow rejected candidate and exact handoff. No breakthrough announcement, PR comment, production change or automation change.
