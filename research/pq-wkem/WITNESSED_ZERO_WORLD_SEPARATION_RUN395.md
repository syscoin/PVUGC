# Run 395 — Known-witness checking-key distinguisher blocks uniform zero-program simulation

**2026-10-09; bounded falsification, not a WKEM construction.** At connected-GitHub PR #1 head `bba5c4bb4e37144a390b40f0b58a7ff633d7a1f1`, branch `research/pq-wkem-validation-20260918`, draft/unmerged. Exact Run 393 note blob `7ee3cc73f1115a2788a4d54021ca808f865405dd`; Run 394 blob `7afc59866028fef93728d6c3da766d7c9deafdc6`; Run 259 source-binding blob `c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2`.

## Candidate assumption falsified

To lift Run 393's ideal real/zero oracle-difference extractor to a published public program, one might claim the REAL witness-gated release program is QPT indistinguishable from a publicly evaluable ZERO program **for all true-instance adversaries with arbitrary auxiliary input, including a valid ORIGINAL witness**. This is impossible in the independently generated native-signing-key model.

**Theorem.** Fix a true statement `x` with valid ORIGINAL witness `w` sampled or supplied independently of freshly generated native signing `(vk,sk)`. Honest classical PPT `Build(x,sk)` produces `P_real`; for every valid `w`, honest public `Recover(P_real,w)` provides the SAME usable native signing capability with probability at least `1-eps_correct`. Suppose `ZeroBuild(x,vk,aux)` and `Recover(P_zero,w)` are QPT simulatable without `sk` or a native signing oracle; their auxiliaries (including advice) are simulatable independently of the fresh secret signing key. Both distributions expose all public outputs, including `vk`.

Given `w`, evaluate `Recover(P,w)`, sign fixed context-bound `m_x`, and check `Verify(vk,m_x,sigma)`. In REAL the test succeeds with probability at least `1-eps_correct-negl_sigcorrect`. In ZERO, a straight-line algorithm receiving EUF-CMA challenger `vk` can simulate `ZeroBuild` and run the test, outputting any accepted `sigma` as a fresh forgery (no signing oracle). Therefore:

`Adv_dist >= 1-eps_correct-negl_sigcorrect-Adv_EUF-CMA^QPT`.

This classical chosen-input distinguisher is already in the arbitrary-QPT attacker class. It uses neither a QROM nor rewinding. If zero-world advice or construction contains non-simulatable signing-secret correlations, the reduction DOES NOT apply. Nor does it apply if the witness itself depends on the native signing secret.

**Checking-key negative control.** Even when the REAL and ZERO released seed marginals are *identically uniform*, the joint pairs `(vk,K)` and `(vk,K_independent)` can be distinguished almost perfectly via signing/verifying. Toy exact census uses `vk=(a*K+b) mod N` with odd `a`, toy `Sign(K,m)=K`, and multiple witness states `w` satisfying `w mod 2=0`. Every REAL source witness recovers the same `K`; independent ZERO seeds authorize with probability `1/N`. For `N=32`, distinguishing advantage is `31/32`. This finite toy is deliberately NOT a secure signature scheme or obfuscator. Native QPT claim rests only on the explicit EUF-CMA assumption and zero-world simulability.

**Correct interpretation.** This DOES NOT refute local mixing, WE, RIO/iO or Run 393's ideal-oracle extractor. A *valid witness holder is supposed* to distinguish actual release from zero. The known-witness attack demonstrates why one cannot assume unqualified QPT real/zero **white-box program indistinguishability** as the missing step. A viable proof must account for such distinctions by deriving a witness or independent break. Calling this needed property "source-enforcing release" or "local mixing" without a separate construction would be circular.

## Taxonomy / boundary

(5) chosen public evaluation: explicit; (8) full joint native checking-key correlation: explicit; (9) classical distinguisher within QPT, no separate coherent attack needed for this falsifier. One capsule suffices, so (4) multi-view and (7) replay not required. (1) seam, (2) gauge, (3) other fingerprints, (6) malicious setup and genuinely coherent attacks against surviving designs remain UNTESTED. The hypothetical ZERO simulator is classical/QPT as stated; the actual setup must be classical PPT. Run 259 starts only from an accepted COMPLETE source representation; this distinguisher recovers no such representation.

**Verdict:** reject global true-instance zero-program indistinguishability. Do not equate Run 393's ideal oracle with publishable local mixing. No false-instance QPT hiding, true-instance arbitrary-QPT ORIGINAL extraction, full malicious setup/erasure, multi-capsule security, practical 128-bit parameterization, or native Bitcoin PQ deployment is established. The research PR stays draft/unmerged and production unchanged.

Relevant primary work: Canetti–Chamon–Mucciolo–Ruckenstein, ePrint 2024/006 (RIO/SCP conditional); Ambainis–Hamburg–Unruh, ePrint 2018/904 (O2H). This checkpoint does NOT claim either paper proves or is broken by the toy.
