# Run 511 — cross-capsule guarded-terminal transplantation

**Research only; 2026-10-14.** Live draft `syscoin/PVUGC#1`, starting SHA `54abffc290d8a7a679a1a17e083abfdd7d834720`. New exact falsification of **reusing the same hidden mixer P across independently scoped release capsules**, not an attack on independent Run-507 capsules, deployed Bitcoin, or the RIO/CLZ literature.

## Direct seed-recovery theorem

Use the precise Run-507 semantic state `(k,z,t)`, with h-bit secret signing seed k, n-bit witness z and one marker t. For each claim c, let `f_c(z)` be the ORIGINAL verifier (or a complete accepted Run-259 predicate with the theorem's exact conditions). Its reversible bit terminal is

`B_{c,i}(k,z,t)=(k,z,t XOR (k_i AND f_c(z)))`.

Assume a proposed amortized construction reuses **one global permutation P and common semantic coordinate system** for two claims. For claim c, it publishes `A_{c,i}=P B_{c,i} P^{-1}` and `a_c=P(K_c,0^n,0)`. The Run-506 publicly conjugated loaders can move any anchor to `P(K_c,z,0)` in <=2n operations.

Let target claim x have **no ORIGINAL witnesses**, so `f_x(z)=0` for every z. Let a separate reference claim r have just **one publicly known valid ORIGINAL witness** z* with `f_r(z*)=1`. The reference native signing seed K_r can remain entirely secret and independent of K_x.

The attacker takes `a_x`, publicly loads z*, obtaining `y=P(K_x,z*,0)`, and computes `d_i = 1[A_{r,i}(y) != y]` for each i. The published reference action satisfies

`A_{r,i}(y)=P(K_x,z*, K_{x,i})`.

By injectivity of P, **d_i=K_{x,i} exactly**. Every target secret bit is recovered in <=2n+h public action evaluations, without target evidence, without P inverse, and without knowing any reference seed. A trivially true reference relation suffices but is not necessary. The attack works even for ideal uniformly random P. It is classical PPT relative to efficiently callable public actions, and therefore also an arbitrary-QPT attack. Actual ideal uniform P is exponential to represent, so this is an oracle/interface impossibility for frame reuse, NOT a practical implementation.

## Exact public-view consequence

Define the public distinguisher `D_i=1[A_{r,i}(Load_{z*}(a_x))!=Load_{z*}(a_x)]`. Conditioned on the target seed bit K_{x,i}=0 versus 1, the complete **joint target/reference public representations** have disjoint supports and total variation distance 1. Therefore Run 507's false-instance **single-capsule** distributional hiding theorem does not compose with an accessible true-reference terminal on the **same** frame.

The source of the failure is structural: Run 507's false-instance coupling `P -> P o T_delta`, where `T_delta` shifts the hidden k coordinate, commutes with the witness loaders and target's identity terminals but not the unrelated reference terminal. A setup proof certifying honest frame reuse does not repair this defect.

With truly independent uniform per-claim P_x and P_r, `Load_{z*}(a_x)` is uniformly distributed independently of A_r. If r has m accepted z among 2^n, the transplantation nonfixing test has probability `m/2^(n+1)` independently of K_x (1/4 in the S8 toy case). Fresh independent frames prevent **this specific** transplant, not all multi-capsule or QPT attacks. Public cross-frame conversion `P_r P_x^{-1}` reopens it. Independent claim seeds and explicit relation/UTXO/branch context are separately mandatory; related K values can leak through a legitimately opened reference capsule despite fresh frames.

## Tests and scope

The **exact committed JavaScript** checker was executed twice byte-identically: all 40,320 S8 permutations, 80,640 false-target key-bit recovery cases, 80,640 loader cases, 40,320 false-instance couplings and 40,320 fixed-point counts. An independent extended Python checker, retained locally, confirms the S8 theorem plus 112 deterministic S32 frame samples and 896 additional seed-bit cases. Tests verify finite identities, not practical PQ hardness. No on-chain proof checking, real SLH signing, Bitcoin protocol implementation, or actual UTXO exploit is claimed.

Attack families: (1) seam between reference action and target anchor; (2) shared frame/gauge without reconstruction; (3) nonfixing bit fingerprint; (4) multi-capsule reuse is central; (5) public chosen-input loading; (6) honest reuse suffices, so setup-ZK alone cannot save it; (7) cross-claim/branch misuse; (8) the native VK need not be used, but confirms leaked K; (9) classical attack is QPT-compatible, no new coherent quantum attack on independent capsules.

Run 259's supplied-complete-representation -> ORIGINAL witness or SIS theorem is not invoked: **the target is false and the attack bypasses the target admission altogether**. The conditional native P2MR/SLH endpoint is likewise not what fails. Nothing here imposes source computation or proofs on Bitcoin.

Dependencies (exact version): Run 506 blob `2d5d10c9a1d7063b08ffb377c5d5e8da2113dde8`; Run 507 (unreferenced research commit `3363d237a42f6992b83c40cdcef7b2398c2eedf7`) blob `68a408db82ae13abb01b487b2b70d05153e8121b`; Run 510 blob `60ac2f2d0a06a9999426adeb7edd8fa1d000f718`; Run 259 blob `c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2`. Literature architectural background: Canetti et al., *Towards General-Purpose Program Obfuscation via Local Mixing*, TCC 2024/ePrint 2024/006; no full paper proof or errata audit here.

**Still UNPROVED:** practical classical-PPT public mixer, full joint QPT false-instance hiding, unauthorized early capability/signature -> accepted COMPLETE source representation or independent QPT break, malicious N-of-N setup/abort/erasure, multi-capsule composition under fresh frames/seeds, concrete 128-bit resources, and exact preauthorized Bitcoin graph under the conditional native-PQ endpoint. No newly named WE/iO-equivalent assumption is introduced. Production unchanged; PR draft/unmerged; stopping condition unmet.
