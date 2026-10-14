# Run 513 — two-reference cancellation of individually uniform claim masks

Research only; 2026-10-14. Draft `syscoin/PVUGC#1`, branch `research/pq-wkem-validation-20260918`, starting SHA `15e65651be3a4c2a68e34f3385ed6e6a76222880`. New scoped multi-view falsifier of a **correlated-mask optimization** to Run 512, not an attack on its independently uniform masks or a practical PQ witness-KEM.

## Exact adversarial setting

Let `F=GF(2^h)`, `S` an honest secret uniform field element, and each public claim identity c have nonzero *distinct* `a_c` and public `b_c`. Instead of independent masks, derive `delta_c=a_c*S+b_c`. Every individual mask is exactly uniform; their joint distribution is not independent. All claims share the same hidden ideal permutation P and public Run-506 witness-loader actions on states `(u,z,t)`. The ORIGINAL-false target x publishes anchor `alpha_x=P(K_x+delta_x,0,0)`. Reference claims r,s each have a known *valid* ORIGINAL witness (not necessarily the same). Their public terminals are `A_{c,i}=P B_{c,i} P^-1` with `B_{c,i}(u,z,t)=(u,z,t+((u_i+delta_{c,i}) f_c(z)))`. Addition is XOR, multiplication is in F. The reference signing seeds are never used.

## Exact two-reference classical attack

Starting from the *target's* anchor, load a valid witness for reference c and collect bit `d_{c,i}=1[A_{c,i}(loaded)!=loaded]`. The combined h-bit word is

`d_c=K_x+delta_x+delta_c=K_x+(a_x+a_c)S+b_x+b_c`.

Using two references with `a_r!=a_s`, obtain

`S=(d_r+d_s+b_r+b_s)/(a_r+a_s)`

and then

`K_x=d_r+(a_x+a_r)S+b_x+b_r`.

This recovers the **entire false-target signing seed** in two witness loads and 2h public terminal evaluations plus polynomial field arithmetic, for every P, S, K_x. It never finds target evidence, uses neither P inverse nor the native checking key, and remains effective under an honest N-of-N setup with a perfectly erased secret master. The proof assumes precisely the publicly callable, shared-frame action interface; a construction that cryptographically prevents cross-claim action input transplantation is outside this attack. Exact branch/UTXO context tags alone do not stop it if transplantation remains possible.

## Joint-only leakage, even though each view is perfect

With `a_x!=a_r,a_s`, each `d_r` or `d_s` separately is uniform over F independent of K_x, giving **zero statistical leakage per single view**. Yet the ordered pair `(d_r,d_s)` uniquely determines `(K_x,S)`: the linear map is bijective, so the supports for distinct K_x are disjoint and their total variation distance is **one**. This sharpens Run 512's independence requirement: merely making every mask uniform, context-distinct and secret is insufficient. The common simplification `delta_c=S+H(c)` is even weaker: its public mask difference makes **one** reference enough.

## Scope, QPT, validation

The attack is classical polynomial time and therefore works for arbitrary QPT attackers; it is not a new coherent quantum attack. It covers local terminal seams, shared-frame synchronization, joint statistical fingerprinting, multi-capsule views, chosen witness loads, honest/correlated setup, cross-claim/branch context and native-VK checking correlations. It does not show insecurity for truly independently sampled masks or a proven jointly-QPT-secure PRF mask derivation. Zhandry's quantum-access PRF results do not automatically imply security of a publicly inspectable locally mixed release compiler. No generic iO/WE/RIO assumption is introduced.

Exact committed Python 3 checker ran twice byte-identically: **13,440** exhaustive GF(8) cases over all 210 ordered triples of pairwise distinct nonzero coefficients, **210** exact joint-view bijections, **3,360** single-view uniformity checks, and **64** simulated opaque-permutation attack transcripts with **384** public terminal calls. The independent extended local checker additionally completed **56,832** finite algebra cases and **6,240** shuffled-permutation attack transcripts across GF(8), GF(16) and GF(256). These checks validate finite identities, not cryptographic security or a real quantum implementation.

## Constructive handoff

Independent per-claim masks preserve Run 512's specified false-target ideal-view theorem against this algebraic attack. A shared master could only replace them with an independently proved QPT-secure joint derivation under the complete white-box/public-program view, not merely a classical PRF label or affine domain tweak. The **unproved central primitive** remains an efficiently representable, protected, source-guarded terminal with arbitrary-QPT key/signature recovery implying accepted complete ORIGINAL evidence or an independently justified break. Run 259 extracts only from accepted *complete* representations; this attack bypasses that interface. The independent native graph signatures and P2MR/SLH endpoint remain explicitly conditional.

No practical classical-PPT local mixer, full-public-output QPT hiding, malicious setup/abort/erasure security, arbitrary true-instance extraction, complete multi-capsule QPT composition, concrete 96/128-bit resource accounting or deployable Bitcoin endpoint has been established. Production unchanged; PR draft/unmerged; stopping condition unmet.

Exact inputs: Run 512 blob `321c8f9993441841acfffeed99ec759fe4733f57`; Run 511 blob `f3e6ba72cffef86d2c5fdeb24dfa86574e911116`, both read at starting head. Background only: Canetti–Chamon–Mucciolo–Ruckenstein, ePrint 2024/006; Zhandry, *How to Construct Quantum Random Functions*, JACM 2021. No full external-paper proof audit in this iteration.
