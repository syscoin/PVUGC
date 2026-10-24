# Run 627 — cross-capsule cycle-space falsifier

Date: 2026-10-19. Research-only checkpoint on draft syscoin/PVUGC#1, branch research/pq-wkem-validation-20260918, starting head 2a24fba14f341c82ee796554c09b4ed59fad8d0b. No production code changes, no PQ witness-KEM construction.

## Exact model and theorem

Let G be a finite efficiently sampled group, and let an oriented public graph have uniformly independent hidden vertex frames F_v. For a fixed secret-world assignment of underlying edges U_e, classical setup publishes the complete edge tables Z_e=F_src(e) U_e F_dst(e)^(-1). Each edge can belong to a different public UTXO or branch capsule. Honest setup and evaluation are classical PPT for an efficient finite group. Adversaries may be arbitrary QPT with the full classical edge transcript and auxiliary public information. The attack below is deterministic classical PPT, requires no oracle and therefore also succeeds for QPT attackers.

FOREST: On any forest, all observed Z_e are independent uniform G elements, regardless of all underlying U_e. Proof: fix the public edge labels; choose one root frame per connected component arbitrarily; all other frames are then uniquely forced. Exactly |G|^(|V|-|E|) frame assignments generate each public edge vector.

GAUGE CLASSIFICATION: For an arbitrary graph the joint Z-law is uniform on the vertex-gauge orbit of the underlying U labels. Different gauge orbits yield disjoint public supports. Fix a spanning forest to identity; the remaining edges define fundamental cycle holonomies, up to simultaneous conjugation by a common root gauge. The simultaneous conjugacy orbit, not separate per-cycle conjugacy classes, is the exact invariant.

## Higher-order cross-capsule distinguisher

Take a directed cycle with t>=3 public edges, exposing exactly one edge in each independently tagged capsule. World zero uses all underlying edges equal to identity. World one differs only at the last edge, which is h!=identity. ANY strict subset of the t capsules forms a forest and hence has an exactly identical joint law in both worlds, even with joint examination of t-1 capsules. Multiplying all public edges telescopes to F_root h F_root^(-1). This equals identity in world zero and cannot equal identity in world one, distinguishing perfectly in O(t) group operations. No single capsule offers a second path. This is a higher-order multi-capsule failure of honest shared-frame masking.

For G=S3, with h a 3-cycle, exact complete-world support sizes for t=3,4,5 are (36,72), (216,432), (1296,2592). The published standard-library Python checker exhaustively verifies the complete distributions and all one-edge deletion marginals, passing 4698 counted assertions; repeated executions give identical output. Expanded local proof and extended checker additionally verify that individual fundamental-cycle conjugacy classes may agree while their simultaneous conjugacy relation distinguishes perfectly (three parallel-edge example), and 4819 additional counted assertions in a separately implemented checker. Neither checker establishes security of a cryptographic release scheme.

## Attack taxonomy and scope

The cycle telescopes local seams and synchronizes global hidden gauges. Cycle classes are statistical fingerprints. Multiple capsules supply a combination unavailable in any separate view. Adaptive evaluation, malicious setup and quantum-only attacks are unnecessary. Context labels and independently generated native checking keys do not cancel shared-frame algebra. Independent endpoint masks remove this *specific* cross-capsule invariant, but fail to construct permissionless all-witness common-key release. Correlated checking keys, malicious setup, replay, coherent quantum attacks against OTHER constructions, and full auxiliary-input security remain independently unproved.

This is a counterexample to transparent group-frame masking with reused vertex frames, NOT to CCMR/RIO or Gaussian WE; it neither recovers a protected signing key nor produces an ORIGINAL witness. Run 259 applies only after a complete accepted source representation; Run 625's ideal oracle extraction theorem does not govern white-box public edge inspection. No new hardness assumption is adopted.

The required compact classical post-quantum WKEM with every ORIGINAL valid witness recovering the same K_x, false-instance arbitrary-QPT hiding, unauthorized true-instance recovery/accepted native forgery implying ORIGINAL evidence or independent QPT break, related-capsule joint security, one-honest N-of-N erasure, unrestricted histories, practical sizes, and conditional native PQ Bitcoin challenge enforcement remains UNPROVED. PR stays draft/unmerged; stopping condition unmet.

Literature: Canetti–Chamon–Mucciolo–Ruckenstein local mixing, TCC 2024/ePrint 2024/006; subsequent quantum extension arXiv:2609.40289, 2026-09-30. Architectural references only; no new full proof or errata audit.
