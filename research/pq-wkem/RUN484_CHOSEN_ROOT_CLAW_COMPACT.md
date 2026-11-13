# Run 484 — chosen-root authenticated-source claw: QPT security parameters

2026-10-13 UTC. Starting live draft PR head: 99601a39d1edce3bf3c11ff98df74276e91909da, branch research/pq-wkem-validation-20260918. Exact Run 483 note Git blob 0933013687e3f39d7a6c4dc9e733d5b203d03f72; Run 259 source-binding note c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2. Last conversation comment ID 6067040320.

## Scoped mathematical result

Run 483 proves: accepted COMPLETE authenticated Merkle source transcript -> ORIGINAL witness OR hash collision. This remains valid. The present checkpoint constructs an explicit false-source admission attack **conditional on a collision between two freely chosen Merkle roots**. The root is selected after the ORIGINAL claim and can incorporate unconstrained witness/padding entropy. This is not a break of the exact published Run 483 compact checker, which had no high-entropy salt leaf, and is not a break of actual SHA-256.

Take the false Boolean circuit u=NOT(b), v=AND(b,u), v=1. No Boolean b satisfies it. Complete assignment A=(b,u,v)=(0,1,1) satisfies NOT but violates AND; B=(1,1,1) satisfies AND but violates NOT. For a fixed authenticated context x (relation/claim/UTXO/branch/anchor), commit the three wires and a free salt leaf r under one Merkle root. Define F_A(r)=Root(x,A,r), F_B(s)=Root(x,B,s). Any claw F_A(r)=F_B(s)=rho allows all NOT openings from A and AND/output openings from B to verify under the SAME rho. All row-index, source-equation and output checks pass although no single valid ORIGINAL witness exists.

Such a claw necessarily supplies a collision in the actual domain-separated Merkle compression hash: the root-node input pairs are distinct but have equal output, unless a collision already happened lower in the tree. Therefore the attack **does not contradict** Run 483's collision-to-ORIGINAL extraction theorem. It shows why the hash assumption and its precise concrete QPT strength matter.

## Coherent quantum attack / exact scope

In an ideal h-bit random-function model of two chosen-root families with at least 2^(2h/3) independent salt candidates per family, sample a table of T≈2^(h/3) values F_A(r). A coherent reversible oracle marks salts s for which F_B(s) is in that table. A random salt is marked with probability approximately T/2^h. Quantum amplitude amplification takes O(sqrt(2^h/T))=O(2^(h/3)) oracle evaluations; building the table also costs O(2^(h/3)) evaluations and massive read-only quantum-accessible storage. This is the Brassard–Høyer–Tapp claw strategy, NOT just classical birthday work renamed quantum. With h=256 its **query exponent** is 85.33, versus 128 at h=384. For a conservative generic 128-bit quantum-query collision-resistance argument based solely on digest width, use at least 384-bit output at EVERY collision-relevant Merkle level, not only at the final root.

This is an ideal-oracle query bound **conditional** on sufficiently high-entropy root families. The derived Merkle functions share an underlying random oracle; complete QROM modeling of their dependence, quantum memory costs, and concrete reversible SHA resource estimates are NOT established. In particular, no practical 2^85-cost SHA-256 attack on the exact short Run 483 fixture has been shown. 2^(h/3) is exponential, not a QPT attack in the asymptotic security definition when h grows linearly in lambda.

## Exact diagnostic and distinctions

The attached checker is a portable deterministic JS diagnostic with an intentionally weak 16-bit FNV-derived toy commitment, one free salt leaf, four independent context fixtures, and exhaustive classical root-table matching. It verifies a real collision under the toy hash, false instance acceptance by splicing NOT and AND rows under one root, full-assignment invalidity, and rejection on a different claim context. It contains NO FE/FHE/WE, no signing key, no quantum circuit, and no concrete cryptographic parameter.

A separate extended local Python checker (SHA-256 truncated to 12/16/20 bits) executed 51,843 assertions across twelve contexts and demonstrated the same source-forgery mechanism; that exact extended proof/checker/output remains in the local checkpoint archive, not the published compact Git artifacts.

Taxonomy: (1) cross-row seam YES via shared-root claw; (2) global mask/gauge NO; (3) class fingerprint NO; (4) conflicting two-view assignments YES, multi-capsule advantage not bounded; (5) public chosen-input root oracle YES; (6) malicious setup NOT required; (7) cross-UTXO replay rejected in the finite test; (8) native public checking-key correlations NOT tested (no capability release); (9) genuinely coherent BHT query strategy as specified, no executable quantum attack.

Literature: Brassard, Høyer, Tapp, Quantum Algorithm for the Collision Problem, arXiv:quant-ph/9705002, Theorem 4 and its section on claws: https://arxiv.org/html/quant-ph/9705002v1 . This is an established algorithm, not a newly proved quantum primitive.

## Research handoff

The positive Run 483 source-binding arrow remains intact with an explicit QPT hash-collision dependency. Run 259 applies only to supplied accepted COMPLETE representations under its exact extractor/residual conditions. The crucial missing arrow remains arbitrary early recovery of native K_x / accepted challenge signature -> accepted complete ORIGINAL representation or independently justified arbitrary-QPT break. No local-mixing release compiler was constructed. Full public-output false-instance QPT hiding, all-valid-witness SAME capability, N-of-N ceremony/erasure, multi-capsule setup and key correlation, practical 128-bit costs, and conditional native P2MR/SLH endpoint remain UNPROVED. Bitcoin still does not evaluate the source circuit. Production unchanged; research PR draft/unmerged; stopping condition unmet.
