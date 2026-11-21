# Run 580 — Independent output relabeling versus equality-only synchronization

2026-10-17. Research on draft syscoin/PVUGC#1, starting verified SHA `7765732ee2c78764cbd282a72dd62fa5511077e5`. Not a practical witness-KEM, production change, or complete QPT security proof.

## Exact two-capsule ideal model

Let D=F_2^n, N=2^n, tau_d(s)=s XOR d. Fix any permutation B:D->D. Independently sample uniform shifts d1,d2 and uniform output permutations pi1,pi2. Public coherent evaluations give Gi(s)=pi_i(B(s XOR di)). For every prescribed pair of permutations g1,g2, exactly one pair of independent masks pi_i can realize Gi=gi. Therefore **(G1,G2) are independent uniform permutations** even when B is known and complete Gi oracle tables are visible; they contain zero statistical information about d1,d2. This ideal permutation experiment has exponential setup cost, and excludes public descriptions exposing the mask secrets, compromised coins and correlated auxiliary keys.

## Exactly one-bit equality oracle versus label translator

Add a coherent public latent comparison oracle Q(s,t)=[B(s XOR d1)=B(t XOR d2)]. Injectivity gives Q(s,t)=[s XOR t=h] with h=d1 XOR d2. Access to Q is equivalent with one reversible predicate call to unique marked-point search O_h(z)=[z=h]. Since G1,G2 are independent of uniformly random h, recovering h using these **exact oracles only** has bounded-error quantum query complexity Theta(2^(n/2)), by Grover's algorithm and the standard unstructured quantum search lower bound. Even disclosure of d1 leaves h uniform, so d2 is recovered only with the same black-box complexity. This is NOT concrete 128-bit security, protection against correlated native public checking keys, or a public classical-PPT encoding for Q.

If a coherent public translator T=pi2 o pi1^{-1} is exposed, then T(G1(s))=pi2(B(s XOR d1)) and G2(s)=pi2(B(s XOR d2)). Their two-branch oracle has exact Simon period (h,1), so the Run 579 polynomial-QPT hidden-shift attack returns. The public translator is **more informative than a bit-valued equality test**. Ordinary raw output equality G1(s)==G2(t) is not the latent comparison Q.

## Transparent efficient affine subfamily and falsifier

A restricted positive output-view lemma *does* admit classical-PPT transparent circuits: B(s)=s, public invertible binary matrices Mi, independently uniform secrets ri and shifts di; Gi(s)=Mi s XOR bi, bi=Mi di XOR ri. The entire published affine code (Mi,bi) is independent of di. This does **not** implement Q or a witness release, and retained ri,di reveal the shifts. If the actual frame translator T(y)=M2 M1^{-1}(y XOR r1) XOR r2 is also public, then T(G1(0)) XOR G2(0)=M2(d1 XOR d2). Public M2^{-1} recovers h **classically from one pair of evaluations**. Output relabeling therefore is not by itself a safe local mixer.

## Attack taxonomy, QPT scope and missing composition

Seam/cancellation: translator and inverse masks destroy hiding. Gauge: independent labels hide shifts only without alignment data. Fingerprints: affine function-class visibility is independent of di in the stated subfamily; arbitrary nonlinear B with only affine masks is NOT covered. Multi-capsule: independent output masks decouple unaligned ideal views, but joint security with many pairwise comparison oracles is UNPROVED. Chosen-input/coherent calls to Q admit Grover point search; public translators admit Simon. Malicious setup and retained builders' seeds break these claims; one-honest N-of-N erasure/abort security is unproved. Cross-UTXO reuse, native branch-specific keys, original source binding and public checking-key correlations are absent. No coherent quantum advice correlated with hidden shifts is allowed in the positive theorem.

No ORIGINAL relation R(x,w), release state s_w or protected signing capability K_x has been constructed. Therefore there is NO all-witness SAME-K correctness, full-public-output false-instance QPT hiding, unauthorized true-instance early key recovery/accepted signature to ORIGINAL representation reduction, malicious ceremony, concrete 128-bit resources or conditional Bitcoin native SLH/P2MR graph. Run 259 applies only after an accepted COMPLETE representation is available, which these oracles do not provide. An assumed general common release oracle would be WE/WPRF circularity.

Literature: Bennett–Bernstein–Brassard–Vazirani, SIAM J Comput 1997, DOI 10.1137/S0097539796300933; Boyer–Brassard–Høyer–Tapp, Tight Bounds on Quantum Searching, 1998, arXiv quant-ph/9605034. CCMR TCC 2024 / ePrint 2024/006 and 2026 arXiv 2609.40289 remain architectural evidence only. Full security proofs and errata were not audited here.

The deterministic JavaScript checker was executed in a V8 runtime and its exact serialized source and captured output are committed alongside this note. It exhausts n=2 output relabeling distributions, checks the equality predicate, verifies transparent affine masking through n=5, checks classical translator leakage and one finite Grover rotation probability; it is not a quantum algorithm execution.

**Handoff:** Develop/falsify a classical-PPT public equality-only witness-sensitive release interface that cannot expose a translator, correlated verification-key leakage or setup trapdoor, without assuming the full WE objective. Stopping condition unmet; research draft remains unmerged and production unchanged.
