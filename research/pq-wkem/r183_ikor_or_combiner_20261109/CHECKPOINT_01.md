# R183 / 2026-11-09 — Independent-key OR cancellation, provisional checkpoint

STATUS: In-progress mathematical construction of a *combiner*, not an instantiated source witness-KEM. This is a genuinely separate question from constructing any branch's evidence-conditioned key release. No new source primitive or native signature has been instantiated, and no experimental/quantum-security result is claimed at this checkpoint.

## Continuity

syscoin/PVUGC PR #1 open/draft branch `research/pq-wkem-validation-20260918`. Observed starting HEAD `ac473d38c97f9450d3a0de00fc524be42f8b0320` (R182 source-activated annex binding). Read R182 and targeted R181. Latest ordinary comments since 2026-11-09T17:00:00Z reviewed (R176/R177 corrections). No full diff or archive sweep; no web/external literature.

## Named attempt: Independent-key OR-masked frozen signature (IKOR)

Previously the architecture requires all 3 challenge branches to open the SAME frozen native cancellation capability. This does *not* require all branches to derive the same *cryptographic intermediate key*: independently sample K_1,K_2,K_3 and build one original-evidence-dependent branch capsule each C_j=Build_j(R_j,x_j,K_j). Publish D_j=sigma_cancel xor H_pad(capsule_id,signer_id,j,K_j). Every qualifying original witness for branch j opens K_j, hence the SAME sigma_cancel. Each branch's `Build_j/Open_j` is still uninstantiated and must be real and secure; an API name is not an implementation.

Challenge branches: (1) qualified BTC competing greater cumulative work, (2) invalid/nonexistent bound PoB with finite authenticated source refutation, (3) qualified Syscoin AuxPoW tag fork/fault with claim-prefix / depth rules. N-of-N graph setup independent from 1-of-N notary activation and permissionless challenge. For participant i use independent native sigma_i and K_{i,j}; no aggregation or live release committee.

## Provisional quantum hybrid idea to verify

Assume the actual branch capsule distributions (C_j,K_j) are independent of dedicated domain-separated H_pad outputs; no source-selected retained K_j and no earlier related-capsule leakage. H_pad is an independent quantum-accessible random oracle; its input includes capsule ID, participant ID, branch. Given C_j and K_j fixed, D_j has a uniform marginal. Couple REAL to a reference world with D_j uniform and H_pad fully independent by programming H_pad(j,K_j)=D_j xor sigma_i in REAL. Quantum telescoping then bounds any final-event difference through total pre-query probability mass at the 3 hidden oracle addresses.

If A makes Q coherent H_pad queries, and delta is REAL-minus-REF event advantage, expected total query-hit mass should obey sum_t E[p_t] >= delta^2/(4Q); measuring one uniformly selected reference query hits some (j,K_j) with probability >=delta^2/(4Q^2). If each branch's *actual* one-way key recovery can be converted to an ORIGINAL witness (or independently justified PQ break) with all other branch capsules and public data as auxiliary input, then this would lift to an OR-capability extractor. REF accepted native signature requires native QPT unforgeability. The exact coupling and independent-domain/extractor prerequisites must be proved before claiming this lemma.

Need check quantum advice dependence on fresh oracle, malicious setup, related capsules, selective openings and actual source correlations. One-wayness of an unspecified branch capsule is not a hash-only leaf construction. No QPT theorem or 'security from SHA' is claimed at this intermediate stage.
