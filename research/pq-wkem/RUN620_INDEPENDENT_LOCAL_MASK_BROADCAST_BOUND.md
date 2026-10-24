# Run 620 — independent local-mask broadcast bound

Date 2026-10-18. New research only on syscoin/PVUGC PR #1, draft/unmerged, branch research/pq-wkem-validation-20260918. Starting SHA 5d52462fb6a11b31135722335099ba3a7ac613d6. This is an independent-token information-theoretic lemma and a multi-capsule falsifier, NOT a QPT-secure witness-KEM construction.

## Exact model and theorem

Fix a statement x with M distinct admissible witness-dependent release states. The honest classical builder samples a common lambda-bit capability K and M independent uniform lambda-bit local bearer tokens T_1,...,T_M, with mutual independence among ALL of these strings. We generously allow the builder to know all tokens before compilation, even though late ORIGINAL witnesses may be unknown in the actual application. It may create an arbitrarily correlated, randomized public finite fixed-length ciphertext C. Every receiver i must recover the SAME K with certainty from only C and T_i: H(K|C,T_i)=0. Require perfect passive secrecy I(K;C)=0, equivalent to H(K|C)=lambda. The public native signing key is NOT included in this ideal information-theoretic model.

THEOREM: H(C) >= M * lambda; hence a fixed-length C uses at least M*lambda public bits.

Proof. For each receiver i, I(K;T_i|C)=H(K|C)-H(K|C,T_i)=lambda. Since H(T_i|C) <= H(T_i)=lambda, equality forces H(T_i|C,K)=0. Therefore (C,K) determines every T_i, jointly. Mutual independence before compilation gives H(K,T_1,...,T_M)=(M+1)*lambda. Since (C,K) determines this entire tuple, H(C,K)>=(M+1)*lambda. But H(C,K)=H(C)+H(K|C)=H(C)+lambda. Subtract lambda. QED.

TIGHTNESS: C_i=K XOR T_i for i=1,...,M, concatenated into an M*lambda-bit public broadcast. Each independent bearer token decrypts one row to the identical K, and the entire public C is uniform independent of K.

This bound does not apply if tokens are correlated with each other or with K, derived from structured ORIGINAL witnesses, or protected only by computational hiding. In particular it is not an unconditional lower bound on CCMR/RIO, WE, local mixing, or PQ signature-based witness-KEM; it only eliminates large sets of independent one-time-pad-like local masks as a compact solution. The native verification key pk(K) can determine K information-theoretically even if recovering K is QPT-hard; therefore perfect mutual-information secrecy WITHOUT that key is intentionally a narrower model, not the actual PQ security game.

## Related-statement/multi-capsule falsifier

Claim A has authorized local tokens T_0 and T_1; claim B has only token T_1. Distinct branch capabilities K_A and K_B are independently sampled, but the same T_1 is incorrectly reused in both capsules. The public rows are C_A0=K_A XOR T_0, C_A1=K_A XOR T_1, and C_B1=K_B XOR T_1. An attacker knowing only authorized A-token T_0 recovers B's capability with the straight-line identity

K_B = C_B1 XOR C_A1 XOR C_A0 XOR T_0.

No B-token or B ORIGINAL representation is provided. This violates true-instance recovery-to-ORIGINAL for this mask-reuse design, even though K_A and K_B differ; the attack is classical polynomial-time and hence also QPT. It does not break Run 259: no accepted B representation is produced. Proper per-branch/UTXO mask-domain separation blocks THIS particular identity, not the overall witness-KEM realization gap.

## Exact executable check

The committed standard-library checker run620_publish_check.py exhausts ALL deterministic encoders in three tiny cases, testing both correctness for every local bearer token and equality of public ciphertext distributions under K=0 versus K=1. It reports (M,public bits,encoders checked,encoders valid): (1,1,16,2), (2,1,256,0), (2,2,65536,24). The extended local checker also exhausts matching OTP rows for M=1..4 and lambda=1 and M=2..3 and lambda=2. Both executed checkers run twice with byte-identical captured results; the 256 cross-capsule trials use 128-bit toy masks. These are finite algebra checks, not quantum experiments or a native-signature implementation.

## Attack/QPT/dependency ledger

Local seam and global gauge cancellation occur when the common recovered K reveals every row mask. Multi-view correlation and cross-UTXO reuse are attacked explicitly. Chosen-input public evaluation needs no oracle in the reuse attack. Statistical fingerprinting is unnecessary; ideal C secrecy is an assumption tested for tiny cases. Malicious setup/seed bias, actual checking-key correlation and genuinely coherent quantum attacks are NOT analyzed for a new construction; the classical attack already lies in the arbitrary-QPT class. Honest algorithms are classical PPT for polynomial M; the theorem itself covers arbitrary finite M. There is no new cryptographic hardness assumption.

The exact live Run 619 ideal relation-oracle theorem remains scoped to oracle queries, not white-box public release programs. Run 259 only turns supplied accepted complete representations into ORIGINAL witnesses or an explicitly assumed SIS break. Neither theorem closes arbitrary actual signature/recovery -> accepted representation for this scheme.

CCMR local-mixing reference: Canetti, Chamon, Mucciolo, Ruckenstein, Towards General-Purpose Program Obfuscation via Local Mixing, TCC 2024, DOI https://doi.org/10.1007/978-3-031-78023-3_2 . Its conditional local reversible-circuit framework is NOT the independent-mask model tested here; no full QPT proof/errata audit was completed this iteration.

CORE HANDOFF: Any compact minimal release frontier with many valid witness-dependent states must exploit nontrivial safe correlations/structure rather than independent bearer-mask rows. Correlation is necessary in the tested model but emphatically not sufficient: full-public-view false-instance QPT hiding, true-instance arbitrary signature-to-ORIGINAL extraction, malicious N-of-N setup, multi-capsules, practical parameters and conditional native PQ Bitcoin signing remain UNPROVED. No completed practical PQ witness-KEM; do not disable research automation.
