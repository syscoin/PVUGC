# Run 586 — Regev-style restricted witness release: exact all-witness correctness, far-false-key break

2026-10-17. Draft research on syscoin/PVUGC#1, live parent ec70a1391c9b685a75b214d61fc765b06c42c58f. Previous checked sources: Run585 blob 97164d9984adda526e5bd109643eb86eaaaac9d2, Run584 blob 4e1f005be26067f53c13fcb222c3091ecaadcf91, Run259 blob c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2. NOT a practical or general-NP witness-KEM.

## Candidate
For q odd, A in F_q^{m x n}, b in F_q^m, define ORIGINAL relation R((A,b),(s,e))=[s binary, ||e||_infty<=B, b=As+e mod q]. Honest classical setup encrypts each bit mu of one common protected K using independent r in {0,1}^m:
  u=A^T r; v=b^T r+floor(q/2)*mu mod q.
Any valid ORIGINAL witness independently decodes mu by rounding v-s^T u to nearest of 0 and floor(q/2). Different valid s,e produce different intermediate residuals. This is a minimal relation-dependent candidate, not a generic iO or WE assumption. A setup holder must still protect/erase K; no keyless Build claim.

## Theorem A: exact multiwitness correctness
If mB < (q-1)/4, then |e^T r|<=mB for EVERY valid witness and EVERY honest encryption coin vector; hence rounding is correct for all witnesses simultaneously with probability one. No common witness, shared short preimage, canonical intermediate state, or random hash collapse is needed. Example q=17,A=((1),(0)),b=(1,0),B=1 has two valid ORIGINAL witnesses s=0,e=(1,0) and s=1,e=(0,0), with different unrounded states but the same recovered bit. This positive result is restricted to the special LWE secret-key relation, not Syscoin's general evidence relation.

## Theorem B: far false statement leaks full protected K
Take q=257,m=4,n=3,B=1,
 A=((1,1,1),(1,2,4),(1,3,9),(1,4,16)),
 b=(32,1,1,1).
The first three rows have determinant 2 mod 257: full column rank. Every A and b entry is nonzero. For every binary s, (As)_0<=3, hence centered (b-As)_0>=29. The minimum possible infinity-norm residual is 29, so the ORIGINAL statement is definitively false and far outside the noise budget.

Still v=32r_0+r_1+r_2+r_3+128mu mod 257. For mu=0 v is one of 0..3 or 32..35; for mu=1 it is one of 128..131 or 160..163. Public rounding of v ALONE recovers mu for EVERY encryption randomness. Independently encrypting 128 secret-signing-seed bits therefore leaks ALL 128 bits with probability one on this false statement. Native checking keys may confirm the recovered secret; they do not make it secret. The attack is classical PPT, hence defeats QPT false-instance hiding. It uses honestly sampled encryption coins and needs no retained setup secret or cross-capsule correlation.

Ordinary honest-key LWE IND-CPA does not imply arbitrary-ORIGINAL-false selected-public-key hiding: the adversarial x here is a malformed encryption key. This does NOT refute Regev's honestly generated encryption theorem. A stronger admission/validation mechanism can reject this particular key; none is constructed or proved here.

## Security ledger and attack taxonomy
Honest algorithms classical PPT; adversary arbitrary QPT with full public outputs, contexts, key-checking data, multiple capsules and auxiliary advice. A classical single-capsule attack already wins, so no genuinely quantum technique is needed for the falsification. Local seams, global gauge synchronization and output-mask cancellation are not needed; the public sparse-range fingerprint is fatal even with full-rank nonzero A. Adaptive public evaluation of v exposes the capability; random-coin or malicious-setup games cannot repair this honest-instance attack. Context/UTXO/branch separation and a native PK.seed/PK.root check do not hide public v. Multiple capsules and unrelated verifier messages do not help.

Run259 only proves accepted COMPLETE source representation -> ORIGINAL (statistically or under its stated SIS condition), not native signature -> such representation. The candidate does not supply the missing arrow, false-instance hiding, true-instance unauthorized extraction, malicious N-of-N setup, independent QPT assumptions, or a concrete Bitcoin P2MR/SLH endpoint. Its q=257 toy is NOT a concrete 128-bit lattice parameter selection.

## Exact reproducibility
run586_lwe_key_release_check.js executes deterministic finite checks and prints the included validation JSON. It was executed twice with byte-identical results before GitHub publication. It checks honest multiwitness decoding, the chosen full-rank far-false statement, exhaustive 32 ciphertext/nonce cases, and 128-bit complete recovery. A separate locally executed Python checker passed 48,336 assertions. Neither test establishes cryptographic hardness or implements native SLH-DSA.

## Handoff
Bounded-error decryption is a positive, exact example of all-witness SAME-capability agreement with distinct internal states. However, even a full-rank nondegenerate far-false public statement can leak the entire capability. The missing object is a source-authenticated local release frontier with provable arbitrary-false-instance QPT hiding, plus arbitrary native forgery -> ORIGINAL evidence (or independent QPT break), not an honest-key IND-CPA shortcut. Stop condition UNMET; production unchanged; PR draft/unmerged.

Literature: Oded Regev, *On Lattices, Learning with Errors, Random Linear Codes, and Cryptography*, STOC 2005, DOI 10.1145/1060590.1060603. CCMR local mixing ePrint 2024/006 is architectural context, not proved here.
