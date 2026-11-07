# Run 698 — Source-covered sparse spectral release (constructive repair)

Date 2026-10-22. Live parent: a3d391983bcc354a16a17dece06435135f9b9557, branch research/pq-wkem-validation-20260918, PR #1 (draft, unmerged). Research-only. NOT a QPT-secure WKEM, extraction theorem, native Bitcoin deployment, or production change.

## Actual new component

Run 697 publishes sparse coefficient matrices C_0=M(e_0)+K I_n and C_j=M(e_j) for j>0. If the sparse baseline M(e_0) has a zero diagonal entry, the corresponding public C_0[r,r] exposes K directly. The new SourceCoveredSetup enforces M(e_0)[r,r]!=0 for EVERY diagonal position without revealing private factors, enlarging the public support, altering source-gate semantics, requiring a common witness, or modifying Run 696 recovery. It repairs exactly this plaintext shift-support defect. It does NOT prove that the remaining public coefficients conceal K.

Use the Run 593 typed 4b-by-4b source gate

G_i(z) = [ a_i I, c_i I, -X_i(z), 0;
           d_i I, b_i I, 0, X_i(z);
           0, 0, b_i I, c_i I;
           0, 0, d_i I, a_i I ].

The source scalars remain field elements; only the X_i are b-by-b matrices. On the projective Boolean source example set a_i=b_i=d_i=z_i and c_i=z_0. The relation z_i^2=z_0 z_i with z_0=1 makes rank(G_i(z))=2b for every valid z and every affine X_i(z). This is a NON-HARD illustrative source; the real ORIGINAL Syscoin relation is not implemented in the checker.

Fix m gates, n=2bm+1, d>=3. Sample private sparse factors L_i in F_q^(n x 4b), R_i in F_q^(4b x n), with at most d entries per L column and R row. Publish ONLY aggregated M(z)=sum_i L_i G_i(z) R_i, in the lossless Run 697 public coefficient codec, and the intended full native pk, x/claim/UTXO/branch/anchor/context bindings. The setup secret K is the fixed common native signing capability.

## Constructive diagonal completion and proof

For outer coordinate r in [0,n), assign (i,p) by i=floor(r/(2b)), p=(r mod 2b) mod b for r<2bm, and (i,p)=(0,0) for the last coordinate. Each (i,p) occurs at most three times. Reserve a nonzero L_i[r,p]=alpha_r and a resampleable R_i[b+p,r]=t_r. Fill all other factor support positions respecting d; this uses no extra support budget.

At baseline e_0=(1,0,...,0), G_i(e_0) e_(b+p)=e_p. Consequently varying only t_r by delta changes column r of M(e_0) by delta L_i[:,p], and leaves every other diagonal M(e_0)[s,s] (s != r) unchanged.

Thus M(e_0)[r,r]=B_r+alpha_r t_r, with B_r independent of all reserved t_s. Draw each t_r uniformly over F_q excluding the unique forbidden value -B_r/alpha_r. Then each baseline diagonal is uniformly distributed over F_q^*, independently conditional on the remaining setup randomness, and is nonzero by construction. No global restart or canonical source witness is used. For a cryptographic field this prevents the earlier immediate key equality on all public diagonal shift positions; it does not imply ciphertext key hiding.

Exactly relative to the same covered-support factor sampler with the t_r initially independent uniform in F_q, the output distribution is that sampler conditioned on all diagonals nonzero. The conditioning event has probability (1-1/q)^n, so the full-private-setup statistical distance is 1-(1-1/q)^n <= n/q. Deterministic public encoding and QPT postprocessing do not increase this distance under auxiliary data independent of fresh t_r. Arbitrary retained setup coins or setup-correlated quantum advice are not covered. Neither reference distribution has an established QPT hiding theorem.

For any complete valid SOURCE representation z, rank M(z) <= sum_i rank G_i(z) <=2bm=n-1. Hence C(z)=M(z)+K I_n has eigenvalue K for EVERY valid z, even though the matrices vary by witness. Run 696's fresh randomized Krylov decoder therefore includes K with probability at least (1-1/q)^2 per projection. Full native public-key matching, seed uniqueness, actual SOURCE/ORIGINAL encoding, and arbitrary accepted-signature extraction remain separate.

The original public support and work bounds remain: |S|<=min(n^2,n+m(4bd)^2), public size at most (v+1)|S| field elements plus support indices, matvec O(|S|), and Krylov O(n|S|+n^2). With illustrative m=15000,d=3,32-byte field elements, b=1 requires up to roughly 1.052 TB; b=2 up to roughly 4.177 TB. These are NOT practical 128-bit QPT parameters.

## Exact executed evidence and limits

Published compact Node.js checker (in this commit) tests the b=2 full-matrix-mask variant over F_257 with m=3, n=13 and d=3: all 13 covered diagonals, 8 valid Boolean witnesses, direct public/private coefficient equality, valid-source singularity, a malformed full-rank source, and factor support caps (106 assertions). It passed node --check and two byte-identical executions. The extended Python checker, preserved in the local research packet, additionally exercised 12 scalar and six b=2 setups: 432 valid source representations, 60 successful Krylov detections, 48 invalid-source vectors with full-rank aggregate operators, and 314 finite completion-distribution fixtures. Passing toy checks is NOT a cryptographic security proof.

Dependency blobs: Run 593 29b9168bfff6043810284cd1960400579f224e31; Run 695 50174666730b93bd20f83bb29ddb2c355ccf1a91; Run 696 e37f51a69c3ca68d584d0b2e0f18b71e876bf217; Run 697 736d8d961f06cc0b26745c27a174d21dc486190b. Run 259 SOURCE-to-ORIGINAL historical blob c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2 is NOT an arbitrary recovery extractor.

The full-output QPT hiding and unauthorized true-instance key recovery/accepted signature -> accepted complete SOURCE OR independent QPT break are UNPROVED. Remaining surfaces include support and gate seams, global factor synchronization, statistical fingerprints, multiple capsules, adaptive public evaluation, malicious N-of-N setup/retained coins, cross-UTXO/branch replay, public checking-key correlation, and coherent quantum attacks. Conditional P2MR/SLH endpoint and the covenant-emulated graph are not deployed or proved.

Next substantive constructive task: retain this source-covered sparse rank/recovery interface while constructing an independently justified QPT-secure opaque public operator that conceals key and factor correlations; then compose arbitrary-source extraction with Run 259. No complete WKEM; do not disable research.
