# Cumulative source-rank spectral WKEM candidate — Run 698

Research-only, not secure or practical. Actual parent a3d391983bcc354a16a17dece06435135f9b9557.

Setup/Build: Bind x=(relation,claim/UTXO,branch,anchors,window,context). In an honest secret-erasure N-of-N setup (NOT implemented), create intended signing seed K and native pk. For complete SOURCE affine gates ab=cd, sample private sparse L_i,R_i and private b-by-b affine source masks X_i(z). Use Run 698 source-covered factor completion so the public seed shift has no untouched diagonal slot. Form M(z)=sum L_i G_i(z)R_i, n=2bm+1; publish ONLY combined sparse coefficient matrices C_0=M(e_0)+KI and C_j=M(e_j), the lossless public support codec, native pk and complete bound context.

Encode: ORIGINAL witness -> accepted complete SOURCE z with z_0=1; exact acceptance by Run 259/source compiler needed, not inferred from an inner proof.

Recover: Assemble the public operator C(z). Run Run 696 randomized Krylov/Berlekamp-Massey/Frobenius root isolation and filter candidate signing seeds against the FULL native checking key and context; then sign the challenge branch off chain. Different witnesses retain different intermediate matrices, while K is the SAME eigenvalue. For each fixed valid z and setup, projection success >=(1-1/q)^2. The actual native-key uniqueness and relation lift are additional obligations.

Proved reusable components: typed rank-2b valid gate (Run 593 blob 29b9168bfff6043810284cd1960400579f224e31), spectral common seed (Run 695 blob 50174666730b93bd20f83bb29ddb2c355ccf1a91), Krylov (Run 696 blob e37f51a69c3ca68d584d0b2e0f18b71e876bf217), lossless sparse public operator (Run 697 blob 736d8d961f06cc0b26745c27a174d21dc486190b), source-covered key-shift support (Run 698). Run 259 SOURCE=>ORIGINAL historical blob c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2 is downstream and scoped only.

Resource ceiling: (v+1)min(n^2,n+m(4bd)^2) field coefficients, plus indices; the 15k-gate 32-byte-field illustrative b=1 and b=2 carriers remain about 1.052 TB and 4.177 TB respectively, not practical. Honest factor setup/evaluation classical; ultimate attacker arbitrary QPT with full classical public output, native checking key, aux data, multiple capsules and coherent access to public evaluation.

UNPROVED decisive step: Complete-view QPT false-instance hiding and arbitrary unauthorized true-instance key recovery / accepted native signature -> accepted SOURCE representation OR independent QPT break. A nonzero source baseline diagonal alone does not hide K from other public algebraic correlations. Malicious N-of-N setup/abort, multiple-capsule composition, graph enforcement and hypothetical P2MR/native SLH endpoint are also not established.

Do not restart generic rank/common-preimage/hash-collapse routes, rename WE as a release assumption, publish gate factors, or treat mathematical correctness/tests as security. The next specific task is a compact opaque *public* operator with an independently justified full-view QPT proof, preserving this source-rank/recovery interface. Production and workflows untouched; draft PR unchanged.
