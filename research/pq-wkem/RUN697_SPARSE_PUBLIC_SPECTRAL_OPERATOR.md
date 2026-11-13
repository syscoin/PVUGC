# Run 697 — Sparse public spectral operator (constructive component)

**Date:** 2026-10-22. **Status:** exact correctness/representation improvement to Run 593→695→696, NOT a practical or QPT-secure witness-KEM. Starting PR SHA: `e3013235e33554b4cf86e6bd39d5d17653d27d03`.

## Explicit construction

For each of m source gates, reuse Run 593's 4b×4b matrix `G_i(z)` with `rank(G_i(z))≤2b` for every valid complete SOURCE representation z. Let `n=2bm+1`, and choose *secret* `L_i∈F_q^(n×4b)` and `R_i∈F_q^(4b×n)`, with at most d nonzero entries per L column and R row. Keep the original source scalars and dense witness-dependent affine mixing form inside each gate. Define

`M(z)=Σ_i L_i G_i(z) R_i=Σ_j z_j M_j`.

Generate signing seed K, publish ONLY combined coefficient matrices `C_0=M_0+K I_n`, `C_j=M_j` for j>0, and the complete bound native `pk`, claim/UTXO/branch/anchors/relation/context and checker. Do NOT publish the setup factors, random seeds or per-gate decomposition. Honest setup/erasure is still assumed, not implemented. This is not a keyless builder.

The *public* union-of-nonzero-positions `S_pub=∪_j supp(C_j)` is derived deterministically from the already public coefficient matrices. Every support lies inside `diag ∪ ⋃_i U_i×V_i`, where `U_i` and `V_i` are the supports of the hidden gate-factor rows/columns, and hence

`|S_pub|≤min(n²,n+m(4bd)²)`.

Publish S_pub once in sorted order, then a coefficient value for each position and each source slice. This is a **lossless and efficiently invertible representation** of the complete public ciphertext. No hidden setup factor is disclosed by the codec itself.

**Recover:** From an ORIGINAL witness obtain its accepted complete SOURCE z using the existing source machinery. Compute the sparse public `C(z)=Σ_j z_j C_j` and use Run 696's fresh randomized Krylov/Berlekamp–Massey/Frobenius finite-root recovery and **full native public-key/context** filtering. For any valid z, `rank M(z)≤Σ_i rank G_i(z)≤2bm=n−1`, so K is an eigenvalue of C(z) with no cofactor requirement. Run 696's fixed-setup/fixed-valid-witness correctness probability `≥(1−1/q)²` per independent projection carries over, conditional on unique native checking-key identification. Different valid witnesses retain different matrices.

**Representation-equivalence lemma:** For this *same sparse-setup distribution*, dense C_j and the codec's (S_pub,values) have deterministic polynomial-time conversions in BOTH directions. Any QPT public-view adversary for either encoding converts to one for the other while leaving arbitrary correlated quantum auxiliary state unchanged (public ciphertext held in a classical register). This does **not** establish QPT security of the sparse distribution, which may differ sharply from the dense original.

## Quantified resources

For v+1 slices, dense costs `(v+1)n²` field values. Encoded costs at most `(v+1)min(n²,n+m(4bd)²)` field values plus one support-index list. One public sparse matvec costs `O(|S_pub|)`; assembly of C(z) is `O((v+1)|S_pub|)`, and Run 696's Krylov phase is `O(n|S_pub|+n²)` field operations.

**Illustrative, NOT cryptographic security parameters:** m=15,000, b=1, d=3, n=30,001, v+1=15,002, and 32-byte field elements give ≤2,190,001 common positions. Dense coefficients ≈432.09 TB; sparse upper bound ≈1.052 TB, ≥410.98× less. This is **still impractical**, and roughly 131 billion field multiplications can be required for Krylov. A 32-byte field has not been justified for 128-bit QPT security.

## Exact validation and security limitations

Published executable JS checker passed **128 assertions**, including **56** independent private/public operator equalities on all enumerated valid Boolean witnesses, **12** fresh Krylov recoveries and three lossless public-codec checks, all over F_257. Expanded local Python checker passed 812 assertions on 368 witness cases and 48 Krylov recoveries; it is preserved separately with its exact captured output, not claimed as the published checker. Tiny examples do not establish cryptographic security.

Public support and multi-slice correlations may expose gate seams, and public evaluation accepts arbitrary z. Full-public-view false-instance QPT hiding, arbitrary true-instance key recovery/accepted forgery→accepted complete SOURCE or an independent QPT break, malicious N-of-N setup/abort, multi-capsule security, and native-PQ Bitcoin deployment remain **UNPROVED**. The Run 259 extraction theorem applies ONLY after an accepted complete SOURCE representation has actually been obtained. No PK assumption, secret PRG seed, or unproved release oracle is silently added.

**Next constructive obligation:** achieve a compact opaque PUBLIC operator whose public support/multi-slice structure does not reveal private gate decomposition, then independently prove the required QPT security reductions. Retain this sparse codec/black-box interface even if the carrier needs replacement.

Dependencies: Run 593 blob `29b9168bfff6043810284cd1960400579f224e31`; Run 695 blob `50174666730b93bd20f83bb29ddb2c355ccf1a91`; Run 696 blob `e37f51a69c3ca68d584d0b2e0f18b71e876bf217`; Run 259 historical blob `c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2` (not invoked here). No production changes. PR remains draft/unmerged.
