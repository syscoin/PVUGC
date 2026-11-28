# Run 699 — Canonical PUBLIC source-direction dictionary for Run 698

Date 2026-10-22. Exact live parent: 6c2008bda0d47c4d59b9ebb8acc9c834589beda1. Research-only draft syscoin/PVUGC#1. This is **lossless public transcript compression**, NOT a secure or practical PQ witness-KEM.

## Concrete construction and exact proof

**No sampler change.** Keep the exact Run 698 source-covered sparse factors, typed block gate, full affine secret mixing forms, context/claim/UTXO/branch/anchors, and native verification key. Publish only combined coefficient matrices of
C(z) = sum_{j=0}^{p-1} z_j C_j = K z_0 I_n + sum_{i=1}^m L_i G_i(z) R_i,
with n=2bm+1 and z_0=1. The secret setup factors and source masks are never published. The existing Run 698 distribution of complete public coefficient matrices is UNCHANGED.

For every *already public* matrix position s=(r,c), let v_s=(C_0[r,c],...,C_(p-1)[r,c]). Omit all-zero positions. Choose first nonzero pivot j, scalar alpha=v_s[j] and normalized direction u_s=alpha^(-1) v_s. Publicly and deterministically intern duplicate normalized directions in lexicographically sorted coordinate order. Store each coordinate as (r,c,alpha,dictionary_index). For a unit direction e_j store only the unit index; otherwise store its pivot and p-1 nonpivot field coefficients. All other coefficients are reconstructed as alpha*u_s. The exact raw-support baseline is selected deterministically instead when the dictionary is larger.

**Losslessness:** Decode(Encode(C))=C for EVERY public C, including colliding sources, nonrandom factors and malformed off-relation evaluation. Direct evaluation computes beta_l=<u_l,z> once per dictionary direction, then C(z)[r,c]=alpha_s*beta_id(s). This reproduces the same complete matrix for ANY chosen public z, not just valid ORIGINAL witnesses.

**QPT transcript-equivalence lemma:** The codec and decoder are deterministic classical polynomial-time conversions from the original complete classical public transcript. An arbitrary QPT adversary with the native checking key, multiple related capsules, setup-correlated quantum advice, chosen-input public evaluation or coherent access can be simulated straight-line in the other representation with polynomial overhead, using reversible evaluation when needed. The same quantum auxiliary state is retained. There is no QROM programming or rewinding. This is a TWO-WAY REPRESENTATION REDUCTION, **not an underlying false-instance hiding theorem**. Public gate seam, global synchronization, fingerprints, capsule intersection, retained coins, replay, checking-key correlation and coherent attacks transfer without change. Publishing the dictionary must not be described as concealing its directions: they were already public/derivable.

## SOURCE-mode counting and resource lemma

Each typed 4b-by-4b gate has 8b scalar-source primitive matrix entries carrying either z_0 or z_(i+1), plus 2b^2 affine-mask entries carrying one of b^2 dense source coefficient vectors (up to sign). Each primitive outer-product footprint has at most d^2 coordinates. Counting the K z_0 I shift,
S <= min(n^2, n+m(8b+2b^2)d^2).
Let E be the number of positions covered by >=2 primitive footprints, counting the K shift as a separate primitive. Every other position contains exactly one primitive source direction, among e_0, e_(i+1), and b^2 full-mask directions per gate. Thus
D <= 1+m(1+b^2)+E.
This is an exact deterministic combinatorial bound, NOT a QPT security argument.

With 32-byte field elements and four-byte indices, DICT size is at most
32[(p-1)D_nonunit+S] + 4[D+3S] bytes;
RAW uses 32pS+8S bytes. Deterministic fallback is never larger than RAW. Assemble a public operator in O(pD+S) products rather than O(pS); Run 696 Krylov sparse matvec cost O(nS) is unchanged.

**Executed standalone compact checker in this commit:** F_257, m=64, b=1, d=3, n=129, p=65; source-covered Run-698-form factors and full affine mask vectors, reconstructed all public coefficients and four different source evaluations. 24246 exact assertions passed; support 4771, directions 866, overlap coordinates 952. Run-697 same-sampler sparse support-union bytes 9961848, public projective codec bytes 1853836, 5.3736x smaller. No claim of 128-bit parameters, secrecy or ORIGINAL extraction. Extended LOCAL standalone Python checker covers b=2 and five fixture sizes including m=128: 89 assertions, m=128 42,683,520 -> 4,841,596 bytes (8.816x), repeated JSON byte-identical; local-only extended work is separate from the published exact JS executable.

**Illustrative only:** m=15,000, b=1,d=3,p=15,002 has provable support bound S<=1,380,001. Conditional on E<=2,000 (NOT proven for this sampler), dictionary size <=8.22 GB versus the prior looser Run-697 ceiling around 1.052 TB. In worst case the fallback may still be hundreds of GB. Neither a cryptographic security parameter nor practical setup/recovery is established.

## Integration and precise unresolved gap

Setup: classical Run-698 source-covered, privately generated K and intended native key in an assumed honest-erasure N-of-N setup (not implemented); publish exact equivalent codec, full native pk and bound context. Encode: valid ORIGINAL witness -> actually accepted complete SOURCE z (not automatically an inner proof). Recover: public dictionary operator -> unchanged Run-696 cofactor-free Krylov/Berlekamp-Massey/Frobenius finite-root procedure and full pk/context filtering -> scoped native signing capability K. All valid SOURCE witnesses retain different matrices but same eigenvalue K, inheriting the prior fixed-valid-witness projection success >=(1-1/q)^2 when native checking-key uniqueness holds.

Historical exact dependencies: Run 593 gate 29b9168bfff6043810284cd1960400579f224e31; Run 695 spectral 50174666730b93bd20f83bb29ddb2c355ccf1a91; Run 696 Krylov e37f51a69c3ca68d584d0b2e0f18b71e876bf217; Run 697 sparse 736d8d961f06cc0b26745c27a174d21dc486190b; Run 698 source-cover 2e93bc9a71f2a4caa6b172ec7bcd940b199243cc. Run 259 historical SOURCE=>ORIGINAL c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2 applies only AFTER accepted SOURCE.

**UNPROVED:** full-public-output false-instance QPT security; arbitrary unauthorized true-instance recovery or accepted native forgery -> accepted SOURCE or independent QPT break; source interface; malicious N-of-N setup/abort; related-statement composition; covenant graph; hypothetical P2MR/native SLH endpoint. Security is NOT inferred from the codec or passing tests.

**Next candidate task:** design independently secure opaque public-source direction carrier retaining the same all-witness spectral rank and black-box evaluator, or repair the current carrier with a concrete QPT reduction; the public direction dictionary by itself may expose pre-existing leakage. No production/workflow edits, PR stays draft, no completion claim.
