# Cumulative spectral WKEM construction — Run 706

Actual checked PR head at start: 0919b22fd91c973e5088e1ff61b53da11f856493, open/draft/unmerged. Reuses Run 701 typed source, Run 704 exact false-shield, Run 705 tag QROM composition, Run 696 cofactor-free spectral decoder, Run 703 local-only SLH native exact-key adapter, Run 259 ORIGINAL-SOURCE extraction.

Build: x scopes relation, claim UTXO, branch and anchors/window. N=2bm+s. Public C(y)=K I+M(y)+sum r_i(y) Q_i(y) includes complete aggregate polynomial coefficient array, native pk/tag and decoder; Q_i secret with fresh independently uniform full-matrix constant terms, M private L/R factors independent of K and Q_i. Actual N-of-N setup remains unimplemented.

Encode: w ORIGINAL -> complete accepted SOURCE y; residuals vanish and rank(C(y)-K I)<=N-s for every w simultaneously, with witness-dependent M(y). Recover: unchanged Run 696 eigenvalue decoder, exact native tag selecting B, sign transaction offline (Bitcoin endpoint conditional). Extract: any supplied (y,alpha) satisfying rank(C(y)-alpha I)<=N-s produces accepted SOURCE except setup probability <=c_(q,s)q^(n+1-s^2), for ANY field alpha, then Run 701/259 yields ORIGINAL witness. No SIS assumption is required for this downstream supplied-pair guarantee.

Proved: whole-public-ciphertext false-instance hiding remains valid on Run 704 unit-certificate subclass; new adaptive any-scalar SOURCE rank soundness holds with independent full uniform residual matrices. Exact Python integration 1,426 assertions; published compact Node census 39,370 assertions. Independent PQ release security has NOT been proved.

UNSOLVED: from arbitrary hard-TRUE B recovery or native forgery to any supplied (y,alpha); QPT hiding of spectral carrier on hard TRUE; polynomial-size all-false mask identities; public storage; native Bitcoin/P2MR/SLH rules; Syscoin fork evidence circuit; malicious N-of-N setup, abort, multi-TRUE capsules, 128-bit security. Do not claim key-only extraction from this source-binding proof.
