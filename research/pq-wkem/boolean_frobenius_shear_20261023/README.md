# Boolean–Frobenius sheared 4×4 sampled-QAP release carrier (23 October 2026)

**Constructive result, not a secure PQ WKEM.** This checkpoint follows exactly the open/draft PR #1 head b3a9b5b43c3d1b7b91e72116ea4b073b3e4581fc and predecessor research/pq-wkem/robust_distance_20261023/ROBUST_DISTANCE_RANK_SELECTION.md (Git blob 0f3eccd2dbddcf363099028db98d5b041478adff). The predecessor used private-affine paired 8×8 gates, honest rank 4, violated rank 8, N=4L+h, and proved only supplied-pair -> ORIGINAL-witness extraction.

The new gate is a **4×4, source-linear Boolean–Frobenius private-affine shear**. For normalized y=(1,w,rho), at every sampled QAP node retain the original public linear forms a,b,c,d=z0,s and residual t=ab+dc+s². Independently choose private field elements gamma, alpha_i and define two LINEAR source forms eta(y)=gamma*z0+sum_i alpha_i*w_i and beta(y)=gamma²*z0+sum_i alpha_i²*w_i. Put
```
G(y) =
[   0      a       d      s+eta ]
[   a      0     s+eta   c+beta ]
[   d    s+eta     0        b   ]
[ s+eta  c+beta    b        0   ]
```
The exact Pfaffian identity over GF(2^kappa) is
```
pf(G(y)) = t(y) + sum_i alpha_i² * (w_i²+w_i)   [y0=1].
```
For EVERY valid ORIGINAL Boolean witness, the second term vanishes identically, and each satisfied gate has rank 2; distinct witnesses retain distinct source/matrix states yet all recover the same field capability K. No canonical witness, added variable, or extra coefficient matrix is needed. The gate arises by an explicit determinant-one y-dependent reversible local congruence of the predecessor's 4×4 alternating gate when w is Boolean.

For any fixed normalized NONBOOLEAN source, at least one w_i²+w_i is nonzero. In characteristic two alpha_i -> alpha_i² is a permutation; independent node masks therefore make all node Pfaffians independent uniform field elements even after conditioning on the public QAP forms. Union over every normalized source gives a SIMULTANEOUS honest-setup guarantee that any nonboolean input violates at least T gates, with error <= T*binom(L,T-1)*q^(k+T-L-2), where k=n+m. For Boolean invalid sources reuse the prior exact sampled-QAP robust-distance event. Set D=2L, N=D+h, h<=T, U_e uniform N×4, V_e uniform 4×N and publish all k full coefficient matrices C_j=[j=0]K I_N+sum_e U_e G_e(e_j)V_e, all source/QAP parameters, exact claim binding, and full native checking key. For every fixed source the mixed distribution is uniform A_R B_R of rank factor size R=2L+2v(y). Existing full-public simultaneous rank bounds apply with v>=T, R>=N+h. Every normalized **supplied pair** (lambda,y) passing rank(C(y)-lambda I)<=2L has lambda=K and projects to an ORIGINAL witness except with sum of the four explicit setup error bounds in the full proof.

An illustrative exact-integer certificate at q=2^256, n=11000, m=16000 uses r=11816, L=27815, T=h=165, N=55795 and bounds each of four *semantic supplied-pair* failure terms below 2^-133. Storage k*N²*32 = 2.6897028696 decimal PB, versus 10.6578151704 PB before (**74.7630933% smaller**). It remains impractically enormous.

**Reproducible FULL source bundle:** `SOURCE_BUNDLE.tar.xz` is a byte-exact, independently Git-blob-hash-checked XZ TAR of the files below, committed beside this README. Extract with `tar -xJf SOURCE_BUNDLE.tar.xz` (no network or setup scripts); execute `OPENBLAS_NUM_THREADS=1 python boolean_shear_check.py > out.json` and byte-compare `out.json` with `validation.json`. Python 3 + NumPy required. Exact 2-run output: 12,777 assertions, 3 independent deterministic GF(16) fixture seeds, 12,288 public candidate-key/source checks, distinct true witnesses, explicit local Pfaffian/congruence and large exact-integer bounds. Toy seeds are NOT cryptographically secure.

Bundle SHA-256: 288c4841f450e1d5e89981c47b976cde3059b7f67fedfc4390f3c42bdcf13b50; Git blob: 6bef29d8f5c6c2f1d5e101f66779846fb88895cc.
Individual exact payload SHA-256:
- BOOLEAN_FROBENIUS_SHEAR.md: 84ad95633dbb611cc1c6570ea95cff0c163d573f5ebb380a419a96a08c30e769
- boolean_shear_check.py: 7193799a3111c2640a5ee49adcc9f51447b885636df440438adf2db3cf386099
- validation.json: 0d11b2f82ef9ae179cead86477574e0b334e96cf846aa1256c18e52b8997e34c
- PROVENANCE.json: ed1cf87ef11a1f38139e2c36531e5c71579b1ea38380248a0b46989777e81bfb

**Explicit non-results.** This does NOT prove key-only recovery -> accepted representation, native accepted forgery -> ORIGINAL witness, full-public-output QPT hiding or false-instance secrecy, quantum multi-capsule/auxiliary-input security, malicious retained-coin setup and abort, a usable 1-of-N BTC challenge graph or practical overhead. The four-moment attack against an earlier carrier is not thereby ruled out against this new tensor. Continue constructively at the full-public tensor arbitrary-recovery-to-ORIGINAL/QPT reduction, and preserve the earlier exact supplied-pair proofs. No production changes or claims of native Bitcoin P2MR/SLH deployment.
