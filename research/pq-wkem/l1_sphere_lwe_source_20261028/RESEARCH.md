# Bounded-L1-sphere LWE SOURCE: exact entropy improvement and shorter capability capsules

Research record: l1-sphere-lwe-source-20261028-turn11. Offline only. Authorized syscoin/PVUGC draft/open PR #1, branch research/pq-wkem-validation-20260918; starting head 63e0a96ddf4c42114d07f385a61106c3b2815ba3. Exact predecessor: research/pq-wkem/lwe_syndrome_source_20261028/RESEARCH.md (blob 08e0bde55d4db739baae3a3ced412a570ffa59a0), checker blob dab84be0117b348a52ecc148e42b0d6637c91fa7, latest substantive ordinary comment 6480366369.

## New constructive delta and exact scope

This is a strictly improved implementation of the *restricted* LWE-ORIGINAL source-release component, not generic-NP witness-KEM, not an independent 128-bit QPT hardness assessment, and not a generic recovery-to-ORIGINAL-witness theorem. We replace independent ternary encryption randomness r with a **classical PPT, exact uniform sampler over signed integer vectors of fixed L1 radius h**. The new source has **more exact collision entropy** than the predecessor's complete ternary distribution even though the maximum decryption noise decreases from m=1600 to h=696. A tighter plaintext gap lets 47 rather than 60 ciphertexts carry the same 256-bit mock native signing capability; the complete-public statistical bound improves as well. The public LWE challenge distribution and its QPT assumption are unchanged.

## Statement, genuine Build, every-witness Release

Let q be an odd prime, m>n, public A in F_q^(m x n), b in F_q^m, and typed context C containing ORIGINAL relation identity, UTXO/claim, branch, anchors/window, intended checking key and signature path. The restricted ORIGINAL relation is:

  R_LWE((A,b,C),(s,e)) = [s in F_q^n, e in {-1,0,1}^m, b=As+e mod q, C bound correctly].

True public source T: A uniform, s uniform F_q^n, e independent uniform ternary, b=As+e. Uniform challenge source U: A,b independently uniform. Independently assumed QPT decisional LWE is **exactly T versus U**, with these q,n,m,chi; no unproved classical-to-quantum lift.

Define S(m,h) = {r in Z^m : sum_i |r_i|=h} with 2h<q. Sample fresh independent r_j uniformly from S(m,h). Set g=2h+1, B=floor(q/g)>=2 and ell=ceil(log_B(2^kappa)). Honest classical Build receives public A,b,C, **not** s,e. Generate real native signing seed K, real native checking key pk(K), uniform independent kappa-bit U0,Z, public D=U0 XOR Z and V=K XOR U0; encode Z to ell radix-B digits a_j, padded. For each j publish complete ciphertext vector

  c_j = A^T r_j mod q,    d_j = b^T r_j + g*a_j mod q.

The full public view is (relation, statement, C, pk(K), D,V, {(c_j,d_j)}, allowed auxiliary data and related capsules). The r_j and K remain secret in Build. The native seed is a **mock 256-bit capability** in tests: a real SLH-like key length and Bitcoin path are conditional and were not implemented.

Off-chain Release first checks **the actual ORIGINAL restricted R_LWE**, then computes for ANY valid ORIGINAL (s,e):

  d_j - s^T c_j = g*a_j + e^T r_j  mod q.

Since |e^T r_j| <= ||e||_infty * ||r_j||_1 <= h < g/2, and all cyclic radix centers g*a are separated by >=g (including the wrap gap q-(B-1)g>=g), nearest-center decoding returns exactly a_j. Thus EVERY valid ORIGINAL witness recovers the identical precommitted Z, and K=V XOR D XOR Z, for every Build randomness outcome, without any canonical or common witness state. This is classical PPT, off-chain; Bitcoin is not asked to evaluate R_LWE or proofs.

## Uniform exact sampler

For h>0 the exact number of vectors is:

  N(m,h) = sum_(k=1)^(min(m,h)) 2^k * C(m,k) * C(h-1,k-1).

Precompute exact big-integer weights w_k=2^k*C(m,k)*C(h-1,k-1). Select k with probability w_k/N using unbiased big-integer sampling; choose k uniform distinct support locations among m; choose k-1 uniformly distinct cut positions among 1,...,h-1 to partition h into k positive parts; choose k independent fair signs. Each integer r with L1=h occurs in exactly one (support,composition,sign) configuration, so each r has probability exactly 1/N. All steps are classical polynomial time, with polynomial-bit integer arithmetic; production needs cryptographic unbiased randomness. The checkers' seeded PRNG is for reproducibility ONLY. The checkers independently establish N by both the binomial sum and coefficients of ((1+x)/(1-x))^m.

## Whole-public information-theoretic bound and QPT hybrid

Let H=[A b] be uniform in F_q^(m x (n+1)), and r uniform on S(m,h). For distinct r,r', their integer difference has at least one nonzero coordinate of absolute value <=2h<q, so H^T(r-r') is uniform in F_q^(n+1). This establishes exact two-universality, not a heuristic:

  E_H Coll(H^T r | H) = 1/N + (1-1/N)/q^(n+1).

Cauchy-Schwarz and Jensen then give the FULL ciphertext vector bound

  TV((H,H^T r),(H,Unif(F_q^(n+1)))) <= delta_h
  delta_h = (1/2)*sqrt((q^(n+1)-1)/N(m,h)).

This is averaged over public uniform H; it is NOT a pointwise guarantee for arbitrary fixed malicious H. Conditional on H, digit shifts d_j += g*a_j and the real pk(K), U0,Z,D,V, typed C and publicly simulatable sibling data, independent fresh columns hybrid one by one with total TV <= ell*delta_h. Given any fixed K, the map (U0,Z)->(D,V) is a bijection, so D,V are independently uniform conditional on the *real* checking key pk(K). With t independent XOR-protected shares, an unopened target share remains uniform conditioned on disclosed other shares; opening the last protected share, secretly correlated auxiliary leaks or another same-key capsule revealing K are EXCLUDED, not silently called secure.

An exact QPT decisional-LWE simulator is given H=(A,b) from T or U without knowing s,e. It constructs **all** actual public source-dependent ciphertexts by sampling the above r_j, real K/pk and XOR shares, C and permitted independently simulatable related capsules and classical opening data. The T branch is genuine Build. In U, replace whole ciphertext vectors by uniform independent vectors (cost ell*delta_h) while retaining all checking-key and share correlations. In that final game a native EUF-CMA challenger pk (with secret K unknown) can be used because public D,V are independent uniform given K, and because permitted unopened-target sibling information can be simulated without K. A recovered usable native signing capability can sign a fresh path message; an accepted fresh intended-path signature directly forges. Therefore for the stated restricted true-distribution game:

  Pr_T[unauthorized K recovery OR fresh native path forgery]
    <= Adv_QPT-DecLWE_(q,n,m,ternary)(B)
      + Adv_QPT-native-EUF-CMA(F) + ell*delta_h.

This is a straight-line QPT reduction, permitting coherent arbitrary internal QPT attacks and independent advice or QPT auxiliary-preparation channels simulatable from public H,pk,C and independent coins. No quantum rewinding, SourceOpen oracle, A-provided representation or classical-hardness lifting. It does NOT handle advice entangled with the hidden LWE secret, target r, true K beyond the specified public correlation, superposition opening or signing queries, arbitrary maliciously correlated sibling capsules, nonfresh pre-signed transaction messages, malicious N-of-N setup or arbitrary fixed false and true statements. Uniform H is a false instance only with high probability under the specified distribution; that is not fixed-false security.

## Exact no-weaker-bound and resource certificate

At q=65537, n=128, m=1600, h=696, kappa=256: g=1393, B=47, ell=47. The old independent uniform ternary r had cardinality 3^1600, worst-case L1=1600, g_old=3201, radix 20, ell_old=60. Both executed checkers establish by EXACT INTEGER arithmetic:

  N(1600,696) > 3^1600,
  (47^2)*(3^1600) < (60^2)*N(1600,696).

Thus the new complete-capsule TV upper bound is strictly smaller **for the same q,n,m and unchanged QPT-LWE game**. Reporting-only logarithms: old log2(60*delta_old) = -231.061690; new log2(47*delta_h) = -235.967427. This is a statistical extractor bound, **not calibrated 128-bit quantum LWE hardness**. Entropy logs: old 2535.940001, new 2545.046872 bits.

The target capsule uses 47*(128+1)=6063 field elements vs 60*129=7740 (21.67% less); packed 17-bit estimate 12,884 vs 16,448 bytes. Public A is unchanged at 204,800 field elements. Expected nonzero r coordinates ≈551.357. Correcting for larger integer coefficients, a **straightforward signed repeated-row-addition** implementation performs exactly 47*696=32,712 signed row contributions vs old expected 60*(2*1600/3)=64,000 when ternary zeros are skipped: 48.9% fewer in that explicit cost model. Scalar multiplications, exact sampler costs and real hardware timing are not benchmarked.

## Executed checks and explicit gap

The independently written JS checker here ran twice with byte-identical output and 40 exact checks, including a 1600x696 generating-function integer DP, complete-column bound comparison, small-norm enumeration and exhaustive 343-matrix small-field collision enumeration. A separately executed local Python checker ran twice with identical output, 1,932 checks, exact support/composition sampling proof checks, finite whole-vector collision counts, all-digit toy two-witness release, and four 256-bit mock full-key recoveries from two distinct valid ORIGINAL LWE witnesses at actual dimensions. The latter uses a deliberately degenerate A only to produce two witnesses for correctness testing, **not** as a hard LWE challenge. These are finite algebra checks, not native-SLH or QPT-hardness experiments. Complete extended Python code and outputs are preserved separately in the downloadable offline research archive.

**Next exact missing equations:** construct a witness-FREE public polynomial compiler Comp(R,x,C)->(A_x,b_x,source) for arbitrary ORIGINAL NP such that for EVERY valid ORIGINAL W, public Open_x(W) outputs (s_W,e_W) satisfying b_x=A_x*s_W+e_W with bounded e_W, all W recover the same bound K, and the full-public TRUE and FALSE distributions admit independent QPT-simulatable hardness reductions. Show any arbitrary unauthorized true-instance capability recovery or native forgery gives an ACTUAL ORIGINAL W or independent QPT break, without demanding an internal representation. Adding unrelated LWE keys does not tie s/e to W. Directly substituting verifier-moment matrices for A forfeits the ordinary-LWE distribution and may expose non-Boolean pseudowitness openings. None of these missing generic equations was solved by the present optimization. Malicious N-of-N preauthorization, abort, erasure, DA, graph, SYS/BTC interval-tag/headers/fork-window validity and conditional PQ-only BTC transaction semantics also remain open. Keep the existing research automation active.
