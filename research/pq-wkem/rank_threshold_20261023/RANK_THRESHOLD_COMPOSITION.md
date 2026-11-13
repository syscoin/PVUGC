# Paired sampled-QAP: global rank-threshold acceptance and ORIGINAL-source lift

Checkpoint: 2026-10-23. STATUS: PROVED SUPPLIED-REPRESENTATION INTERFACE; NOT A KEY-HIDING OR PRACTICAL PQ WKEM.

## Dependencies and constructive change

Verified PR syscoin/PVUGC#1 at open/draft head ef33ef4be94d46807b7be30acc42bf3d1a89c060, branch research/pq-wkem-validation-20260918. Exact previous Frobenius-QAP compiler: research/pq-wkem/qap_frobenius_projective_20261022/frobenius_qap.py, Git blob d5b35ae77076e0e6bbf927a41b819130ac84fead and SHA256 6da9e9519c1f9b21d00b736679ba498cb56a7518e9610abc7934ec3aacf66d9a. Exact sampled SOURCE compiler: research/pq-wkem/sampled_frobenius_qap_20261023/sampled_qap.py, blob 3c568a1035865a20a98a271fd1d9c186db20c755. Prior private-affine paired-gate/sampled integration: local-only paired_sampled_integration_20261023.zip; it proved honest all-witness same-K correctness, not key secrecy. The previously published four-moment QAP subpencil is classically key recoverable. This result does not silently repair that leak or prove that the paired carrier is secure.

NEW: keep the same paired 8x8 local gates but use N=4L+h rather than 4L+1, and require a public rank-threshold check, not merely an eigenvalue hit. This supplies a simultaneous, setup-statistical theorem: every normalized publicly supplied representation which passes the correct-K rank threshold projects to an ORIGINAL valid witness, including when chosen after examining the entire public tensor and native verification key. The key-only / native-forgery -> supplied-representation implication remains unproved.

## Algorithms, complete public output and honest model

Fix field F=GF(q), q=2^kappa, a complete, bound original R1CS statement x containing relation identity, UTXO, claim/path, BTC/SYS anchors, observation window, intended native verifying key, epoch and replay context. There are m R1CS rows and n original free coordinates, with explicit Booleanity. The exact prior compiler interpolates A_z(T), B_z(T), C_z(T) and a Frobenius quotient H_rho(T) from y=(z0,w,rho) with k=n+m homogeneous source coordinates. After binding the complete relation, honestly sample r fresh distinct off-domain tail nodes and keep m-1 fixed nodes; total L=m-1+r. Each node has five linear forms f_e(y)=(a,b,c,d,s), with d=z0 and residue t_e(y)=ab+cd+s^2.

Define over characteristic two:

P(a,b,c,d,s) =
 [ [0,a,d,s], [a,0,s,c], [d,s,0,b], [s,c,b,0] ].
Pstar(a,b,c,d,s) =
 [ [0,b,c,s], [b,0,s,d], [c,s,0,a], [s,d,a,0] ].
G_e(y) = [ [P(f_e(y)), eta_e(y)*I4], [0, Pstar(f_e(y))] ],
eta_e(y)=sum_j eta_ej*y_j.

Set D=4L, choose h>=4, N=D+h. Setup picks independent uniform secret U_e in F^(N x 8), V_e in F^(8 x N), eta_ej in F and a claim-specific secret capability K; it publishes EVERY coefficient C_j = 1[j=0]*K*I_N + sum_e U_e G_e(e_j) V_e, every relation/source parameter, all node locations, all context/graph bindings, the complete native verification key or independently justified key selector, and the applicable setup transcript. These are full-public-output games; no hidden checking-key omission or private public-evaluation oracle is allowed. The N-of-N ceremony must protect/erase seeds, factors and native signing secrets; malicious seed choice, abort fairness and retained-coin/keyless security remain UNPROVED. The toy RNG is not a CSPRNG. This construction is not deployed on Bitcoin or Syscoin.

Encode(w): given any valid ORIGINAL witness, normalize z0=1, compute the exact quotient of A_z*B_z + C_z by the vanishing polynomial Z, square-root its coefficients into rho, and return y=(1,w,rho). Different valid w may retain different intermediate states.

Recover(w): evaluate the ordinary public coefficient sum C(y), compute field eigenvalue candidates by polynomial-time finite-field methods, retain a candidate lambda only if its public native checking key equals the intended key AND rank(C(y)-lambda I_N)<=D, and return the corresponding native seed/capability. Every valid w recovers the SAME K. Root enumeration is over polynomial roots, not a brute force of all q keys. The synthetic checker uses a toy field and key candidate, NOT a native SLH signing API.

SuppliedExtract(y,K): require y0=1, verify the above rank threshold for the intended K, normalize the ORIGINAL coordinates, and return w. The theorem below guarantees R(x,w)=1 on an overwhelmingly likely honest setup event. This algorithm needs y; it is not an extractor from arbitrary recovered K or a native signature alone.

## Full simultaneous rank theorem, without a new assumption

Because P*Pstar=Pstar*P=t_e I4, a valid node with t_e=0, d=z0=1 and hence P != 0 has rank(G_e)=4 for any eta_e. An invalid node with t_e!=0 has rank(G_e)=8. Thus for every fixed normalized y the block-diagonal local operator has exact rank R_y=D+4*v(y), where v(y) is the number of violated off-domain checks. If v=0, its random two-sided outer projection M(y)=C(y)-KI always has rank <=D: perfect honest rank correctness.

Suppose v>=1. Then R_y>=R0=D+4, and N=D+h>=R0. For fixed y, invertible factorization of the local block diagonal matrix and independence/full uniformity of all U_e,V_e imply M(y) has exactly the distribution of A_R B_R for independent uniform A_R in F^(N x R), B_R in F^(R x N), with R=R_y. The rank of this product is stochastically nondecreasing in R: append independent columns to A, condition on rank(A)=s, observe that AB has the distribution of a full-uniform s x N matrix, whose rank only stochastically increases as s increases. Therefore the worst rank-failure probability occurs at R0.

For R0=D+4<=N, define delta_A=R0-rank(A_R0) and delta_B=R0-rank(B_R0). Sylvester gives rank(A_R0*B_R0)>=R0-delta_A-delta_B. Hence rank(M)<=D requires delta_A+delta_B>=4.

For an N x R0 uniform matrix, the union bound over a-dimensional kernel subspaces proves for a>=1:
Pr[delta>=a] <= gamma_q*q^(-a*(N-R0+a)),
where gamma_q=product_(j>=1)(1-q^-j)^-1<4 for q>=2. (An a-subspace count is <=gamma_q*q^(a*(R0-a)); forcing it into the kernel costs q^(-Na).) The same bound applies to the transposed R0 x N matrix. Union over a=0,...,4 and independence yields EXACTLY the usable upper estimate:
Pr[rank(M(y))<=D | v(y)>=1]
 <= 8*q^(-4h)+32*q^(-(4h-6))+16*q^(-(4h-8))
 < 56*q^(-(4h-8)).                       (1)
Here the two extreme terms have only one nontrivial factor, while the three interior terms have two.

There are exactly q^(k-1) normalized y with y0=1. Union over ALL y, regardless of adaptive selection or access to full public coefficients/auxiliary/checking key, gives
epsilon_outer <= 56*q^(k+7-4h).          (2)
The resulting GoodOuter event is a PROPERTY OF SETUP and covers arbitrary later classical or quantum processing of the complete public data when the adversary eventually supplies a classical y. It does not depend on QROM extraction, rewinding, or a computational assumption.

The exact predecessor GoodNodes sampling theorem establishes (for a complete relation committed before fresh nodes were sampled) that every normalized all-zero-residual y comes from an ORIGINAL witness except with
epsilon_source <= ((q^(n+1)-1)/(q-1)) * product_(j=1)^r ((m-1)/(q-2m+2-j)).
Union of these two failure events establishes the claimed supplied-representation -> ORIGINAL extraction for ALL y with total probability error at most epsilon_source+epsilon_outer. There is no theorem deriving y from K or a native signature. A validating key match does not magically extract an ORIGINAL witness, and rank-check failure does not imply K is hidden.

## Reproducible parameters, security scope and costs

Exact illustrative values: q=2^256, n=11000, m=16000, r=11636, L=27635, k=n+m=27000, D=110540, h=6752, N=117292. The companion executable computes, using only integer arithmetic, that
2^129 * ((q^(n+1)-1)/(q-1)) * (m-1)^r < (q-2m+2-r)^r,
so epsilon_source<2^-129. Equation (2) evaluates to 56*2^-256<2^-129. Hence their SUM is <2^-128 as an HONEST-SETUP SOURCE/REPRESENTATION theorem, NOT 128-bit quantum capability secrecy.

Full dense package: k*N^2 = 371450158128000 field elements = 11.886405060096 decimal PB at 32 bytes/element, excluding native proof/graph costs. This is 12.5875% larger than the prior paired package and remains impractical. It is a clear security-interface strengthening with an honest and substantial overhead, not an efficiency result.

Companion executed rank_threshold_check.py is standalone NumPy/Python over GF(16), synthetic 3-node (k=3) two-witness local relation, h=4,N=16,D=12, exhaustive 256 normalized y, three independent fixture seeds. All six witness evaluations had rank 12; 762 invalid evaluations failed the rank threshold. Captured validation.json reports 1034 assertions; twice-repeated executions were byte identical. Exact checker SHA256 8c2d02afe8234ecfd4f29fc4c95318bae5ca202c4a56a1d13c10d768e65ca664 and validation SHA256 4be970391162da6dab0cec611867327925b30bcb7ba2443c22998b7499333218. This toy is not the exact SOURCE QAP, a 128-bit instance or an empirical secrecy claim. The theorem, not absence of fixture failures, supports the result.

## Remaining explicit security obligations

Arbitrary unauthorized QPT K recovery OR a native accepted signature forgery -> supplied rank-accepted y OR an independently motivated QPT-hardness break: UNPROVED. False-instance full-tensor QPT hiding including correlated checking key, quantum advice, multiple capsules, cross-UTXO context, coherent attacks and malicious/biasable setup: UNPROVED. Distinguish the supplied ORIGINAL lift above from the scoped Run259 SIS/source-binding proof: that older result cannot be applied to an arbitrary K-only attacker absent a supplied accepted representation. Bitcoin P2MR-like and native SLH signing are conditional hypotheses, not deployed primitives; covenant funding graph, pre-signatures and abort security need independent proofs. No global key privacy, practical parameterization, no trustless/keyless builder, and no automatic automation disablement are claimed. Production/workflows/PR state remain unchanged.
