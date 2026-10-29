# Restricted dual-LWE SOURCE: adaptive adversarial related-capsule oracle

**Outcome: positive restricted full-joint-public composition lemma, NOT generic-NP witness-KEM.** The existing dual-LWE short-preimage SOURCE gains an explicit adaptive chosen-related-capsule simulator, including public source correlations that the predecessor did not claim. The arbitrary-ORIGINAL-NP witness-free compiler, fixed-false security, and recovery-to-ORIGINAL-witness reduction remain UNPROVED.

## Provenance and exact predecessor

Offline 2026-10-28 research iteration, descriptive marker \`constructive-pq-wkem-20261028-2240-PDT\` (no independent scheduler UUID provided). Repository \`syscoin/PVUGC\`, draft/open/unmerged PR #1, existing branch \`research/pq-wkem-validation-20260918\`, starting head \`29afd8806af76b985fa6de277233cee8d05d24a3\`. Latest ordinary substantive comment \`6488827853\`. Exact starting-version file read: \`research/pq-wkem/dual_lwe_short_preimage_20261028/RESEARCH.md\` blob \`d702c096ff2bc227629ca7d8f2ee9f5e27199f42\`. No external literature or web research.

The preceding planted-TRUE SOURCE already provided correctness for distinct bounded-L1 short-preimage witnesses and a QPT decisional-LWE/native-signature reduction, but its related capsules were described as independently simulatable, honestly generated siblings. Here an attacker may choose arbitrary related SOURCE matrices as functions of the complete target public transcript, even choosing the identical matrix, and obtain complete related plaintexts, native signing secrets, shares, and encryption coins. No SOURCE opening oracle is introduced.

## Honest target algorithms and distributions

Let q be odd prime, m>n, d,t,h,kappa positive, 2h<q, g=2h+3<q, radix T=floor(q/g)>=2, ell=ceil(log_T(2^kappa)), L=ceil(ell/d), chi uniform independent ternary errors {-1,0,1}. Signed L1 sphere S(m,h) has cardinality

N(m,h) = sum_{k=1}^{min(m,h)} 2^k binom(m,k) binom(h-1,k-1).

Honest restricted planted target: A <- uniform F_q^(n x m), columns Z_j <- independently uniform S(m,h), U_T=A Z. Build receives only A,U_T and does not know Z. This is a restricted SHORT-PREIMAGE relation, not an arbitrary ORIGINAL verifier and not authenticated future Bitcoin data. The source generator DOES know planted Z: no future-fork/source-creator non-bypass claim follows.

Let K_T be the precommitted native PQ signing capability (e.g. a private-key seed from which the native signing keypair is deterministically derived), and pk_T its genuine native verification key. Generate independent uniform kappa-bit U0 and t XOR shares z_i. Publish D=U0 xor XOR_i z_i, V=K_T xor U0, with typed binding to ORIGINAL relation identity, claim/UTXO, branch, anchors/window, context and native intended-path verification key. For each share and each padded d-radix-digit batch a, independently sample s <- uniform F_q^n, e <- chi^m, epsilon <- chi^d. Public ciphertext:

c = A^T s + e;    v = U_T^T s + epsilon + g a       (mod q).

All target and related Build and Release computation is classical PPT. All ORIGINAL witness verification and large evidence are off-chain; no Bitcoin-side NP verifier or new opcode is assumed.

Every valid restricted ORIGINAL source witness W with A W=U_T (mod q), ||W_j||_1<=h and proper claim/context bindings recovers

v - W^T c = g a + epsilon - W^T e (mod q).

The coordinate error has absolute magnitude <=h+1; distinct cyclic radix centers are separated by >=2h+3. Thus EVERY valid W, including different ones with different intermediate states, recovers precisely the SAME precommitted K_T. This is a restricted relation and does not turn arbitrary Bitcoin evidence into a source opening.

## New adaptive chosen-related-capsule service

An arbitrary QPT adversary receives the complete public target statement/source, genuine pk_T, D,V, target ciphertexts, public context and permitted preparable auxiliary data. It may interleave polynomially many CLASSICAL \`Related(U_j,claim_j,K_j,mode_j)\` queries with at most t-1 whole target-share openings (including their full coins) and classical target signing queries on nonchallenge messages. On a Related request:

1. U_j is any adversary-selected n-by-d field matrix. It may equal U_T, have no bounded short preimage, or be an adaptive function of ANY earlier public target/related data and opened shares. Neither Build nor the simulator requests or knows a witness for U_j.
2. K_j may be adversary-chosen (and hence known) or independently honestly generated and then disclosed; pk_j must differ from the protected pk_T. Requests whose native pk matches pk_T are rejected. All sibling authorizations/claims have their own explicit path/context identifiers. The oracle NEVER supplies or encrypts the unknown protected K_T, target source witness, target hidden share, or target coins.
3. The service generates a genuine pk_j, independently fresh XOR shares, pads and EVERY batch coin (s,e,epsilon), and builds the sibling ciphertexts using the SAME public A and the attacker-selected U_j. It can return all sibling signing keys, shares, masks and coins, or disclose them later. Every disclosed coin set exactly replays its published ciphertext. There is NO target decryption oracle.

This service even allows arbitrarily correlated source matrices and full known-coin/known-plaintext ciphertexts under exactly U_T. Correlation through public fields is allowed. Sharing the protected target SIGNING SECRET or target encryption coins is NOT allowed. The full public view includes R,x,claim/UTXO,branch,context,anchors/window,A,U_T,pk_T,D,V,all target ciphertexts,all U_j,pk_j,ciphertexts and selectively disclosed sibling/target data and QPT adversary workspace.

The adversary can coherently process all classical public registers and carry quantum memory across queries. Sign/Related/Open interfaces are CLASSICAL, not quantum-superposition oracles. Initial quantum advice must be efficiently preparable without the hidden planted target Z, unknown protected K_T or other secret-correlated input. Malicious arbitrary target setup and source-witness-correlated auxiliary advice are excluded.

## Exact full-public QPT statistical and computational hybrids

Because 2h<q, for distinct z,z' in S(m,h), A(z-z') is uniform F_q^n for random uniform A. Collision counting and Cauchy-Schwarz give, for delta_src=0.5 sqrt((q^n-1)/N(m,h)):

TV[(A,A Z),(A,U_uniform)] <= d delta_src.

This is a bound averaged over honest A, not a guarantee for each fixed malicious A.

**New proof step:** Given the public target SOURCE register (A,U_T), genuine native target Build plus the ENTIRE adaptive Related/target Open/signing transcript is a channel requiring no hidden target Z: every Related response is computed using public A, adversary-selected U_j, known freshly sampled/supplied K_j and fresh known coins. It remains such a channel even when the adversary chooses U_j after quantum computation on prior registers. The entire interactive execution is a CPTP map from the classical source plus independent challenge-preparable advice to the final quantum state. Trace-distance contractivity shows that substituting planted target U_T with uniform U_T changes arbitrary QPT winning probability by <=d delta_src. The number M of adversarial Related queries contributes NO M multiplier. This is a selected single-target theorem, not simultaneous protection of M unknown targets.

In the uniform-target-source game, H=[A^T ; U_T^T] in F_q^((m+d) x n) is exactly uniform. After subtracting known plaintext shift ga, each target ciphertext batch equals y=H s+nu, with uniform s and independent chi^(m+d) nu. This is exactly the ordinary uniform-secret small-noise decisional-LWE experiment, not a marginal pad claim or SourceOpen oracle. Guess one survivor target share J uniformly; abort if the adversary opens J. Replace its L ciphertext batches by uniform one at a time using a REAL ordinary QPT DecLWE challenge (H,y), generating all other batches honestly. Every adversarial Related query is simulated EXACTLY with public H, its chosen U_j and fresh known coins, even after the challenge sample is shown. Thus there is an L times ordinary QPT decisional-LWE hybrid cost, but no M cost and no challenge secret access. The J guess costs a factor t.

When J ciphertexts are uniform, J's hidden share remains an independent one-time pad despite all other target whole-share/coin openings and any sibling disclosures. For fixed unknown protected K_T and the other shares, the map from independent (U0,z_J) to public (V,D) is bijective. A target native EUF-CMA simulator can therefore use its challenger pk_T without knowing K_T, choose D,V uniformly, simulate all non-J target coins and every related capsule exactly, and forward allowed classical signing queries. A recovered usable protected K_T yields a fresh intended-path native signature; a direct valid fresh native signature already wins EUF-CMA. No adversary-volunteered representation, classical rewinding, random-oracle extraction or quantum lifting is used.

For one honest planted target with polynomially many adaptively malicious public-source related capsules, the previous bound is **unchanged**:

Pr[unauthorized protected K_T recovery OR fresh native intended-path forgery]
 <= t [ d delta_src + L Adv_QPT-DecLWE(n,q,m+d,chi) + Adv_QPT-native-EUF-CMA ].

This depends on exact QPT decisional-LWE hardness for the stipulated distribution and separately native QPT EUF-CMA security, classical oracle interfaces, challenge-preparable quantum advice, no leaked target SOURCE opening, no target last-share disclosure, no adversarial oracle for the unknown protected key, no target native pk collision and honest target setup. The reduction is straight-line, and related-capsule simulation is not an extra assumption. No concrete QPT parameter estimate is certified.

## Executed tests and finite verification

The exact committed \`check.js\` is the same JS checker function executed in the connected local JS runtime and its stdout is preserved. The separately developed LOCAL-ONLY standard-library Python checker in the downloadable companion archive was run twice identically: **6437 assertions per run**, 30 complete target 32-bit MOCK capability recoveries with two distinct accepted short-source witnesses (a deliberately duplicate-column A for correctness only), 180 adaptively chosen arbitrary-U related capsules including identical target U, zero U and chosen native keys, and exact replay of disclosed encryption coins. This toy target is intentionally NOT a hard LWE instance or native SLH signature.

The Python checker exhaustively computed q=3,n=1,m=2,h=1 planted-vs-uniform source TV =8/27. Applying 0,1,2,3,4 adaptively chosen related-source kernels with fresh per-query disclosed coins preserved **exactly the same 8/27** total variation at every step; this tests full-distribution postprocessing, NOT QPT security. Illustrative large source q=65537,n=128,m=1600,d=14,h=800 gives log2[d delta_src] = -358.56093398. Computational DecLWE and native-signature QPT hardness at those numbers are NOT certified.

## Precise mandatory unresolved ORIGINAL-NP equation

Still required is witness-free classical PPT Comp(R,x,claim/UTXO,branch,anchors/window,context,pk)->(A_x,U_x,capsule), and public off-chain Phi(R,x,W), such that for EVERY valid ORIGINAL NP W,

A_x Phi(R,x,W)=U_x mod q,    max_j ||Phi_j||_1<=h,
Release(Phi(R,x,W),capsule)=one SAME precommitted K.

For every FIXED FALSE ORIGINAL x, prove K hiding from the complete checking-key/auxiliary/multiple-capsule view against arbitrary QPT; for arbitrary unauthorized HARD-TRUE final-key recovery or native forgery, reduce to an ACTUAL ORIGINAL W or independently justified QPT break. Accepted SOURCE representation->ORIGINAL witness is distinct and insufficient. The earlier 3CNF/two-tier public pseudo-moment attacks remain fatal; the present planted source creator already knows a bypass preimage, so no authentic future Bitcoin fork challenge follows.

Other open items: malicious N-of-N preauthorization/erasure and graph non-bypass, optional keyless Build under retained builder coins, prefunding abort and DA, challenge inclusion and witness timing, complete SYS/BTC AuxPoW/coinbase/Merkle/ancestor/window authentication with actual Bitcoin best-chain and censorship assumptions, and a hypothetical native no-EC-key-path PQ Bitcoin output. No deployment is claimed. Continue existing research automation; do NOT disable it.
