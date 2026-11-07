# Native-key-checked bounded-list LWE reference release (2026-10-27)

**Research-only, NOT a practical generic-NP or Bitcoin/Syscoin witness-KEM.** New algorithmic component: list-decode the nondivisor-radix transverse-LWE release against its ALREADY-PUBLIC native signing checking key. Unlike independent nearest-digit decoding, this tolerates up to a bounded number of incorrect digit decisions without adding a key digest, public hint or supplementary LWE assumption.

Pinned exact predecessor: syscoin/PVUGC PR #1 commit a906fb4201b93905c15dbdddf406a0e2b064d63e, research/pq-wkem/nondivisor_radix_lwe_20261027/PROOF.md, blob f2c8aafee7a5b625ccee544cd2fe840f864d35d5. Pinned Gaussian/kernel certificate: commit bc7bec84ef2dd73933821566589e020c7547b80e, research/pq-wkem/random_kernel_filtered_gaussian_20261027/PROOF.md, blob 6b39e9d9093fd07adcbeca98887ce8b2e90ab8b8.

## Full public setup and actual release algorithm

Let q=2^a, and n,d,h,k positive, with integer g divisible by h, c=g/h, c*n<q, m=floor(q/g)>=2, ell=min{e:m^e>=2^k}. Select honest uniform native master seed K in {0,1}^k, derive its real deterministic native secret and pk(K), and bind the intended signing path and claim/UTXO/branch/context. Draw independently uniform U,Z in {0,1}^k, set V=K xor U and D=U xor Z. Encode the exact uniform Z into correlated radix-m digits t_0...t_(ell-1), with Z=sum_j t_j*m^j.

Select **unplanted uniform** B in Z_q^(d x n), independent of all key/pad/noise coins. The actual reference relation is R_card(B,w)=[w binary, weight(w)=h, B*w=0 mod q]. Define alpha=c*1_n, A_1=alpha, A_(i+1)=B_i+b'_(i+1)*alpha, b=g*b', with b' public, first coordinate 1, and other coordinates depending only on pk/claim/context. Because c*n<q, binary A*w=b is exactly R_card. This source is NOT arbitrary ORIGINAL NP or SYS/BTC chain evidence.

For each j sample independent u_j uniform Z_q^d and e_j from chi^n, where chi is the exact pinned strict-PPT finite-dyadic Gaussian approximation (T=56, P=320, centered sigma=16/5 in the illustrative instance). Publish p_j=alpha*t_j+B^T*u_j+e_j mod q. Independently create the predecessor's actual physical Fourier/polar arbitrary-ORIGINAL-NP capsule F for V, using its real dither and masks. Full public view is x, relation identity, claim/UTXO/burn authorization/output, branch, anchors/window and intended native path, B,A,b,alpha,g,m,ell, all p_j,D,F, REAL pk(K), all declared simulatable auxiliary context and independently keyed related capsules. No future witness, planted B, SOURCE opening oracle or online release authority is assumed. The baseline N-of-N honest-erasure setup is not a proven malicious-ceremony/keyless-Build scheme.

For any accepted reference w, y_j=w^T*p_j=g*t_j+E_(w,j) mod q, where E_(w,j)=sum_{i:w_i=1}e_(j,i). Find the nearest cyclic codepoint index a_j among {0,g,...,(m-1)g}, tie broken toward the smallest index. Only clamped floor(y_j/g), successor, zero and m-1 need examination. Enumerate candidate digit vectors by choosing s positions (s=0..tau), and changing each chosen a_j by +1 or -1 **cyclically modulo m**. For every candidate reconstruct Z'=sum_j a'_j*m^j; reject Z'>=2^k. Given V recovered by a valid ORIGINAL-NP witness, form K'=V xor D xor Z'. Rebuild the native key and accept only candidates whose *real* native public verification key is the precommitted pk and whose signer can produce an ordinary valid intended-path signature off chain. Enumerate increasing s and stop at the first matching native capability.

The candidate bound is L(ell,tau)=sum_{s=0}^tau binom(ell,s)*2^s. For fixed constant tau, honest opening is classical polynomial time. The decoder adds NO public data, and pk checking was already present in the joint transcript. The byte-identical original seed K is always on the list on the good event. A different candidate could generate the SAME native pk if native seed-to-pk derivation collides: that still grants the same precommitted **verification capability**, but claiming byte-identical seed recovery in that case requires an additional independently justified native key-binding property. Do not add a public digest H(K) without proving its joint pk-only simulation.

## Rigorous simultaneous *all accepted reference witnesses* list-correctness

The cyclic codebook has adjacent distances g, with wrap gap q-(m-1)g=g+(q mod g)>=g. **Adjacency lemma:** if |E_(w,j)|<3g/2, the nearest codepoint's index is the true t_j or one of its two cyclic neighbors. If |E_(w,j)|<g/2, it is the true t_j. Therefore if every accepted w has <=tau coordinates with |E|>=g/2, and none with |E|>=3g/2, then its true Z lies on the enumerated list. This statement simultaneously covers every accepted w, even after public-capsule-dependent adaptive witness selection. It does not require identical witness states.

For fixed binary weight-h w, uniform B gives Pr[Bw=0]=q^-d even for q a power of two. B is independent of the Gaussian errors, and errors are independent ACROSS COLUMNS for this fixed w. The pinned centered discrete Gaussian MGF bounds give

~~~text
p_half <= 2 exp(-g^2/(8h sigma^2))
p_far  <= 2 exp(-9g^2/(8h sigma^2)).
~~~

Put M=binom(n,h), and delta=TV(chi,G_sigma). The original exact finite-dyadic error matrix can be coupled ONCE to the ideal independent G_sigma matrix at cost n*ell*delta. Union over all h-weight w and the six-or-more bad positions and far errors; do NOT assume independence BETWEEN different witnesses. The rigorous all-witness bound is

~~~text
eps_all <= n*ell*delta + M*q^(-d) * [
   binom(ell,tau+1) * p_half^(tau+1)
 + ell * p_far
].
~~~

This is honest random-source completeness, not security for maliciously selected false B. The pinned pairwise-kernel proof gives Pr[R_card false]<=q^d/M, hence eps_true<=eps_all/(1-q^d/M). Changing the decoder never conditions or postselects B, so the standard-LWE source distribution is preserved.

For the unchanged illustrative, QPT-UNCERTIFIED distribution q=2^20,d=32,n=4096,h=128,k=256,sigma=16/5,T=56,P=320, choose g=640=5h,c=5,m=1638,ell=24,tau=5. We have c*n=20480<q; q mod g=256, wrap gap 896; and 1638^23<2^256<=1638^24. Compare predecessor g=1536,m=682,ell=28. The ciphertext VECTOR payload falls from 28*4096*20/8=286720 packed bytes to 24*4096*20/8=245760: **40,960 bytes (14.2857%) saved** without changing uniform B, LWE dimensions, q or chi. B itself consumes 327680 packed bytes, so B-plus-vector size falls 614400 -> 573440, a 6.6667% reduction. Strict worst-case candidate count is exactly L(24,5)=1,547,489, which may make off-chain native-key checking costly; expected runtime was not benchmarked.

Exact certificate (not a QPT attack estimate): 2^816<M<2^817, q^d=2^640, source false probability <2^-176. The Gaussian half-gap exponent is 625/16, far exponent 5625/16. The rational positive Taylor partial sum of exp(694/1000) through degree four exceeds 2, proving ln(2)<694/1000. Since (56*694/1000)<625/16 and (506*694/1000)<5625/16, p_half<2^-55 and p_far<2^-505. binom(24,6)=134596<2^18, so the six-error union term is below 2^(177+18-6*55)=2^-135; the far-error term is below 2^(177+6-506)=2^-323. The pinned exact dyadic chi satisfies delta<2^-157+2^-313<2^-156; n*ell=98304<2^17, so coupling <2^-139. Hence eps_all<2^-134, and conditioned on honest source true, eps_true<2^-133. Budget an independent Fourier-NP all-witness failure <2^-129 to keep total completeness error <2^-128. The predecessor's tighter g had <2^-138 correctness error: this step trades margin for ciphertext saving while retaining the stated target.

## Complete joint-public quantum game and simulator scope

Assume ordinary **decisional QPT LWE** for exactly uniform B in Z_q^(d x n), u uniform in Z_q^d, and the pinned chi error in Z_q^n, against arbitrary coherent QPT distinguishers in the specified advice/access game. Fix target independent secret coins and prohibit target-linear secret disclosure and arbitrary adversarial quantum advice correlated with those fresh coins. For each LWE hybrid column j, a STRAIGHT-LINE reduction receiving (B,z) where z=B^T u+e or uniform generates its real native K,pk, the full U,Z,V,D correlation and all correlated radix digits, all genuine B-derived source A,b/context, the actual arbitrary-NP Fourier SOURCE/capsule for V, real checking key and permitted auxiliary/independently keyed related capsules. It substitutes p_j=alpha*t_j+z; other columns are sampled in their prescribed adjacent hybrid distributions. This is EXACT standard-LWE challenge embedding; no source-opening oracle, planted uniform-B distribution, quantum rewinding or internal-representation cooperation is assumed.

In the all-uniform hybrid all p_j are independent uniform and independent of Z, while for every fixed real K and pk the map (U,Z)->(V=K xor U,D=U xor Z) is a bijection. Hence (D,V) is exactly JOINT uniform conditional on the **actual** pk, not merely separately uniform; the native unforgeability challenger possessing only pk can simulate the null source/capsule and permitted context. Under the inherited restricted adversary/challenge native-signature model, an unauthorized exact-key recovery (convert to a fresh native signature) or fresh intended-path forgery satisfies

~~~text
p_win <= Adv_native_QPT(B*) + 24 * Adv_standard_QPT_decLWE(B*;d,n,q,chi).
~~~

B* includes coherent computation, native-signing interface, QPT reduction and its overhead and permitted independent advice. Public checking of list candidates does not enlarge the public distribution and was already available to the adversary. False arbitrary ORIGINAL-NP conjuncts preserve the separate inherited exact Fourier whole-quotient simulator P0=P1 with actual linear capsule and checking-key correlations. **No theorem for all adversarially false linear/kernel instances, arbitrary target linear opening leaks, malicious N-of-N setup, reused claim keys or arbitrary correlated selective opening** follows from ordinary average-case LWE. The illustrative LWE parameters have no concrete 128-bit QPT security assessment.

## Critical unsolved ORIGINAL-to-source obligation

Nothing here makes the random reference relation equivalent to real Bitcoin/Syscoin PoW or arbitrary generic NP. Still missing a strict-classical-PPT ORIGINAL source compiler for EVERY accepted W:

~~~text
f_x(W) in {0,1}^n,
weight(f_x(W))=h,
B_x f_x(W)=0 mod q,
~~~

and a straight-line independently justified QPT challenge simulator for **that same statement-dependent B_x** together with relation, capsule, real checking key, full auxiliary and multiple-capsule correlations. A fixed-weight encoding alone almost certainly does not satisfy the random kernel equation. Generic Fourier NP release remains exponential for nonlinear circuits. Final native key recovery/forgery must imply ORIGINAL W or an independent PQ break, without the adversary volunteering an internal representation; a supplied-representation lemma alone is insufficient.

Actual SYS/BTC evidence must bind intended claim/UTXO/path, burn authorization/output, authenticated strict Bitcoin headers/AuxPoW/coinbase tags, correct interval/ancestor linkage/lag and qualification, competing forks and broken-tag veto, separately from cumulative parent work. One hundred already-public Bitcoin headers are not a cryptographic timed release. N-of-N honest preauthorization, malicious abort and DA, challenged transaction graph, observation/inclusion assumptions and conditional no-EC-path native PQ signature endpoint remain unresolved. Do not infer deployed Bitcoin features.

## Executed offline checks

The separately published Python stdlib checker was actually executed twice with identical JSON bytes, 368925 assertions each, with 368896 enumerated toy openings and 280832 repaired one-digit-misrounding cases across two distinct accepted reference witnesses, plus full fixed-K (D,V) null-distribution and exact integer certificate. Its toy pk map is deliberately invertible and proves ONLY algebra/correctness, no signature security or quantum hardness. An additional local Node checker passed 396987 assertions twice identically, including 25920 literal LWE opening-column identities. Local extended proof and both checkers are separately preserved. No external literature or websites, deployment, merge, workflow change, review or production code modification.

