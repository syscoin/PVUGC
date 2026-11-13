# Random-kernel-filtered Gaussian correctness (RKG-CERT): complete restricted checkpoint

Research only, offline 2026-10-27. This is an exact certificate improvement to the Gaussian transverse ordinary-QPT-LWE **reference relation**, NOT a generic-NP/Bitcoin/Syscoin witness-KEM. Pinned predecessor Git blobs: Gaussian 69b4983e296531b5696bbcca34cb4d4e82d4c07e; cardinality 2260a962953b11dd3bbcf1b92784e73d9460e439; adaptive independently keyed claims 6cf07e0374f5d303c3528c79caeb30a3aacf7301. The previous all-witness Gaussian certificate counted all fixed-weight binary vectors, although only random-kernel vectors can open. We prove an exact independent-kernel filter that improves capsule efficiency WITHOUT conditioning public B or changing the LWE challenger distribution.

## Concrete classical honest release (same algorithms; narrower spacing g)

Let q=2^a, d,n,h,k positive, g=2^nu, h divides g, c=g/h, c*n<q, r=a-nu>0, ell=ceil(k/r). Define the exact **reference ORIGINAL linear relation** R_card(B;w): w is binary length n, weight exactly h, and B*w=0 mod q. B is sampled uniformly from Z_q^(d x n), independently of all secret/noise coins. Public context binds ORIGINAL relation identity, claim/UTXO, actual burn/authorization/output, branch, authenticated anchor/window and native signing key/path. A public b'=(1,b'_2,...,b'_(d+1)) may depend on public pk and context, not the secret K or fresh private coins. Put alpha=c*1_n, A_1=alpha, A_(i+1)=B_i+b'_(i+1)*alpha and b=g*b'. Under c*n<q, R_card is exactly binary A*w=b. It is NOT the claim-bound BTC/SYS witness predicate.

Sample ACTUAL native uniform seed K in {0,1}^k and real pk(K); choose U uniform and set V=K XOR U. Fix a public GF(2) full-row-rank L from ell*r bits to k bits. For every column j sample t_j uniform Z_q, u_j uniform Z_q^d, independent noise e_j in chi^n where chi is the predecessor's *same* strict-PPT P-bit finite-dyadic discrete-Gaussian approximation (support [-T,T], centered sigma; tabulated rounded integer masses). Release

  p_j = alpha*t_j + B^T*u_j + e_j (mod q),
  D_L = U XOR L((t_1 mod(q/g)) || ... || (t_ell mod(q/g))).

Generate the ACTUAL previously specified physical Fourier/polar arbitrary ORIGINAL-NP source and capsule F for V, with its independent public dither and private mask coins. Full public transcript contains B,A,b,all p_j,D_L,F, real pk(K), checking/context/auxiliary material and all declared independently keyed related capsules. Honest setup protects/erases K,U,V,t,u,e,NP coins and transcripts, with no future witness, source-opening oracle, canonicalization, online release authority or keyless Build. The linear component's setup and recovery are classical PPT; the generic-NP Fourier component retains its exponential nonlinear-gate cost.

Any accepted w gives y_j=w^T*p_j=g*t_j+E_wj mod q, where E_wj=sum_{i:w_i=1} e_{j,i}. If |E_wj|<g/2 for all j, cyclic nearest-g-multiple rounding extracts t_j mod(q/g), and U. Any accepted ORIGINAL-NP witness v decodes V through the inherited polar certificate. K=U XOR V is therefore the SAME precommitted native seed for all accepted witness pairs, modulo the globally bounded honest error event. Check pk(K) and sign intended challenge path OFF CHAIN; Bitcoin does not evaluate NP, PCP or traces.

## New unconditional all-accepted-witness correctness lemma

Let M=binom(n,h). For ANY fixed binary vector w of weight h>=1 and fresh uniform B, B*w is uniform in Z_q^d: choose one nonzero coordinate of w, which has coefficient 1, then each independent B row's dot product is uniform after conditioning on its other coordinates. Hence

  Pr_B[B*w=0]=q^(-d),

even for q a power of two. This holds independently of all error coins; NO independence is asserted between different witnesses' error events.

Let G_sigma be centered discrete Gaussian with mass proportional to exp(-z^2/(2 sigma^2)), and let e*_j be independent G_sigma^n. Its MGF is at most exp(s^2 sigma^2/2), as shown in the pinned predecessor via the shifted Gaussian theta inequality. For each fixed h-weight w, Chernoff gives

  Pr[ |sum_{i:w_i=1} e*_{j,i}| >=g/2 ] <= 2 exp(-g^2/(8 h sigma^2)).

The correct simultaneous all-accepted-witness bad event is
  Bad(B,E*) = exists j,w with wt(w)=h AND B*w=0 AND |w^T*e*_j|>=g/2.

Union bound the JOINT kernel-and-bad events, factoring each fixed-w event only across the independently sampled B and e*, not across w:

  Pr_{B,E*}[Bad] <= 2 ell M q^(-d) exp(-g^2/(8 h sigma^2)).   (1)

This bound is over the ACTUAL uniformly sampled honest source B and all error columns. Because it quantifies over ALL accepted w simultaneously, a QPT adversary choosing w after observing the public capsule cannot escape the certified event.

For the unchanged finite-dyadic noise chi, let delta=TV(chi,G_sigma). The pinned finite-table construction obeys
  delta <= 2 exp(-(T+1)^2/(2sigma^2))+(2T+1)*2^(-P).
Couple all n*ell independent chi samples to ideal independent G_sigma samples; data processing and the union bound give a SINGLE additive n*ell*delta, not one penalty per witness. Hence the NEW correctness certificate is

  eps_RKG <= 2 ell binom(n,h) q^(-d) exp(-g^2/(8 h sigma^2))
           + n ell delta.                                    (2)

The old certificate omitted q^(-d). Equation (2) assumes independent honest uniform B and error coins. It is NOT an all-adversarial-B guarantee, is NOT a QPT hardness claim, and does not justify conditioning or rejecting B by witness existence. It needs no witness enumeration and does not postselect the released challenge distribution.

## True reference-source probability and conditioning

Distinct h-weight binary incidence vectors w,w' have two coordinates making their 2x2 incidence minor +/-1, a unit in Z_(2^a). Their B-kernel-zero events are pairwise independent even for composite q. Thus for W=count of accepted vectors:
  E[W]=M/q^d, Var[W]=M q^(-d)(1-q^(-d)),
  Pr[W=0]<=q^d/M.                                         (3)

When q^d/M<1, conditional on source True (W>0), simultaneous honest opening failure is at most eps_RKG/(1-q^d/M). The honest simulator and public distribution remain **unconditioned**, as required by ordinary standard decisional-LWE; there is no PPT exact test of source truth invoked in setup.

## Exact illustrative numerical certificate and executed checks

Keep the predecessor's exact LWE reference distribution/dimensions/noise: q=2^20, d=32, n=4096, h=128, k=256, sigma=16/5, finite-dyadic T=56,P=320. This is an UNCERTIFIED QPT-LWE parameter set, not a 128-bit PQ recommendation. Take g=2048=2^11, c=16 so c*n=65536<q, r=9, ell=29. Predecessor Gaussian full-weight certificate took g=4096, ell=32; NEW-CERT reduces noisy n-vectors and LWE hybrid steps by 3/32=9.375% without changing n,d,q,chi or uniform B. Compared to prior deterministic bound ell=43, the reduction is 14/43=32.56%. Public capsule remains large.

The EXACT integer bounds are 2^816<M=binom(4096,128)<2^817; q^d=2^640, so source False probability <2^-176. At g=2048, g^2/(8 h sigma^2)=400. Using e>2 gives exp(-400)<2^-400 and hence first term <2*29*2^817*2^-640*2^-400<2^-217. The dyadic delta from T=56,P=320 satisfies delta<2^-157+2^-313 (because (T+1)^2/(2sigma^2)=81225/512>158), while n*ell=118784<2^17; its total coupling is <2^-139. Thus unconditionally eps_RKG<2^-217+2^-139<2^-138; conditionally on true source eps_RKG/(1-2^-176)<2^-137. These are conservative powers-of-two guarantees for all-witness CORRECTNESS only. Budget independent Fourier NP decoding error <=2^-129 to keep combined correctness error <2^-128; this does not set QPT security strength.

The self-contained published JS checker was executed twice in the isolated local JavaScript runtime with identical output. A separate Python stdlib checker ran twice byte-identically (66,076 assertions each; sha256 734cd6e7c2d27777511b87924ba4dbb0dff43d8a5b4d1b6309448b3fa9259e06; output sha256 1d7bcd07a8df5c4e9ed9c764e3f7fe51f086c50a25eab6c85eef66026660e6cd). The finite test enumerates every B in Z_4^(1x4), every error in {-2,-1,0,1,2}^4, and two distinct accepted witness openings. Exact factorization, correlated union inequality and the large integer certificate were checked; these are not QPT/hardness tests.

## Entire joint-public QPT security (unchanged inherited theorem)

Assume ordinary decisional QPT LWE for uniform B in Z_q^(d x n), uniform secret u in Z_q^d and EXACT finite-dyadic chi noise e, against arbitrary coherent QPT distinguishers in the specified quantum advice/access model. The full transcript simulator, given challenge (B,z) where z=B^T u+e or uniform, generates the REAL native pk, K,U,V, all context/checking keys, public b' and A, actual physical F protecting V, target/no-target related capsules and all allowed auxiliary/path-signing responses. For challenged column j it sets p_j=alpha*t_j+z with known uniform t_j, and generates remaining columns honestly or uniformly. This is a **straight-line**, standard-LWE embedding with no SourceOpen oracle. In the all-uniform hybrid, independent uniform p_j hide all t_j; full-rank L makes P=L((t_j mod(q/g))_j) uniform, and (D_L,V)=(U XOR P,K XOR U) is jointly uniform 2k bits conditional on *any* real K and pk(K). Hence a native challenger simulates the entire null transcript from pk alone, including independently keyed opened related capsules in the predecessor's restricted game. The unchanged bound is

  p_win <= eps_native(B*) + ell*Adv_QPT-decLWE(d,n,q,chi;B*),

now ell=29, B* accounting for entire QPT adversary, reduction, native legitimate signing access, public checking-key and auxiliary simulation. Advice must be independent of fresh target secret/error coins; target linear share/randomness cannot be opened, nor are malicious setup, reused cross-claim signing keys or arbitrary secret-correlated auxiliary outputs included. No quantum rewinding or volunteer representation. For false arbitrary ORIGINAL-NP, the independent Fourier whole-quotient P0=P1 preserves exact full-public false-NP simulation when its protected share remains unopened. False arbitrary adversarial R_card does NOT follow from average-case LWE.

## Decisive unsolved ORIGINAL obligation

This improvement does NOT map arbitrary ORIGINAL BTC/SYS headers, AuxPoW tags, ancestor proofs, burn authorization and arbitrary attached NP witness into the random kernel. The exact missing equation is a classical polynomial-cost source f_x such that for every accepted ORIGINAL W, B_x*f_x(W)=0 mod q and wt(f_x(W))=h, with the SAME precommitted capability for all witnesses, while B_x and all source-dependent opening/capsule/checking-key/auxiliary distributions still admit an ACTUAL standard-QPT-LWE full-joint simulator. Arbitrary final-key recovery or unauthorized native forgery must imply ORIGINAL W or an independently justified QPT break; no internal representation may be demanded. Fixed-weight padding alone fails B*f(W)=0. The generic NP Fourier side remains exponentially costly; concrete Bitcoin 100-block QPT work bound, malicious N-of-N graph/setup/abort, arbitrary correlated selective openings, qualified fork/broken-tag veto, source DA/observation and conditional native no-EC PQ Bitcoin endpoint are unresolved. No deployment or completed WKEM is claimed.
