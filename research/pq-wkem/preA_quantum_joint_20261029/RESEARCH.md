# Pre-matrix quantum auxiliary information for dual-LWE short-preimage SOURCE

**Status: a positive restricted full-public security proof, not a generic-NP witness-KEM.** This closes an excluded case of witness-correlated quantum auxiliary information for the previously constructed honestly planted dual-LWE SOURCE. It does not fix the failed witness-free arbitrary-NP compiler and does not solve extraction to an actual ORIGINAL witness.

## Provenance and predecessors
Offline 2026-10-29, scheduled research turn 11; no separate scheduler execution UUID provided. Repository syscoin/PVUGC, open/draft/unmerged PR #1, branch research/pq-wkem-validation-20260918. Observed starting head d3ce8c7b363a838e1b7e5ce3f4720b5f40f8e45a; latest substantive ordinary PR comment 6493616426. Exact-version input blobs: dual_lwe_short_preimage_20261028/RESEARCH.md d702c096ff2bc227629ca7d8f2ee9f5e27199f42; full_coin_adaptive_survivor_20261028/RESEARCH.md ff67640f12ba0701903272262f1ac4931681b25a; noise_scaled_public_pseudodecryptor_20261029/RESEARCH.md 1526d5928c7ce1e370834a385e4e4d80198d205a; paired_binary_np_source_20261028/RESEARCH.md edfa385fcec0bfaf915f309d41c349cd3c355a40. No external literature or web research.

## Exact distributions and full-public game
Choose odd prime q; integers m>n, d,t,h,kappa with 2h<q, g=2h+3, T=floor(q/g)>=2 and noise chi uniform on {-1,0,1}. Set ell=ceil(log_T(2^kappa)) and L=ceil(ell/d). Let S(m,h) be all signed integer vectors w of L1 norm exactly h, N=|S|=sum_{k=1}^{min(m,h)} 2^k C(m,k) C(h-1,k-1). The predecessor's exact classical polynomial-time sampler selects support cardinality by those weights, support locations, positive composition, and independent signs. Honest setup, Build and off-chain Release are classical PPT.

An honestly planted TRUE SOURCE samples W_1,...,W_d independently uniformly from S; A uniformly from F_q^(n x m) independently of W; and publishes U=A W in F_q^(n x d). Its restricted ORIGINAL source opening is any W' with A W'=U mod q and integer L1 norm of each column <=h. The source generator initially knows W and hence has an unacceptable bypass for unknown-future Bitcoin evidence. This is a restricted SOURCE, not an arbitrary-NP or SYS/BTC source compiler.

The new auxiliary experiment permits a specified efficiently sampleable QPT channel G to receive classical W and allowed independent quantum advice, BEFORE A is sampled, and prepare a joint accessible classical/quantum register E with total Hilbert dimension D<=2^lambda. Conditional on W=w, the density matrix rho_w can be arbitrary, noncommuting, entangled and correlated across all SOURCE columns. ALL retained W-correlated side registers, references, classical leakage and accessible quantum workspace must be counted in D. The simulator can sample W and run G without A, the challenge secret or SourceOpen. Independent challenge-independent auxiliary advice is carried identically in both hybrids. No unbounded stored W, uncounted purification, post-A W-dependent leakage, generator given target K, or quantum superposition signing/Open queries are covered. The attacker may coherently process E and all public registers AFTER A is revealed.

Build receives only public A,U and samples an independent genuine native seed K and checking key pk(K), independent uniform kappa-bit U0,Z_1,...,Z_t. Publish mask Dm=U0 xor (xor_i Z_i) and Vm=K xor U0. Encode each Z_i in ell base-T digits padded to batches of d. For each batch sample independent s uniform F_q^n, e uniform chi^m and eps uniform chi^d. Publish the COMPLETE ciphertext
~~~
 c=A^T s+e mod q,       v=U^T s+eps+g*a mod q.
~~~
The complete adversarial joint public view includes R,x,claim/UTXO,branch,anchors/window/context, A,U, all c/v, genuine checking key, Dm,Vm, E, permitted auxiliary information, and adaptively requested related capsules. Related replies are efficiently generated from public data, adversarial classical queries, independent own keys and fresh known coins, without target W, hidden target share or target K. Classical Open(i), at most t-1 whole distinct shares, returns a whole share AND all its s/e/eps coins; valid native signing queries are classical and freshness is enforced on the intended challenge path. Adversary is arbitrary QPT with allowed independent nonuniform quantum advice. Quantum rewinding, generic-group extraction, a SourceOpen oracle and adversary-volunteered representations are NOT assumed.

## Every accepted SOURCE witness opens the SAME key
For ANY valid restricted W', not just planted W:
~~~
 v-W'^T c = g*a+eps-W'^T e mod q.
~~~
Each residual coordinate has integer absolute value <=h+1, while g=2h+3 and wrap gap q-g(T-1)>=g. Nearest cyclic center recovers every digit for all honest coins and any valid W'. The recovered shares give K=Vm xor Dm xor (xor_i Z_i), the ONE precommitted capability. W' need not share intermediate states or equal planted W. This is exact source correctness ONLY.

## New unconditional quantum joint-public SOURCE lemma
Let Q=q^n, rho_E=(1/N) sum_w rho_w and let A be uniform independent of W,E. For the single-column classical-quantum state of (A,AW,E), versus (A,U_uniform,E) with U independent uniform F_q^n:
~~~
 TD(real,ideal) = (1/2)||rho_real-rho_ideal||_1
      <= delta_D = min(1,(1/2)*sqrt(D*(Q-1)/N)).
~~~
This is proved directly in quantum trace norm, NOT inferred from a classical total-variation claim. For fixed A,y set
~~~
 T_Ay=(1/N) sum_{w:Aw=y} rho_w,  X_Ay=T_Ay-rho_E/Q.
~~~
The cq difference is block diagonal over classical A,y. For Hermitian X on D-dimensional E, ||X||_1<=sqrt(D)||X||_2. Cauchy across Q y-blocks yields
~~~
 TD <= (1/2)*sqrt(Q*D*E_A[sum_y Tr(X_Ay^2)]).
~~~
Expanding the squares, using sum_y T_Ay=rho_E, and distinct S residues (from 2h<q), gives exactly
~~~
 E_A sum_y Tr(T_Ay^2)
  = (1-1/Q) (sum_w Tr(rho_w^2))/N^2
    + Tr(rho_E^2)/Q;
 E_A sum_y Tr(X_Ay^2)
  = (1-1/Q) (sum_w Tr(rho_w^2))/N^2
  <= (1-1/Q)/N
~~~
because for w!=w', random A has Pr[A(w-w')=0]=1/Q, and every density matrix has purity <=1. Substitution proves delta_D. The derivation allows noncommuting and entangled E and arbitrary QPT measurements chosen after public A.

For d independently sampled SOURCE columns but **one shared A and one JOINT quantum E** correlated with all W_i, replace public U_i=A W_i one at a time. In an adjacent hybrid, condition FOR PROOF ONLY on other classical W_j (not revealed to the adversary). Then W_i remains uniform and E is an arbitrary D-dimensional conditional state prepared independently of A. Other U_j are either fresh uniforms or deterministic functions of A and those conditioned W_j; they, the public checking-key/XOR/capsule generator and adaptive adversarial interaction are postprocessing channels. Trace-distance contractivity gives <=delta_D per hybrid. Averaging and telescoping:
~~~
 TD((A,AW_1,...,AW_d,E),(A,U_1,...,U_d,E))
       <= min(1,d*delta_D).
~~~
No independence of E_i, no classical-only argument, and no exponential D^d penalty. This is an averaged **honestly uniform A** theorem, never a per-fixed-A, structured NP-source or fixed FALSE statement theorem.

## Exact full-public simulator and conditional QPT bound
The SOURCE-to-uniform simulator samples fake W and runs G to create the correct E joint distribution, then replaces all planted U columns by independent uniform ones. The joint quantum trace bound d*delta_D applies before every capsule, checking-key, correlated XOR mask, related-capsule and allowed Open transcript is generated; coherent QPT processing and classical adaptive queries cannot increase trace distance. In that uniform hybrid H=[A^T;U^T] is genuinely uniform (m+d) by n AND independent of E. Each selected hidden-share batch after subtracting known g*a is exactly the ordinary uniform-secret ternary-error decisional-LWE challenge H*s+(e,eps). The challenge-secret-free simulator embeds one selected batch, makes all other batches/whole shares with known fresh coins, simulates full replayable Open(i) replies for i!=J, and runs L such hybrids. Random independent J in 1..t remains un-opened with probability >=1/t on success. In the final ideal, J ciphertexts are independent uniform, and (U0,Z_J) -> (Vm,Dm) is a bijection conditional on unknown native K and all other shares. This preserves the REAL native checking-key correlations while reducing recovered K or a fresh intended native signature to independent QPT-EUF-CMA. No SourceOpen, quantum rewinding or offered internal representation.

Under the specified planted TRUE SOURCE distribution, exact (n,q,m+d,chi) uniform-secret ordinary QPT decisional-LWE and independent native QPT-EUF-CMA assumptions with classical signing/Open interfaces, the full-view bound is
~~~
 Pr[unauthorized native capability recovery OR fresh intended-path forgery]
 <= t*(d*delta_D + L*Adv_QPT-DecLWE + Adv_QPT-native-EUF-CMA).
~~~
The trace-distance lemma is proved unconditionally; the composite security conclusion is conditional on genuinely independent QPT LWE/native assumptions and the stated classical-PPT setup, pre-A advice generator, related-capsule and selective-opening model. Quantum side info correlated with W after seeing A, key-correlated aux, malicious setup, every-fixed-FALSE NP security, and arbitrary hard-TRUE recovery-to-ORIGINAL-witness are NOT established.

## Exact executed checks and resource example
The exact published check.js function was executed twice identically in the V8 runtime: PASS 9,241 finite assertions. It enumerates an injective 18-vector signed sphere and all 27 A matrices over F_3^(1x3), uses genuinely noncommuting one-qubit cq ensembles depending on one or BOTH hidden W, verifies the exact quantum Hilbert-Schmidt variance identity and average joint trace distances: single source 0.178539184959 <= 0.235702260396; two SOURCE columns under shared A and one joint E: 0.160196370796 <= 0.471404520791.

Separately, the extended LOCAL-ONLY standard-library/numpy Python checker was executed twice with byte-identical JSON outputs: PASS **168,684** finite assertions. It adds explicit 2-qubit entangled Bell and phase-rotated noncommuting states; joint two-SOURCE quantum trace distance 0.122101594749 <= 0.500000000000, one-qubit single 0.127380941275 <= 0.176776695297, one-qubit joint 0.109481578171 <= 0.353553390593, exact Hilbert-Schmidt variance 0.020833333333; it also tests distinct restricted witness decoders recovering the same 256-bit mock capability. A first LOCAL harness comparison mistakenly chose orthogonal Bell-derived states for a noncommutation assertion; that failed assertion was corrected using phase-rotated entangled states before BOTH final passing runs. The extended Python checker is NOT claimed committed. These are finite classical density-matrix calculations, not a physical quantum security test, real SLH implementation, or concrete QPT hardness analysis.

At illustrative q=65537,n=128,m=1600,h=800,d=14,t=3,kappa=256,L=4 and whole-joint E dimension <=2^457 (including ALL accessible W-related quantum/classical side information), log2 N=2770.739395550 and log2(t*d*delta_D)=-128.475971481. This quantifies the **statistical portion only**, not 128-bit QPT DecLWE or native-signature security.

## Handoff / missing ORIGINAL-witness theorem
Still require witness-free classical PPT Comp(R,x,claim,path,anchors,window,context,pk)->(SOURCE,capsule) and public off-chain Phi(R,x,W), for arbitrary ORIGINAL NP, such that **every valid ORIGINAL W** releases exactly one bound K, **every fixed false x** has secure COMPLETE public output against arbitrary QPT, and **arbitrary unauthorized hard-true K recovery or fresh native forgery** reduces to an ACTUAL ORIGINAL W or independently justified QPT break without asking for an internal representation. The prior paired-binary public pseudo-decryptors and global polynomial clause-mask extractors still break those proposed sources; the planted SOURCE generator still knows a bypass W. This quantum advice extension is NOT a repair. Remaining: malicious N-of-N preauthorization/erasure/no-bypass graph, abort/DA before funding, optional keyless Build under retained builder coins, actual authenticated SYS/BTC headers/AuxPoW/coinbase tags/ancestor/window and reorg/censorship assumptions, and hypothetical no-EC-key-path native PQ-only Bitcoin endpoint. No production change, merge, approval, deployment or completion claim. Keep this research automation enabled.
