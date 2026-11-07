# R35 — MINK-UNIFORM-PRODUCT-SPAN: exact mask sampling and all-instance equivalence to R32/R34

## Constructive result and provenance

**Proved advance:** Replace R32/R34's many bilinear random-mask products by **one exactly uniform draw from their public product span**, without computing a rank basis or supplying a refutation. This reduces generator work for the same 10-clause fixture, strengthens the qualified FALSE-branch mask-hiding result from approximate to exact, and—via a new statistical Fourier bound—preserves the full classical/quantum public-output distribution of R32 with sufficiently large t for **every instance**, TRUE or FALSE. This is an efficiency/distribution replacement, **NOT a fix of R32's hard-TRUE pseudoevaluation or a generic NP WKEM**.

Offline research only, no internet or literature search. At start, syscoin/PVUGC PR #1 open/draft/unmerged at head 3bd048ee413174122118995f2831ea9c7ffe9745, branch research/pq-wkem-validation-20260918; latest substantive ordinary comment 6599379370. Read exact R32 RESEARCH.md blob 5a7e9acf5330665d22885a39cb4cf52c9679637b and R34 RESEARCH.md blob 84e77dc3f5ff4c018f376096e8d2fe62475b425d. No PR-wide diff or archive sweep. The CHECKER.js published alongside this note is the exact V8-executed function plus a Node.js print wrapper; OUTPUT.json captures the checker result from two byte-identical runs, 7,505 assertions each. The toy checker uses a non-cryptographic deterministic pseudorandom generator, only to reproduce finite algebra checks.

## Honest classical algorithms

Take q odd prime, Delta=(q-1)/2 and d=6; work in A=F_q[z_1,...,z_n]/(z_i^2-z_i) with squarefree coefficient representation of total degree <=6 (M=sum_{j<=min(6,n)} binom(n,j) coefficients). Compile ORIGINAL R_x(x,w) faithfully to a 3CNF with m clause-failure polynomials f_j(z), each a product of three 0/1 literal-violation factors. The ORIGINAL x **must** bind the verifier/relation identity, actual claim/UTXO, branch, SYS/BTC anchors/window/context, intended native verification key vk and challenge capability/path. A valid ORIGINAL witness w yields a faithful Boolean assignment z_w with all f_j(z_w)=0. Verifying an unrelated proof without ORIGINAL binding is insufficient.

Define g_{jk}=f_j*f_k in the Boolean quotient for 0<=j<=k<m, G=m(m+1)/2 generators, W=span_Fq{g_{jk}}, r=dim W<=min(G,M). These g are entirely public; each polynomial has at most 64 squarefree coefficient terms because each f_j has at most 8. **Rank computation is NOT part of Build.**

For every bit mu of the single precommitted native signing capability K, every independent base scope and every ORIGINAL branch, sample all a_{jk} independently uniformly from F_q (classical rejection sampling); independently sample the centered coefficient noise e_T=eta*xi_T with xi_T uniform in {-1,+1} for every squarefree monomial of degree <=6, exactly as R34. Publish

  C_mu = sum_{j<=k} a_{jk} g_{jk} + Delta*mu*1 + e   (mod q)

and public x,vk,context, capsules, and only publicly reproducible CK/related-capsule operations; destroy mask/noise coins in the honest-erasure baseline. Honest Build may know K; this does not implement optional keyless Build or prove malicious-builder safety. Native SLH-like signing and no-EC-key-path Bitcoin support are CONDITIONAL endpoints, not deployed software.

**Lift(x,w,C):** use the ORIGINAL witness to compute z_w, evaluate every C_mu(z_w), decode nearest 0/Delta and obtain the SAME K for every valid ORIGINAL witness. Because all f_j(z_w)=0, g_{jk}(z_w)=0, thus C_mu(z_w)=Delta*mu+e(z_w). The R34 uniform-all-assignment concentration inequality remains unchanged:

 Pr[exists valid w, bit, scope with bad decoding] <=
  2*ell*S*sum_branch 2^{n_branch} exp(-(q-1)^2/(32 eta^2 M_branch)).

This is honest random-coin correctness including adaptively selected genuine ORIGINAL witnesses, NOT malicious-setup soundness.

## Theorem 1: EXACT uniform mask sampling without a span basis

Let L:F_q^G -> W be L(a)=sum a_{jk}g_{jk}; by definition L is surjective. Every y in W has exactly q^{G-r} preimages, so uniform a gives L(a) exactly uniform over W. This holds for every x, irrespective of satisfiability, rank deficiency or dependencies among g_{jk}. Sampling a rank-reduced basis is unnecessary. Multiplication-free online mask generation takes <=64G signed field additions per bit (plus accumulation/initialization of the M output coefficients), with the sparse g_{jk} reused from public x. No cryptographic hardness or idealized oracle is used in this proof.

**Qualified FALSE exact simulator:** If 1 belongs to W, for each fixed mu, K, vk, relation/context and auxiliary side data independent of the fresh source coins conditional on K, U_W+Delta*mu*1+e is IDENTICALLY DISTRIBUTED to U_W+e. A straight-line simulator given the genuine vk/CK external inputs samples a_{jk}, e and builds *zero-bit* capsules, with NO knowledge of K, SourceOpen or a public certificate. Any CK/related output that is deterministically publicly derived from these capsules is also identically distributed, including across many fresh independent base capsules/branches and under arbitrary coherent QPT postprocessing. Existing auxiliary quantum data may be correlated with K but must be independent of the target mask/noise coins conditional on the declared side data. A CK containing target private coins, adaptive target-base private opening, malicious setup or an unavailable secret-dependent CK algorithm invalidates this simulation premise. Any side channel that directly reveals K defeats final-key security independently of capsule hiding.

The exact FALSE property is NOT generic: some adversarial FALSE ORIGINAL x have 1 not in W. For a TRUE x, any valid witness has eval_{z_w}(W)=0 and eval_{z_w}(1)=1, so necessarily 1 not in W.

## Theorem 2: all-instance statistical equivalence to R32's t bilinear products

Let V=span{f_j}. R32 samples independent uniform r_i,s_i in F_q^m, and D_t=sum_{i=1}^t (sum_j r_{ij}f_j)*(sum_k s_{ik}f_k). For every NONZERO additive character lambda in the dual of W, let T_lambda be the m×m matrix T[j,k]=lambda(f_j*f_k). Since {g_{jk}} span W, T_lambda is nonzero; rank rho(lambda)>=1. For a nontrivial field additive character chi and one product P,

 E[chi(lambda(P))]=q^{-rho(lambda)}.

This is exact: condition on s; averaging r is zero unless T_lambda s=0, occurring with probability q^{-rho}. Independent products raise the coefficient to the power t. Fourier Parseval on the r-dimensional additive group W gives

 TV(D_t,U_W) <= (1/2) sqrt(q^r-1) q^{-t} <= (1/2) q^{r/2-t}.

This is an *unconditional* all-x statistical coupling, not LWE hardness or a false-only assumption. It also holds for r=0 with zero bound. Adding the same independent noise, translating by Delta*mu*1, publishing vk, and applying public deterministic CK/related-capsule functions cannot increase TV; condition first on K and any side registers independent of the fresh coins. For ell capability bits and S base scopes across branches with ranks r_i and old bilinear counts t_i, the total classical joint transcript difference is bounded by

  sum_{branch i} ell*S_i*(1/2)*sqrt(q^{r_i}-1)*q^{-t_i}.

Data processing of this *classical transcript distribution*, also with QPT quantum auxiliary advice satisfying the specified independence, controls ANY coherent quantum adversary's distinguishing advantage. This DOES NOT lift a classical computational conjecture to quantum security: the equivalence is statistical. Consequently replacing a suitably mixed R32/R34 capsule by R35 does not silently weaken any security property of R32 by more than this explicit TV error, although R32's desired hard-TRUE security has never been established.

For m=10, M=16, rank W=13, q=101, R32's t=30, log2 TV(D_t,U_W) <= -157.46796984466718 PER capsule, before multi-capsule union. The two-scope 256-bit error <=2^-148.46. R35 has **exact** qualified-FALSE masking, not this approximate old-source error.

## Test fixtures / work and resources

The exact R32 four-variable FALSE 3CNF used in CHECKER.js has 10 authentic failures, rank{f_j}=10, rank{f_j f_k}=13 over q=3,101,65537, and the same R32 exact integer unit certificate:

  1 = f0²+f1²+f2²−f2*f6+f3²+f4²+f5²−f5*f9+f6²+f8²+f9².

The checker verifies this identity in coefficient form, tests 128 exact **whole-capsule couplings** using shifted uniform a plus shared noise, and checks 3,584 correct bit recoveries for seven distinct ORIGINAL valid assignments to a separate TRUE 3CNF. It independently exhausts all 81 random pairs of two-dimensional linear masks over F_3, then computes the full convolution for t=1..7 over 27 source outputs, verifying the Fourier TV bound. No QPT hardness test or practical performance benchmark is claimed.

Direct symbolic generator expansions per bit in the illustrative R32 implementation are t*m²=3,000 versus G=55 sparse g_{jk} in R35 (54.545x fewer expansions). Independent uniform field coefficient draws are 2tm=600 versus G=55 (10.909x fewer). These count basic generator terms/coins, **not verified wall-clock speedups**. The dense public capsule still contains M=16 field elements in this fixture; general d=6 material remains enormous, and generic-NP parameterizations are impractical. Basis rank reduction, optional compression and implementation benchmarking remain separate.

## Hard security and ORIGINAL endpoint obligations — not solved

The original central theorem remains unproved:

 Pr[QPT adversary recovers final K or makes fresh accepted native target signature from FULL joint public view]
   <= Pr[reduction outputs an ACTUAL ORIGINAL witness] + independent QPT break + negligible.

No assumption that adversary volunteers a representation/decoder/functional is allowed. R35 gives no such reduction and **does not repair** the public-short-pseudoevaluation attacks R28/R32 identified. In particular if 1 not in W, public linear algebra finds a functional h with h(W)=0,h(1)=1, making h(C)=Delta*mu+h(e); sufficiently small h(e) can decode without ORIGINAL w. This is a hard-TRUE and arbitrary-FALSE attack surface. Enlarging W, public basis randomization, ordinary-LWE marginal pads or noise alone do not establish the missing theorem. Nor does an accepted inner proof automatically extract ORIGINAL evidence.

Still missing: independently justified arbitrary-QPT primitive/reduction (possibly a structurally different LWE or hash route); source-dependent opening and LWE challenge simulation JOINTLY including checking-key correlations, quantum advice and related capsules; arbitrary adversarial FALSE security (without bounded-degree public product certificate); private selective target openings and multiple TRUE branches; full malicious one-honest N-of-N ceremony/abort/DA; and a conditional native Bitcoin PQ signature/output. Keep ORIGINAL chain context (burn/output, headers/AuxPoW, authenticated tags and window/ancestor rules) in its faithful off-chain relation; Bitcoin is never asked to execute NP verification/VM/PCP/BitVM trace disputes. One honest observer still needs timely admissible evidence and enforceable inclusion. No deployment, no network access, no production files.

**Exact next mathematical step:** find a nonlinearly witness-gated release E_x(K;coins) whose arbitrary-QPT full-public hard-TRUE key recovery/native forgery admits a straight-line ORIGINAL-witness extractor OR an independent PQ reduction, and whose FALSE-public simulator can generate all correlated source openings and CK without K for every FALSE x. This exact-efficiency result is not that step.