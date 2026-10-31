# Restricted dual-LWE SOURCE with bounded pre-matrix classical leakage

**STATUS: positive restricted full-public QPT-composition lemma; NOT generic NP witness-KEM.** Offline bounded 2026-10-29 automation turn 11 (no independent scheduler execution UUID supplied). Authorized existing syscoin/PVUGC PR #1, open/draft/unmerged, branch research/pq-wkem-validation-20260918; starting head 929d6863d6d293f3f67a75f8fb54ecdb7f79e2eb; last substantive ordinary comment 6491199106. Exact-version inputs: dual_lwe_short_preimage_20261028/RESEARCH.md at d702c096ff2bc227629ca7d8f2ee9f5e27199f42, adaptive_related_source_oracle_20261028/RESEARCH.md at 05b6198158bfd99d34af798e055fd9997cb77707, latest failed global_polynomial_clause_mask_20261029/RESEARCH.md at abae018f27120a7e0b3406befd2ce1567968d744. No external internet/literature.

## Exact distribution and algorithms

Fix odd prime q, m>n, 2h<q, d columns, t>=2 shares, security seed length kappa. Define S(m,h) as signed integer vectors of L1 norm exactly h; N = sum over k=1..min(m,h) of 2^k*binom(m,k)*binom(h-1,k-1). For each column j choose a public polynomial-time classical leakage function or randomized channel f_j, with at most r_j<=2^lambda_j classical outputs; its description, randomness distribution and selection must be independent of both undisclosed W and sampled A. These channels may depend on fixed public relation/claim/path/context before A. Independently sample W_j uniform S(m,h), output L_j=f_j(W_j), THEN sample A uniform F_q^(n*m) and publish U_j=A W_j modulo q. Since A and W are independent, this reorders the previous honestly planted SOURCE without changing its distribution. The source generator knows W and MUST NOT be treated as an acceptable future-fork witness-free source.

Generate the genuine native signing seed K and native public checking key pk(K) independently, uniform mask U0 and t independent XOR shares Z_i of the same kappa-bit length. Publish D=U0 XOR XOR_i Z_i, V=K XOR U0. Typed statement contains relation identity, claim/UTXO, branch, anchors/window, context and intended pk/path; target SOURCE A,U,L, real pk(K), D,V and all ciphertexts are public. Large ORIGINAL evidence remains off chain. K and pk may be generated before source sampling if they must be included in the fixed typed context; all remain independent of hidden W.

As in the independently established restricted dual-LWE construction, g=2h+3<q, radix T=floor(q/g)>=2, ell=ceil(log_T 2^kappa), b=ceil(ell/d). For each share and batch of d radix digits a, independently sample s uniform F_q^n, e uniform {-1,0,1}^m, eps uniform {-1,0,1}^d, and publish c=A^T s+e and v=U^T s+eps+g*a modulo q. All source, build, leakage evaluation and release algorithms are classical PPT.

For EVERY valid ORIGINAL witness W' of this restricted bounded-short-preimage relation, A W'=U modulo q and every column of W' has L1 norm <=h, the public off-chain release computes v-W'^T c=g*a+eps-W'^T e modulo q. Residual absolute value <=h+1 and cyclic radix centers are separated by >=2h+3, so EVERY valid W' recovers exactly the same precommitted K, including distinct states and witnesses. Source leakage L changes neither this equation nor deterministic correctness. This does not turn arbitrary NP evidence into a short preimage.

## Newly proved leakage-conditioned source lemma

Let W uniform S(m,h), A uniform independent W, and classical leakage L=f(W) of at most r outcomes, with f independent A. First take deterministic f, and write S_l={w:f(w)=l}, N_l=|S_l|. Since 2h<q, distinct w,w' differ nontrivially modulo q; for uniform A, Pr[A(w-w')=0]=q^-n. Exactly,

  E_A sum_u (Pr[AW=u | A,L=l]-q^-n)^2 = (1-q^-n)/N_l.

Cauchy-Schwarz on the output group gives

  TV((A,AW)|L=l, (A,Uuniform)|L=l) <= 0.5 sqrt((q^n-1)/N_l).

Average over leakage cells of probability N_l/N, apply Cauchy-Schwarz a second time:

  TV((A,L,AW),(A,L,Uuniform))
    <= sqrt(q^n-1)/(2N) * sum_l sqrt(N_l)
    <= 0.5 sqrt(r*(q^n-1)/N)
    <= delta_lambda = min(1,0.5 sqrt(2^lambda*(q^n-1)/N)).

The identical r/N collision bound extends to randomized classical leakage P(l|w), independently of A: sum_l Pr[L=l] Coll(W|L=l) = (1/N) sum_l (sum_w P(l|w)^2)/(sum_w P(l|w)) <= r/N. This is a full JOINT (A,L,U) statistical bound averaged over honest uniform A; it does not assert hardness for a fixed malicious A.

With independently planted W_j and separate bounded-output leakage f_j(W_j) under one common A, conditioning on (A,L_1,...,L_d) preserves independence among W_j. Conditional product telescoping yields

  Delta_leak <= sum_{j=1}^d delta_{lambda_j}.

The reference comparison world must have the SAME leakage distribution but each U_j uniform independent of A,L. The simulator samples fake independent W_j and computes f_j(W_j) to reproduce all L_j; fake W is never a SOURCE opening for uniform U. No SourceOpen oracle exists.

## Exact full-public QPT composition

The protected target game includes typed R,x and context, genuine native pk(K), XOR correlations D,V, all target ciphertexts, leakage L and permitted auxiliary data. Arbitrary QPT processing can adaptively choose polynomially many related capsules with SOURCE U' chosen after seeing the target, even U'=U, and disclose those capsules' independent native keys, shares and encryption coins. It can query classical signatures for allowed messages and adaptively Open at most t-1 complete target shares INCLUDING their full encryption coins. All related keys/coins are freshly generated independently and never expose protected K or target W; related capsules reusing the protected native key, source opening, target coins or release oracles are excluded. Interfaces are classical, adversary may maintain coherent quantum state between interactions. Quantum advice is public-view/challenge-preparable, with no extra hidden-W-correlated quantum information beyond the declared classical L; the leakage programs themselves are not allowed to encode W.

From the full-view planted target to uniform U target, use the unconditional Delta_leak trace-distance bound and CPTP contractivity for the complete adaptive QPT transcript; there is NO penalty multiplying the number of related capsules. In the uniform-source hybrid, H=[A^T;U^T] is exactly a uniform (m+d) by n LWE matrix, independent of L. Each shifted batch (c,v-g*a)=H s+nu is an ACTUAL uniform-secret ternary-noise decisional-LWE sample. Embed one genuine real-or-random DecLWE challenge in a selected hidden target share/batch, honestly generate ALL other encryption coins and related capsules, then hybridize b batches. Guess survivor share J uniformly and abort if J is opened, costing factor t; the t-1 other adaptive target whole-share/coin disclosures remain exactly consistent. Finally replace J ciphertexts by uniform. For fixed protected K and other shares, (U0,Z_J)->(V,D) is a bijection, so independently uniform D,V can be generated with a genuine native EUF-CMA checking-key challenge without signing seed K. Forward allowed classical signing queries. A usable recovered seed generates a fresh path-native signature; a fresh valid forgery wins EUF-CMA directly. No QPT rewinding, lifted classical PoK, adversary-volunteered SOURCE representation or undocumented native primitive is invoked.

Consequently, for ONE selected honestly planted restricted TRUE source, arbitrary QPT adversary and classical opening/signing/related interfaces:

  Pr[unauthorized usable K OR fresh intended-path native forgery]
    <= t*(Delta_leak + b*Adv_QPT_DecLWE(n,q,m+d,uniform s,independent ternary noise)
                     + Adv_QPT_native_EUF-CMA).

QPT DecLWE and genuine native PQ signature EUF-CMA remain **independent, explicit, unverified concrete-parameter assumptions**. The leakage lemma itself is exact finite-field probability, valid for arbitrary QPT postprocessing. At lambda_j=0 the source bound returns to its predecessor. Honest setup and classical leakage selection pre-A are essential; A-dependent/chosen-after-A leakage, arbitrary coupled f(W_1,...,W_d), superposition oracles, full target SOURCE opening disclosure, retained builder coins and malicious N-of-N setup are NOT covered.

## Reproducibility and exact scope

The committed check.js is the exact function executed in the offline V8 runtime, with its JSON stdout in check-output.json. A separate local-only standard-library Python checker executed twice identically, with 110835 assertions, checking exhaustive exact q=7,n=1,m=3,h=2 distributions for 0,1,2,3 leakage bits, two sources under the SAME A, target-public-source-dependent related data, and 90 common-capability decoding fixtures with distinct accepted W. Its captured output and extended derivation are in the companion local archive, not claimed committed. An initial Python harness invocation had a TypeError from passing two arguments to a one-argument test helper; the final corrected checker and both identical outputs supersede that local error. Neither checker tests quantum hardness or real SLH/native Bitcoin.

Illustration ONLY (NOT certified QPT hardness): q=65537,n=128,m=1600,h=800,d=14,t=3,kappa=256 gives log2(N)=2770.739395550297 and log2(delta_0)=-362.3682889040215. A common lambda=457 bits of independent pre-A classical leakage PER SOURCE COLUMN gives log2(t*d*delta_lambda)=-128.47597148124277; lambda=458 gives -127.97597148124277, failing this conservative <=2^-128 statistical budget. The bound does not certify DecLWE or PQ-signature 128-bit quantum hardness, nor malicious setup/security of all possible auxiliary inputs. Honest classical evaluation and ciphertext lengths are unchanged.

## Mandatory unresolved exact equation, not a repaired NP source

Still need a witness-FREE classical PPT Comp(R,x,claim/UTXO,branch,anchors/window,context,pk)->(A_x,U_x,capsule) and public off-chain Phi(R,x,W) such that for every valid ORIGINAL arbitrary-NP W:
  A_x Phi(R,x,W)=U_x mod q, each column L1<=h, Release(Phi(...),capsule)=ONE precommitted K.
The complete public checking-key/auxiliary/related-capsule distribution must hide K for EVERY FIXED FALSE ORIGINAL x against arbitrary QPT; arbitrary unauthorized HARD TRUE K recovery or fresh native forgery must reduce to an ACTUAL ORIGINAL witness or independent justified QPT break. Accepted short representation -> ORIGINAL W alone is insufficient, and the adversary must not volunteer a representation. The preceding global clause-mask and 3CNF pseudo-decryptor compilers are demonstrably broken. The present SOURCE creator ALREADY KNOWS planted W, making it unfit for future unknown Bitcoin fork evidence. The proved extra leakage tolerance is NOT a repair of this gap.

Separate outstanding prerequisites: one-honest N-of-N preauthorization, abort/erasure/no bypass and prefunding DA; optional fully keyless Build under malicious retention of builder coins; complete authenticated SYS/BTC headers/AuxPoW/coinbase tags/Merkle/ancestor/window/lag and censorship/reorg controls; and an assumed, NOT deployed, native no-EC-key-path PQ-only Bitcoin endpoint. BitVM remains covenant-emulation only. This iteration is not completion and does not justify disabling the existing research automation.
