# Coordinate-shift extraction of an ORIGINAL witness from arbitrary QPT final-key recovery (restricted planted SOURCE)

Record: coordinate-shift-planted-extractor-20261028-turn11. OFFLINE only. syscoin/PVUGC draft PR #1, branch research/pq-wkem-validation-20260918, verified starting SHA b207f7bd9103990ff97801a3c7c9a2f96a241136, latest relevant ordinary comment 6475133139. Exact predecessor notes: planted_source_spectral_extractor_20261028/RESEARCH.md, blob 3d708d2b9ceeb211299ab27a60d480f82739ddc4, and xor_share_selective_opening_20261028/RESEARCH.md, blob 63d20eecda19c7c5a5965237e4655d50b41cbfa8.

## Scope and qualified positive result

The previous planted-SOURCE full-public Fourier concentration proof has a much simpler, **explicitly constructive black-box extractor**: query the arbitrary-QPT success function on a sample ciphertext and M translated versions to recover the actual anchored binary ORIGINAL witness. It uses O(M gamma^-2 log(M/beta)) independently initialized adversary invocations for one identified conditional signed gap gamma, not q-ary prefix Fourier listing, generic Fourier transform, tau^-4 energy estimation, a SourceOpen oracle, rewind, or any adversary-volunteered representation. All old restrictions on planted source, advice, security assumptions, simulator, and oracle access remain. This is a genuine reduction-efficiency advance **within a restricted already-instantiated statistical theorem**, not a generic-NP construction, practical extractor benchmark, independent planted QPT-hardness proof, or 128-bit security claim.

## Exact SOURCE, real checking-key correlations, and Release

The ORIGINAL restricted relation is R(G,w)=[w in {0,1}^M, w0=1, sum(w)=h, G w=0 mod q]. Fix odd prime q, g=2h+1, b=floor(q/g)>=2, ell=ceil(kappa/log2 b), e0=(1,0,...). Planted classical honest setup chooses an unknown anchored binary w then publishes uniform rank-r G with rowspace contained in w-perp; the generator knows w, which is the unsolved independent-hardness/generic-compiler issue.

Build samples a real native deterministic signing seed K and its actual public verification key pk(K), uniform independent U,Z of kappa bits, sets D=U XOR Z and V=K XOR U; encodes Z into ell radix-b digits a_j; samples fresh hidden u_j uniform in F_q^r and iid eps_j uniform in {-1,0,1}^M; publishes p_j=G^T u_j+eps_j+g a_j e0. The entire public view includes R, G, capsules, checking key, D,V, context and authenticated source/claim/UTXO/path/anchor/window binding fields, admissible auxiliary data and independently masked related capsules. Real BTC/SYS semantics are not instantiated by this restricted relation.

Public off-chain Release first verifies the actual ORIGINAL R(G,w') and computes w'^T p_j = g a_j+w'^T eps_j mod q; |w'^T eps_j|<=h and q-g(b-1)>2h make every radix digit unique. Consequently **EVERY valid ORIGINAL witness** recovers the identical precommitted K=V XOR D XOR Z, even when different witnesses have different intermediate states. Release is not a Bitcoin NP verifier, and the ordinary native signature endpoint is conditional, not implemented.

A previously established optional ordinary-QPT-LWE wrapper replaces hidden uniform u by an actual source-dependent LWE challenge output (A,A^T s+eta), with public A and the same G; the straight-line real-to-uniform hybrid does not assume a SourceOpen oracle. The current coordinate lemma operates on the uniform-rowspace construction and does not infer any hard-true source assumption from LWE alone.

## Exact full-public coordinate-shift identity

Let P_a be the COMPLETE vector law of G^T u+eps+g a e0 (all M coordinates). For the unknown planted binary w, let P_a^(w) draw T=w^T eps+g a and then a uniformly random p in the FULL affine fiber {p:w^T p=T}. This is a mathematical comparison distribution, **never sampled by the reduction**. The exact predecessor Fourier theorem proved that for GOOD planted G, every a satisfies TV(P_a,P_a^(w))<=delta, where delta<=sqrt(theta)/2 from its exact off-witness Fourier tail V_G<=theta. Its specified planted distribution has a proved overwhelmingly high GOOD probability, but this is NOT true for arbitrary fixed false/true NP x.

Fix one hybrid ciphertext column j and nonzero digit a. Construct f(p) in [0,1] as the conditional probability that a fresh independent nonuniform QPT adversary recovers the correct FINAL native signing seed or produces a fresh accepted intended-path signature, AND does not open the designated target share, when the reduction samples all other actual public data and classical adaptive replies and forcibly installs target ciphertext p. The reduction knows K and native checking data for these f queries; it does NOT know planted w. The whole public pk(K),D,V and independent sibling capsules have their real correlations. It is essential that all other public variables, contexts and query answers are simulatable given G and the selected digit a, independent of the hidden target rowmask/error. Arbitrary target-coin-correlated auxiliary leakage, quantum superposition opening/signing and unclonable stateful quantum advice are excluded. The QPT computation within each fresh invocation can be fully coherent.

Define mu*=E_{P_a}f, mu_i=E_{p<-P_a} f(p-ga e_i), d_i=mu*-mu_i. For i=0, P_a-ga e0=P_0 EXACTLY, hence d_0=Delta=E_{P_a}f-E_{P_0}f. Because w_i is BINARY, for every i:

  if w_i=1, P_a^(w)-ga e_i=P_0^(w);
  if w_i=0, P_a^(w)-ga e_i=P_a^(w).

The first is equality of full quotient-label fibers (w^T shift=-ga); the second is exact tangent translation (w^T shift=0). Total variation invariance under permutation and triangle inequality give the **exact extraction estimate**

    |d_i - w_i Delta| <= 2 delta, for every i, every bounded f.

This is a full-vector bound retaining genuine checking-key/XOR-share context and applies after arbitrary coherent QPT processing by classical-data trace-distance/data processing. No Fourier frequency estimation is needed. It does NOT assume a ciphertext marginal pad-hiding proof.

## Explicit bounded black-box algorithm and QPT reduction model

Assume the predecessor's hybrid argument isolates some (target index, column j, nonzero digit a) with POSITIVE conditional gap Delta>=gamma>0, and the separately proved GOOD bound delta<=gamma/16. The reducer enumerates polynomially many j,a as needed, sampling Z conditional on its exact digit a (including finite-range top-digit bias) by exact rejection/conditional integer sampling. For each candidate it independently samples N ciphertexts from the real P_a **without knowing w**, calls one fresh QPT adversary instance for each forged translated ciphertext, and estimates each mu*,mu_i as classical Bernoulli means. It then sets w_hat[i]=1 if d_hat[i]>gamma/2, else 0, and accepts only if the **ACTUAL ORIGINAL** verifier R(G,w_hat)=1.

Hoeffding plus a union bound: estimating all M+1 means to gamma/16 requires

    N >= 128 gamma^-2 ln(2(M+1)/beta)

fresh calls per mean for failure probability at most beta. Each d_hat has error <=gamma/8. For w_i=1, d_hat_i >=gamma-2delta-gamma/8>=3gamma/4; for w_i=0, d_hat_i <=2delta+gamma/8<=gamma/4. Threshold gamma/2 exactly recovers w. Total O((M+1) gamma^-2 log(M/beta)) independent-QPT invocations per candidate, plus polynomial sampling. No adversary state is rewound or cloned; quantum advice must be independently preparable for each new instance, or given as a reproducible nonuniform circuit description. Running a huge number of fresh attacker copies may still be impractical; this is a polynomial reduction, not a practical cost certification.

The prior zero-shift hybrid is EXACTLY simulatable using only native EUF-CMA checking key pk because the real XOR share mapping (U,Z)->(D,V) is a bijection even conditioned on actual pk(K), with source ciphertexts independent of K after zero shift. Correct final seed recovery produces a fresh intended-path native signature; accepted fresh signature is itself a native forgery. Thus beyond native EUF success, an arbitrary-QPT final-key/fresh-forgery adversary yields a real-to-zero signed gap in one column/digit; apply the coordinate algorithm to obtain a valid ORIGINAL w without requesting an internal representation. For t-share adaptive openings, choose a random unopened I, simulate independently sampled other sources and classical source coins, abort on opening I, and use f=win AND never-open-I; the prior t-factor guessing and restricted auxiliary model remain. Optional real LWE adds its ordinary decisional-LWE hybrid term. The proof depends CRITICALLY on the planted GOOD theorem and does not establish independent QPT hardness of planted short-kernel search.

## Finite reproducibility

The included exact executed verify.js passed twice with identical captured output, exhaustively enumerating the COMPLETE q=17,M=3 planted ciphertext laws and their support/non-support translations, then extracting a hidden 9-coordinate binary original witness using only a noisy Bernoulli success oracle with independent calls. It separately tests two distinct valid kernel witnesses decoding the same precommitted 256-bit seed over q=257. The independent local Python checker (supplementary local archive, not automatically in this commit) passed 8,969 assertions twice. All are finite algebraic experiments, not QPT/native SLH tests.

## Unresolved obligations / exact handoff

The planted generator knows w, its planted short-kernel SEARCH QPT hardness is not justified independently, and unplanted SIS hardness does not imply it. A general classical witness-free compiler C(R,x) remains absent. The next necessary property is: for EVERY false ORIGINAL x, security of the COMPLETE public checking-key/capsule/context/auxiliary/multiple-capsule distribution under independently justified QPT assumptions, AND for EVERY hard true x any arbitrary QPT final-K recovery or fresh native challenge-path forgery -> actual W with R(x,W)=1 or independent QPT break. The coordinate method helps once its binary planted single-fiber GOOD premise is independently established, not before. Malicious N-of-N graph/abort/erasure, actual SRC burn/header/AuxPoW/coinbase/ancestor/window/DA authentication, native SLH signatures/no-EC-key-path P2MR-like output, real signing preauthorization and concrete 128-bit PQ parameters remain unproved. Nothing here changes production/main or makes Bitcoin execute NP/proof verification. Do NOT disable the continuing research automation.
