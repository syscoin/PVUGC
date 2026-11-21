# STM-QPT-20261031: polynomial-capsule telescoping and native master-seed release

Status: restricted constructive theorem and executable release component for honest uniform binary-ISIS SOURCE; **NOT a completed post-quantum witness-KEM, generic ORIGINAL compiler, adversarial-FALSE security theorem, calibrated QPT-128 parameter set, or native Bitcoin deployment.**

Continuity: syscoin/PVUGC PR #1, open/draft/unmerged on research/pq-wkem-validation-20260918 at verified beginning head b348495b58e9778cf39f06bfcecd2e4e427b5120. The latest substantive ordinary comment inspected was 6553585207. Exact predecessor texts read: ICSO-2 RESEARCH.md Git blob 0330a6425ae0219efc9b102509aec6ffafb4470e and native_256bit_master_20261030 RESEARCH.md Git blob 3d992b47ab3dec20f2badd60bfceadf07c26f0e8. No other repository or external literature was searched.

## 1. The concrete classical-PPT release algorithm

Native signature assumption: an ordinary native signing family admits canonical 256-parameter private key representation (SK.seed[32] || SK.prf[32] || PK.seed[32] || PK.root[32]), with actual public checking key vk=(PK.seed[32] || PK.root[32]); actual KeyGenFromSeeds and Sign/Verify produce and check genuine correlations. This is hypothetical for the proposed Bitcoin no-EC-keypath SLH-like endpoint and is **not** an assertion of deployed capability. SK.seed and SK.prf have **256 bits each**, correcting NCSR/ICSO-2's prior two-128-bit-seed width mismatch.

Conservative raw-core mode: sample the two native private 256-bit seeds independently uniformly and encrypt all 512 bits; use 37 fourteen-bit symbols per XOR lane. There is no added PRG premise in this mode.

Optional compressed-master mode: choose m uniformly in 256-bit strings and use G(m)=SHAKE256(domain || m, 64 bytes), parsed as SK.seed and SK.prf. The concrete domain is PVUGC.offline.STM.master-expander.v1 followed by one zero byte. Choose independent PK.seed and run actual native KeyGenFromSeeds to determine genuine PK.root/vk. Encrypt only m (19 symbols per lane), rather than the two derived 256-bit secret fields. This compression adds an **explicit, currently unproved, nonuniform-QPT 256-to-512 PRG assumption on G**. It is NOT a like-for-like efficiency result under unchanged assumptions. In particular a 256-bit input may admit roughly 2^128 generic quantum seed search, while the former 128-bit SK.seed could admit roughly 2^64; neither observation is a concrete full security calibration.

Use q prime, d,n,B,b and g=floor(q/2^b). Generate A uniform in F_q^(d×n) and t uniform in F_q^d, independently of private master and native KeyGen. There is **no planted, retained or oracle-supplied SOURCE witness**. Restricted relation R_SRC((A,t),w)=1 iff w is binary length n and A w=t mod q. No claim that this source represents an arbitrary ORIGINAL NP statement.

For C related capsules (C polynomial), and for payload K equal either the 256-bit master or the 512-bit raw private core, independently select U[c,0],U[c,1] as uniform payload-length strings; put U[c,2]=K xor U[c,0] xor U[c,1]. This creates independent 3-of-3 XOR sharings of exactly the same precommitted payload, with NO assumption that the three lanes or capsule labels agree across capsules.

For each capsule, lane, and packed b-bit symbol a, sample independently s uniform in F_q^d and each component of e in {-B,...,B}^n and e_star in {-B,...,B}; publish

  beta = A^T*s + e (mod q)
  tau = t^T*s + e_star + g*a (mod q).

All error coins are ordinary unconditioned LWE sampling. There is no SourceOpen oracle, security-relevant rejection or setup certificate. The complete public view includes R_original, x, relation identity, scope with actual claim/UTXO, branch, anchors/window/context, intended native vk, all capsules, all capsule hashes, genuinely signed manifest/preauthorization P-domain transcripts, checking key, authentication keys/receipts, and allowed auxiliary data. N-of-N preparation, watcher data availability, abort/refund graph and actual Bitcoin PQ signature verification are separate conditional protocol requirements.

Public **OFF-CHAIN** Lift(c,w) checks the binary SOURCE predicate, computes rho=tau-w^T*beta mod q per symbol, nearest-decodes 2^b circular symbols, checks canonical final padding, recovers three share plaintexts, XORs to payload, and for compressed mode expands G(payload) into both 256-bit private fields. Rebuild canonical native secret signing key from private fields plus the actual public vk; independently re-run actual native KeyGenFromSeeds and reject if its vk disagrees with the precommitted vk. Then use ordinary native Sign on the intended challenge transaction/path. Bitcoin is **not** required to verify ORIGINAL NP evidence, VM steps or any general proof. Different valid SOURCE witnesses may obtain different noise/intermediate states while obtaining the SAME precommitted signing key.

## 2. Every valid honest random-SOURCE witness decodes the same payload

For fixed binary w satisfying A w=t, rho=g*a+e_star-w^T*e (mod q). Independent uniform errors have zero mean, bounded absolute value B, and variance B(B+1)/3. Set V=(n+1)*B*(B+1)/3, u=ceil(g/2), T=3*C*ceil(payload_bits/b). For every fixed binary w, the honestly uniform (A,t) event Aw=t occurs with probability q^(-d), independently of errors. Bernstein and a union bound over **every** binary w and all T symbols imply

  eta_C <= T*2^n*q^(-d)*2*exp(-u^2/[2*(V+B*u/3)]).

For distinct binary w,w' over odd prime q, the random SOURCE membership events are pairwise independent; with N their count, E[N]=2^n/q^d and Var(N)=E[N]*(1-q^(-d)). Thus delta=P[N=0] <= (q^d-1)/(2^n+q^d-1). Conditioned on TRUE, all-valid-witness/all-capsule failure probability is <=eta_C/(1-delta). This is honest-setup probabilistic completeness, NOT deterministic correctness for every emitted capsule and NOT adversarial-SOURCE security. Illustrative uncalibrated q=1099511627689, d=512,n=20680,B=16384,b=14 yield log2(eta_2)=-191.487287765 in compressed mode (T=114). For C=8, log2(eta_8)=-189.487287765. No computational QPT 128-bit hardness is inferred from these correctness exponents.

## 3. The new C-polynomial adaptive-opening theorem

Adversary: arbitrary nonuniform QPT with coherent processing of the complete **classical** joint public view and independent quantum advice, but only classical adaptive opening and signing queries. It can disclose at most TWO distinct complete XOR lanes per capsule, with authentic plaintext and all encryption coins, even if the unopened lane differs across capsules. It can condition queries on prior ciphertexts and disclosures. Excluded: individual-bit/cross-lane leakages, coherent opening or signing-oracle queries, target master leakage, malicious SOURCE setup, secret-correlated public advice/metadata, builders retaining coins, and the ORIGINAL-witness challenge itself. Only genuine public checking keys and authentically signed P-domain manifests are permitted; all auxiliary context must be simulatable from source/scope, genuine vk, independent ceremony keys/coins and classical P-domain signing-oracle answers. Native challenge-domain signatures are never preauthorized.

Let E denote a fresh ordinary native challenge-domain signature or recovery of a usable native secret key which can generate such a signature. Hold an independent uniform dummy payload D of the same size as K. For c=0..C define joint games H_c: first c capsules encrypt independent fresh 3-lane XOR sharings of D; remaining capsules encrypt independent fresh 3-lane sharings of the actual K. All use the SAME honest uniform A,t, genuine native vk generated with actual K, all actual signatures, signed hashes, auxiliary data, and independent encryption coins.

For one adjacent transition H_(c-1) -> H_c choose only one target capsule c. Guess J uniformly in {0,1,2}. Sample the two other lane plaintexts uniformly; derive lane J by XOR with K in the first arm, D in the second. In either entire endpoint game the full vector of three shares is uniform among triples with the required XOR and hence **independent of J**. Any classical opening query for J aborts; other lanes and all other capsules are genuinely simulated with known coins. On a non-aborted final event E, let O_c be its (adaptive) opened-lane set and accept E with additional probability 1/(3-|O_c|). The exact per-transcript identity is

  (1/3) * sum_(J=0..2) [J not in O_c]/(3-|O_c|) = 1/3,

because |O_c|<=2. It holds with adaptive queries and coherent quantum adversarial computation: in each **genuine endpoint**, J is independent of the complete view and resulting classical transcript. No classical rewinding, representation extraction or invalid conditioning on survivor transcripts is used. Thus the weighted-abort endpoint success probability equals Pr_H[E]/3, and only ONE capsule's protected lane needs to be guessed per transition.

For each of L packed symbols of J, change genuine Enc(a_real) to genuine Enc(a_dummy) via Enc(a_real)->Uniform->Enc(a_dummy). Interpret an ordinary QPT decisional-LWE challenge as M=[A^T;t^T] uniform in F_q^((n+1)×d) and y either M*s+chi^(n+1) or uniform. Shift the last coordinate of y by public g*a_real or g*a_dummy. Other ciphertexts are locally sampled using the very same M with independent coins. In these reductions the **actual native sk is known**, hence actual correlated vk and signing of the actual challenger-ciphertext-bound manifest are generated correctly. Opening J aborts, so unknown challenge coins are never required. Every other opening transcript is genuinely answered. Under the exact nonuniform-QPT decisional LWE assumption,

  |Pr_H(c-1)[E]-Pr_H(c)[E]| <= 3*(2*L)*eps_LWE.

Telescope c=1..C; these losses **ADD** rather than multiply:

  |Pr_H0[E]-Pr_HC[E]| <= 6*C*L*eps_LWE.

Unlike ICSO-2's simultaneous 3^C protected-lane guess, the new theorem has POLYNOMIAL loss O(C*L), even with different adaptively chosen unopened lanes across polynomially many capsules. Earlier dummy capsules can be simulated with known D; later genuine ones with known K. This is the independently established restricted joint-public-output composability advance. It works equally for the conservative raw-512 payload (L=37, no PRG needed) and compressed 256-master payload (L=19, extra PRG needed).

## 4. Checking-key correlations and PRG/native final hybrids

After *all* ciphertexts encrypt dummy D, the published ciphertext plaintexts, openings and coins no longer depend on the native master K. ONLY NOW can the compressed-mode reduction change the native private seed pair from G(K) to uniform 512 bits. A QPT PRG challenger gives X either G(K) for a hidden uniform K or a genuine uniform 512-bit pair. From X the reducer generates native actual pk/vk, correctly correlated signatures/manifest, independent dummy ciphertexts and all permitted source/scope/auxiliary data. Since K itself is not required after dummy replacement, the complete full-public distribution is simulatable. **Doing this PRG switch before dummy replacement would be invalid**, because X=G(K) does not give the reducer the master K needed to construct authentic encrypted share plaintexts. This order closes a concrete public-correlation simulation obligation, not just a marginal pseudorandom-seed assertion.

In the resulting final uniform native-key game, a genuine native QPT-EUF-CMA challenger gives vk and a classical signing oracle. All capsules encrypt known dummy D independently of the native secret; every allowed whole-lane opening is answered with actual coins. All independent N-of-N authentication keys can be generated locally. Signed preauthorizations on strictly disjoint P domain use classical signing queries. Any E provides a fresh ordinary challenge-path signature; a recovered secret key is used to make that signature. No adversary-supplied internal SOURCE representation is requested.

Restricted compressed bound (without silent assumptions):

  Pr_real[E] <= 6*C*L*eps_nonuniform-QPT-decisional-LWE
              + eps_nonuniform-QPT-PRG(G)
              + eps_native-QPT-EUF-CMA(classical signing queries)
              + eps_public-authentication.

For raw-512 mode remove the PRG term and set L=37. If explicitly conditioning the honest uniform SOURCE on TRUE, divide the unconditional bound by 1-delta. The native signing family, q/d/n/B parameters and SHAKE expander have not been independently calibrated to computational 128-bit QPT security; the SHAKE QPT-PRG property is an unproved assumption, not a consequence of LWE by fiat.

## 5. Resource and negative controls

At above illustrative parameters, one shared public matrix is 52,940,800 bytes. For C=2, compressed master has 3*2*19=114 vectors, 11,788,170 ciphertext bytes; raw-512 has 3*2*37=222 vectors, 22,955,910 ciphertext bytes. These figures exclude context, genuine native signatures, large off-chain ORIGINAL evidence, ceremony and Bitcoin scripts. Classical-PPT matrix-vector encryption is extremely expensive; no practical deployed scheme is claimed. The compressed saving is CONDITIONAL on the added QPT PRG assumption, not a demonstrated same-assumption security improvement.

Fatal chosen-FALSE control: with A=[1], t=[3], no binary witness satisfies A*w=t, but public NONBINARY z=3 yields tau-3*beta=g*a+e_star-3*e. In the supported zero-error case every secret-master symbol is recovered. The attacker reconstructs the real native key and can sign the intended path without any ORIGINAL witness. Checking binary shape inside honest Lift is not a cryptographic gate; the earlier CORN/QGL nonbinary/interpolation counterexamples remain. There is also no ORIGINAL NP -> SOURCE compiler, no generic hard-TRUE recovery-to-ORIGINAL extraction, no malicious N-of-N setup theorem, and no complete SYS/BTC/Bitcoin native PQ consensus implementation.

## 6. Reproduction, exact obligation and checkpoint

The **published executed JavaScript checker** is the precise self-contained function in checker.js, with captured output.json. It checks 12,390 finite-algebra assertions: 343 three-capsule joint opening-pattern distributions, 2,401 four-capsule single-transition vs global survivor identities, adaptive classical opening, toy binary-SOURCE/LWE symbols and known FALSE nonbinary recovery, corrected 512-bit native private-seed width, LWE vector counts/bytes and honest correctness exponent. It is **not** a cryptographic proof of quantum hardness. An extended **LOCAL-ONLY** Python checker, using genuine *classical Ed25519* fixture correlations, 256-bit master SHAKE expansion, 512-bit raw fallback, three valid SOURCE witnesses, 3 related master capsules, 2 raw-native capsules and the same disclosure patterns, executed twice identically and passed 12,453 assertions. Its exact RESEARCH.md/checker.py/output.json/provenance.json are preserved in the local evidence archive, whose separate SHA-256 should not be conflated with published file hashes. No external literature research or independent agent was invoked.

The next indispensable equation remains a witness-free classical-PPT Comp(R_original,x,scope,vk) plus public Lift(C,W_original) such that EVERY valid ORIGINAL witness recovers the SAME precommitted signing capability, jointly with a simulator for all SOURCE-opening/checking-key/context/capsule correlations, and arbitrary unauthorized QPT adversarial-FALSE or hard-TRUE final-key recovery/native forgery => actual ORIGINAL witness OR independently justified PQ break. No SourceOpen oracle, assumed common intermediate, canonical common preimage, or volunteered representation. The STM theorem does **not** establish this. Do not merge or deploy, and do not disable the research automation.
