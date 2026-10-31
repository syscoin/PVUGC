# Native 256-bit secret-seed width in the surviving packet-separated LWE SOURCE release

**2026-10-30, offline restricted constructive security-width correction. This is NOT completed generic PQ witness encryption.**

## Exact predecessor and limits

The research starts from syscoin/PVUGC#1 on branch research/pq-wkem-validation-20260918 at commit 7d029ab88b1e32f85653d2bc310b1ca0cc53f5f6, open, draft, unmerged; the latest substantive comment is 6535156557. Exact predecessor research file research/pq-wkem/packet_separated_source_open_20261030/RESEARCH.md has blob 0fc4f9f849526875e135c9d6d3bf8ce12f64931c. No other GitHub repository or internet research was used.

The predecessor's 32-byte hidden master was a concatenation of **16-byte SK.seed + 16-byte SK.prf** with a public 16-byte PK.seed, following a hypothetical SLH-128-style interface. If an efficiently testable native public root is derived from only SK.seed and PK.seed, quantum exhaustive search for its 128-bit signing seed costs approximately 2^64 generic Grover queries; hiding an additional 128-bit PRF seed cannot turn that into 2^128 quantum seed-search resistance. The predecessor's <2^-128 planted-target statistical term never established native 128-bit QPT security.

This correction instantiates **32-byte SK.seed, 32-byte SK.prf, 32-byte PK.seed** as the hypothetical native 256-parameter interface, with a uniform 64-byte master K = SK.seed || SK.prf. A generic black-box Grover search over a 256-bit signing seed then has ~2^128 query cost, not a proof of total 128-bit quantum security. Native EUF-CMA, concrete LWE hardness, and the Bitcoin endpoint remain independently unproved prerequisites.

## Explicit classical PPT release

Illustrative parameters: q=16,777,213 prime, n=256, m=4469, g=524287, chi uniform independent centered errors in [-128,128], signed-unit opening weight w=2006. One honestly uniform public A in F_q^(256 x 4469) may be shared across 400 signer/scopes. All claim/packet targets, planted openings, encryption coins and native seeds are independently sampled; do not reuse these across scopes.

1. Sample independent 32-byte native SK.seed, SK.prf, and PUBLIC PK.seed. Call the actual native 256-parameter KeyGenFromSeeds to produce a genuine checking key pk, and set K = SK.seed || SK.prf. The executed checkers use a TEST-ONLY mock checking key, not real SLH-DSA. Use a PK-independent pre-funding label to derive the key, and subsequently bind pk, relation identity, actual claim/UTXO, branch, source anchors/window, context, and intended native challenge path in the final manifest; there must be no PK self-reference in seed derivation.
2. Draw independent 64-byte V uniform in GF(256)^64. Construct S_i=K+alpha_i*V bytewise over GF(256) for alpha_i=1,2,3. Each S_i is 64 bytes.
3. Convert S_i to its canonical little-endian base-32 representation of L=ceil(512/5)=103 five-bit digits. The final digit has ONLY 2 meaningful bits (0..3); the opening algorithm rejects noncanonical upper bits.
4. For each packet i and each digit ell, independently sample hidden Z_(i,ell) from T = {signed-unit z in {-1,0,1}^4469 of weight exactly 2006} and publish U_(i,ell)=A*Z_(i,ell) mod q.
5. Independently for each packet draw uniform r_i in F_q^256, centered e_c,i in chi^4469, e_d,i in chi^103; publish c_i=A^T*r_i+e_c,i and d_(i,ell)=U_(i,ell)^T*r_i+e_d,(i,ell)+g*a_(i,ell), modulo q. The public view includes A, ALL three U/c/d, native pk, scope/auxiliary/related capsules and permitted signature transcripts.
6. Public OpenPacket(i, z_(i,1..103)) accepts only if each z is a signed-unit vector of weight w and A*z=U_(i,ell). Decode each plaintext digit from d_(i,ell)-z^T*c_i using nearest circular 32-symbol codeword, then reject noncanonical final digit.
7. Public Recover(i,j) with any two DISTINCT properly opened packets interpolates the 64-byte K from S_i,S_j over GF(256), verifies reconstructed native pk against the precommitted genuine pk and manifest, then permits an ordinary off-chain native signature on the intended challenge path. The BTC endpoint does not run ORIGINAL NP proof verification.

This is an actual packet release algorithm, **not** a setup oracle providing witness-dependent SOURCE openings. No ORIGINAL NP witness->SOURCE map is supplied. For any accepted packet opening, the residual is g*a+e_d-z^T*e_c, with error at most B*(w+1)=256,896. The two strict minimum circular digit margins are g-2B(w+1)=10,495 and q-31g-2B(w+1)=10,524. Hence EVERY accepted short opening for that packet gives the identical authentic share, and any two different shares give the same precommitted K, even when legal openings have different internal states.

## Exact statistical bound, QPT assumptions and scope

For uniformly random A and independent planted Z in T, each public target column has statistical-distance bound eps <= 1/2 * sqrt((q^n-1)/|T|), |T|=2^w*binom(m,w). Across 400 scopes, three choices of protected two-packet pair, two packets per pair and L=103 columns per packet, J=400*3*2*103=247,200. The exact integer condition J^2*(q^n-1)*2^256 <= 4*(2^w*binom(m,w)) first HOLDS at w=2006 (FAILS at 2005). The approximate log2(J*eps) is -128.509352. This is statistical target uniformity ONLY, not a certified QPT hardness level.

The inherited RESTRICTED full-public hybrid applies only to honest classical setup using independent Z, QPT decidional LWE for uniform [A|U] with m+103 columns and chi noise, genuine native 256-parameter QPT EUF-CMA, and QPT authentication of scope/manifest. Adversaries may be arbitrary nonuniform QPT with independent quantum advice and coherent processing of all classical public view (including checking keys, related capsules, public context and permitted signing transcripts). At most ONE packet's planted SOURCE openings and/or encryption coins may be adaptively disclosed per target scope through classical queries; quantum-coherent leakage requests, target K disclosure, actual ORIGINAL-conditioned openings, malicious correlated setup/aborts and hidden-correlated quantum advice are excluded. Other signers and scopes must be independently generated or straight-line simulatable from the challenge view.

Under precisely those restrictions, the predecessor's two-protected-packet hybrid has the conditional form, for one target scope:
  Pr[Win] <= 3*(2L*eps + 2*Adv_QPT-LWE(n,m+103,chi) + Adv_QPT-native-EUF + Adv_QPT-auth).
For 400 target scopes every term needs an additional 400-factor conservative union/target-guessing reduction. The LWE assumption must cover the 103-column challenge; it cannot silently use a bounded 52-column assumption. This does NOT constitute an independently checked complete QPT proof or a generic NP WKEM reduction.

Illustrative SOURCE plus three packet storage: one A=3,432,192 bytes; 400 scopes each with 3*n*103 target elements and 3*(m+103) ciphertext elements at 3 bytes per field element gives 114,816,192 bytes, versus 67,630,992 before this width correction. This excludes native signatures, genuine key material, N-of-N setup transcripts and Bitcoin scripts. No concrete QPT 128-bit LWE calibration is claimed.

## The ORIGINAL-witness security gap is unchanged

Still missing an honestly witness-free classical PPT Comp(R_original,x,context,pk) and PUBLIC Lift(x,W,A,U1,U2,U3), such that EVERY valid ORIGINAL witness W opens AT LEAST TWO independent packet targets to the same precommitted K, including distinct valid W that retain distinct states. This must be jointly simulated with the LWE challenge WITHOUT its secret. Neither an oracle for SOURCE openings nor a marginal LWE ciphertext hybrid satisfies this obligation.

Also still unproved: FALSE-instance complete-public secrecy for arbitrary ORIGINAL statements, and arbitrary unauthorized hard-TRUE native key recovery/forgery -> an actual ORIGINAL witness or an independently justified QPT break (without attacker-volunteered internal representations). One honest N-of-N setup and erasure, abort-safe pre-funding graph, data availability, authentic SYS/BTC qualification and a hypothetical no-EC-key-path native-PQ Bitcoin endpoint remain separate obligations. Do not deploy or merge.

**Next exact missing equation:** Comp and Lift must generate source-dependent, all-ORIGINAL-witness openings together with an LWE challenge simulator, such that R_original(x,W)=1 implies Recover(Lift(x,W))=K* and arbitrary unauthorized full-public recovery implies ORIGINAL witness or independently justified QPT hardness break.

## Exact executed check and reproduction

checker.js (Node.js, plain standard JS) was generated from the exact runCheck function executed during this iteration. Captured result is OUTPUT.json. A separate local Python checker was executed TWICE with byte-identical output and 44,507 assertions per run. Both verify exact BigInt planted-target threshold minimality, strict decrypt margins, 64-byte GF(256) 2-of-3 reconstruction, canonical 103-digit packing and storage; the Python checker also tests small toy packet decryption. Neither executes real SLH signatures or QPT attacks.
