# Affine-group-shift black-box ORIGINAL witness extraction — restricted planted SOURCE

Research record: affine-group-shift-extractor-20261028-turn11. OFFLINE. Repository syscoin/PVUGC, open/draft PR #1, research/pq-wkem-validation-20260918. Starting SHA 8413fcb545d72b9683a36122215dc534726f898a. Predecessor research/pq-wkem/coordinate_shift_planted_extractor_20261028/RESEARCH.md, blob 87a8ec29f89911c59ca840e3e63fca008ae37a03; exact predecessor checker blob 8ee2e1968110bd57fe82770ce195d7da69f28bed; latest substantive top-level comment 6476316756. No outside research.

## Constructive change and precise limits

Proved a group-shift theorem that replaces coordinate-by-coordinate black-box extraction from the predecessor with adaptive group testing. It reduces fresh nonuniform-QPT adversary invocations for sufficiently sparse planted anchored binary witnesses, with no extra cryptographic premise. It does NOT solve the witness-free generic-NP SOURCE compiler, independently justify planted short-kernel QPT hardness, or establish a practical 128-bit PQ KEM. Its bound is a conditional reduction optimization inside the predecessor's independently calculated restricted GOOD planted-source Fourier/TV theorem, not a new hard-true assumption or a security claim for arbitrary false NP instances.

## Exact Build and every-ORIGINAL-witness Release (unchanged)

Fix odd prime q; public G in F_q^{r x M}; anchored binary ORIGINAL relation R(G,w)=[w in {0,1}^M, w0=1, sum w=h, Gw=0]; g=2h+1, b=floor(q/g)>=2; kappa-bit genuine native signing seed K with authentic checking key pk(K). Independent uniform U,Z in {0,1}^kappa give published D=U xor Z and V=K xor U. Encode Z in ell=ceil(kappa/log2(b)) radix-b digits a_j. For independently sampled hidden u_j uniform in F_q^r and eps_j uniform in {-1,0,1}^M, Build publishes

    p_j = G^T u_j + eps_j + g*a_j*e0  (mod q).

The full public output comprises ORIGINAL relation/statement G, checking key pk(K), all capsules, D,V, intended claim/UTXO/branch/context/anchors/window, allowed auxiliary data and permitted related-capsule transcripts. Build and Release are classical PPT; the endpoint native signature and no-EC-key-path output are only conditional assumptions, NOT implemented Bitcoin functionality.

Release publicly verifies the ORIGINAL predicate on each supplied W, then projects w^T p_j=g*a_j+w^T eps_j. Because w is binary with h nonzero coordinates, |w^T eps_j|<=h. With g=2h+1 and q>=2g, each radix digit is uniquely decoded. ANY valid ORIGINAL W returns the SAME precommitted Z and K=V xor D xor Z without requiring the same intermediate state or a canonical witness.

An optional previously instantiated source-dependent ordinary-QPT-LWE hybrid replaces hidden uniform u by the challenge output (A,A^T s+eta), publishing the genuine A, computing G^T times that challenge output and keeping pk/D/V correlations. It does not require a SourceOpen oracle or infer hard-true security from LWE. The present new lemma uses direct uniform masks.

## Full-public group-shift theorem and proof

Condition on public G and a nonzero digit a. Let P_a be the complete M-coordinate law of G^T u+eps+ga e0, P_0 the unshifted law. The predecessor's GOOD planted-source bound states for the unknown anchored binary w that both P_t are within statistical distance delta of P_t^(w), for t=0,a. P_t^(w) first draws label L=w^T eps+g*t and then uniformly samples the ENTIRE affine fiber {p:w^T p=L}. This comparison distribution is NOT used as a sampler by the reduction. The GOOD premise is NOT established for arbitrary G, x, or all false NP instances.

Fix a target hybrid column, public checking-key/real XOR-share correlations, context, permitted classical signing/opening oracles, independent related-capsule randomness and auxiliary input Y which is conditionally samplable from public G and digit a independently of the hidden target mask/error. Define bounded f(p) in [0,1] as the probability a freshly initialized arbitrary-QPT adversary succeeds at FINAL native K recovery or fresh intended-path signature forgery (and never opens any protected target share) when that column is forcibly set to the arbitrary classical vector p. The other complete public variables retain their authentic conditional correlations. The adversary's internal computation may be fully quantum/coherent; samples/queries are classical, independent fresh invocations, NOT a rewind or quantum oracle to f. Unclonable single-use quantum advice, coherent opening/signing queries, target-secret-correlated auxiliary leakage and opened same-K target shares are outside this theorem, as in the predecessor.

For a group S subset of coordinate positions, draw uniform v over F_q^S (zero outside S) independently and define

    Delta = E_{P_a} f - E_{P_0} f >= gamma > 0,
    T(S) = E_{p~P_a,v} f(p+v) - E_{p~P_0,v} f(p+v).

If S is disjoint from supp(w), w^T v=0, and the ideal complete affine-fiber laws P_t^(w) are invariant under adding v. If S intersects supp(w), then because some w_i=1, the scalar w^T v is exactly UNIFORM on F_q, making the ENTIRE smoothed ideal vectors exactly uniform on F_q^M in both games. Therefore the ideal T*(S) equals Delta* on a miss and zero on a hit. Full-vector total variation contracts under the public randomized translation map. Importantly, Delta is itself a real-law gap; accounting for comparisons of both the smoothed and the unsmoothed laws gives the exact valid bounds

    |T(S)| <= 2*delta                           on a hit,
    |T(S) - Delta| <= 4*delta                  on a miss.

This is a full-public success-function statement for arbitrary bounded f, NOT a marginal pad argument, a supplied-representation extractor or a SOURCE-opening assumption.

Suppose the predecessor's final-key/native-forgery hybrid isolates one column and digit with positive signed Delta>=gamma, and its independently established GOOD bound gives delta<=gamma/16. Estimate both means of T(S) within gamma/8 each using fresh independent adversary invocations. Then miss groups have estimated T(S)>=gamma/2, while hit groups have |estimated T(S)|<=3gamma/8. Comparing with threshold 7gamma/16 tests whether S intersects the hidden support. Hoeffding and a union bound over at most Q adaptive queries give total failure <=4Q exp(-N gamma^2/32), for N >= 32 gamma^-2 ln(4Q/beta) fresh calls PER MEAN; the conditional bound holds at adaptive nodes given freshly sampled coins.

With w0=1 specified by the ORIGINAL predicate, binary split unknown indices 1,...,M-1; descend only into positive groups and mark positive leaves. Verify the reconstructed w using the ACTUAL ORIGINAL predicate R(G,w)=1 before accepting. If h=1, check e0 directly. For L=ceil(log2(M-1)), a deterministic group-test bound is

    Q <= 1 + sum_{d=1}^L min(2^d, 2*(h-1)).

Compared with the predecessor's M+1 means, each estimated using N >= 128 gamma^-2 ln(2(M+1)/beta) QPT calls, this gives the following bound improvements (logs/failure beta comparable): M=256,h=8 -> Q<=85 versus 255 coordinate tests, approximately sixfold fewer calls; M=1024,h=128 -> Q<=1017 versus 1023 coordinate tests, approximately twofold fewer. This counts extractor oracle calls, NOT Build/Release operational throughput or certified attack costs. A reducer may choose the coordinate method if its public M,h predict cheaper work.

Candidate hybrid-index/digit discovery, sign selection, genuine native-EUF-CMA zero-hybrid simulation, permitted sibling openings and optional ordinary-QPT-DecLWE hybrid are unchanged from the predecessor. All public target samples P_a and P_0 and group translations can be generated from public G and independent classical source coins without knowing w. No adversary internal representation is requested.

## Verification and exact remaining gap

The published verify.js is the exact twice-executed source of a deterministic classical V8 checker, and output.json is its captured result. It passed 215669 finite checks twice identically. Exact q=11,M=4 enumeration constructs complete ciphertext-vector laws with 6655 distinct states, verifies entire-vector group-smoothed equality for hit coordinates and invariance for missed coordinates, and exercises all 16 subgroup quotient laws. In a toy M=256,h=8 systematic rank-(M-1) SOURCE, a black-box classical success oracle yielded the ORIGINAL anchored witness after 83 subgroup queries versus 255 per-coordinate queries. Twelve two-valid-witness tests retained same protected-digit release. THIS TOY SOURCE IS EASY TO SOLVE and is NOT an independent planted-hardness test; there was no actual native-SLH implementation or QPT cryptanalysis. A separately executed extended local-only Python checker passed 215927 assertions twice; preserve its exact bytes/output in the attached offline archive. Local Python SHA-256: 4ad6c714a754b4c4a07802a0b6437d2c75ec60d1c5be1cbb3e65ccb0949c80af; output SHA-256: 212fe3eded2d2a834a0b2cdd085eb1048b3b2b1394f5e9a37f7e5ddb19f51c20.

NEXT MISSING CONSTRUCTION: a classical polynomial-time, witness-FREE C(R,x) for arbitrary ORIGINAL NP with a jointly simulated source-dependent public capsule/checking-key/context/related-capsule distribution; every valid ORIGINAL witness must release one SAME precommitted capability; all false x must hide it; arbitrary hard-true final-K recovery or fresh intended-path native forgery must reduce to actual ORIGINAL W or an INDEPENDENT QPT break without attacker-supplied representation. The planted generator knows w; planted-short-kernel QPT hardness is unproved and ordinary unplanted SIS/LWE cannot substitute. General false security, malicious N-of-N setup/abort/erasure, bypass graph, pre-funding signatures/data availability, full SYS/BTC headers/AuxPoW/tags/ancestor/fork/window checks, censorship/observer inclusion and conditional native Bitcoin PQ endpoint remain unresolved. Preserve the current research automation; NO complete WKEM or deployment claim.
