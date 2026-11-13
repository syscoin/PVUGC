# Multi-quotient SOURCE release: exact full-public false smoothing with independent side-information

Research record: multi-quotient-source-20261028-turn11. Offline only; no external literature/web research. Repository syscoin/PVUGC, draft/open PR #1, branch research/pq-wkem-validation-20260918. Verified starting SHA e55dd4a1f5e00b51e669d499262ab80cf88f2742. Exact predecessor research/pq-wkem/uniform_rowspace_bridge_20261028/RESEARCH.md, blob 66bd316622cefeb27dd2e80e56618df6f0168363; executable verify.js blob 6dcc2a56602c0a091d6d3dad7e95461756e180f7. Latest relevant PR comment at initial read 6470963710.

**VERDICT:** New restricted full-public composition, NOT generic-NP WKEM. This note proves an exact arbitrary-quotient source-noise reduction and independently instantiates a TWO-dimensional false SOURCE that has no row-shift certificate, yet hides its entire protected digit statistically to distance 3^-128. It remains secure against disclosure of independent second-block source coins. It also proves a multi-capsule, same-native-key, unopened selective-view bound using actual native verification-key/XOR-share correlations, and describes a correct ordinary-QPT-LWE challenge simulator if using the former LWE-based mask. It does NOT prove hard-true unauthorized final-key recovery or native forgery -> ORIGINAL witness or an independent PQ break. The two-block source is deliberately false and easy to classify; it is not a general NP compiler or SYS/BTC source.

## 1. Exact whole-vector quotient theorem

Fix public G in F_q^(r x M), public protected coordinate e, and independent error eps with known source-dependent distribution E_x. Honest classical Build samples UNIFORM u in F_q^r and publishes

    p = G^T u + eps + g*a*e  mod q.

Let H=im(G^T), Q=F_q^M/H and pi be the natural quotient. Because G^T u is uniform over its image even if G has dependent rows, conditional on pi(p) the COMPLETE vector p is uniform over that coset. If mu is the actual law of pi(eps), then, for any two digits a,b,

    TV(complete P_a, complete P_b)
      = TV(mu + g*a*pi(e), mu + g*b*pi(e)).                 (1)

This is EQUALITY of complete public ciphertext-vector distances, not a marginal security assumption or a SourceOpen oracle. It holds pointwise conditional on a fixed G and public context not leaking the protected source coins. It extends the predecessor's certified-false row-shift case: if e in rowspace(G), pi(e)=0 and the shift distance is exactly zero. It also covers rank-deficient sources with e outside the rowspace, provided the actual quotient noise is smooth.

For any source, Parseval and Cauchy-Schwarz supply the exact finite-field criterion

    TV(P_a,P_b) <= 1/2 * sqrt( SUM_{z in ker(G), z != 0}
       |E_eps[exp(2*pi*i*<z,eps>/q)]|^2
       * |1-exp(2*pi*i*g*(a-b)*<z,e>/q)|^2 ).             (2)

The sum may require exponential computation; equation (2) is not an assumption, a generic efficient evaluator or a proof of arbitrary false-NP security.

## 2. Actual two-dimensional false ORIGINAL source

Take prime q=257, h=128, M=256, r=254, and e=(1,0,...,0). In each disjoint block of h coordinates include source rows

    (-j,0,...,0,1_at_coordinate_j,0,...,0), j=2,...,128.

There are 127 independent rows per block. The complete public source G has

    ker(G) = span{ z1=(1,2,...,128,0,...,0),
                   z2=(0,...,0,1,2,...,128) }.

Define the ACTUAL restricted ORIGINAL predicate (not an added surrogate):

    R(G,w)=1 iff w in {0,1}^256, w_0=1, sum(w)=2, G*w=0.

It is false. Any kernel vector with anchor 1 necessarily has first block (1,2,...,128), which is not binary. Also <z1,e>=1, so e is NOT in rowspace(G); there is no certificate G^T lambda=e. This is why the previous exact row-shift simulator alone is insufficient.

Draw genuine independent source error eps_i uniform in {-1,0,1}. Its two quotient coordinates are

    S1=sum_{j=1}^128 j*eps_(j-1) mod257,
    S2=sum_{j=1}^128 j*eps_(128+j-1) mod257.

They are independent. The digit adds g*a only to S1. For any nonzero character of F257, the half-orbit ternary product is EXACTLY -3^-128. Proof: pairing +/- j factors gives the complete product 1, because multiplication by 3 permutes all nonzero residues. The real half-product therefore has absolute value 1. Precisely 43 factors 1+2*cos(2*pi*j/257) are negative, so the sign is -1. Fourier inversion gives, for N=3^128 ternary strings,

    count(S1=0)=(N-256)/257,
    count(S1=t)=(N+1)/257 for all t != 0.

Every nonzero additive shift of S1 has EXACT total variation distance 1/3^128. S2 is independent and does not change under the protected shift; by (1), for g=5 and any distinct radix-51 digit values a,b,

    TV(the ENTIRE 256-coordinate p | a,
       the ENTIRE 256-coordinate p | b) = 3^-128.       (3)

This remains exact if arbitrary details of the independently sampled second-block u2,eps2 are revealed, as long as the first-block u1,eps1 remain hidden. It is a concrete selective-source-information correlation, not an idealized independence claim about the whole public view. The source matrix has 254 rows and 256 columns, and one illustrative 256-bit capsule uses 46*256=11,776 F257 ciphertext elements (23,552 bytes if encoded naïvely in two bytes each).

## 3. Classical Build, true Release, genuine native key correlations

For the formal conditional native security game, use a genuine classical native KeyGen that yields an arbitrary kappa-bit full secret serialization K and its actual pk; no assumption of uniform K is needed. Draw independent uniform kappa-bit U,Z; publish D=U xor Z and V=K xor U. Encode all of Z in radix-51 using ell_kappa=ceil(kappa/log2(51)) source columns. The checker uses an illustrative uniform 256-bit mock K with ell_256=46; this does NOT test native SLH, nor assert that a real native SLH secret serialization is 256 bits.

Build publishes the actual relation and x, G, all p_j, genuine native checking key pk, D,V, binding of intended claim/UTXO/branch/anchor/window/context/verification-key identity, eligible public auxiliary data and any related capsules. In a real deployment the ORIGINAL relation must authenticate those inputs and genuine burn/authorization/output evidence; the restricted example here does not. No source oracle/online release authority, NP execution by Bitcoin, new opcode, or native signature implementation is assumed.

For any TRUE source in the explicitly defined anchored binary-weight-two relation, public OFF-CHAIN Release FIRST checks the ORIGINAL relation and computes w^T p_j. Since Gw=0 and w^T e=1,

    w^T p_j = 5*a_j + w^T eps_j mod257,
    |w^T eps_j| <= 2.

Radix-51 cyclic codepoints are separated by >=5 including the final wrap gap 7. Thus EVERY valid ORIGINAL witness deterministically recovers the same Z, hence the SAME precommitted K=V xor D xor Z, although distinct witnesses need not share internal states or noise projections. The separate explicit easy TRUE source G_true=(1,-1,-1) accepts w1=(1,1,0) and w2=(1,0,1), each returning the identical 256-bit mock capability in the checker. These are not hard-true security examples.

## 4. Joint-public multi-capsule QPT reduction, precise games

Suppose t false target capsules from this explicit family share one genuine K/pk, while each uses independently sampled U_i,Z_i, row masks u_ij and errors eps_ij. Target capsules are UNOPENED. Independent-key sibling capsules, including true siblings, may be opened through classical adaptive requests because the reduction knows their separate sampled secrets. A same-K sibling with an obtainable opening trivially exposes K and is EXCLUDED. All public context and auxiliary strings must be simulatable from public x,pk and independent coins; no K-dependent side-channel, retained signing secrets, or first-block source-coin leakage. Full second-block source randomness may be disclosed independently. Only classical signing/opening oracle queries are covered; an arbitrary QPT adversary may coherently process the resulting classical transcripts and use nonuniform advice not correlated with hidden target coins.

Fix K, real pk, U_i,Z_i,D_i,V_i and all allowed aux. Use (3) and independent source coins to change every protected digit in every false target to zero, in the COMPLETE joint public view, at statistical cost at most

    delta <= t*ell_kappa/3^128.

The genuine checking-key and XOR correlations are preserved throughout this conditioning. In the zero-shift hybrid, for fixed K the transformation (U_i,Z_i)->(D_i=U_i xor Z_i,V_i=K xor U_i) is bijective, so all (D_i,V_i) are independent uniform pairs, independent of K. The zero-shift p_j are also independent of K. Thus a straight-line QPT native-EUF-CMA reduction given only genuine pk (without K) perfectly generates the final game, produces independently keyed sibling capsules, and forwards allowed native signing queries for nonchallenge messages to its genuine signing oracle. On a fresh intended-path native signature, it forges directly; on output of an exact valid native K, it signs a fresh intended challenge to forge. No adversary-supplied source representation, rewinding, quantum random-oracle extraction or quantum SourceOpen oracle is used.

Therefore, for this restricted false family under honest classical setup and the above auxiliary/opening model,

    Pr[unauthorized K recovery OR fresh native challenge forgery]
       <= Adv_QPT_Native_EUF-CMA + t*ell_kappa/3^128.     (4)

For one illustrative 256-bit seed, 46/3^128 < 2^-197. Arbitrary coherent QPT postprocessing cannot amplify the statistical distance by quantum data processing. The EUF theorem is conditional on a separately justified genuine native QPT signing-security game; the checker does not instantiate one.

OPTIONAL LWE VERSION: For every column sample public A in F257^(n x254), secret s, and independent error eta, retain unpublished y=A^T s+eta and set the EXACT same source capsule p=G^T y+eps+5*a*e. A straight-line ordinary QPT-decisional-LWE challenge simulator given (A,y) constructs this real source-dependent ciphertext, including genuine K/pk,D,V, context and independently sampled sibling correlations, WITHOUT the LWE secret or SourceOpen. Switching t*ell_kappa columns changes the distribution by <=t*ell_kappa*Adv_QPT_DecLWE(n,254,257,chi), then use (4). This is conditional on independently justified parameters/hardness and does not solve hard-true extraction; if n>=r and s is uniform, the predecessor's unconditional full-rank theorem can instead make this LWE wrapper statistically redundant.

## 5. Exact unfinished hard-TRUE equation

For any TRUE source with a valid short anchored w, projections of P_a and P_b on w have disjoint bounded-error codepoint supports for distinct a,b, so TV(P_a,P_b)=1. Therefore the statistical false-source simulator cannot be used to prove hard-true secrecy. The unresolved required reduction is:

    arbitrary QPT A(full public R,x,capsule,pk,context,aux,siblings)
        -> FINAL native K or fresh intended native signature
       implies an ACTUAL ORIGINAL witness W with R(x,W)=1
         OR an independently justified QPT break,

WITHOUT A providing an internal moment vector or representation. No such reduction is proved. Likewise no generic all-false SOURCE compiler, malicious N-of-N honest-erasure/abort graph composition, SYS/BTC headers/AuxPoW/tag/ancestor/window authenticated relation, finite-evidence/DA/censorship assumptions, native no-EC-key-path SLH output, or 128-bit QPT resource assessment is resolved. This is a restricted constructive false-view composition and does NOT qualify for completion.

## 6. Reproducibility

Exact published verify.js was executed twice offline and produced byte-identical JSON: PASS 6,012 finite-field assertions, including q=5/17/257 exact ternary counts, exact two-quotient shifts, FULL 4-coordinate public-vector exhaustive enumeration at q=5 with TV=1/9, nonexistence of an ORIGINAL anchored binary weight-two witness in the false family, and 12 full 256-bit true-source two-witness SAME-seed trials. An independent extended Python checker passed 6,829 assertions in each of two byte-identical runs, with 20 full-seed trials. Finite arithmetic and mock-seed demonstrations do not establish any QPT hardness, arbitrary true-instance soundness or native signature functionality. The complete extended notes, independent Python checker and both output sets are preserved as LOCAL artifacts; the exact executed JS checker and captured output are published here.

Next handoff: an independently instantiated computational source compiler and hard-true FINAL-key/native-forgery extractor, with full checking-key/auxiliary/multiple-capsule correlations and no submitted representation. Keep the research automation enabled; no practical WKEM solution has been established.
