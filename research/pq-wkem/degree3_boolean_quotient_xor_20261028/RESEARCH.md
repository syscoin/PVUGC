# Degree-3 Boolean-quotient SOURCE — a new exact false-instance certificate (NOT generic WKEM)

Record: degree3-xor-cycle-source-20261028-turn11; offline, no outside literature. syscoin/PVUGC draft/open PR #1, research/pq-wkem-validation-20260918, expected starting SHA 27ff4106020426c8abfac193cafbdb6aa79c0d82. Read latest substantive issue comment 6477810915 and exact predecessor research blobs 54fe531fb63e271ae91f0fa1d88afba2f0ac14c4 (affine group extractor), 3d708d2b9ceeb211299ab27a60d480f82739ddc4 (planted spectral extractor), and 66bd316622cefeb27dd2e80e56618df6f0168363 (uniform-source release). The new result is a **genuinely instantiated restricted false-source compiler**. It does NOT repair arbitrary hard-true final-key-to-ORIGINAL-witness extraction or provide independently justified planted SIS/LWE QPT hardness.

## Explicit witness-free compiler and public release

Given an ORIGINAL NP Boolean verifier R(x,W), deterministically introduce Boolean gate wires z (including W) with gate polynomials f_i(z)=0, and work in the finite-field Boolean quotient z_i^2=z_i. Context x must bind the ORIGINAL relation identity, actual claim/UTXO, branch, anchors/window, intended checking key/capability and proof/evidence. For a fixed constant d, index columns by all squarefree monomials z_S, |S|<=d; there are M=sum_{j=0}^d C(n,j). Include a SOURCE row of coefficients for every reduced product z_T*f_i whose squarefree degree is at most d. Select actual linearly independent rows G_x from this public row collection. Source construction needs only R,x, never a witness; it costs n^{O(d)} for fixed d and is NOT asserted efficient for large n.

Every valid ORIGINAL witness W determines the unique honest evaluated gate state z=z(x,W) and binary moment vector phi_d(z)_S=prod_{i in S}z_i. It has anchor phi_empty=1 and G_x phi=0. Distinct valid ORIGINAL witnesses MAY retain distinct states/moment vectors.

Honest classical Build runs real native KeyGen to get K and genuine pk(K), then samples independent uniform kappa-bit U,Z and publishes D=U xor Z, V=K xor U. With prime q>4M+2, g=2M+1, b=floor(q/g)>=2, write Z in ell=ceil(log_b(2^kappa)) radix-b digits a_j. Independently sample u_j uniform F_q^r and eps_j uniform {-1,0,1}^M and publish whole vectors

    p_j = G_x^T u_j + eps_j + g*a_j*e_empty   (mod q).

The full public output includes R,x,G,p_j, real pk(K),D,V, typed context/auxiliary data, eligible related capsules and opening transcripts. Neither u nor eps is disclosed. Public OFF-CHAIN Release checks the actual ORIGINAL R(x,W), computes phi_d(z(x,W)), and projects phi^T p_j = g*a_j + phi^T eps_j, |phi^T eps_j|<=M. Cyclic digit centers are separated by >=2M+1, so EVERY valid ORIGINAL W decodes the SAME Z and the SAME precommitted K=V xor D xor Z deterministically. There is no canonical-witness or common-intermediate-state requirement, no on-chain NP/proof/VM checking, no release authority. A real native no-EC-key-path SLH-like Bitcoin endpoint is only an assumption, not deployed.

## New exact d=2 versus d=3 separation

Use three Boolean variables x0,x1,x2 and f_ij=x_i+x_j-2*x_i*x_j-1 (zero means xi XOR xj=1). The ORIGINAL three-edge odd triangle f01=f12=f02=0 is FALSE. With d=2, 7 squarefree monomials and 12 rows give rank 6 over F_257. The formal vector (1,1/2,1/2,1/2,0,0,0) is in the degree-2 kernel with anchor 1, so e_empty is NOT in that rowspace. This is a fake formal moment, NOT a valid ORIGINAL witness, not a short opening, and not a demonstrated attack.

With d=3, the cubic monomial x0*x1*x2 and all allowable Boolean-reduced multipliers give 8 columns, 24 rows, rank 8. There is an **explicit six-row refutation certificate**, valid exactly in the Boolean quotient:

    1 = -f01 - f02 + (1-2*x0-2*x1+4*x0*x1)*f12.

Its coefficient list is -1 at (f01,1), -1 at (f02,1), +1 at (f12,1), -2 at (f12,x0), -2 at (f12,x1), +4 at (f12,x0*x1), all others zero. The identity follows from 1+f01+f12+f02+2*f01*f12 = 2*x1*(x1-1)*(2*x0-1)*(2*x2-1) = 0 modulo x_i^2=x_i. Thus G^T lambda=e_empty after choosing 8 independent original rows. This is an actual false instance newly certified by d=3, not merely a rank basis change.

For a TRUE analogue f01=f12=0 and x0 XOR x2=0, the d=3 source rank is 6 and exactly two ORIGINAL witnesses (0,1,0) and (1,0,1) have different moment states but release the identical K. Toy q=257, M=8, g=17, b=15, ell=66 for a 256-bit mock seed, giving 528 ciphertext coordinates. q=257 and all generated seeds in the checker are toy; there is NO 128-bit QPT calibration, native SLH implementation or Bitcoin deployment.

## Instantiated whole-public QPT certified-false theorem

When a fixed SOURCE matrix has verified G^T lambda=e_empty, for each digit a, each error vector eps and any mask u:

    G^T u+eps+g*a*e_empty = G^T(u+g*a*lambda)+eps.

Since u is UNIFORM over its full finite-field row space, the complete ciphertext-vector law (not just a projection) is exactly independent of a. Conditional on genuine native K and pk(K), the map (U,Z)->(D=U xor Z,V=K xor U) is bijective. Hence D,V are independent uniform conditional on K. A straight-line QPT native-EUF-CMA simulator given only genuine pk(K) generates the ENTIRE false-instance view (G,p,D,V,typed context, independently samplable permitted auxiliary data) without K, a source opening, or the challenge secret. Usable native-K recovery converts to a fresh intended-path native signature; a fresh accepted signature is itself a native forgery. Exact simulator gives

    Pr[unauthorized FINAL K or fresh intended-path native forgery]
       <= Adv_QPT_Native_EUF-CMA

for honestly generated certified-false capsules, real KeyGen distribution and the appropriate native signing-query/freshness model. It holds against coherent internal QPT computation and ordinary independent classical-query oracles, without classical rewinding, random-oracle programming or an ideal extractor. Multiple unopened same-K certified-false capsules may be simulated when all target source masks/shares are independently sampled and no opened same-K or true sibling leaks K. Independent-key siblings with permitted classical adaptive openings can be simulated using known keys. Secret-correlated auxiliary leakage, malicious N-of-N setup/erasure/abort, arbitrary coherent source/opening oracles and unclonable secret-dependent advice are excluded.

An OPTIONAL ordinary QPT-DecLWE bridge embeds (A,y) into the source as p=G^T y+eps+g*a*e with real public checking-key/share correlations, but does NOT prove arbitrary false or hard-true security. Under earlier n>=r uniform-secret sampling, the LWE wrapper may even be statistically redundant. This advance uses exact uniform row masks and no independent LWE hardness claim.

## Reproducibility and exact handoff

The committed verify.js is constructed directly from the function **actually executed** in the publication call, and committed output.json is its captured result. Independently, a longer local standard-library Python checker was executed twice with identical output, 6,492 assertions each; it verifies the d2/d3 ranks, six-row identity, d2 fake, 1,500 actual full-vector false shift couplings, 32 mock 256-bit two-original-witness SAME-K releases, and miniature exhaustive conditional XOR bijections. These tests establish finite-field algebra only, NOT QPT hardness. The published compact JS checker performs the same core claims with its own reported assertions/trials.

Open: a classical witness-FREE source compiler with all-false full-joint-output hiding for arbitrary NP statements and an actual reduction from arbitrary QPT unauthorized hard-true native-K recovery or fresh intended-path forgery to ORIGINAL W or an INDEPENDENT QPT cryptographic break, **without requesting an adversary-supplied moment representation**. Exact desired equation:

    Pr[A(View(R,x,K)) -> usable K or fresh intended native signature]
       <= Pr[R(x,E^A(R,x))=1] + Adv_QPT_independent_break + negl.

No such general proof or independently justified hard-true SOURCE premise was obtained. Higher degree alone scales badly and does not solve the gap. Also unresolved: source burn/headers/AuxPoW/tags/interval/ancestor/fork rules; N-of-N preauthorization, one-honest exclusion/erasure, abort, presignature/DA, transaction graph and timely observer evidence under reorg/censorship; hypothetical native PQ no-EC-key-path Bitcoin endpoint. Do not disable the existing research automation.
