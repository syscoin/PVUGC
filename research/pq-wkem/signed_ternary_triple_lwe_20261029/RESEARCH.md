# Signed-ternary constant-weight three-bit distributed LWE SOURCE

Offline, research-only iteration continuing \`packed_pair_lwe_source_20261029\` at original head \`3550fd9cd1faaa8d0c4fe95e869940c97bd0935d\`, exact predecessor blob \`5a4615d48ec6db2f107c22ff53e3b1567f541a8d\`, ordinary PR comment 6504383353. **Restricted substantive efficiency result; generic ORIGINAL-NP recovery remains unsolved.** The independently executed Python checker and longer equations are retained in the local research archive; the separately committed JS checker is exact executable source.

## Classical setup, release and deterministic SAME capability

Take odd prime q, n,m,N,J polynomial, chi efficiently sampled with support [-B,B]. Honest SOURCE setup chooses uniform A in Z_q^(n*m), uniform s in Z_q^n, e in chi^m and publishes H=[A;b^T] with b=A^T s+e. Valid SOURCE witnesses are ALL (s',e') with b=A^T s'+e' and ||e'||_infinity<=B. This does NOT compile arbitrary ORIGINAL NP. Generate the genuine native signature pair (sk,pk) and bind the complete native-secret serialization and bit length to relation identity, UTXO/claim, branch, anchors/window, challenge path and intended pk. Only same-scope related capsules may reuse this native key.

Split the complete secret into L=ceil(keybits/3) 3-bit digits a in {0,...,7}; require its padding to decode as zero. For each digit independently choose N-1 uniform q-ary shares z_i and set z_N=a-sum_{i<N}z_i mod q. A separate keyless assembler receives authenticated ciphertext contributions, never sk or private coins.

Choose the **signed constant-weight** encryption coin distribution uniformly on

    T={r in {-1,0,+1}^m : ||r||_0=w},  |T|=binom(m,w)*2^w.

Sample a uniform w-subset of [m] and w unbiased independent signs. To implement strict classical PPT, draw a uniform integer below binom(m,w) using k-bit rejection (each attempt succeeds with probability >=1/2), cap at 4 lambda attempts, combinatorially unrank, and abort BEFORE irrevocable funding if all attempts fail (probability <=2^(-4 lambda)). This is independent of sk and witness. The finite checker's seeded PRNG is not a cryptographic sampler.

Contributor i publishes u_i=A r_i and v_i=b^T r_i+g z_i mod q, g=floor(q/8), with independent r_i for every capsule/digit/participant. Assembler sums (u,v). Every valid SOURCE witness (s',e') releases off-chain by computing

    d=v-s'^T u=g a+e'^T sum_i r_i (mod q),
    |e'^T sum_i r_i|<=N*w*B.

All eight circular centers 0,g,...,7g are separated by at least g, including the last-to-zero gap q-7g>=g. Therefore **g>2NwB** gives deterministic nearest-center recovery of every digit by EVERY valid SOURCE witness for every honestly sampled coin and each independently randomized related capsule. Reassembled sk matches the real pk before producing a normal native signature off-chain. No on-chain NP verifier, adaptor arithmetic, trace dispute or tiny PQ signature is assumed.

## Full-public QPT bound under honest TRUE-LWE SOURCE only

For uniform H in Z_q^((n+1)*m), the maps r->H r over this T are exactly two-universal: any r!=r' has a nonzero coordinate difference in {-2,-1,+1,+2}, nonzero mod odd prime q. Direct complete-output second moment gives

    TD((H,H*r),(H,U_uniform))<=delta_T
    delta_T=(1/2)*sqrt((q^(n+1)-1)/|T|).

Shifting its last coordinate by g z preserves that bound; real protected-share ciphertext and encryption of zero differ by at most 2delta_T. The protected q-ary z depends on genuine sk but is independent of independently sampled H and private protected r. For a fixed-in-advance corruption cohort of at most N-1 contributors, all corrupt shares and COMPLETE encryption coins may be adaptively exposed: these shares are uniform independent of sk and reproduced exactly by the straight-line simulator. All individual and aggregate ciphertexts, genuine native pk, public relation/scope/context, independently authenticated contributions, J independently randomized same-scope related capsules, and simulatable auxiliary inputs are included jointly.

Take ordinary decisional QPT-LWE for exactly (q,n,m,chi), honest classical source sampling, independent nonuniform QPT native EUF-CMA, and only classical public/opening/signing interfaces. The straight-line games honest H -> uniform H -> replace protected contributions by zero encryptions -> honest H give

    Pr[unauthorized usable native sk recovery OR accepted fresh signature]
       <=2 Adv_QPT-DecLWE + 2 J L delta_T + Adv_QPT-native-EUF-CMA.

In the middle hybrid a native EUF-CMA challenger provides real pk, while its simulator never learns sk, protected shares/coins, or a SOURCE witness. A recovered usable sk yields an actual native fresh-message forgery. QPT attackers may coherently process all classical public outputs. No quantum rewinding, SourceOpen oracle or adversary-supplied representation is required. Exclusions: malicious dealer/key generation or corrupted setup, protected share disclosure, source-witness-correlated quantum advice, superposition interface queries, SAME-key reuse across unrelated claim/branch scopes, and auxiliary authenticators that cannot be simulated. The stated QPT assumptions are NOT empirically calibrated or independently proven here.

## Parameters and proven strict efficiency

For illustrative unvalidated prime q=16777213, n=256, m=6800, B=128, N=4, J=2, w=2000, g=2097151:

    max absolute noise = N*w*B = 1,024,000
    half minimum center gap = 1,048,575.5
    deterministic margin = 24,575.5.

The coin entropy is log2(binomial(6800,2000)*2^2000)=7936.513670 bits, compared to approximately 6800 bits for the predecessor's weight<=4095 binary support, with **exactly the same** q,n,m,chi and native signature assumption. A 256-bit secret uses L=86 rather than 128 ciphertexts. At three bytes/field element, the aggregated ciphertext shrinks 98,688 -> **66,306 bytes** (-32.81%) and all four contributions shrink 394,752 -> 265,224 bytes per capsule, excluding H (5,242,800 bytes), authenticators/framing/PKs. Approximate dominant sparse field work is (n+1)*w*L*N = 176,816,000 signed additions per capsule versus about 447 million predecessor additions at ~m/2 nonzero binary coins; this is a theoretical operation count, NOT a benchmark. The full J=2 joint statistical upper-bound term changes from roughly 2^-308.000033 to 2^-876.830603. This does not calibrate QPT-LWE hardness or demonstrate practical 128-bit security.

## Exact checks, source limits, and next equation

The committed standalone \`check.js\` was actually executed twice identically in V8, testing complete individual/aggregate ciphertexts, N-1 corrupt share/coin consistency, TWO valid SOURCE witnesses recovering the SAME complete 256-bit mock secret in TWO related capsules, and all 6,561 small uniform H matrices for signed ternary support size 24 over F_3 (including exact collisions and full-output/shifted-TV bounds). The separately executed local Python standard-library checker passed 2,437 assertions twice byte-identically, independently testing the same construction, exact large binomial-support logarithms and mock SHA256(sk) linkage. Toy seeded randomness and finite enumeration are NOT QPT tests, real native signatures, or Bitcoin verification.

**Original unsolved interface:** No witness-free classical-PPT generic-NP compiler \`Comp(R_original,x,scope,pk)\` has been instantiated TOGETHER with the above LWE challenge simulator to let every valid ORIGINAL W recover the SAME precommitted sk while hiding it on EVERY fixed FALSE x. Nor is arbitrary unauthorized hard-TRUE sk recovery/native forgery reduced to actual ORIGINAL W or independently justified QPT break. The planted LWE SOURCE witness is a bypass if retained; this restricted theorem does not make it an ORIGINAL witness. Previous signed pseudo-openings break naive affine factor-local compilers. The N-of-N malicious setup/erasure/abort/graph composition, source SYS/BTC authentication, finite evidence and the conditional no-EC-key-path PQ Bitcoin endpoint are unproved. No deployment or automation-stop claim.
