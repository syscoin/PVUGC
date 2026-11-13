# Global degree-two NAND source with an instantiated ordinary-LWE false-view reduction

Research record: global-degree2-nand-lwe-20261028-turn11. Offline continuation from draft/open/unmerged syscoin/PVUGC PR #1, research/pq-wkem-validation-20260918, independently re-read starting SHA 3b0e8eaaa7fd77216e5ba5738088e3ad001c9e42; latest substantive ordinary comment 6467170778. Exact predecessor README blob 778e491b73bfa732bde549efc7537304e12bb29d. No external web or literature was used.

## Verdict

CONSTRUCTIVE BUT RESTRICTED: instantiate (i) a classical-PPT globally quadratic NAND source; (ii) a release that gives every valid ORIGINAL witness the same precommitted secret; (iii) a full-public ordinary-QPT-LWE simulator; and (iv) a machine-checked degree-two refutation certificate for the concrete false NAND source broken by the predecessor's signed fake. For this specifically certified false-source class, there is an actual straight-line QPT-LWE plus native-EUF-CMA security theorem, not a hypothetical SOURCE-opening oracle. **No generic-NP witness-KEM, no hard-true recovery-to-ORIGINAL-witness reduction, and no Bitcoin implementation or 128-bit parameter certification is established.** This does not revive the previously compromised pivot-SL2 carrier or establish security for arbitrary false statements.

## 1. Public source generated from ORIGINAL statement, not a new easy NP relation

For an arbitrary Boolean NAND verifier V(x,W), specialize only the PUBLIC x bits and build the previous classical NAND one-hot matrix C_x over prime F_q. There are v wires and G gates, with m=1+2v+4G coordinates: anchor z_0; wire entries u_i^0,u_i^1; gate entries t_g^00,t_g^01,t_g^10,t_g^11. The homogeneous rows encode one-hot wire/table sums, each gate's input and NAND-output marginals, the public x bits, and the forced accepting final output. Every actual valid ORIGINAL W gives a binary z=f_x(W), anchor z_0=1, C_x z=0, exactly h=1+v+G nonzero coordinates. Distinct witnesses may have distinct z. Checking V(x,W) is OFF CHAIN.

Make the global degree-two monomial vector phi(z)=(z_i z_j) for 0<=i<=j<m, dimension M=m(m+1)/2. The public row matrix F_x (r rows, M columns) comprises coefficient vectors of:
  L_k(z) z_i, for EVERY C_x row L_k and EVERY coordinate i=0,...,m-1;
  z_i^2-z_0 z_i, for EVERY i=1,...,m-1.
These global polynomial constraints are determined by x alone, in classical polynomial time and without any valid witness or private SOURCE-opening oracle. Every ORIGINAL valid W satisfies F_x phi(f_x(W))=0 and phi_00=1. Its phi has exactly B=h(h+1)/2 one-bits, so it has bounded projected ternary noise even though each witness can have different intermediate states.

## 2. Build and public OFF-CHAIN Release

Honest Build samples a genuine native keypair (sk,pk) and uses the full canonical fixed-length serialization K of sk, kappa bits. It samples independent uniform kappa-bit U,Z; publishes the actual checking key pk and shares D=U XOR Z, V=K XOR U. A real implementation must use the real native KeyGen distribution and secure random coins; the attached executable checker uses only a mock 32-byte key, NOT SLH signatures.

Let g=2B+1 and b=floor(q/g)>=2. Encode all kappa bits of Z as ell=ceil(kappa/log2(b)) base-b digits a_j (exact integer capacity). For each column j sample independently
  A_j <- Uniform(F_q^(n x r)),
  s_j <- Uniform(F_q^n), eta_j <- chi^r,
  y_j=A_j^T s_j+eta_j (mod q), NEVER PUBLISHED,
  eps_j <- Uniform({-1,0,1}^M).
Publish p_j=F_x^T y_j + eps_j + g a_j e_00 (mod q), with public A_j, F_x, ORIGINAL (R,x), actual pk, D,V, bound context, permitted auxiliary data and related capsules. LWE error eta and SOURCE error eps are distinct. Honest Build and Release are classical PPT for polynomial r,M,ell.

For any ORIGINAL valid W, Release first checks V(x,W)=1, computes its own z=f_x(W) and phi(z), and obtains
  phi(z)^T p_j = g a_j + phi(z)^T eps_j (mod q).
The last noise term has absolute integer magnitude <= B for EVERY honest ternary draw. Cyclic radix centers g*a_j have separation >=2B+1, including the last-to-zero wrap gap. Every original valid W therefore decodes every digit EXACTLY and reconstructs the SAME precommitted Z, and K=D XOR V XOR Z, without a shared or canonical intermediate state. The native signature is then produced OFF CHAIN on the intended challenge path; Bitcoin verifies only the hypothetical ordinary native PQ signature, not this verifier or proof. A future Bitcoin application must include the full relation identity, claim/UTXO, branch, anchors/window, actual burn/authorization/output and pk in x and prevent bypass graph edges; these are NOT implemented here.

## 3. Independently instantiated exact false-source certificate

For the exact earlier FALSE original NAND instance with one input a and gates
  g0=NAND(a,a)=NOT a,
  g1=NAND(a,g0)=1,
  g2=NAND(g1,g1)=0,
and a forced final output g2=1, no ORIGINAL W exists. At q=65537, generated F_x has shape r=377, M=231, rank 230. An ordinary public Gaussian elimination, implemented in verify.js and independently in the extended Python checker, computes lambda with
  F_x^T lambda = e_00.
The local Python certificate uses exactly 79 generator rows; exact serialized certificate SHA-256 59cf23b9d5a2c2873b27ee3192eed6b02f75d1dde6b0777115328a09a52cd0af. The independently written standalone JavaScript check uses a different column/row pivot order, obtaining a separate equally valid 112-term certificate, then checks ALL 231 coordinates of its equality. The certificate can be reconstructed by running the included source; it is NOT an assumed oracle.

Such an equality certifies falsity for every source constructed as above: if a valid W existed, phi^T F_x^T lambda=0 and phi^T e_00=1 would contradict. More generally this gives the following theorem for ANY x with a polynomial-size computable degree-two certificate, NOT all false NP statements. A false x with no such certificate is outside the theorem.

The previously explicit signed fake z_fake still satisfies C_x z_fake=0 and has anchor 1, but its quadratic phi(z_fake) CANNOT satisfy F_x phi=0. Indeed the public certificate proves there is NO normalized quadratic kernel opening of any norm for this false x, so the earlier direct public LWE cancellation is unavailable. Other true/higher-degree-false recovery attacks are not excluded.

## 4. Joint PUBLIC-output ordinary-QPT security theorem, exact distributions

Fix a certified false x and all public F_x, actual R,x, context, pk and auxiliary distributions as above. Let adversaries be arbitrary nonuniform QPT, with advice independent of hidden target secret coins, coherent processing of classical public values, and classical adaptive signing/sibling-opening queries. Assume ordinary QPT decisional LWE for EXACT dimensions (n,r,q,chi): (A,A^T s+eta) computationally indistinguishable from (A,u), with A uniform, s uniform and eta drawn from chi. Independently assume ordinary QPT native EUF-CMA security for the EXACT native key distribution. Neither assumption promises witness release or an obfuscated verifier. No concrete 128-bit parameters are certified.

For a target column, the challenger supplies (A,y). The reduction knows F_x and samples REAL K,pk,U,Z,D,V,eps and emits p=F_x^T y+eps+ga e_00. This reproduces every SOURCE-dependent public correlation EXACTLY when y is LWE, and needs neither the challenge secret s nor an oracle giving SOURCE openings. In the uniform-y game, because F_x^T lambda=e_00, the replacement u'=u+ga lambda is still uniform. Thus p has EXACTLY the same complete vector distribution for every digit a, even conditioned on the actual pk(K), other public shares and independent related-capsule randomness. This is a joint distribution statement, not marginal pad hiding. Switch ell columns by a straight-line ordinary-QPT-LWE hybrid, with no rewind, random-oracle programming, extraction or generic-model step.

In the final uniform-y game p is independent of Z. For every fixed K, the map (U,Z)->(D=U XOR Z,V=K XOR U) is a bijection; therefore the actual D,V are independent uniform strings even conditional on the genuine pk(K). A simulator given only a genuine native EUF-CMA challenger pk samples D,V and the final-hybrid p without sk, answers admissible signing requests through the challenger, and emits all real public correlations. A fresh native challenge-path signature is an EUF-CMA forgery; a recovered full native signing sk yields such a forgery by signing a fresh intended-path message. Therefore for one certified false target:
  Pr[unauthorized target sk recovery OR fresh native signature forgery]
    <= ell * Adv_QPT-DecLWE(n,r,q,chi) + Adv_QPT-Native-EUF-CMA.
A bounded multiple-target game incurs its explicit number-of-targets/hybrids factor. This proof is conditional on independently QPT-secure LWE and native signature schemes; none were implemented or parameter-certified here.

The related-capsule simulator may prepare independent keys/capsules, including actual checking keys, and answer adaptively chosen CLASSICAL sibling openings because it knows those sibling secrets. Public context and auxiliary input may be adversarial or derived from x,pk and allowed transcripts; they may NOT leak K,U,Z,s,eta,eps or an equivalent target-key capability. Target-key reuse with an opened sibling, secret-dependent auxiliary leakage, adversarial malicious Build coins and coherent superposition SOURCE-opening queries are NOT covered. Arbitrary coherent QPT operations on all permitted classical transcript data and classical replies ARE covered; no automatic lifting of a classical extractor is used.

## 5. Executed tests, limits and precise next missing equation

The exact executable verify.js ran twice offline byte-identically: PASS, 85 assertions, q=65537, false F shape 377x231, false rank 230, a 112-term exact full-vector certificate, true F shape 98x66, three distinct ORIGINAL valid W for NAND(a,b)=1, radix 2114, 24 columns, SAME 256-bit test pad. Its 32-byte key and deterministic PRNG are MOCKS. The independent extended local Python checker was run twice identically, with 1,071 exact assertions each, a separately computed 79-term certificate (full JSON preserved locally), explicit toy A,s,eta challenge couplings, and six complete 256-bit key recoveries for each of the three valid original witnesses. These finite checks are not QPT hardness, native signature, or endpoint tests.

**Missing generic-NP FALSE equation:** for every false x, prove or construct a polynomial-dimension F_x with a full-public QPT simulator; the degree-two refutation property need not hold, and worst-case degree-D lifts may require superpolynomial resources.

**Missing hard-TRUE equation:** for an arbitrary hard-true original x, an arbitrary algorithm that returns the FINAL K or fresh accepted native signature (without volunteering any internal moment vector) must yield a valid ORIGINAL W satisfying V(x,W)=1 OR a separately justified QPT cryptographic break. For true x, a valid phi ensures e_00 is NOT in the span of F_x: the false-source shift used here CANNOT simply be reused. A supplied short/low-rank moment -> W theorem is not the demanded arbitrary-final-key extraction. No such hard-true reduction has been established here. The older pivot/tensor, reversible-frame, local-switching, affine-closure, and signed/low-rank pseudo-opening failures remain tests, not supposedly fixed by this note.

Further unresolved: malicious N-of-N preauthorization and erasure, abort/useful completeness, keyless builder with all builder coins retained, pre-funding data availability, one-honest-observer inclusion, BTC header/AuxPoW/coinbase tag/ancestor/window/fork checks, ChainLocks optionality, native no-EC-key-path SLH-like output and transaction graph, concrete resource/quantum security estimates, selective opening under target-key reuse, and any deployed functionality.

**Progress accounting:** a genuinely instantiated restricted false-source full-public QPT composition and explicit classical every-original-witness release, not a practical generic-NP/BTC/SYS witness KEM. Keep the existing research automation enabled.
