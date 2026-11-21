# R66 — Rounded-source LWE release (restricted uniform-A SIS only)

Run: R66-ROUNDED-SOURCE-LWE-20261104. Offline continuity from open/draft syscoin/PVUGC PR #1, branch research/pq-wkem-validation-20260918, head 64c5beb14f59349ac4371861ed5f85804c59525a. Latest prior substantive ordinary comment 6635149980. Exact R63 and R65 research notes read at this head (blobs 25b55c74f1e72e94cb1a3f7e4f2f00e966696bec and f859586100002a78846d2a28c637299fdd09a3dc). No internet or external literature.

## Constructive delta — real release encoding plus its QPT-compatible whole-view challenge simulator

R65's surviving ORIGINAL relation is **only** R_SIS(A,r): r in {0,1}^m, r[0]=1, A^T r=0 mod q, with A independently uniformly sampled from Z_q^(m x n). R66 keeps the exact ordinary source-DLWE(q,n,m,chi) assumption and all R65 root/CK/native-signature relationships but releases **rounded ciphertext vectors modulo p<q**. It is an exact algebraic all-witness-correct source, and its complete joint-public-view source hybrid embeds an actual q-LWE challenge. When q is larger than the minimum recovery modulus, this reduces source bytes without weakening the q-LWE assumption. It is NOT a repair for hard-TRUE arbitrary ORIGINAL/SYS-BTC witness encryption.

Honest Build/Open are classical PPT. Let q=2^t, p=2^u, p|q, q/p=s. Let errors e have centered coordinates <=E; sample A uniformly, independent source secrets z_i uniformly over Z_q^n, errors e_i independently from chi^m, and K uniformly in {0,1}^k. Parse K into B=ceil(k/b) b-bit little-endian words mu_i (zero-pad its final word). Pick integer Lambda so that

    T = m * ((p/q)*E + 1/2)
    Lambda > 2*T
    p - (2^b-1)*Lambda > 2*T.

Set Delta=s*Lambda. Use public coordinate rounding Rnd(z)=floor((z mod q + s/2)/s) mod p (illustrated s even; otherwise fix a deterministic balanced tie rule). Publish the ACTUAL source

    Ctilde_i = Rnd(A*z_i + e_i + Delta*mu_i*e0 mod q) in Z_p^m.

Keep the matrix A published over Z_q. R65's common root/CK algorithm is unchanged: take ONE entire standard-LWE 2k-bit generator output (S,Kbind)=G_A0(K), mask the one already precommitted native signature sigma_star with Dsig=sigma_star XOR TreeG_A0^d(S), form canonical Base including relation identity, actual statement and claim/UTXO/branch, anchor/window, intended native vk/challenge message, source A/A0/Ctilde, Dsig, related capsules and opening policy, and calculate correlated CK=F_Kbind("CK",Base), Aux=F_Kbind("AUX",CK,Base). CK/Aux must be excluded from Base to avoid a cyclic hash. The full Base must be separately preauthorized before funding; m_star cannot cyclically commit to its later encrypted signature. Binding/unforgeability against QPT, N-of-N ceremony and endpoint remain separate assumptions, not accomplished by R66.

For an ACTUAL ORIGINAL-SIS binary witness r, r0=1, r^T A=0 mod q, public off-chain Open computes y_i=r^T Ctilde_i mod p, decodes nearest legal circular codeword Lambda*mu_i, restores exactly the same K, recomputes S,Kbind/CK/Aux, unmasks and verifies the same native sigma_star for the authorized challenge path. The original NP proof/evidence is not verified by Bitcoin. Two valid witnesses may have distinct representations/states.

**Exact all-witness proof:** write each rounded coordinate as (p/q) times its original canonical q-representative plus an individual rounding discrepancy delta_ij in [-1/2,1/2]. For every binary r above, the underlying integer sum r^T(A z_i + e_i + Delta mu_i e0 mod q) equals r^T e_i + Delta mu_i + a_i*q for some integer a_i, because r^T A=0 mod q. Hence

    r^T Ctilde_i = Lambda*mu_i + (p/q)*r^T e_i + sum_j r_j*delta_ij  (mod p).

The total centered error is <=T. The two displayed inequalities make legal codeword arcs disjoint; each witness therefore decodes the SAME original K for every allowed error realization.

## Entire-public-view simulator and QPT assumptions

An ordinary decisional source-LWE challenger provides (A,Y) with uniform A over Z_q^(m x n), Y=A z+e mod q OR Y uniform over Z_q^m. The straight-line classical simulator samples K, independent related claim coins, A0, native vk/context and masked signature as in Build, then substitutes

    Ctilde_i = Rnd(Y + Delta*mu_i*e0 mod q)

for the challenged word. It constructs/reconstructs the ACTUAL Base, CK, Aux, source manifest and related-capsule metadata with known Kbind. A real Y exactly reproduces Build's full joint view. Uniform Y plus a fixed shift is uniform modulo q, and the Rnd map has exactly q/p preimages per p-residue, so Ctilde_i is **exactly uniform over Z_p^m independent of mu_i**. This is an exact distributional identity, not a marginal-CK independence assertion or an x-structured LWE assumption. After B word hybrids, R65's previously verified whole 2k-bit base-LWE challenge jointly supplies S and Kbind (not separately treated random), followed by its tree expansions, recomputing CK/Aux in every hybrid.

For an unopened target, one independent root per related claim, separate distinct native challenge messages, authenticated immutable scope, and permitted adaptive CLASSICAL related-opening responses on independently sampled claims, an arbitrary nonuniform QPT adversary with target-coin-independent quantum advice is covered conditionally by

    Pr[accepted unauthorized target native signature]
      <= B Adv_QPT-DLWE_source(q,n,m,chi)
         + 2^d Adv_QPT-DLWE_base
         + Adv_QPT-native-EUF-CMA
         + Adv_QPT-binding + negligible/sampling.

Exact hidden-root recovery has the 2^(-k) final guessing term in place of native EUF. Coherent quantum processing of the full CLASSICAL public transcript is permitted; no quantum rewinding, SourceOpen oracle, supplied representation, random-oracle extraction, automatic classical-to-QPT lifting or witness-encryption assumption is invoked. Excluded are malicious A generation, target/sibling openings releasing the shared signature, secret-dependent auxiliary tags outside the displayed Base, target-correlated advice, coherent target-opening oracles, lost setup secrets, rebinding without independent authentication, and malicious N-of-N setup. This is a **restricted** theorem only. QPT hardness of source/base LWE and native signature and binding must be justified independently.

## Concrete size and executed finite checks

Illustrative intentionally insecure toy q=2^40, p=2^23, n=2, m=64, chi=uniform{-1,0,1}, E=1, k=256, b=16, B=16, Lambda=65, Delta=8,519,680. T=32.00048828125, Lambda>2T, p-65,535*65=4,128,833>2T. At the SAME q,m,n,chi source assumption, 16 original 64-coordinate vectors at 5 bytes/coordinate occupy **5,120 bytes**; the 23-bit rounded vectors occupy **3,072 bytes** (40% source-ciphertext reduction). A remains q-modulus and is not included in the 40%; neither are CK/Aux, manifest, tree, graph, source evidence or native signature. At tighter QPT-secure q choices this improvement may be smaller or zero. No 128-bit security/estimator claim.

The exact published V8/Node CHECKER.js was executed *before* Git blob creation, and published OUTPUT.json is its actual captured deterministic output: **131,641 assertions** covering all 65,536 words at the two worst signed rounding offsets (131,072 nearest-center checks); five exact small-q uniform-rounding push-forward histograms; 80 planted two-distinct-SIS-witness source/CK/Aux SAME-root cases and independently opened related TRUE claims; 64 real uniform-A q-LWE challenge source/full-view CK/Aux couplings; and 32 negative controls in which a PUBLIC SIGNED NON-BINARY kernel h recovers the root anyway. The published checker uses a toy deterministic keyed hash and synthetic signature-pad placeholder, not native PQ; these finite tests do NOT establish QPT hardness.

Separately offline, an independent local Python3 checker with SHA256/HMAC and R65-structured toy whole-LWE generator passed **132,522 assertions**, and a Node implementation with a toy whole-LWE generator passed **132,490**. Their source and exact captured outputs are LOCAL-ONLY, not claimed identical to CHECKER.js published here. This publication's source and output are exact byte-preserved copies of its executed V8 checker.

## What this does NOT solve; exact next necessary equation

R63's signed linear-kernel bypass still defeats the attempted deterministic statement-dependent 3CNF-to-SIS source. The R66 negative control proves rounding does not cure it. R58's public TRUE-quotient trace attack also remains. There is **no positive generic ORIGINAL witness-encryption advance**, no arbitrary-FALSE security, and no hard-TRUE generic recovery-to-ACTUAL ORIGINAL witness theorem. Nor is there malicious N-of-N ceremony/abort/erasure proof, generic-NP practical resource estimate, reliable SYS/BTC observation/DA/censorship composition, or deployed Bitcoin native PQ signature/P2MR path.

The indispensable missing equation remains a classical-PPT, ORIGINAL-sound x-dependent source compiler and full-public-output QPT simulation satisfying, for arbitrary hard-TRUE x and arbitrary QPT attacker A,

    Pr[A(V_x) obtains final capability or valid native forgery]
      <= Pr[R_ORIGINAL(x, Ext^A(V_x))=1]
         + Adv_independently_justified_QPT_break
         + negligible(lambda),

where Ext returns an ACTUAL ORIGINAL witness without expecting A to volunteer an internal representation; every valid ORIGINAL witness must still open ONE identical precommitted capability. Witness privacy is optional but original soundness is not. R66 is an independently instantiated conditional efficiency improvement to the restricted R65 source, **not the completion criterion**. Leave existing research automation enabled.

Provenance: exact V8 CHECKER.js Git blob ebc16ec3b445e0a7dd497a4ea5d4fed69e87095e; exact captured OUTPUT.json Git blob cfffa960c6a6e36f70090c21e44fafec0ad56549. Reproduce: node CHECKER.js > OUTPUT.json.
