# R42 — SPLIT-CK-JOINT-SIM (2026-11-03, offline)

**Constructive full-public-output checking-key correlation component for the R41 restricted OR-of-LWE-secret source; NOT generic NP witness-KEM.** This run began from the actual draft/unmerged PR #1 head b34dfa0e2633b15a541a4a55d8305635f32ecd59, branch research/pq-wkem-validation-20260918. It read the current PR metadata, the latest relevant R37–R41 comments (latest 6608286647), and the exact-head R41 RESEARCH.md/CHECKER.js blobs 0b024a724100218f92b2e0ea065569f4b7c45836 and 0eee56fb5346f8d22092da9a6ed146628368aa12. No external research was used.

## Substantive repair relative to R41

R41's straight-line QPT proof only allowed checking keys and auxiliary data reproducible from public fields/independent coins; CK could not depend on hidden capability or source-secret-derived values. R42 replaces its one encrypted seed K by **two independently uniform seeds** K_bind and K_pad, each encrypted to every branch witness. It instantiates a genuine **witness-recoverable secret-correlated checking key**

 CK = F(domain, public claim/UTXO/path/anchors/window/statement ID, public source keys, all capsules, native vk, prescribed m, DEM D, K_bind)

where F is any specified classical PPT deterministic function of the listed fields, such as a domain-separated cryptographic hash. The public auxiliary record may be any deterministic PPT function of (public transcript, CK, K_bind, independent coins, disclosed non-target records), but not an independent leak of K_pad, the target native signature or target source secrets. The actual concrete tested tag includes the full capsule array and D, not only context. An honest Open recovers K_bind and K_pad and checks CK before recovering the prescribed pre-signature from D.

CK is **not publicly reproducible without K_bind**. Nevertheless the source LWE hybrids and the final native-signature challenge simulator construct it *with all correlations intact*, without a SOURCE-opening oracle or the challenge signing secret. The cost is doubling the per-branch encrypted seed bits, not adding a native pre-signature or a canonical witness. This closes one actual excluded full-joint-public-view correlation class. It does NOT solve the more important ORIGINAL NP witness binding.

## Exact source, distributions, and algorithms

Security parameter lambda. Let number of claims, target OR branches J, seed length kappa, fresh independent ciphertext scopes and total target ciphertext count T be polynomial in lambda. Choose odd prime q, n,m polynomial, signed noise chi supported on [-B,B], Delta=(q-1)/2, with mB<Delta/2. For each distinct claim c and OR branch j generate independent A_cj uniform in Z_q^{n x m}, s_cj uniform in Z_q^n, e_cj from chi^m, b_cj=A_cj^T s_cj+e_cj mod q; publish pk_cj=(A_cj,b_cj). R_LWE,c holds on a branch witness (j,s',e') if b_cj=A_cj^T s'+e' (mod q) and ||e'||_infinity<=B. **This is not an authenticated SYS/BTC ORIGINAL relation.**

Generate a single native (sk_N,vk_N), and per claim c fix a canonical, distinct, fully determined message m_c=M(domain, R_LWE identity, all pk_cj, claim/UTXO, native path, anchors/window/context, vk_N), including actual sighash semantics. Privately pre-sign sigma_c=Sign(sk_N,m_c) and ensure its availability before irreversible funding. Choose independent uniform K_bind,c,K_pad,c from {0,1}^kappa, independent across claims. Define

 D_c = encode(sigma_c) XOR G(K_pad,c ; domain, claim, context)

where G is a QPT-secure PRG with enough output for the canonical native signature. Across every branch and every seed bit and scope, sample independent r from {0,1}^m. Publish u=A r mod q, v=b^T r+Delta * seed_bit mod q, for BOTH K_bind and K_pad. Reuse neither r nor encryption coins. Let CK_c=F(the public data and K_bind,c), and aux_c=Aux(the public data, CK_c, K_bind,c, independent coins), with the exact permitted dependency class above.

OffChainOpen(c,j,s',e') first checks the **restricted** R_LWE,c relation; for each ciphertext recovers bits by nearest-center decoding v−s'^T u, reconstructs BOTH K_bind,c and K_pad,c, verifies CK and aux against the recovered K_bind,c and public context, and produces sigma_c = D_c XOR G(K_pad,c). It checks native Verify(vk_N,m_c,sigma_c) off chain; only sigma_c is intended for a conditional native endpoint. Distinct ORIGINAL/actual SYS-BTC witnesses are NOT recognized by this source.

The public adversarial view includes relation/statement, all branch public keys and ciphertexts, D, vk, m, CK, context, auxiliary records, other claims and their capsules, and a polynomial-size fixed table of opened non-target claim LWE source witnesses, bind/pad seeds and signatures. One predesignated target **claim**, all of whose branches remain unopened, is required. An adversary may query a reversible non-target opening table coherently and may carry arbitrary QPT quantum computation and nonuniform advice independent of target secret sampling. No adaptive target selection, target source opening, malicious key generation, secret native-sk advice or secret target-branch correlated auxiliary beyond the allowed CK form.

## Simultaneous EVERY-valid-restricted-witness correctness

For ANY valid (j,s',e') on any branch of a claim, independent of whether it is the original setup witness, and for ANY sample r,

 v−s'^T u = e'^T r+Delta*bit (mod q).

Since |e'^T r| <= mB < Delta/2, cyclic nearest-center decoding recovers the exact bit. Thus every valid restricted LWE OR witness (different branches or internal states) recovers the SAME exact precommitted K_bind,c, K_pad,c, and native signature sigma_c, under fresh coin generation. This is an unconditional algebraic correctness theorem for that restricted relation. The tag is checked using the SAME recovered K_bind; it cannot gate source soundness by itself.

## Full-joint-public-output straight-line QPT theorem

Assume independently specified exact-distribution QPT decisional-LWE for (n,m,q,chi) with honest keys, a QPT-secure PRG G, and a multi-message native QPT-EUF-CMA signature scheme. The native challenge message may depend on pk and vk. The number of target branches J and target fresh Regev bit ciphertexts T includes BOTH seed families and all scopes. Define delta_LHL = (1/2)*sqrt(q^(n+1)/2^m). With public auxiliary generated as specified, including CK dependent on K_bind and the full ciphertexts and D,

 Pr_QPT[A outputs ANY accepted native signature on unopened target m_t]
 <= Adv_QPT-EUF + Adv_QPT-PRG
    + 2 J Adv_QPT-DLWE + 2 T delta_LHL.

Exact K_pad,t recovery or exact pair recovery implies native signature recovery via D XOR G(K_pad,t), and obeys the same bound. K_bind,t alone is NOT claimed secret: CK is permitted to reveal it completely.

Proof. H0 is honest generation including the secret-correlated CK. H1 replaces ALL target-claim encryptions of K_bind,t and K_pad,t with encryptions of zero, branch by branch. For each branch, the LWE -> uniform-pk -> LWE sandwich and strong leftover-hash bound for h_(A,b)(r)=(Ar,b^T r), with r uniform {0,1}^m, give at most 2 Adv_QPT-DLWE + 2T_j delta_LHL. In both halves of every hybrid the simulator KNOWS K_bind,t,K_pad,t and locally signs m_t, so it constructs CK=F(public transcript,K_bind,t) and aux with EXACT source-message/public-key/signature/DEM/ciphertext correlations. The challenge pk is embedded before determining its pk-dependent native message and CK. The statistical LHL step is average over the honestly generated random uniform public key, not a per-key guarantee. Deterministic public transcript transformations (including F) cannot increase classical total variation; coherent QPT postprocessing cannot distinguish distributions more than their statistical distance. All non-target claims, their source secrets, pad/bind secrets and signatures remain independently simulated; their polynomial-size opening table can be prepared ahead of time and implemented reversibly for coherent queries.

H2 replaces G(K_pad,t) with independent uniform bits in D_t, leaving H1's zero target capsules in place. Because K_pad,t is independently uniform from K_bind,t and does not appear in CK/aux except **through public D_t**, the QPT PRG challenger can produce D_t and then generate CK=F(public transcript,D_t,K_bind,t) and aux with exact correlations. An unmasked CK containing K_pad or sigma_t would invalidate this step; the negative control demonstrates the direct leak. The single QPT PRG replacement costs Adv_QPT-PRG.

H3 reduces native accepted target signature to QPT-EUF-CMA. The reduction receives vk_N, generates all source public keys and zero target capsules, chooses K_bind,t, chooses D_t uniformly, computes the secret-correlated target CK from K_bind,t,D_t and other public transcript fields, and produces all auxiliary and opened non-target records. It obtains ONLY distinct non-target native signatures from its signing oracle (pre-query the polynomial table to support reversible coherent opening); it never signs target m_t. The zero-target ciphertexts and uniform D_t mean sigma_t is not needed to simulate any target public field. Therefore any accepted signature on m_t is a fresh-message EUF forgery. Each reduction calls the QPT adversary once, performs no rewinding, asks for no internal representation, and does not access an original witness.

The independent distributional assumptions are REQUIRED, not inferred from small tests. In particular strong leftover hashing gives the stated delta only if m is sufficiently large; m >= (n+1)log2 q + 2 lambda + 2log2 T is a sufficient bound for 2Tdelta <= 2^(-lambda). Correctness also needs mB<Delta/2. No practical parameter set or concrete 128-bit estimate is claimed. All honest algorithms are classical polynomial time for polynomial J,T,m,n,kappa.

For sound binding of the CK tag against a party deliberately attempting inconsistent candidate openings, instantiate F as a suitably domain-separated QPT collision-resistant hash and analyze its exact encoding/canonicalization; this is a SEPARATE assumption/obligation. The secrecy theorem above does not use collision resistance and applies to any specified efficient deterministic F. An arbitrary unbounded leakage function F(K_bind) is permitted if it does NOT independently leak K_pad or sigma. CK can include D because D is already public and the simulator recomputes F after each change. This proves a concrete, nontrivial target-secret-correlated public CK class, not unrestricted auxiliary leakage.

## Offline checker, negative controls, provenance

CHECKER.js is the EXACT V8 checkR42() function executed directly twice in the same functions.exec isolate before publication. The two outputs matched exactly: 616 assertions; 960 bit decodings over seven restricted OR branch openings in three claims, two non-target full-source opening records, all 16 tiny exhaustive independent-key/pad conditional-uniformity fixtures, and 32 negative disclosures for the intentionally bad CK=K_pad construction. Mutation checks reject changed native message, DEM, UTXO context and one capsule via the checked tag. An altered ciphertext can also fail decoding; no quantified cryptographic tag authenticity follows from this toy. The checker uses q=257,n=2,m=12,B=1,Delta=128,kappa=16,two independent scopes; toy RSA modulus 3233, FNV hash, xorshift and 16-bit PRG are intentionally INSECURE and prove no QPT hardness or 128-bit security.

The server-side local Python and container tools returned redis.exceptions.ResponseError during this run. The authoritative successfully executed computation was functions.exec V8; no downloadable local archive is claimed.

## Outstanding ORIGINAL-witness reduction (still central)

The source witness remains a short-error LWE decryption secret. Including a hash/identity of the ORIGINAL SYS/BTC claim in m and CK binds metadata but **does not make possession of an LWE secret authenticate a fork, burn, authorization or any ORIGINAL NP relation**. No reduction turns arbitrary unauthorized recovered signature/K_pad into ORIGINAL evidence. Arbitrary false-instance security (including R39's A=0 example), target openings, secret K_pad/native-sigma leakage, malicious one-honest N-of-N setup and abort composition, finite DA/observation conditions, the conditional P2MR/SLH native endpoint and resource feasibility remain unsolved.

Next indispensable equation: construct from x alone an ORIGINAL-gated public source S_x with classical Build/Open satisfying EVERY w such that R_ORIGINAL(x,w)=1 -> SAME K_pad, and prove for arbitrary QPT A, with full transcript including CK and opened non-target claims, Pr[A recovers K_pad or produces accepted native signature] <= Pr[reduction outputs ACTUAL ORIGINAL witness] + Adv_QPT-independent-break + negl(lambda), without assuming a SourceOpen oracle or a supplied internal representation. R42 does NOT instantiate this source or reduction.