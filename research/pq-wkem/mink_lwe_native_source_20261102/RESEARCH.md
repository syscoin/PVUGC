# MINK-LWE-NATIVE-SOURCE-20261102-R11 — hard-TRUE release for a restricted ORIGINAL LWE source

**Status:** finite classical-PPT source-native release algorithm with a scoped arbitrary-QPT straight-line reduction and an explicit fatal exception for *adversarial FALSE statements*. This is NOT generic NP witness encryption, not a full original-fork SOURCE compiler, not an honest-one-of-N setup/erasure protocol, and not a deployable Bitcoin solution. The previous source was the easily solved signed-XOR relation; this iteration replaces it with a search-LWE-type **hard-TRUE** original relation. No internet or external literature was consulted.

## Exact source distribution and release

For an odd prime q, integers n<m, 0<eta, fixed binary Hamming weight t<=m, and gap=floor(q/2), require t*eta < gap/2. Public ORIGINAL x contains A in F_q^(m×n), b in F_q^m, relation identifier R_LWE, claim/UTXO, intended challenge branch, anchors/window, source/authentication context and intended native verification key identity. ORIGINAL evidence is *any* s in F_q^n satisfying all centered residuals |b_i-(As)_i|_q <= eta. An honest distribution for **hard TRUE** testing chooses A uniform, s uniform, e_i independent bounded in [-eta,eta] and b=As+e. Auxiliary quantum advice must be independent of these fresh secrets; specifically neither s nor correlated source secrets are handed to the attacker.

Builder samples exactly one K uniform in {0,1}^L, computes genuine deterministic native KeyGen(K,context), and precommits its vk. For each bit i, each related capsule j independently samples a_(i,j),b_(i,j) uniform in {0,1}, sets protected share c_(i,j)=K_i XOR a_(i,j) XOR b_(i,j), and publishes 3 ciphertexts under **the SOURCE pk (A,b)**. All coins are fresh. For bit mu and binary randomness r in {0,1}^m of exact weight t:

    Enc_x(mu;r): u=A^T r mod q; v=b^T r + gap*mu mod q.

**Every valid ORIGINAL s recovers the SAME precommitted K**. Off-chain Lift checks the full ORIGINAL residual bound, decrypts each bit as the nearest circular center of v-s^T u in {0,gap}, XORs 3 lane results, recomputes native vk and checks the full claim/context/branch/manifest. Since v-s^T u=gap*mu+(b-As)^T r and |(b-As)^T r|<=t*eta<gap/2, decoding succeeds for *all* distinct valid ORIGINAL s, without canonical witness, shared state or supplied representation. Sign intended branch off-chain with the deterministic native seed. Native Lamport is only the predecessor's off-chain hash-based prototype; BTC native PQ functionality is conditional, not deployed.

The full classical public joint view comprises x, manifest, source context, genuine native vk, honest-source checking key, setup-proof checking keys/CRS, all M related capsules, auxiliary public inputs, one authorized native signing transcript if requested, the public setup-consistency proof transcript, and authenticated **adaptive** source openings of only audit lanes 0 and 1. Protected lane 2 may NEVER be opened. The two audit lanes are independent uniform bits **even conditional on K**; their encryption randomness can be disclosed in arbitrary adaptive order while source lane 2 remains unopened. This is NOT a proof of unrestricted adaptive any-two-of-three opening, coherent quantum opening queries, secrets in auxiliary data, or related TRUE capsules that publicly release K.

## Straight-line arbitrary-QPT restricted hard-TRUE reduction

The setup NP statement is existence of K and Build coins realizing ALL published capsule shares/encryptions, real native vk and context binding; it does *not* require an ORIGINAL s. A real honest Build knows those coins even if x is ORIGINAL FALSE. Compile that polytime checking circuit to 3-colorability and apply previously instantiated MINK-ECZK interactive encrypted-edge setup proof with two independent honest-public-coin LWE CRS keys. The real-world proof keys have their private keys erased; this is an HONEST-CRS qualification, not the missing unknown-one-honest malicious N-of-N ceremony. The full actual Build-to-3COL compiler is not implemented here.

For arbitrary QPT attacking the joint classical transcript, use an honest-CRS malicious-verifier ECZK straight-line simulator retaining sk_ch and NO native secret or SOURCE opening. For the original TRUE setup statement its output is QPT-indistinguishable from a genuine proof, with predecessor error eps_ZK. After that substitution the simulator also produces accepting-looking transcripts for *hypothetical false setup statements*, because it decrypts each encrypted verifier edge before constructing graph commitments. This property is crucial to the next hybrid; it is NOT claimed as real-world soundness in a CRS with sk_ch exposed.

Replace every protected lane-2 ciphertext from Enc(K_i xor a_i xor b_i) to Enc(0). Crucially, all unprotected share bits are uniform independent of K and the simulator answers adaptive lane-0/1 audits using its own actual opening randomness. Never ask a PKE challenge to reveal its ciphertext randomness. The setup simulator re-generates the corresponding transcript for every intermediate X, even when X becomes false. No SourceOpen oracle, adversary-supplied representation or quantum rewinding.

Let k=M*L protected ciphertexts. Under an *honest LWE-source* public (A,As+e), one full shared-key decisional-LWE-to-uniform-key-and-back hybrid, plus k fixed-weight leftover-hash changes, gives

    eps_protected <= 2 Adv_QPT-DLWE_source + 2 k eps_ext,
    eps_ext = (1/2) sqrt(q^(n+1)/binomial(m,t)).

Justification of the statistical term: for independent uniform (A,b), r->(A^T r,b^T r) on the fixed-weight domain is pairwise independent; a difference of two distinct r vectors has a +/-1 coordinate invertible in F_q. All k protected ciphertexts use independent randomness but the SAME public key. The two LWE-key switches cover the entire joint view, while k statistical hybrids apply conditional on that uniform key. This covers coherent QPT processing of a complete classical transcript and **only** the specified classical audit oracle, for independent nonuniform quantum advice. It makes no automatic quantum lift of a classical extraction or rewinding argument.

In the all-Enc(0) hybrid, all capsules and audit openings are generated from vk **without K**; simulated setup proofs are equally generatable from the checking keys. Thus any unauthorized K' matching vk in this hybrid inverts the actual native seed-to-vk distribution rather than being granted an opening oracle. For the predecessor's explicit QPT-LWE generator G_Aprg (L=45,056 bit uniform seed, O=294,912 bit output, 15 matrix expansion rounds, independent A_prg), native vk consists of SHA384 images of 768 output leaves; optionally one legitimate SHA384 Lamport signature reveals selected leaves. Given a pseudorandom-versus-uniform complete leaf vector Y, a straight-line reduction forms the exact vk, authorized signature and simulated public SOURCE view, invokes seed-recovery A, and tests the returned K' against actual vk. In the **uniform** leaf branch, if SHA384(G(K')_i)=SHA384(Y_i) for every i, then either one leaf differs, yielding an explicit SHA384 collision, or Y is EXACTLY in Image(G), probability at most 2^(L-O). Therefore seed recovery implies a standard QPT native-generator LWE distinguisher, a QPT SHA384 collision, or that negligible image event. The predecessor's straight-line generator reduction has <=15 Adv_QPT-DLWE_PRG loss. One legitimate signing transcript can be formed directly from Y and does not change the proof. A fresh accepted Lamport signature on a different path/digest is a separate straight-line SHA384 preimage/collision reduction under the predecessor's one-signature scope.

Consequently, **under all of the stated restricted assumptions**,

    Pr[unauthorized K' matching native vk]
    <= eps_ZK + 2 Adv_QPT-DLWE_source + 2 k eps_ext
       + 15 Adv_QPT-DLWE_PRG + Adv_QPT-SHA384-collision
       + 2^(L-O) + UNPROVED ceremony/abort/binding terms.

This is a genuine special-case **hard-TRUE => independently justified QPT break** path: recovering native K without the LWE ORIGINAL s either breaks the explicitly named QPT-LWE/hashing assumptions or an unproved setup/auxiliary condition. No assumption itself promises generic common-witness release. It does NOT produce the required arbitrary-ORIGINAL-witness extraction or a generic NP compiler.

## FALSE security: exact limitation, not handwaved

For public uniform (A,b), a union bound gives

    delta_false <= q^n * ((2 eta+1)/q)^m

for existence of ANY valid ORIGINAL s. Conditional on this random-key FALSE distribution, the protected ciphertexts enjoy eps_ext statistical hiding even given the correlated native vk, audits and an ECZK-simulated setup transcript, modulo delta_false and eps_ZK. This is **distributional FALSE-source privacy**, NOT universal false-instance security.

**Concrete counterexample:** A=0, b=(10,0,...,0), eta=1,q=257,gap=128 and any t<m. This is ORIGINAL FALSE for every s. Nevertheless for every ciphertext v is in {0,10} for mu=0 and {128,138} for mu=1. Anyone reads all three shares and recovers K. Thus the required **all-adversarial-FALSE** protection FAILS. Neither a public setup proof nor an LWE wrapper repairs it.

## Parameters, executed tests and missing generic reduction

Illustrative and security-UNASSESSED q=65537,n=256,m=4800,eta=3,t=2400 yields max error 7200 < gap/2=16384, log2 eps_ext about -341.777 and log2 delta_false about -59228.8. At 3 bytes/coefficient SOURCE pk is about 3,700,800 bytes, bit ciphertext 771 bytes. For a 256-bit abstract K, three-lane SOURCE capsule is 592,128 bytes; for the predecessor's full 45,056-bit LWE-PRG native signing seed it is **104,214,528 bytes**, excluding native vk, CRS, presignatures and proofs. No 128-bit quantum hardness estimate; impractical as-is.

The exact standalone JS checker below was executed twice with byte-identical output. It tests two different ORIGINAL valid LWE witnesses against three SOURCE-related capsules, exact fixed-weight dual-LWE encryption and public adaptive lane audit openings, the malformed FALSE leakage example, and **all 59,049** uniform public keys in a q=3,m=5,n=1,t=2 leftover distribution: mean TV 0.352927229928 < analytic 0.474341649025. An independent local-only Python checker executed twice with 212,985 assertions/run, the same exact mean TV and bound, a finite FALSE-sample exhaustive ORIGINAL search, and separate SHA384 context-binding checks. Its full derivation, checker, outputs and provenance are preserved in the downloadable local archive. Neither checker tests real QPT hardness or full setup-graph compilation.

**Exact missing equation for generic-NP BTC/SYS:** produce a polynomial-size, classical-PPT, builder-witness-independent compiler

    (A_x,b_x,aux_x) = Compile(R_orig,x,context),
    s_w = Translate(R_orig,x,w,aux_x)  for EVERY R_orig(x,w)=1

with small LWE residual for all original w, *without the public compiler, any corrupt party, or auxiliary view revealing a decryption capability*, with QPT TRUE recovery-to-ORIGINAL-witness or independent-break security and **all** FALSE x security, not merely LWE-key-distributed false inputs. This is not constructed and may be as hard as witness encryption itself. The malicious one-honest N-of-N ceremony, abort/useful completeness, DA, authenticated BTC/SYS qualified fork proofs, actual Bitcoin PQ native signing, and practical resource bounds remain open. The honest-builder prototype does NOT meet the stronger unknown-one-honest N-of-N erasure requirement. Do not fund or deploy.
