# MINK-NATIVE-SEED-20261102-R12 — compact native-key release for restricted hard-TRUE SOURCE

**Status:** A constructive reduction-interface and size improvement over MINK-LWE-NATIVE-SOURCE at parent `c63c790bcad1ec125f3d529b57f2dba5cd9f2252`. This is *not* a generic PQ witness-KEM. Its LWE-native hard-TRUE distribution is restricted; adversarial universal-FALSE security **still fails**. No production/deployment claims.

## Explicit release and every-ORIGINAL-witness correctness

Let Sig=(KeyGen,Sign,Verify) be an independently QPT-EUF-CMA-secure **native** signature algorithm with classical-PPT KeyGen/Sign/Verify and a classical chosen-message signing interface. Regard KeyGen as deterministic on its actual **uniform standard random tape** rho in {0,1}^kappa. It returns sk,vk. Kappa is scheme-specific; **256 bits is illustrative**, not a verified SLH-DSA entropy/tape size. The builder chooses a uniform rho and precommits the *real* vk (and verification algorithm), relation identity, claim/UTXO, branch, SYS/BTC anchors/window/context, authorization credential and intended native challenge message. It must erase/protect all final native signing material before irreversible funding; one-honest N-of-N ceremony correctness is *not* established.

The ORIGINAL relation in this note is *only* R_LWE((A,b),s): every centered residual b_h-(As)_h has magnitude <=eta. An honest hard-TRUE distribution samples A uniformly in F_q^(m*n), s uniformly in F_q^n, e_h independently from the named bounded-error law, and b=As+e mod q. Keep q odd prime, gap=floor(q/2), t fixed Hamming weight, and t eta < gap/2. For each of M_c related capsules and each bit rho_i, choose fresh uniform independent a_i,b_i and let c_i=rho_i XOR a_i XOR b_i. Encrypt all three shares with fresh coins under the SOURCE pk (A,b):

```
 Enc_x(mu;r)=(u=A^T r mod q, v=b^T r+gap*mu mod q)
 r uniform from {0,1}^m with |r|=t.
 Open_s(u,v) decodes v-s^T u to its nearest center {0,gap}.
 Lift(x,s,C): check ORIGINAL s, decrypt every share, XOR the
 three lanes -> rho, run KeyGen(rho), check exact vk/manifest,
 then Sign(sk,intended_message) OFF CHAIN.
```

For **every** ORIGINAL s, v-s^T u=gap*mu+(b-As)^T r, and |(b-As)^T r| <=t eta<gap/2. Thus all distinct valid ORIGINAL witnesses return **the same precommitted rho and native signing capability**. No common witness, state, canonical preimage, SourceOpen oracle or adversary-supplied representation is required. Bitcoin verifies only the conditional *ordinary native signature*, never the original NP relation or setup proof.

## Joint QPT composition and direct native EUF-CMA reduction

The **restricted** full classical view must include x/R_LWE, capsule(s), genuine native vk, exact claim/branch/context, setup/manifest checking key, honest ECZK CRS/checking keys and transcript, independent auxiliary public inputs, one or finitely many authorized native signatures and adaptive authenticated **classical openings of audit lanes 0/1 only** (never lane 2). All M_c related capsules carry the SAME rho but use independent masks and encryption randomness. Any public checker/certificate auxiliary data must be reproducible from vk,x,context,capsules and public coins **without rho**, or directly from the permitted native signing oracle. A rho-dependent auxiliary tag, corrupt builder retention of rho, opened lane 2, a correlated SOURCE secret in nonuniform advice, arbitrary adversarially generated checking key or coherent quantum signing/opening oracle falls outside this theorem.

Honest setup/evaluation are classical PPT. Adversaries are arbitrary QPT with independent nonuniform quantum advice and may perform coherent quantum computation on the *complete joint classical transcript*. The reductions are straight-line; no quantum rewinding. The predecessor's independently generated honestly distributed ECZK CRS admits a *programmed* challenge-key simulation under its own decisional-QPT-LWE hypothesis, permitting simulated accepting setup transcripts even for invalid intermediate Build statements. Its complete Build-to-3COL compiler, malicious-N-of-N CRS and abort/auxiliary composition **were not executed or proved here**; retain their exact joint error as eps_ECZK_joint and eps_missing_setup, not a false numeric security guarantee.

First simulate all ECZK proof transcripts. Then replace all k=M_c*kappa protected lane-2 ciphertexts Enc(rho_i XOR a_i XOR b_i) with Enc(0). The audit bits and their true encryption coins remain independently uniform and answerable without the SOURCE secret; the protected coins are never exposed. The **single shared SOURCE key** is treated jointly: two decisional-QPT-LWE key swaps (honest LWE key -> uniform key -> honest key) and k fixed-weight leftover-hash steps give

```
 eps_src <= 2 Adv_QPT-DLWE_source + 2 k eps_ext,
 eps_ext = (1/2) sqrt(q^(n+1) / binomial(m,t)).
```

This is an *average honest-LWE-source distribution* bound; do not apply to adversarial FALSE SOURCE keys. Each intermediate proof is simulated, not honestly proven for the now-invalid Build statements. All native checking-key and signer correlations must be maintained. The native vk and authorized signatures are never discarded.

In the all-Enc(0) hybrid, SOURCE ciphertexts, audit opening coins and the simulated proof depend only on vk, public data and random coins, **not on rho**. A QPT-EUF-CMA forger given the *actual native challenger vk* can sample this whole restricted view and forward any permitted native signing request to its classical signing oracle. If A returns rho' for which KeyGen(rho') can sign under vk, the reduction signs a fresh message outside all oracle queries; if A returns a new accepted native signature, the reduction outputs it directly. Both are **straight-line accepted native forgery**, with no supplied internal SOURCE representation. Even a *different* rho' with equivalent signing capabilities yields the same forgery. For the scoped game,

```
 Pr[unauthorized usable native rho' or fresh accepted signature]
 <= eps_ECZK_joint + 2 Adv_QPT-DLWE_source
    + 2 (M_c*kappa) eps_ext + Adv_QPT-EUF-CMA_native
    + eps_missing_setup_and_aux.
```

The *selected native algorithm's* QPT-EUF-CMA is an **independently necessary endpoint security property**, not a witness-encryption/key-release assumption. It eliminates the predecessor's extra 45,056-bit LWE-PRG Lamport generator, its 15-round QPT-LWE stretch proof, SHA384 image-collision hybrid, and seed-to-native-vk support event. This is an **assumption substitution** to an actual native signature-security premise, not a proof of native QPT security or deployment. A challenge/claim/path-scoped credential is not automatically a designated-owner credential. Signatures must be generated only on authorized paths; the reduction's fresh test message is a cryptographically distinct native message, not permission for an unintended spend.

## Resource effect, exact test and failure boundaries

Under previously illustrative, **128-bit-security-UNASSESSED** q=65537,n=256,m=4800,t=2400,eta=3, a SOURCE ciphertext is 771 bytes and each private capability bit requires three lanes. Per single capsule: 256-bit tape -> **592,128 B**, 384-bit tape -> **888,192 B**, 512-bit tape -> **1,184,256 B**, versus the prior 45,056-bit Lamport/LWE-PRG seed -> **104,214,528 B**. Three independently randomized related 256-bit capsules total 1,776,384 B, versus 312,643,584 B: **176x smaller**. The public SOURCE key still costs about 3,700,800 B; all ECZK proofs, presignatures and native signature sizes are extra. These are illustrative sizes, not practical Bitcoin deployment.

Executed code: the independently constructed Python SHA384 toy OTS algebra/assembly checker passed **4,122 assertions twice**, byte-identical, preserved in the extended offline archive; the **exact published stand-alone JS checker** passed **5,584 assertions** in Code Mode. It tests distinct valid ORIGINAL LWE-native s, three related capsules, exact audit openings, simulated key-free protected ciphertexts, and size arithmetic. The JS signature is an explicitly **insecure modulo-tag toy**; the Python test is only a **one-bit SHA384 OTS**, not native SLH or a QPT security experiment. Neither executes the real ECZK simulator or generic compiler. Do not infer 128-bit security from the tests.

**Fatal FALSE counterexample remains:** with q=257,eta=1,A=0,b=(10,0,...), no ORIGINAL s exists, but Enc_x(mu) has v in {0,10} for mu=0 and {128,138} for mu=1; the public ciphertext reveals every share and rho. Hence **universal adversarial-FALSE security is false** and unrepairable by replacing the signature primitive alone. The other decisive unsolved requirement is polynomial classical-PPT generic-NP source-dependent Compile(R_orig,x,context)=(A_x,b_x,aux_x) and Translate(x,w,aux_x)->s_w for EVERY valid ORIGINAL w, with all-FALSE full-public secrecy, correct SOURCE-opening/checking-key correlations simulatable without challenge rho, and arbitrary hard-TRUE recovered-key/accepted native forgery -> actual ORIGINAL witness **or independent QPT break**. Honest-erasure unknown-one-honest N-of-N graph, malicious setup/abort, DA, authentic SYS/BTC fork evidence, censorship/reorg assumptions and conditional Bitcoin PQ-native endpoint remain unproved. **Do not fund or deploy.**
