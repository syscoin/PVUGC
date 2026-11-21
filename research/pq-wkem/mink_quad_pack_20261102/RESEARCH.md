# MINK-QUAD-PACK-20261102-R13 — same-assumption 4-ary SOURCE release efficiency

**Status:** Restricted, conditional LWE-native SOURCE **component** improvement over MINK-NATIVE-SEED-20261102-R12 at parent `1e20d1f8980a08aee6327f61d342dcf5c90fdaf8`. This is **NOT generic PQ witness encryption**, and the predecessor's universal adversarial-FALSE failure persists. There is no claim of practical security, malicious N-of-N setup, or deployment.

## Concrete release

The ORIGINAL relation **only in this restricted component** is
`R_LWE((A,b),s): ||center_q(b-As)||_infty <= eta`.
Honest SOURCE distribution: `A <- F_q^(m x n)` uniform, `s <- F_q^n` uniform, each `e_h` sampled independently from the specifically bounded-error source law, and `b=As+e mod q`. Keep predecessor's illustrative unassessed parameters `q=65537,n=256,m=4800,t=2400,eta=3`, and source encryption randomness independently uniform among binary r of **exact Hamming weight t**.

For the exact unchanged parameters, define four modular centers `gamma_j=floor(j*q/4)`, `j=0,1,2,3`, giving `[0,16384,32768,49152]`. A source encryption of one quaternary digit is
`Enc4_x(j;r)=(u=A^T r mod q, v=b^T r+gamma_j mod q)`.
The decoder chooses the unique nearest center to `v-s^T u` in centered modular distance and rejects ties/noncanonical encodings.

Represent the actual native PQ signing scheme's uniformly random classical `KeyGen` tape rho by `d=ceil(kappa/2)` base-4 digits. `kappa=256` here is an **illustrative resource fixture**, NOT a verified SLH-DSA random-tape parameter. For every digit `j`, choose independent `a,b <- Z4`, set `c=j-a-b mod 4`, encrypt all three lanes under x using independent fresh fixed-weight r. Do this independently for M_c related capsules, all sharing the identical precommitted rho. The public manifest binds relation identity, exact x, claim/UTXO, branch, anchors/window/context, intended native verification key, challenge path and authorization credential. Every valid ORIGINAL s decrypts all lanes off chain, sums in Z4, reconstructs rho, recomputes native `KeyGen(rho)`, checks true vk/manifest, and signs the intended path off chain. No Bitcoin NP/PCP proof verifier or BitVM trace is introduced.

## Unconditional every-witness algebra; optimal center capacity for stated noise

For every accepted ORIGINAL witness s (not a canonical witness):
`v-s^T u=gamma_j+(b-As)^T r mod q`.
Each residual magnitude is at most eta, so `|(b-As)^T r| <= t eta=7200`. The minimum circular center separation is 16384; hence `2*7200=14400<16384`. All four radius-7200 decoding balls are disjoint. Every valid **distinct** s recovers every original digit, therefore the **SAME** precommitted native KeyGen tape and capability. No SourceOpen oracle, common intermediate state or supplied adversarial representation is needed.

Five center balls of integer radius E=7200 would require at least `5*(2E+1)=72005>q=65537` residues. Four symbols are thus maximal for a one-coordinate nearest-center decoder under this deterministic worst-case error guarantee; this is NOT an information-theoretic bound on other lattice systems.

## Conditional QPT view, correct limits

For independent uniform public (A,b), the map from exact-weight r to (A^T r,b^T r) is pairwise independent on distinct r. Elementary L2/leftover hashing gives total variation
`eps_ext <= (1/2)*sqrt(q^(n+1)/binomial(m,t))`,
whose base-two logarithm is approximately -341.777055 at these illustrative parameters. Translating v by any of four public centers does not alter this classical statistical bound. It continues to bound coherent QPT processing of the resulting **classical** public transcript and independent quantum advice. It is NOT a concrete 128-bit QPT-LWE hardness estimate.

In the predecessor's restricted honestly generated ECZK proof-CRS model, one can switch each unopened lane-2 ciphertext to Enc4(0), while preserving exact audit lane-0/1 openings and their coins, all related capsules, actual native vk, authorized classical native signatures and public context. For N=M_c*ceil(kappa/2) protected ciphertexts, the SAME ordinary decisional QPT-LWE public-key distribution and fixed-weight leftover steps yield the inherited **conditional** source error `<= 2 Adv_QPT-DLWE + 2N eps_ext`. The earlier `eps_ECZK_joint` and `eps_missing_setup_and_aux` remain explicit **unproved** terms. In the all-zero view a straight-line native EUF-CMA challenger could generate the view from real vk and its classical signing oracle, and a usable recovered capability or accepted fresh signature becomes a native forgery. That **restricted inherited theorem** does not establish arbitrary ORIGINAL-NP witness extraction, universally malicious checking-key security, or the entire joint setup proof.

Full public output MUST include R/x, every capsule, the honest and maliciously supplied checking keys, branch/context/claim, proof and signing data, auxiliary input and arbitrarily related capsules. This note does **not** simulate adversarial correlated keys, source-dependent aux, retained builder coins, exposed lane 2, coherent signing/opening oracles, or malicious one-honest N-of-N setup. Its QPT hybrid cannot silently discharge those missing obligations.

**Concrete universal-FALSE counterexample remains:** q=257, eta=1, A=0, b=(10,0,...), exact weight 12 has no valid ORIGINAL witness, but public v for j in Z4 belongs to four disjoint sets `{0,10},{64,74},{128,138},{192,202}`. Ciphertext alone reveals each quaternary digit. This architecture is therefore NOT secure for every FALSE instance, even with the improved packing.

## Exact resource result and reproduced checker

Because q=65537 requires 17 rather than 16 bits, strict canonical little-endian packing of 257 field elements uses `ceil(257*17/8)=547 B`, rejecting integers >=q, incorrect lengths and nonzero padding bits. R12 used 3 bytes/field element: 771 B. For kappa=256, its 256*3 binary ciphertexts cost 592,128 B. This iteration uses 128*3 quaternary ciphertexts totaling **210,048 B/capsule**, a **2.819012797x** reduction. Three related capsules cost 630,144 B. The public SOURCE key (~3.7 MB), ECZK proof, actual native vk/signature and off-chain claim evidence are additional. No smaller native signature is assumed.

The exact published standalone JS checker executes deterministic algebra tests: two distinct accepted ORIGINAL witnesses, three related SOURCE capsules carrying identical 256-bit tape digits, audit equations, maximal decoding-error boundary and 5-center exclusion, 17-bit field serialization, 4-ary adversarial-FALSE leakage, entropy and resource arithmetic. An independent longer local Python standard-library checker ran twice byte-identically with 903827 assertions each, including eight actual n=256 ciphertexts, and is retained in the offline archive rather than misidentified as GitHub-published. Neither is a QPT experiment, a real native signature test or the complete graph simulator.

## Next exact open obligation

Instantiate classical-PPT `Compile(R_original,x,context)->(source,aux,checking_key,capsule)` plus witness translation/opening for **EVERY** valid original witness, with the same precommitted capability and a full-public-output simulator for **ALL adversarial FALSE original statements**; prove arbitrary unauthorized hard-TRUE key recovery/accepted native forgery -> actual ORIGINAL witness or an independently justified QPT break, without the adversary volunteering an internal representation. This remains unresolved. One-honest N-of-N pre-funding setup/abort, data availability, actual SYS/BTC semantics and the conditional Bitcoin-native PQ endpoint are unresolved. Do not fund or deploy.
