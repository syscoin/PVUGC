# BASO — Bit-Adaptive Selective Openings for packed SOURCE-LWE release

**Research ID:** BASO-2026-10-31-T10. **Exact predecessor:** `syscoin/PVUGC#1`, branch `research/pq-wkem-validation-20260918`, head `4a57fd2e70299a452ed40b9a845cb1cd8daebf87`; predecessor `research/pq-wkem/stm_telescoping_20261031/RESEARCH.md` blob `2e6f8703ee43d7838b3a5a1099b17d2ce6f43c2a`, substantive ordinary comment `6554141924`. This is a **restricted constructive proof extension** to the honest-uniform binary-ISIS SOURCE release; **not** a generic-NP witness-KEM, adversarial FALSE security theorem, hard-TRUE recovery-to-ORIGINAL-witness theorem, calibrated QPT-128 parameters, or Bitcoin PQ deployment. Research was offline.

## 1. New release/leakage model

The prior STM proof allows disclosure of two **entire share lanes** per related capsule, keeping an entire lane unopened. BASO instead allows arbitrary **adaptive plaintext-bit** disclosures with a different unopened lane at each bit and in every related capsule. Two kinds of classical security-game leakage queries exist:

- `Bit(c,lane,k)` releases one share **plaintext bit** without its LWE encryption coins.
- `Coins(c,lane,j)` releases the **whole packed plaintext symbol** and its complete encryption randomness `(s,e,e_star)`; the query counts as opening every actual payload bit of that packed symbol on that lane.

Let `O[c,k]` be the set of disclosed share lanes at bit k in capsule c, including all bits implicitly opened by coin leakage. The adversarial query schedule is unrestricted and adaptive except `|O[c,k]| <= 2` for every `(c,k)`. No source opening, entire native private key, quantum-coherent leakage/signature-oracle queries, or full retention of setup encryption coins is available. This leakage API models compromise of pre-erasure secrets, **not** a new online release authority.

The theorem does **not** require extra ciphertexts or a different LWE distribution. Changing *one secret bit* per reduction transition (rather than an entire packed symbol) increases the hybrid factor to `6*C*ell` for C capsules and ell private payload bits, versus STM's `6*C*ceil(ell/b)`. For ell=512 and C=2, factors are 6144 vs 444; this is a quantitatively larger loss, **not** unchanged concrete hardness. The enlarged permitted leakage model is the constructive advance.

**Necessary public-output exclusions:** do not publish hashes/commitments/MACs of whole plaintext shares, which allow brute force of a single unrevealed bit once the others leak. Only **ciphertext hashes** and honest signatures on ciphertext-bound manifests are allowed. No independent plaintext-share verification tags, source-witness disclosure, or arbitrarily secret-correlated auxiliary strings. Authenticated classical P-domain preauthorization, independent ceremony signing keys and native verification-key correlations are retained.

## 2. Exact classical-PPT Build and public Lift

Choose prime q, dimensions d,n, error bound B, packed plaintext width b, C polynomial related capsules and ell=512 native private-core bits. Generate `(A,t)` uniformly and independently as `A <- F_q^(d x n)`, `t <- F_q^d`. The restricted SOURCE relation is `R_SRC((A,t),w)=1` iff `w in {0,1}^n` and `A*w=t mod q`. Honest Build does **not** know, plant, retain or sample a witness.

Independently run the genuine hypothetical native classical-PPT PQ KeyGenFromSeeds: native private payload `K=SK.seed[256] || SK.prf[256]` uniform; independent `PK.seed[256]`, derived `PK.root[256]`, public verification key `vk=(PK.seed,PK.root)`. Native SK canonical reconstruction uses `K || vk` and must agree with the actual KeyGen/Sign/Verify specification. This is conditional no-EC-keypath SLH-like functionality, **not deployed Bitcoin consensus**. Native `vk` is genuinely correlated with K.

For every capsule c choose two independent uniform ell-bit XOR shares `U[c,0],U[c,1]` and let `U[c,2]=K xor U[c,0] xor U[c,1]`. Independent fresh shares across capsules, same precommitted K. Pack each share into `L=ceil(ell/b)` little-endian b-bit symbols (the final unused high bits are zero). For each `(c,lane,j)` independently sample `s <- F_q^d`, independent entries `e <- U({-B,...,B}^n)`, `e_star <- U({-B,...,B})`, and set

    g = floor(q / 2^b)
    beta = A^T s + e                 mod q
    tau  = t^T s + e_star + g*m      mod q,

where m is the packed share symbol. Errors are **unconditioned ordinary LWE**. The public view includes `(R_original,x,A,t,scope,vk,all beta/tau,auth,aux,related capsules)` with scope binding relation identity, ORIGINAL claim/UTXO, branch, anchors/window/context, intended native signing path, all authentic checking keys, signed P-domain preauthorizations, public ciphertext hashes, honest watcher receipt and independent ceremony data. Aux and authentication must be jointly simulatable from publicly known inputs, generated genuine native vk, independent ceremony keys and permitted classical P-domain signing-oracle answers; no hidden share commitments or arbitrary secret-dependent advice. Full source-dependent ORIGINAL compiler is **not** instantiated here.

Public OFF-CHAIN Lift checks w binary and `A*w=t`, decodes each `rho=tau-w^T*beta=g*m+(e_star-w^T e)` by nearest circular q-ary symbol, reassembles each lane and XORs the three recovered lane strings to K. The true native KeyGenFromSeeds verifies the precommitted vk and the resulting **ordinary native signing algorithm** signs the claim-scoped challenge path. Bitcoin itself runs no ORIGINAL verifier, SNARK/PCP, VM steps or trace dispute. Distinct valid source witnesses may have different residuals and intermediate states but reconstruct the **same** K.

For uniform source and errors, put `V=(n+1)*B*(B+1)/3`, `u=ceil(g/2)`, `T=3*C*ceil(ell/b)`. The same Bernstein+pairwise-source-membership argument as STM gives all-valid-source-witness/all-capsule correctness failure

    eta_C <= T * 2^n * q^(-d) * 2 exp[-u^2/(2*(V+B*u/3))].
    delta = Pr[uniform SOURCE is FALSE] <= (q^d-1)/(2^n+q^d-1).
    Pr[any valid SOURCE witness misdecodes | TRUE] <= eta_C/(1-delta).

At illustrative, computationally **uncalibrated** `q=1099511627689,d=512,n=20680,B=16384,b=14,ell=512,C=2`, `T=222`, `log2(eta_C)=-190.5257619124` and `log2(delta)<-200`. These correctness exponents do not establish any concrete 128-bit QPT computational security. Source matrix ≈52.94 MB and ciphertexts ≈22.96 MB, before scripts, evidence, signatures and setup.

## 3. Information-theoretic bit-leakage lemma

For any one K-bit v, sample independent uniform bits u0,u1 and define u2=v xor u0 xor u1. For every subset O of lanes with |O|<=2 and every observed |O|-bit pattern, there are exactly `2^(2-|O|)` legal completions for each v. Therefore exposed bits are uniform independent of v; this tensorizes across independent capsules and bit positions and remains valid for adaptive classical queries with the per-position cardinality rule. Conversely all three share bits immediately disclose v by XOR. This lemma is only about share plaintexts; it does not by itself cover native checking-key/ciphertext correlations, handled jointly next.

## 4. Complete *permitted* joint-public QPT hybrid

Security assumptions: ordinary **nonuniform QPT decisional LWE**, challenger `M <- U(F_q^((n+1) x d))`, `s <- U(F_q^d)`, `chi <- U([-B,B]^(n+1))` vs a uniform challenge vector; quantum adversaries and independent quantum advice may process **all** classical public ciphertexts, vk, context, authentic P-domain signed manifests and related capsules coherently. The reduction is classical PPT with straight-line interaction and a QPT subroutine, with *classical* adaptive leak/sign queries only. Also assume independent QPT-hard authentication and genuine **native nonuniform QPT EUF-CMA with classical signing queries**, excluding preauthorization of the challenge-signature path. No classical rewinding, oracle for SOURCE openings, attacker-volunteered representation, postquantum lifting of MinRank/SIS, or arbitrary secret-correlated aux.

Let independent dummy D be uniform ell bits. Enumerate C*ell bit positions `(c,k)`. In game H_h the first h positions use fresh 3-of-3 XOR sharing of D[k], the rest use fresh sharing of the genuine native K[k], maintaining correct joint distributions at every game endpoint. Native checking key vk, independent signer keys, source `(A,t)`, honest P-domain signatures, all ciphertext-bound manifests and restricted auxiliary data remain genuinely correlated through all LWE hybrids.

For one adjacent bit `(c,k)`, pick a simulator-private J uniform in {0,1,2}. Generate the other two lane bits independently uniform, then determine the J bit using XOR of either K[k] or D[k] and the other two bits. **Every other bit of that entire packed symbol remains unchanged**. At both genuine endpoints, all three shares at the target bit have exactly the required uniform conditioned-XOR distribution **independent of J**, including given native vk and other capsules. Consequently the adversary's complete classical transcript, despite coherent QPT processing, is independent of J at each genuine endpoint.

The only modified ciphertext is lane J's packed symbol j=floor(k/b). Embed one ordinary QPT LWE challenge via `M=[A^T;t^T]`, `y=M*s+chi` or uniform, and `beta=y[0:n]`, `tau=y[n]+g*m_arm mod q`. All other ciphertexts are independently sampled using the **same M** and known coins. The reducer knows K, actual vk and keys for authentic public manifest and P-domain signatures, and locally simulates every other capsule, checking-key correlation and permitted classical opening query. If `Bit(c,J,k)` or `Coins(c,J,j)` is requested, abort. Queries opening **other bits of this protected packed ciphertext** return the correct known plaintext bits but **no coins**; their values are unchanged between arms. Thus there is no requirement to reveal unknown challenge encryption randomness. An encryption-coins request necessarily reveals the targeted bit and is refused as a forbidden protected opening.

For an arbitrary completed **genuine endpoint** transcript with target opened set O (|O|<=2), after a successful unauthorized fresh native challenge signature E and only if J notin O, accept with probability `1/(3-|O|)`. Because J is private uniform and independent of that endpoint distribution, the exact per-transcript identity holds:

    (1/3) * sum_{J=0}^2 [J notin O] / (3-|O|) = 1/3.

Hence weighted genuine endpoint success is exactly Pr[E]/3. This remains true for adaptive classical opening choices and quantum computation between them; no transcript rewinding occurs. `Enc(m_real) -> uniform -> Enc(m_dummy)` changes only **one packed LWE ciphertext** and costs two ordinary QPT-LWE distinguishing advantages in the full simulatable public distribution. Therefore

    |Pr[H_(h-1):E] - Pr[H_h:E]| <= 6 * Adv_nonuniform-QPT-LWE
    |Pr[H_0:E] - Pr[H_(C*ell):E]| <= 6*C*ell * Adv_nonuniform-QPT-LWE.

Intermediate uniform hybrids need not satisfy the endpoint J-independence identity; only genuine endpoints are reweighted. After **all** bit positions have dummy shares, ciphertexts, permitted plaintext-bit leaks, coin openings and public ciphertext hashes are independent of the native K, while vk/authentic P-domain transcripts remain genuine. Only now substitute a genuine native QPT-EUF-CMA vk and classical P-domain signing oracle. Any returned usable private core can be used by the reducer to sign the fresh challenge path, and any new valid signature is directly the native EUF break. Thus for **raw-512** under exactly these assumptions,

    Pr[unauthorized challenge-domain native forgery]
       <= 6*C*ell*Adv_nonuniform-QPT-LWE
          + Adv_native-QPT-EUF-CMA(classical P signing)
          + Adv_QPT-independent-authentication.

Conditioning honest uniform SOURCE on TRUE costs at most `1/(1-delta)`. An optional compact 256-bit master expanded to 512 native seed bits requires a **separate unproved nonuniform-QPT PRG assumption** and its hybrid must be applied **after** all capsules are dummy, per STM. No same-security savings are asserted. The proof does not cover quantum-coherent leak/sign oracle access, malicious SOURCE matrices, chosen FALSE/hard TRUE ORIGINAL relations, all coins retained by builders, or unconstrained advice.

## 5. Negative controls and remaining ORIGINAL obligation

The chosen-FALSE source `A=[1],t=[3]` has no binary witness, but a public **nonbinary** `z=3` computes `tau-3*beta=g*m+(e_star-3*e)` and can reconstruct the native core when error is small; the supported zero-error case breaks security completely. CORN/NGCE/QGL public interpolation and nonbinary repairs remain inadequate. A public plaintext-share hash would also allow guessing any remaining one-bit share secret in two candidates (the local Python checker explicitly tests 162 guesses). The new result is only a stronger **restricted honest-random-source leakage** theorem. It does not provide a generic SOURCE compiler, malicious one-honest N-of-N setup/abort, real SYS/BTC evidence qualification and timely watcher/DA/censorship guarantees, or a Bitcoin native PQ consensus endpoint.

**Next indispensable equation:**

    Classical-PPT witness-free Comp(R_ORIGINAL,x,scope,vk) -> capsule C;
    R_ORIGINAL(x,W)=1 => public Lift(C,W)=K_precommitted FOR EVERY W;
    arbitrary QPT recovered signing key / fresh native forgery,
    on FALSE or hard TRUE and the FULL correlated public view,
      => an actual ORIGINAL witness or an independently justified QPT break.

Neither SOURCE-opening oracles, canonical/common short preimages, local occurrence switching, public hash collapse, nor a volunteered internal representation satisfy this obligation.

## 6. Reproducible bounded computation

Published `checker.js` is the exact executed standalone V8/Node deterministic checker; `output.json` is its captured run, reproducibly identical on two executions. It uses a **toy deliberately planted** 2-witness source at q=65537,d=2,n=6,B=2,b=3,ell=18,C=3 solely to test arithmetic, same-key recovery, all <=2-of-3 opening sets, adaptive mixed bit/coin openings, forbidden third-lane disclosures and inverse-survival identities. **This does not sample the random QPT-LWE security source** or implement actual native signatures. An independent extended **local-only** Python checker ran twice with 30,426 identical assertions and 162 plaintext-hash guess negative controls; its evidence archive is downloadable separately (SHA-256 `9dd1a1383a4ae77cf5a759311699ccfd5eef871ffc56d6b2ff0cead1d7975ee9`). No independent agents or external internet/literature research. Only approved research Git objects/PR comment are authorized; no deployment or production changes.
