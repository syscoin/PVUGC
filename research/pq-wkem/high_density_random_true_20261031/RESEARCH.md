# HDRT — high-density random-TRUE binary-ISIS with byte-packed threshold SOURCE release

**2026-10-31, offline research continuation of syscoin/PVUGC#1 at 94084b474263c5dea14a1d92ca63c4970445afc1.** The exact previous substantive SOURCE note is `research/pq-wkem/same_scope_threshold_open_20261031/RESEARCH.md` (blob `da6f48042ce42633452d39e48f24ec63cf8f1c41`). This is a *restricted average-case new component*, not a general post-quantum witness KEM, a generic ORIGINAL witness reduction, or a Bitcoin deployment. No external literature used.

## Uniformly generated TRUE sources with no witness retained

Let q be prime, A uniformly distributed in F_q^(d x n), t independently uniform in F_q^d, Q=q^d, and R_ISIS((A,t),w)=[w in {0,1}^n and Aw=t mod q]. **Comp samples only A,t, not a planted w, and does not test satisfiability.** Let N=#{w in {0,1}^n : Aw=t}, mu=2^n/Q. The events [Aw=t] for different binary w are pairwise independent: distinct nonzero binary vectors are linearly independent over F_q, and w=0 is independently handled by t=0. Thus E[N]=mu, Var(N)=mu(1-Q^-1), E[N^2]=mu^2+mu(1-Q^-1). Cauchy-Schwarz implies

    p_false=Pr_uniform[N=0] <= (Q-1)/(2^n+Q-1) <= (Q-1)/2^n.

Uniform (A,t) conditioned TRUE is at exact statistical distance p_false from uniform (A,t); the actual classical PPT sampler simply outputs the uniform pair and is TRUE with probability >=1-p_false. No efficient TRUE test or SourceOpen oracle is needed. This gives **average-case TRUE**, not adversarial TRUE.

In a separate *hidden planted witness* experiment, sample A uniform and W uniform {0,1}^n, publish t=AW but never give W or source-dependent auxiliary leakage to the adversary. Pairwise-universal hashing gives E_A sum_t P_A(t)^2=2^-n+(1-2^-n)/Q. Therefore Delta((A,AW),(A,U_d)) <= (1/2)*sqrt((Q-1)/2^n). This alternative requires W to remain unknown to every adversary/setup party; it is analytical only and is not the primary witness-free generator.

## Classical-PPT byte-packed capability and exact all-witness correctness

Native KeyGen outputs an authentic (sk,vk), with canonical sk consisting of ell bytes. Choose h>=2 lanes and share the **same precommitted sk** by sampling h-1 uniform byte strings and XORing them with sk for the last lane. For L=256, g=floor(q/L), a discrete LWE error distribution chi with support [-B,B], and each lane a, byte j, related capsule r, sample independently s_ajr <- F_q^d, e_ajr <- chi^n, e*_ajr <- chi. Publish source-dependent

    beta_ajr=A^T s_ajr+e_ajr mod q,
    tau_ajr=t^T s_ajr+e*_ajr+g*u_a[j] mod q,

along with actual relation and x=(A,t), native vk, signed-message domain bound to claim/UTXO, branch, anchors/window, intended challenge path, all genuine native P-domain preauthorization signatures, permissible context/auxiliary material, and related capsules. All secrets, errors, signing keys, share plaintexts and encryption coins are treated according to disclosure rules; none is a public SourceOpen oracle. The native C-domain challenge signature was never preauthorized.

Public off-chain Lift on a valid ORIGINAL binary w computes rho=tau-w^T beta mod q, rounds to the closest cyclic codeword g*m (m=0..255), XORs recovered byte lanes, checks that reconstructed sk matches genuine vk, and returns that *same sk*. Every valid original w with Aw=t satisfies

    rho=g*u_a[j]+e*_ajr-w^T e_ajr,   |e*_ajr-w^T e_ajr|<=(n+1)B.

If 2(n+1)B<g and q>=L*g, every valid w, **simultaneously**, decodes every byte of every related capsule exactly. Different witnesses need not have a common state or representation. The public relation check is not a cryptographic barrier; this construction's restricted hardness comes from the LWE ciphertext distribution.

The adversary may adaptively open at most h-1 *whole* share lanes of a selected target, including their plaintext bytes and **all** encryption coins, and unrelated sibling scopes. The target protected lane stays closed. Arbitrary cross-lane per-byte openings, leaked W, key-related auxiliary advice, malicious source setup, quantum signing/opening oracle queries, and exact challenge pre-signatures are EXCLUDED. The adversary may process all classical public output in arbitrary coherent QPT state; the reductions may be nonuniform with independent quantum advice.

## Instantiated full-public QPT reduction; no independent WE assumption

Assume ordinary nonuniform-QPT decisional LWE for exactly M <- F_q^((n+1) x d), y=M*s+chi^(n+1) versus uniform y, with s uniform in F_q^d, and genuine QPT native EUF-CMA for **classical** signing-oracle queries. For uniform source (A,t), M=[A^T;t^T] is *exactly uniform*. In a fixed target scope/protected share lane, replace every ciphertext vector in turn with uniform using a single ordinary LWE challenge vector shifted in its final coordinate by g*u_a[j]. All other real source-dependent ciphertexts/coins, vk, context, sibling related capsules, permitted share disclosures, and adaptive genuine P-domain signatures are generated consistently because the LWE reduction knows native sk in each hop. If protected lane a is opened, score zero for that event, which cannot win on lane a.

Once all vectors of protected lane a are uniform, those vectors are independent of its plaintext. The other h-1 XOR share lanes are **jointly uniform independent of sk even given authentic vk**. The final reduction therefore embeds a genuine native EUF challenger vk and uses only its classical Sign oracle for adaptive preauthorizations; any accepted fresh native C-signature is a native EUF forgery, and any reconstructed usable canonical sk signs a fresh C-message. Partition adversarial success by target scope i and least-indexed still-protected lane a; straight-line simulation requires no extraction from an adversary-supplied representation, SourceOpen, classical rewinding or random oracle.

For polynomially many related capsules sharing the same single uniform source, and T_ia ciphertexts in protected lane a, the restricted event obeys

    Pr_(U | TRUE)[fresh native C-forgery or canonical sk recovery]
       <= p_false + sum_(i,a) [ sum_(j=1..T_ia) Adv_QPT_DLWE(B_iaj) + Adv_QPT_native_EUF(F_ia) ].

The conditioning loss p_false is incurred **once** for the entire joint view, because channels cannot increase statistical/quantum trace distance. For the hidden planted TRUE experiment replace p_false by epsilon_LHL. QPT-LWE assumptions are for the exact error distribution and dimension; no 128-bit calibration is claimed. All setup/evaluation are classical PPT, and signing/opening queries are classical. No arbitrary correlated auxiliary input or same-secret key leakage is covered.

## Concrete eightfold ciphertext-count improvement, restrictions

Packing one byte per q-ary ciphertext instead of one bit per ciphertext reduces ciphertext-vector count **8x at unchanged q, chi, matrix, native checking key, and QPT-LWE assumption**. The only changed symbol shift is g*m, which preserves the same straight-line LWE hybrid; correctness requires g>2(n+1)B. At illustrative **not security-calibrated** d=512, q about 2^40 prime, n=21,000, B=2^14, h=3, 64-byte sk, and two related capsules: p_false <= about 2^-520, e_LHL <= about 2^-261, and worst-case all-witness residual <=344,080,384, below g/2 about 2.15 billion. There are 384 q-ary ciphertext vectors instead of 3,072 bit ciphertext vectors. At five bytes per field element that is **40,321,920 bytes** ciphertext instead of **322,575,360 bytes**; A itself adds **53,760,000 bytes**, so the result is still much too large for a practical small capsule. Very small relative LWE noise at this illustration could be insecure; no concrete QPT strength estimator was run.

**Decisive unsolved requirement:** for arbitrary/adversarial original NP evidence y, there is still no witness-free PPT Comp(R_original,y,context,vk), no source opening for every ORIGINAL W that cryptographically binds to y, and no chosen-FALSE/hard-TRUE joint-public QPT key/native-forgery -> ORIGINAL W or independent PQ break. In particular chosen FALSE A=[1],t=[3] has public nonbinary opener z=3 recovering all lanes and sk under small noise. High-density average-case statements cannot be substituted for SYS/BTC burn/authorization/fork evidence merely by putting it in context. Neither malicious N-of-N setup, abort/funding/DA, qualified SYS/BTC best-chain observations, nor an actual no-EC Bitcoin native-PQ endpoint is solved. Do not claim completion or disable the research task.

## Executed evidence and provenance

The exact attached `checker.js` (self-contained Node.js, console report) was executed by calling the same `runChecker` source directly in V8. It exhaustively enumerates eight finite source families, validates first/second moments, exact conditioned TRUE distance and planted leftover bound, checks deterministic 8-bit three-lane correctness across distinct witnesses and related capsules, and the chosen-FALSE nonbinary opener; its JSON report is stored as `output.json`. It is a **toy check, not QPT hardness**. A larger separate Python offline checker (not the same source) passed **11,019 assertions twice with byte-identical JSON outputs**, covering nine exact enumerations, 9,216 original-witness bit releases, 1,152 packed-byte releases and chosen-FALSE failures; the 16,400-byte full derivation and exact Python checker/output/provenance were also retained in the offline archive. No external literature, subagents, native SLH implementation or quantum attack tests.
