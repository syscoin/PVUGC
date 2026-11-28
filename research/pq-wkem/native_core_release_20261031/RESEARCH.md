# NCSR — Native-Core Split Release for the RS14 honest-random-source LWE candidate

**Research checkpoint:** 2026-10-31 NCSR. **Status:** a concrete native-capability release and significant storage reduction for the earlier **restricted** uniform binary-ISIS source; **not** generic-NP witness-KEM, adversarial-FALSE security, or Bitcoin PQ deployment. All research was offline. The exact predecessor is RS14 `research/pq-wkem/random_source_14bit_20261031/RESEARCH.md`, read at Git blob `d151791ea70048497dc5725122d83c2f8f3c9484` on `94c923208b9deb6a37404bbaff2264994746a3e6`; the latest ordinary comment read was `6552552416`.

## 1. Concrete algorithm and native capability, not just a packing substitution

Assume a classical-PPT native signature system whose **canonical secret key** decomposes exactly as `(secret_core || public_key_fields)`, with `Compose(secret_core,vk)` reconstructing the original canonical signing key and `Sign(Compose(...))` using the ordinary native signature algorithm. A conditional SLH-DSA-like 128-bit-instance layout has `secret_core=(SK.seed,SK.prf)` and `vk=(PK.seed,PK.root)`, each 32 bytes. The canonical 64-byte private signing-key representation is `(SK.seed,SK.prf,PK.seed,PK.root)`. The native checking key already publicly contains the final 32 bytes. We do **not** claim a native no-EC Bitcoin endpoint is deployed or that a toy signature checker is SLH-DSA.

Let the scope message bind relation identity, ORIGINAL statement, claim/UTXO and spending branch, source anchors/window and context, full native vk and all intended signature domains. Manifest binding and funding readiness are separate protocol obligations (see earlier SCFB/RSEG).

**Build (classical PPT, witness-free for the restricted SOURCE):**
1. Pick prime q and binary-ISIS parameters `(d,n,B,b)` and uniformly sample `A <- F_q^{d×n}`, `t <- F_q^d`, independently of native key generation. No SOURCE witness is planted, sampled or retained.
2. Generate `(sk,vk)` by the native classical-PPT key generator, check the exact `sk=Compose(core(sk),vk)` representation equation, and precommit to the genuine `vk` in the full scope manifest.
3. For `ell=256` *secret-core* bits, choose independent uniform XOR lanes `u0,u1 in {0,1}^ell` and define `u2=core(sk) XOR u0 XOR u1`. Do **not** encrypt the publicly reconstructible 256 vk bits.
4. For each of two related same-scope capsules and each of the `h=3` lanes, divide 256 bits into `ceil(256/14)=19` 14-bit symbols (last symbol zero-padded). For each symbol m independently draw `s <- F_q^d`, `e <- U([-B,B])^n`, `e* <- U([-B,B])` and publish

   `beta=A^T s+e mod q`, `tau=t^T s+e*+g m mod q`, where `g=floor(q/2^14)`.

   **No rejection/certificate and no SourceOpen oracle.** The same shares, independently generated encryption coins, and all authentic native checking-key/preauthorization/context correlations are present across both related capsules. Off-chain authorizations must use actual signatures on nonchallenge domains; challenge-path signatures are never preauthorized.
5. In the honest-erasure baseline, securely erase unneeded plaintext core, share and encryption coins after the authorized N-of-N preparation/availability ceremony. This does **not** satisfy the optional stronger keyless Build against a builder retaining all coins.

**Public OFF-CHAIN Lift(C,W):** Check binary witness shape and `A W=t`; for every symbol compute `rho=tau-W^T beta mod q`, nearest-decode its q-ary symbol, unpack the three lane strings and set `core_hat=u0_hat XOR u1_hat XOR u2_hat`. Then return **`Compose(core_hat,vk)`**, the ordinary canonical native signing key for the intended scope. Distinct valid witnesses may have different residuals and intermediate states; they return the identical precommitted `sk` whenever every symbol decodes. No original-NP verifier or VM step runs on Bitcoin.

## 2. All-valid-witness correctness (same distribution and assumptions as RS14)

For each binary `W` with `A W=t`,

`tau-W^T beta = g m + (e* - W^T e) mod q`.

The error law is unchanged from RS14. Writing `V=(n+1)B(B+1)/3`, `u=ceil(g/2)` and `T=2*3*ceil(256/14)=114`, the same Bernstein + pairwise-independent SOURCE-moment calculation gives

`Pr[exists valid W, some symbol decoding failure] <= T 2^n q^(-d) * 2 exp(-u^2/[2(V+B u/3)]) = eta`.

For `N=#binary witnesses`, `E[N]=2^n q^(-d)` and `Var(N)=E[N](1-q^(-d))`, so `delta=Pr[N=0] <= (q^d-1)/(2^n+q^d-1)`. Conditional on TRUE, the all-witness decoding failure is at most `eta/(1-delta)`. This is honest-setup *overwhelming-probability* correctness simultaneously for **every** valid binary SOURCE witness and both related capsules, not a per-capsule deterministic certificate and not ORIGINAL generic-NP correctness.

At illustrative, **uncalibrated** `q=1099511627689`, `d=512`, `n=20680`, `B=16384`, `b=14`, `T=114`, the executed formula reports `log2(eta)=-191.487288`; the negligible FALSE-source estimate remains `<2^-200`. The prior 512-bit secret encoding required `2*3*ceil(512/14)=222` ciphertext vectors; the native-core release requires **114**, a 48.648649% reduction. Each `(beta,tau)` has `n+1=20681` q-ary elements, five bytes each: ciphertext bytes `22,955,910 -> 11,788,170`, saving **11,167,740 bytes** per two-capsule scope. The unchanged matrix occupies 52,940,800 bytes; matrix-plus-ciphertext volume `75,896,710 -> 64,728,970` bytes (14.7144% smaller). This is still enormous and not a practical completed WKEM.

## 3. Full joint public-view QPT reduction opportunity — precise restricted model

For each selected ciphertext target, ordinary decisional LWE challenger supplies `M` uniform in `F_q^{(n+1)×d}` with last row interpreted as t and first n rows as `A^T`, and a vector either `M s+chi` or uniform. The classical straight-line reduction (knowing `sk,vk` in each LWE hybrid) adds the known `g*m` to the last coordinate and samples *all other* ciphertexts, contexts and authentic signatures in their genuine joint distribution. This jointly supplies `(A,t,beta,tau,vk,scope,aux,related capsules)` **without the LWE challenge secret** and without a SOURCE-opening oracle. Crucially, omitting public `vk` fields from secret plaintext does not alter native checking-key correlations: `vk` is generated genuinely throughout, not faked or independently sampled from sk.

Openings are restricted to **complete share lanes**, including their plaintexts/coins, for at most two of three lanes, with one protected lane unopened **in every related capsule**. Guessing the globally protected lane costs a factor at most three. The LWE hybrid replaces all ciphertexts of that protected lane with uniform ciphertexts, one at a time, while the reduction opens any nonprotected lanes with their actual independent randomness. Because other lanes are independent uniform strings even conditional on the native core, after the protected ciphertexts become uniform the reduction can use a genuine native QPT-EUF-CMA challenger `vk` and its **classical** signing oracle for allowed P-domain preauthorizations. A final candidate `core_hat` that can produce a fresh challenge-path native signature under that `vk` yields the independent native EUF-CMA break. In particular the final reduction **never needs to recover W from adversarial key output**; that disjunction branch is an independently justified PQ break in this restricted model.

The QPT adversary may perform coherent processing of the entire **classical** public view. The reductions are straight-line (not classical rewinding), under nonuniform QPT decisional LWE and native QPT-EUF-CMA with classical signing queries. The claim is **restricted**: it does not cover arbitrary secret-correlated auxiliary advice, quantum signing-oracle queries, adaptive individual-bit/cross-lane selective openings, malformed adversarial SOURCE setup, adversarial FALSE instances or arbitrary ORIGINAL relations. Context data must be exactly public-simulatable from `vk`, honestly produced independent ceremony keys, published coins and allowed signing-oracle answers; do not silently add `H(core)` or leak honest encryption coins. Multiple capsules have independent LWE coins and a common protected lane.

Native EUF-CMA is an assumption of the **conditional hypothetical native signature endpoint**, not proof that Bitcoin today can verify those signatures. The source's real QPT-128 hardness has never been parameter-calibrated. No production, deployment or consensus claim is made.

## 4. Exact boundaries — no generic ORIGINAL reduction

An adversary choosing FALSE `A=[1]`, `t=[3]` still uses public `z=3` to recover each encrypted core symbol as `tau-3 beta=g*m+(e*-3e)` (e.g. zero supported errors). There is no binary ORIGINAL witness yet the adversary obtains the native signing core and reconstructs the canonical `sk=Compose(core,vk)`, and so can sign the intended challenge path. The exact local checker reproduces this failure **after** stripping the public half. The prior CORN, NGCE and QGL invalid-opening/interpolation attacks remain unrepaired for structured generic-NP compilers. Public checking-key fields being left unencrypted improves size but offers no nonlinear ORIGINAL-integrality gate.

The exact missing construction remains a witness-free classical-PPT `Comp(R_original,x,scope,vk)` plus publicly evaluable release `Lift(C,W)=K_precommitted` **for every valid ORIGINAL W**, with the complete full-public-output simulator and an arbitrary-QPT adversarial-FALSE and hard-TRUE recovered-key/fresh-native-forgery reduction to an **actual ORIGINAL witness** or independent PQ break. Neither a supplied representation nor a SourceOpen oracle may be assumed. Malicious one-honest N-of-N preauthorization/abort, one honest timely watcher and DA, complete SYS/BTC evidence qualification, censorship/reorg assumptions, and conditional native Bitcoin PQ support are separately unfinished.

## 5. Exact executed reproducibility/provenance

`checker.js` is the exact standalone Node.js 22 offline checker executed twice with byte-identical `output.json`. It uses a seeded **noncryptographic** fixture RNG, q=2147483647 and explicit LWE arithmetic to test two distinct binary SOURCE witnesses, two related capsules and three 256-bit XOR lanes. The **toy hash-only Merkle-Lamport one-time signer** uses a 32-byte secret core, a 32-byte public `vk` and a 64-byte canonical secret-key encoding; it signs and verifies intended-path mock messages, proving the exact core/public recomposition **as a functional toy**. Its enormous 7168-byte fixture signature, 32-bit message digest and truncated Merkle root are **not** secure PQ signatures, SLH-DSA, or a Bitcoin test. The checker deliberately verifies chosen-FALSE nonbinary full-key recovery and a valid signature, so this cannot be mistakenly promoted as secure. Analytical parameter/byte calculations are separate from toy cryptographic security. No external web/literature research or independent agents were invoked.
