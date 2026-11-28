# Run 380 — a restricted linear SPHF succeeds for one fixed source word, but related capsules reveal the key exactly at an affine-span threshold

## Basis and scope

At the start of this bounded iteration, connected GitHub verified `syscoin/PVUGC#1` open/draft/unmerged at `3d12b3180e4943a137c8669171f47cc0dd4ad759` on `research/pq-wkem-validation-20260918`, with ordinary comment `6067040320` the latest. Exact relevant files: `TRAPDOOR_GREY_ZONE_NOTE_RUN379.md` blob `d58ff0eddacd9fd1840b1b3939e39b401750ff90`, Run 259 `GLOBAL_FINGERPRINT_SOURCE_BINDING_RUN259.md` blob `c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2`, and the CLZ application note blob `c19d9d9cd515140e3ce62eac960cd548c0add622`. Only these notes and live metadata/comment tail were read; no PR diff or archive reconstruction. New results are a complete finite-field linear SPHF special-language toy and a necessary-and-sufficient reused-mask joint-hiding criterion. This is **not** a secure general-NP/Syscoin WKEM, real LWE instance, or full CLZ/SPHF literature proof audit.

## 1. Explicit fixed-word projective release toy with q distinct ORIGINAL witnesses

Work in a prime field F_q. Define A:F_q^2 -> F_q^2 by A(u,v)=(u+v,0). Public source word x=(s,t), ORIGINAL relation R(x,(u,v)) iff `u+v=s` and `t=0`. There are q distinct ORIGINAL witnesses when t=0 and none when t!=0. Source membership and witnessing are polynomial-time linear algebra; there is **no NP-hard source assertion**.

Sample independent uniform `a,b,K in F_q`. Let the secret hash key h=(a,b), projection key p=A^T h=(a,a), full hash `Hash(h,x)=a*s+b*t`, and public capability pad `C=K+a*s+b*t`. Public capsule includes `(x,p,C)` and may also include a public checking key `vk=PK(K)` and any auxiliary public information independent of b conditional on K,a,x. Release from supplied ORIGINAL z=(u,v) is `C-p.z = C-a(u+v)`.

**Correctness:** for every true x with t=0 and every one of its q valid ORIGINAL witnesses, release equals the SAME K exactly. The intermediate z need not be canonical. Since z=(s,0) is publicly available, true-instance early key recovery trivially yields an ORIGINAL witness for this **P-language**, not for general NP or Syscoin evidence.

**Single-false-word perfect masking:** when t!=0, `b*t` is uniform in F_q even conditioned on a,K,x; hence C is exactly uniform and independent of K conditional on public `(a,x,vk(K))` and permitted side information not correlated with b. This is an information-theoretic statement about the **extra pad**, not about hiding K against a public checking key or a retained b. A simulator can choose C uniform, so any false-word unauthorized native signature is no easier than against its checking key alone if the rest of the transcript is simulatable. Classical public evaluators may be executed coherently; identical underlying cq distributions remain identical. This does not prove native QPT EUF or secure compilation. A malicious setup participant retaining b trivially computes K=C-a*s-b*t.

This is an example of a gap-free SPHF *only for a trivial linear language*. It evades the Run-379 NP-in-BPP barrier because no claim is made that arbitrary NP x maps into this easy fixed-word language. It does not convert general NP to LWE-SPHF, and it is not a local mixer for the Syscoin relation.

## 2. Exact multi-capsule necessary-and-sufficient criterion

Generalize the unused hidden direction to d coordinates. Let a and K be shared, b uniform in F_q^d, and k public fixed words x_i=(s_i,t_i), where each `t_i in F_q^d` is nonzero (every instance is false). The pads are

`C_i=K+a*s_i+<b,t_i>`, so public subtracting gives `Y_i=C_i-a*s_i=K+<b,t_i>`.

Put rows t_i into T in F_q^{k x d}, and `1` for the all-ones vector in F_q^k. Then

**THEOREM (exact joint-view dichotomy):** If `1 in Col(T)`, the entire joint distribution of Y is uniform over Col(T) and is identical for every K. If `1 notin Col(T)`, there is a publicly computable lambda in F_q^k such that `lambda^T T=0` and `lambda^T 1=1`, and thus `lambda^T Y=K` deterministically. Equivalently, perfect hiding holds iff `0` is **not** in the affine span of the hidden-direction vectors `{t_i}`. All quantifiers cover chosen public words and the *complete correlated tuple*, not separate marginals.

Proof: uniform b makes T*b uniform on Col(T). Changing K translates this coset by K*1. If 1 belongs to the image, the coset is identical. Otherwise its translates for different K are disjoint, and the separating functional lambda follows by linear algebra over F_q. This is information-theoretic, no computational assumptions and no quantum restrictions on postprocessing. It applies only while b is uniform and no auxiliary view leaks b or couples to it.

**Three-way-only exact attack:** take d=2 and

`t1=(1,0), t2=(0,1), t3=(1,1)`.

Each individual capsule and EVERY PAIR of these three capsules has a joint distribution independent of K: the 2-by-2 T of any pair is invertible and its image contains 1. But together,

`Y1=K+b1`, `Y2=K+b2`, `Y3=K+b1+b2`, so `K=Y1+Y2-Y3`.

The reuse of just a two-coordinate hidden mask causes a deterministic classical key-recovery attack even though all 1- and 2-view security tests pass. This is the relevant multi-view/cancellation/gauge/checking-key attack: once K is recovered, `vk(K)` publicly confirms a branch credential. UTXO/branch domain separation does not help if those pads intentionally share K and mask b and permit the three related false directions. Reusing K with **independently fresh** b_i on every false word instead makes the full joint tuple uniform independent of K, because the block-diagonal T has full row rank for all nonzero t_i. Whether such fresh independent local frames can coexist with an actual secure *common* release compiler is UNPROVED.

**Explicit limitations:** This lemma does not establish a cryptographic release from a hard ORIGINAL source, arbitrary-QPT true-instance signature-to-source extraction, honest one-party distributed setup or erasure, or practical 128-bit parameters. The public checking-key security assumption remains independent. The base toy permits public calculation of a witness whenever the statement is true, so it cannot be promoted to Syscoin WKEM. An output-only native signature still does not supply a Run-259 accepted complete representation. The Run-259 downstream extractor applies only if its actual residual-map and accepted-representation conditions hold.

## 3. Local attack taxonomy and next constructive test

- Local seam/cancellation: subtract `a*s_i`; hidden `b` directions remain.
- Global synchronization/gauge: joint left-null relation isolates K exactly when `1 notin Col(T)`.
- Statistical fingerprint: all one- and two-view distributions in the highlighted d=2 attack are PERFECTLY hiding, but the three-view distribution reveals K.
- Multi-view/related statement: exact three-capsule attack. Fresh independent masks avoid this **specific** attack.
- Adaptive/chosen public input: maliciously chosen nonzero directions can enforce the affine-span relation; independently prebound statement sets require separate analysis.
- Malicious setup/retained randomness: retained `b` reveals K from one false capsule; distributional independence fails for biased/correlated b.
- Cross-UTXO/branch replay: not solved by labels alone if key and mask are reused under related source words.
- Public checking-key correlations: the attack recovers exact K and can validate via vk; false single-capsule pad leaks no additional information if independent of b.
- Coherent quantum attacks: the positive joint-distribution identities are unconditional under the narrow uniform-mask view; the negative key recovery is already classical PPT. No QPT hard assumption, iO/RIO/WE or genuine quantum-only attack is inferred.

**Next target:** find an NP-hard *source-bound* projective release mapping with a sound ORIGINAL input interface and worst-case false-instance hiding, then test whether its full correlated multi-capsule channel has a similarly exploitable affine-span/gauge relation. The toy demonstrates *what a complete joint proof must include*, not a new assumption that silently supplies the missing release primitive.

## 4. Reproducibility

`linear_sphf_affine_span_run380_check.py` is standard-library Python, executed twice with byte-identical JSON outputs and py_compile PASS. The deterministic checker exhausts q=5,7,11 fixed-word correctness, uniform false pads, two-false repeated-mask K recovery and retained-b leakage; exhausts all nonzero 2-dimensional direction families of k<=3 over F3 and k<=2 over F5 against exact joint distribution histograms and rank-based extraction; and verifies a three-way-only attack over q=3,5,7,11 with every pair still uniformly hiding. Finite checks are **not** a cryptographic hardness or PQ parameter test.

Source anchors: Run 379 exact live blob above; Bettaieb et al., *Post-Quantum Oblivious Transfer from Smooth Projective Hash Functions with Grey Zone*, https://arxiv.org/abs/2209.04149 (architectural background); Run 259 exact live blob above. Full literature proof audit NOT performed this iteration. No production or workflow changes. Final practical WKEM stopping condition UNMET.
