# Source-glued LWE SOURCE repair: exact public-residual collapse

**Status:** bounded offline research iteration, **NO qualified positive WKEM advance**. This is a supporting failed-repair record, not a claim of generic-NP witness encryption or Bitcoin/Syscoin security.

**Continuity/provenance:** syscoin/PVUGC draft PR #1 on research/pq-wkem-validation-20260918, parent head d1d75264082a521cd96a137416d110d15888642c, latest substantive comment read 6461769177; exact predecessor research/pq-wkem/all_witness_tail_pack_20261028/README.md blob ea37e94cf35273a2144e0a98590c799f996f42df. No internet or external literature was used. The initially guessed predecessor RESEARCH.md returned a read-only 404; its actual path was obtained from the exact parent commit.

## Construction and complete honest distribution

For an ORIGINAL relation R and statement x, suppose a public classical-PPT compiler gives source matrix C_x in F_q^(d×k) and anchor e in F_q^k, and public Release maps **each valid ORIGINAL witness W** to integer w=w_x(W) with

    C_x*w=0 mod q,   e^T*w=1 mod q,   ||w||_1 <= h.

This premise is **not instantiated for arbitrary ORIGINAL NP** by this experiment. The compiler must verify actual claim/UTXO, branch, anchors, context, source evidence and intended native verification key—not just a random-kernel label. For each independent capability, sample actual native seed K and checking key pk(K), U,Z uniform independent pads, D=U XOR Z, V=K XOR U. For each digit a of Z, sample independent public A uniform in F_q^(d×m), public Rmix in F_q^(m×k), secret s,t uniform in F_q^d, and errors eps_L~chi^m and eps_R~chi^k. Publish

    p_L = A^T*s + eps_L,
    p_R = Rmix^T*p_L + C_x^T*t + eps_R + g*a*e.

The entire public transcript includes relation x, C_x, A, Rmix, p_L, p_R, genuine checking key pk(K), D,V, context, auxiliary data and all related capsules. Public off-chain Release(W) first validates the ORIGINAL relation, computes w and

    r = p_R - Rmix^T*p_L = C_x^T*t + eps_R + g*a*e;
    w^T*r = g*a + w^T*eps_R mod q.

When |w^T*eps_R|<=E<g/2, cyclic nearest-center decoding recovers a, hence all digits of Z and the same precommitted K=V XOR D XOR Z for every valid W meeting the error bound. Distinct W may have distinct intermediate w. Deterministic all-witness error bound is E=h*beta for chi supported on [-beta,beta]; improving it requires a joint all-witness statistical argument. Public checking pk(K) alone does not stop unverified private decoders from using pseudo-openings.

## Genuine joint LWE-challenge simulator, but no SOURCE hiding

On an ordinary decisional-LWE challenge (A,y), where real y=A^T*s+eps_L and null y is uniform in F_q^m, the reduction samples Rmix,t,eps_R,a, all independent native keys and pads, and publishes

    p_L=y;
    p_R=Rmix^T*y+C_x^T*t+eps_R+g*a*e.

This is an exact classical simulation of the **entire specified ciphertext correlation** in the real case, without a SourceOpen oracle or the unknown LWE secret. However, the public invertible transformation

    (p_L,p_R) -> (p_L, p_R-Rmix^T*p_L) = (p_L,r)

isolates the source-dependent residual. Given public x,C_x,A,Rmix, the independently sampled p_L and r are independent conditioned on a and the properly sampled native-key/pad view. Switching p_L from LWE to uniform leaves r unchanged. Thus ordinary QPT decisional LWE on A proves **nothing** about protected digits after this public cancellation.

The exact missing full-public condition, for every false ORIGINAL x and correlated public auxiliary view, is a QPT indistinguishability statement between

    (C_x, C_x^T*t+eps_R+g*a*e, pk(K),D,V,ctx,aux,siblings)
and
    (C_x, C_x^T*t+eps_R,         pk(K),D,V,ctx,aux,siblings),

jointly sampling a=Digit(Z), D=U XOR Z, V=K XOR U with the actual native pk(K). This equation is **not proven or independently reduced** for general x. Positing it directly would rename witness encryption.

When e=C_x^T*lambda for a computable certificate lambda and t uniform, the straight-line shift t'=t+g*a*lambda gives an **exact** false-source simulator, including the genuine checking-key correlations when aux/related openings do not disclose t or target-secret-dependent material. This is restricted certificate-conditional row-span hiding, already established in earlier research, not a fixed-false generic-NP compiler. Every valid normalized kernel opening w implies e is outside row(C_x); a public polynomial-time compiler giving the row-span certificate for *every* false NP statement and such an opening for *every* true one would decide SAT by Gaussian elimination. No such compiler is claimed.

## Attempted repairs within this bounded iteration

Public linear mask changes to Rmix and more independent left LWE columns still leave the public residual unchanged. Suppressing Rmix would prevent public Release from evaluating the source correction unless a separate witness-conditioned Rmix*w computation were constructed; no such computation exists here. Masking with the actual native checking key detects wrong K but neither prevents algebraic raw-key recovery nor proves ORIGINAL evidence soundness. A distributed setup or source-specific native signature does not solve the missing public residual security.

## Reproducibility, assumptions, and status

The accompanying **exact executed** standard-library Python checker check.py was run twice offline with byte-identical captured stdout checks.jsonl. It performed **147,343 finite exact assertions** for q=257: 5,000 joint challenge/cancellation samples, a bounded-noise same-digit toy true witness, 243 uniform-y residual identities, and 132,098 exact false row-shift identities. These are algebraic checks only, not an arbitrary-QPT, native-SLH or Bitcoin endpoint evaluation. The challenge-side comparison is to ordinary QPT DecLWE with independently sampled quantum advice, but it does NOT prove SOURCE security; no unsourced hardness assumption is silently introduced.

The remaining construction must jointly instantiate SOURCE-dependent Build, every-ORIGINAL-witness SAME-K Release, a false-instance full-public QPT simulator, and arbitrary unauthorized hard-true K recovery/native forgery -> ORIGINAL W or independently justified QPT break. It must allow large evidence off chain; the Bitcoin endpoint must use ordinary native signatures without executing the NP verifier. N-of-N honest-erasure graph, malicious setup/abort, shared-key selective opening, tags/AuxPoW/fork/DA/window constraints and 128-bit concrete QPT parameters remain unproved. In particular, a random true kernel relation cannot substitute for actual SYS/BTC source authorization.

**Do not count this candidate as positive progress.** GitHub publication records this *failed repair and exact next equation*, not a security milestone.
