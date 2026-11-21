# Run 564 — public homomorphic acceptance overwrite at a late-witness frontier

Date 2026-10-16; `syscoin/PVUGC#1` draft branch `research/pq-wkem-validation-20260918`; verified starting head `8c1b20a3b7f95fcf41d024faa1f9955747202da1`.

## Theorem A — unrestricted public FHE evaluation is insufficient

Fix ORIGINAL NP relation R(x,w), secret capability K and a setup ciphertext c0 encrypting (K,0,x). Grant the defender an *ideal secret-derived* release gate D_x(c) which yields K' when c encrypts (K',1,x), otherwise bottom. An honest watcher uses public homomorphic evaluation to compute c_w encrypting (K,R(x,w),x), and all valid witnesses then obtain the same K while retaining distinct witness-dependent evaluated states.

If the same public evaluator also permits g(K,b,x)=(K,1,x), any outsider computes c*=Eval(g,c0) and obtains D_x(c*)=K regardless of R. This is a one-evaluation classical attack and therefore a QPT attack; no inverse, plaintext recovery, retained setup secret, local-gate leakage or new cryptographic assumption is needed. The attack persists if the gate authenticates x but evaluates only the decrypted acceptance bit.

A multi-capsule version uses unrestricted evaluation to splice the target false-instance encrypted K/x with an encrypted acceptance flag from another true capsule. Copying x from the targeted capsule preserves a literal context check, yet D_x releases the wrongfully unlocked K. No witness for the target false relation is required.

The exact limitation is *unrestricted Eval plus a release gate that trusts the evaluated acceptance bit without authenticating its computation provenance*. Controlled transformations confined to a verified Join_R program can avoid this particular attack. This is **not** a break of generic FHE, functional encryption, Canetti–Luo–Zhang's actual restricted homomorphism, or all local mixing.

## Theorem B — public IND-CPA join/open barrier

Suppose a caller-chosen-message IND-CPA encryption Enc_pk(m) also had classical-PPT public Join(pk,c,w) and Open(pk,Join(...)) recovering m with probability at least 1-epsilon for a publicly computable true pair (x,w). Suppose any extra helper data is efficiently samplable from pk and x independently of the challenge bit without the decryption secret. Choose m0 != m1 in the IND-CPA game; run Join and Open on the challenge ciphertext using w. The result distinguishes the challenge bit with success at least 1-epsilon. This straight-line reduction works against arbitrary QPT challengers, so ordinary IND-CPA encryption/homomorphic evaluation **cannot by itself** supply public witness-sensitive release under those helper restrictions.

Actual release needs either statement-dependent confidentiality (WE-like) or nontrivial setup-secret-derived controlled functional decryption. This lemma does not rule out bona fide FE keys generated during the one-honest-party N-of-N setup and properly erased. It also does not assume they exist or are QPT secure.

## Attack surface and honest scope

Local seam: overwrite an encrypted Boolean flag. Global frame/fingerprint: none required. Multi-view: cross-capsule flag splicing. Adaptive public evaluation: essential. Malicious setup: not needed, so honest erasure does not repair the tested design. Cross-UTXO/relation replay: public equality of x alone is inadequate when its encrypted register can be copied. Public checking key: not needed to recover K, though it validates native authorization. Quantum: this is classical PPT, not a novel coherent-only algorithm; any alternative still requires quantum evaluation analysis.

Run 259, `GLOBAL_FINGERPRINT_SOURCE_BINDING_RUN259.md` blob `c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2`, extracts ORIGINAL witnesses only from a *supplied accepted complete representation*. An overwritten flag and subsequent native signature produce none, so the upstream arbitrary-unauthorized-recovery -> representation/SIS-break implication is still missing. The operational target remains ORIGINAL evidence off chain -> SAME credential for all valid witnesses -> ordinary native challenge signature; Bitcoin does no NP/VM proof checking.

Literature: The 2026 Canetti–Luo–Zhang author presentation https://simons.berkeley.edu/talks/ji-luo-mit-csail-2026-07-13 states its public homomorphism permits only controlled transformations and disallows others. Its full security proof and concrete PQ applicability are not supplied by the present note. Exact live CLZ assessment blob `c19d9d9cd515140e3ce62eac960cd548c0add622` remains relevant. Run 562 ruled out witness-selected iteration on one fixed polynomial public unary orbit; this iteration instead supplies **late witness input** but shows unrestricted programmable evaluation defeats a naive gated release.

The executed deterministic checker `run564_homomorphic_flag_check.js` models opaque ciphertext handles and an idealized protected gate; it tests two witness tags, false-instance release, cross-capsule splicing and context enforcement. It is **not** real FHE/SLH-DSA, a practical mixer, or a QPT security proof.

## Handoff

Audit whether the *actual* CLZ allowed transformation language and its functional key can accept late-chosen ORIGINAL witness data jointly with a fixed hidden capability while preventing unauthorized acceptance-register edits. Only an independently proven protected join and source-binding release could help. All-valid-witness correctness, false-instance full-public-view QPT hiding, unauthorized true-instance native-forgery/source extraction, malicious N-of-N ceremony, multi-capsule security, concrete 128-bit resources and conditional P2MR/SLH graph remain **UNPROVED**. No practical WKEM is established.
