# Run 562 — polynomial fixed-unary orbit cannot itself admit a late ORIGINAL witness

Date: 2026-10-16. Research only; `syscoin/PVUGC#1`, branch `research/pq-wkem-validation-20260918`, starting head `67b4c1edf6ccf5e4d4dc1f96b5d78e7d7fa45a79`. This is a precisely scoped adapter falsifier, NOT a theorem against CLZ, arbitrary FE, controlled homomorphism or WE.

## Theorem A: public finite orbit enumeration

Consider classical-PPT public setup `Setup(x)->(c0,U,D,pk)`. The only allowed witness influence on the secret-bearing state is choosing an integer `j(x,w)` with `0<=j<=T(lambda)`, where `T` is polynomial and publicly bounded. The public deterministic unary update `U` yields `c_j=U^j(c0)`; `D(c_j)` outputs a candidate credential and public `B_x` tests whether that credential genuinely authorizes the intended ordinary native challenge-path signature. No witness is allowed into `U`, `D`, an initialization/joining circuit or key issuance.

If any ORIGINAL witness `w` produces `B_x(D(c_j))=1`, an outsider without `w` computes all `c_j` sequentially and checks every `D(c_j)`. It succeeds in at most `T+1` public steps (plus ordinary evaluation costs). If an honest watcher succeeds with overwhelming probability over setup, so does the outsider. The result is **classical PPT**, so it also defeats arbitrary-QPT true-instance knowledge security. No local-mask inversion, global gauge alignment, fingerprints or oracle assumption is involved.

**Scope:** This does NOT preclude witness-dependent public ciphertext joining, a programmable transition `U_w`, functional-key selection from an exponentially rich family, or a protected verifier that genuinely authenticates witness data. Those would be ADDITIONAL cryptographic capabilities. Unbounded iterations of a fixed unary `g`, as advertised in the CLZ application, do not by themselves supply late witness injection. For polynomial honest execution, the selectable orbit is polynomial. Do not extrapolate this claim to CLZ's complete FE and controlled-homomorphism theorem.

## Theorem B: independent false hiding and true source extraction

Assume, **conditionally and separately**, a public efficiently computable one-way permutation `f:{0,1}^n->{0,1}^n` secure against arbitrary nonuniform QPT inversion, including input-independent quantum advice. It is NOT claimed to follow from LWE. Define `R((b,y),(u,t))=[b=1 AND f(u)=y]`, with `t in {0,1}`. Every `b=1` statement has two ORIGINAL witnesses, but finding either on random `y=f(u)` is QPT-hard. Every `b=0` statement is false.

The following deliberately insecure-on-TRUE-inputs classical-PPT KEM shows a strict game separation:

```
Encap(b,y):
  K,Z <- independent uniform L-bit strings
  C := (b==1) ? K : Z
  return (C,K)
Decap(b,y,C,w): return C
```

Every valid ORIGINAL witness returns **the same exact K**, with perfect correctness. For every FALSE statement, `(C,K)` and `(C,U_L)` have identical distributions, hence false KEM key-pseudorandomness is information-theoretic under the *isolated KEM challenge view*. But on a true statement `C=K` is public. Any supposed general true-instance key-recovery-to-ORIGINAL extractor that works given public setup, the public recovery algorithm and its output could be used to invert `f`. Its inverter receives `y=f(u)`, samples setup and runs the explicit recovery adversary and extractor, without receiving `u`. Conditional QPT-OWP hardness rules out such an extractor.

For native-signature correlation, independently generate `(sk,pk)`, publish `T=sk XOR K` with fresh `K`. For false statements `C` and `T` are uniform independent of `(sk,pk)`; conditional on QPT signature EUF-CMA, an outsider cannot produce a fresh authorized signature merely from that view. For true statements `T XOR C=sk` publicly, yet no ORIGINAL witness follows. DO NOT claim that `K` is pseudorandom jointly with `T,pk` against candidate testing: that is NOT the isolated KEM-key game. No native SLH/Bitcoin implementation or graph is provided.

Thus all-valid-witness SAME key + false-instance confidentiality do **not** imply true-instance ORIGINAL extraction. The separation is intentional and not a viable witness-release construction.

## Attack taxonomy and composition

(1) **Seams:** none needed; public orbit and native checker suffice. (2) **Gauge:** all states already traverse one public orbit. (3) **Fingerprints:** public credential acceptance is the distinguisher. (4) **Multi-capsules:** one capsule breaks the pure-orbit true-instance game; key/pad sharing would add cross-capsule risk. (5) **Chosen-input:** an outsider enumerates every public iteration, regardless of the watcher's source-side `j(x,w)` calculation. (6) **Malicious setup:** attack holds against *honest* setup; retained seeds, aborts and bias remain separate unresolved risks. (7) **Replay:** bind `(relation,claim/UTXO,branch,anchors/window,graph/sighash)`; this proof fixes one context. (8) **Checking-key correlation:** a fresh branch public `pk` makes successful readouts recognizable; Run 561's EUF hybrid is the appropriate false native-signature game. (9) **Quantum:** no coherent-only attack is necessary, as an efficient classical adversary already succeeds.

## Run 259 / primary literature / remaining duties

Run 259's exact `accepted complete z -> ORIGINAL witness` requires a *supplied* globally consistent representation; a naked recovered key/signature or a public orbit index does not supply it. Theorem B shows why that missing upstream implication cannot follow from false-instance KEM hiding alone.

Verified exact dependencies at the starting head: Run 561 note blob `34e5e98a17b2dd089041ec723227df5070574db2`; Run 259 note blob `c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2`; CLZ applicability blob `c19d9d9cd515140e3ce62eac960cd548c0add622`; Run 560 blob `bc8bcde5819519bf1519a832813ae26facf5442f`. The Canetti–Luo–Zhang 2026 author/publication descriptions confirm unary `g` iterations and separately available FE functions (https://simons.berkeley.edu/talks/ji-luo-mit-csail-2026-07-13 ; https://cris.tau.ac.il/en/publications/how-toencrypt-withrandom-reversible-circuits-functional-homomorph/). Full paper proof, exact quantum assumptions and late-witness composition were **not audited** in this iteration.

The exact independently executed checker tests polynomial public-orbit enumeration, two-valid-witness common-credential functionality, false independence and public key-mask identities with toy **publicly invertible** affine maps. No QPT OW permutation, obfuscator, WE, SIS, native signature or Bitcoin endpoint is instantiated. Theorem A is unconditional for the stated interface; Theorem B's impossibility of extraction is conditional on QPT OWP hardness. Setup, extraction, multi-capsule, 128-bit physical resources, N-of-N abort/erasure and challenge/timeout graph remain UNPROVED.

**Core handoff:** Seek a concrete, QPT-justified, public late-witness-indexed *secret-bearing state transition* `Join_w(c)` or protected source admission beyond a polynomial unary orbit. It must authenticate the complete ORIGINAL representation before a shared capability can be recovered, avoid a WE/iO-equivalent renamed assumption, and route arbitrary unauthorized native signing through an independently proved recovery-to-source reduction. No completed practical PQ WKEM; stopping condition unmet.
