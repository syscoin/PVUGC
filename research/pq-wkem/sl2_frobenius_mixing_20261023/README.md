# SL₂–Frobenius compensated local mixing (2026-10-23)

**Scope: a constructive source-linear release-operator integration, NOT a secure or practical PQ witness-KEM.** Continues `syscoin/PVUGC#1` from the exact 3×3 Schur predecessor `d7d7862522faf1603c0a2e6e572b03d320f56045`; does not create a new NP relation or a WE-like release assumption.

The predecessor's source-to-3×3 gate is now augmented with **secret independent per-node SL₂(F) mixing of its a,b inputs**, together with a characteristic-two **Booleanized Frobenius correction** to c. Its public output is still exactly `k=n+m` matrices, still `N=2L+h`, and its gate rank remains **2 for satisfied / 3 for violated** SOURCE equations. Crucially, the correction vanishes on **every normalized Boolean ORIGINAL assignment**, while non-Boolean source errors remain in the base field and cannot cancel the extension-separated Reed–Solomon Booleanity code. Distinct ORIGINAL satisfying witnesses retain distinct QAP quotient/source states and recover the **same K**.

The exact new formula at node e is

```
 [p q; r t] in SL₂(F),   p*t + q*r = 1,
 a' = p*a + q*b,
 b' = r*a + t*b,
 c' = c + (p*r)*LinearizeFrobenius(a²) + (q*t)*LinearizeFrobenius(b²).
```

The full **homogeneous polynomial identity for arbitrary projective source inputs**, exhaustive notation, complete Setup/Encode/Recover/Extract algorithms, inherited proof of simultaneous *supplied-pair* semantic soundness, exact entire public tensor, and QPT limitations are in [the complete reproducible bundle](SOURCE_BUNDLE.tar.xz). Importantly this is *not* merely the predecessor's removable constant gamma gauge: for a formal independent a-direction the new derivative generically has rank two instead of rank one. That is an algebraic distinction, **not** evidence of key hiding from the whole public tensor.

**Verified checker:** 173,408 assertions, two byte-identical executions. Besides toy finite-field checks, includes an actual 3-row ORIGINAL Boolean R1CS -> off-domain QAP -> Frobenius encoding -> this new local release -> public dense matrices, with two different valid ORIGINAL witnesses giving source vectors `[1,0,0,0,0]` and `[1,1,1,15,7]` and both recovering K=157. Toy fields and tests do not prove QPT security.

At the predecessor's illustrative (not deployable) `F=2^128,E=2^256,n=11000,m=16000,k=27000,r=375,L=16374,T=234,h=117,N=32865`, the earlier honest-setup error bound **<2^-133 for every rank-accepted supplied (lambda,y) -> lambda=K and ORIGINAL valid w** remains valid. Extra private setup randomness: 49,122 base-field elements (~786 kB). Public coefficient storage is **unchanged: 933,213,506,400,000 bytes (~0.933 PB)**, impractical.

**UNPROVED:** key-only/public-operator QPT secrecy and unauthorized native forgery -> ORIGINAL-witness extraction; false-instance QPT hiding; multiple correlated capsules; malicious setup/abort; practical storage; Bitcoin PQ signature/settlement graph. The prior quotient-only subpencil does not itself prove K recovery, but original-variable slices might restore missing factors. The precise remaining joint-slice expression is preserved in the bundle. No production/workflow modifications, no merger/approval, no claim of completed WKEM.

Reproduce with Python 3.10+ standard library:

```sh
python sl2_frobenius_mix_check.py > output.json
cmp output.json sl2_validation.json
```

Archive contains `SL2_FROBENIUS_MIXING.md`, `sl2_frobenius_mix_check.py`, `sl2_validation.json`, and `PROVENANCE.json`.
