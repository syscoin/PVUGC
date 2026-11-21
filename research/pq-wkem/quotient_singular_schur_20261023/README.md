# Quotient-singular 3×3 Schur–Frobenius release (2026-10-23)

**Constructive continuation of `syscoin/PVUGC#1` from exact parent `de75993dee8c7e1b8a954a1bbcea2248700424b2`. Honest-setup supplied-pair theorem only; NOT a secure/practical PQ witness-KEM.**

The existing extension-separated sampled Frobenius-QAP carrier uses a 4×4 alternating gate with honest/violated rank 2/4 but *full-rank* quotient derivative. Its published quotient Hankel moments can expose the complete local `U_e,V_e` supports and enable a known unconditional linear-functional recovery of K.

This continuation replaces that gate with a **source-linear 3×3 Schur gate**, keeping the same source semantics and same capability for **every** ORIGINAL satisfying witness:

```
                 [ c+beta    a      s+eta ]
      S_e(y) =    [ b         z0     0     ]
                 [ s+eta     0      z0    ]
```

Over characteristic two, `det S_e = z0*(a*b+z0*(c+beta)+(s+eta)^2)`. For normalized `z0=1`, the private extension-separated shears give precisely the predecessor's QAP residual plus its `theta`-separated Reed–Solomon Booleanity code. Honest/violated ranks are **2/3**. Crucially, the quotient-dependent part is proportional to `J=E13+E31` of rank **2 < 3**, rather than full rank. The old **quotient-only** pencil no longer reveals every local gate factor.

An exact *restricted* masking theorem also holds. Even if the quotient pencil plus both exposed gate coordinates per node are revealed, the missing private second column/row of `U_e,V_e` leave `C0` containing `L` independent uniform rank-one outer products. Any linear functional selected **before inspecting C0 and the nonquotient slices** from that quotient-only information has scalar-output statistical distance at most `|E|^{-L}` from uniform. This is **not** hiding against inspection of the complete tensor; other coefficient slices also depend on those hidden gate factors.

To compensate for rank 2/3 rather than 2/4, use `T>=2h` invalid QAP nodes in the prior exact robust-distance/source extraction argument. Exact example: `F=GF(2^128)`, `E=GF(2^256)`, `n=11000,m=16000,k=27000,r=375,L=16374,T=234,h=117,N=32865`. Every one of the **three supplied-pair** setup-error terms is `<2^-135`, sum `<2^-133`. The full published matrix package is **933,213,506,400,000 bytes (0.933 PB)**, **1.700996% larger** than the predecessor's 0.918 PB; private outer-factor bytes decrease **23.72%**. Still prohibitively large.

[Full derivation, exact algorithms, theorem, checker, captured output and dependency/provenance record](QUOTIENT_SCHUR_BUNDLE.tar.xz). The archive holds `QUOTIENT_SINGULAR_SCHUR.md`, `schur_release_check.py`, `validation.json`, `PROVENANCE_SCHUR.json`. Run `python schur_release_check.py > out.json` and byte-compare to `validation.json`. The GF(16)/GF(256) toy builds actual public coefficient matrices but is **not the full QAP or a QPT test**. It passed **103,544 assertions** on each of two byte-identical executions.

**UNPROVED decisive gap:** unauthorized bare-K recovery/native forgery from the **entire** public tensor and checking key, with arbitrary QPT attacks, multiple capsules and malicious setup, ⇒ ORIGINAL witness or independently justified hardness break. The old quotient-only attack is blocked at its exact full-support inference, not proven impossible by any means. Neither false-instance QPT secrecy, practical size, honest-erasure/abort ceremony nor native Bitcoin P2MR/SLH endpoint is solved. The PR remains draft and production remains untouched.
