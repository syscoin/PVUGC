# Extension-separated Boolean–Frobenius sheared release (2026-10-23)

**Constructive honest-setup supplied-pair improvement. NOT a practical or QPT-secure witness-KEM.**

Continuing precisely from PR #1 head `6cf8de49d07a79e798ca953b146fd63f2d767f9f`, the 4×4 Boolean–Frobenius gate is moved from a single GF(2^256) to base SOURCE field F=GF(2^128) and outer matrix field E=GF(2^256). Pick θ∈E\F and, for every sampled off-domain QAP node e and original Boolean coordinate i, choose private α satisfying

`α_(e,i)^2 = b_(e,i) + θ·e^(i−1)`,  b_(e,i)∈F.

The normalized local Pfaffian **exactly** becomes

`pf(G_e(y)) = [t_e(y)+Σ_i b_(e,i)(w_i²+w_i)] + θ·Σ_i e^(i−1)(w_i²+w_i)`.

For any SOURCE representation y typed over the base field F, the second extension component is a Reed–Solomon evaluation of the Booleanity-defect vector. If any w_i is non-Boolean it is nonzero on **at least L−n+1 nodes**, simultaneously and deterministically. For Boolean w the extra term vanishes, preserving every valid ORIGINAL witness, its distinct intermediate state and the same 256-bit capability K. Counting only 2^n original Boolean assignments (but still all q^(m−1) quotient states) improves the earlier sampled-QAP robust-distance bound. Combining this exact improvement with the previous honest uniform outer-factor rank theorem proves supplied (λ∈E,y∈F^k) accepted by the public threshold lifts to λ=K and an ORIGINAL valid w except on a setup event <2^−133.

Illustrative *exact integer* certificate: n=11000, m=16000, k=27000, q=2^128, E=2^256, r=237, L=16236, T=h=117, N=32589. Public coefficient payload **917,605,083,744,000 bytes (0.917605 PB)**, **65.884519% smaller** than the prior 2.689703 PB. **Still impractical.** Source values MUST be checked to lie in base F; the theorem DOES NOT cover evaluating arbitrary E-valued SOURCE states.

**Complete exact reproducible record:** [EXTENSION_RELEASE_BUNDLE.tar.xz](EXTENSION_RELEASE_BUNDLE.tar.xz), SHA-256 `8f5f29ab5cbe03fa6402c25ac1734d9e3643151aeb6928a63d71cf58bb53cbe1`, Git blob `b3c8dffde56e719c70555d7ea754c5d31fa4241c`. Deterministic archive holds the full `EXTENSION_SEPARATED_SHEAR.md` (algorithms, proofs, scope, exact dependencies, costs), `extension_shear_check.py`, captured `validation.json`, and `PROVENANCE_EXTENSION.json`. Extract with `tar -xJf EXTENSION_RELEASE_BUNDLE.tar.xz`; run `python extension_shear_check.py > out.json` and byte-compare to `validation.json`. Pure Python; two independent executions produced byte-identical output with **136,803 assertions**. The GF(16)/GF(256) synthetic fixture is not the entire QAP, not a cryptographic security test, and not an independent QPT proof.

**Still UNPROVED and unchanged:** arbitrary unauthorized full-public E-tensor key-only recovery/native accepted forgery ⇒ ORIGINAL witness or independent QPT-hardness break; false-instance QPT secrecy, checking-key/multi-capsule/quantum correlated leakage, retained/malicious setup, native Bitcoin P2MR/SLH semantics and funding/abort graph. The extension/subfield fingerprint may itself introduce public algebraic attacks. Neither arbitrary key secrecy nor practicality follows from supplied-pair soundness. All files are research-only; production and workflows untouched.