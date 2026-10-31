# Cumulative spectral WKEM state after Run 705

**State and exact dependencies:** GitHub PR #1 open/draft, verified starting head `35c321bec188155936842af2d17603e855682d39`; Run 704 shield exact note blob `67e2ea70503c0b4cf9379b89b90d98a536e56bba`; Run 259 global accepted SOURCE binding `c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2`. Run 703 DER/native adapter remains local-only after an explicit commit-stage GitHub safety denial. This file records a partial construction and does **not** claim a solved WKEM.

**Build/Setup:** Fix context x with relation version/claim UTXO/branch/anchors/window. Privately generate independent typed source matrix factors Run 593/701 and claim-scoped SLH-DSA credential B=SK.seed||SK.prf. Publish native pk, exact-key tag tau=H_tag(domain||x||pk||B), field q=2^256+297, and a single aggregate public polynomial matrix `C(z)=M_x(z)+K(B)I+sum_i r_i(z)Q_i(z)` with hidden independent uniform mask Q_i in public multiplier spaces P_i; publish spaces and evaluator/decoder specification. Honest N-of-N setup/erasure not yet implemented. Tag security is proved in an independent ideal QROM, *not* concrete SHA3.

**Encode:** any valid ORIGINAL witness w -> complete accepted Run701 SOURCE z via original verifier; r_i(z)=0 for all i. All valid witnesses may have distinct SOURCE/matrices, but K(B) is a shared spectral root.

**Recover:** run Run696 cofactor-free Krylov/linear-recurrence/Frobenius field-root decoder on the public C(z); filter candidate field roots through the Run703 exact tag and reconstruct full native credential; sign the intended transaction off-chain. Bitcoin native SLH/P2MR endpoint remains conditional. The complete native adapter was independently executed in local Run703, not committed.

**Extract:** accepted complete SOURCE z -> ORIGINAL witness by Run701 direct compiler and Run259 global source-binding under its explicitly stated statistical-folding or QPT-SIS premises. **Missing** arbitrary recovered B or valid native forgery -> accepted SOURCE z for hard TRUE x. No known extraction for a forgery not outputting z.

**Proved security component (Run704):** if false x has formal `sum r_i p_i=1` with each p_i in published P_i, uniform mask translation makes the full public C independent of B pointwise for all source evaluations. Polynomially efficient coverage for all false original relations remains unproved.

**Proved composition (Run705):** with a separately domain-separated quantum random oracle H_tag independent of native signing, arbitrary QPT access and correlated pk, the extra public exact-key tau=H_tag(d||B) in the Run704 false-x simulation reduces by standard O2H query extraction to ordinary native QPT EUF-CMA. Recovering extracted exact B yields a signer and a fresh forgery. With independent masks, poly-many false capsules can be handled by a hidden-point hybrid; mixed TRUE capsules are excluded. The finite checker verifies the distributions/algebra but not QPT theorem. No new augmentation-hardness assumption is needed in *ideal QROM* for that subclass.

**Concrete resource note:** current toy native B is 32 bytes; q is 257-bit; tau 64 bytes; prior large-circuit public storage remains impractical and is not re-estimated here. No invented 128-bit QPT parameters.

**Precisely open:** hard-TRUE recovery/forgery -> SOURCE, QPT full-view security of spectral carrier, polynomial all-false mask spaces, concrete hash security, native PQ endpoint, original SYS/BTC evidence authentication, malicious N-of-N setup, aborted/retained key attacks, correlated true capsules, usable runtime/storage. Continue *this* spectral candidate's actual local release/security design, not further compression or generic frontier reports.
