# R46 — MINK-QUOTIENT-EXACT (offline, 2026-11-03)

## Result and exact provenance

A constructive *efficiency* advance on R35 (uniform-product-span) and R36 (sparse one-lift), not a generic PQ witness-KEM and not a recovery-to-ORIGINAL-witness theorem. Started on syscoin/PVUGC PR #1, open/draft/unmerged, branch research/pq-wkem-validation-20260918, head e4dbf39a8a82aa1ab2a3a75de1e5367ee60d27ef. Read latest relevant ordinary issue comment 6613934590 and exact-version R35/R36/R45 RESEARCH.md blobs 986ff360ea2853308127ace2b99a5476e4645a92 / 97d6211be34d905fe5a10952459b425f74c1f911 / d2b276764fcfb5b0cac09101da369374d9e55527. No external internet research, full PR diff, or old-archive reconstruction.

**Positive delta:** R35/R36 originally publishes a full M-element vector C_mu = L(a) + Delta*mu*1 + e, where L(a) is uniform over the publicly computable mask subspace W and independent of mu,e. Replace C_mu by exactly M-r quotient coordinates, r=rank(W), sampled *without drawing a at all*. Every genuine ORIGINAL witness evaluates this compact capsule to exactly the same value as the original, and a PPT reverse simulator recreates the *exact complete full-capsule distribution* from the compact capsule without K, the witness, or SOURCE-opening coins. This equivalence preserves the existing hard-TRUE vulnerability, too.

## Exact public algorithms

Work over A = F_q^M, q odd prime, in the degree-d squarefree Boolean quotient. For R35/R36, d=6 and M=sum_{j<=min(d,n)} binom(n,j). Let W=span(g_1,...,g_G) for public product-of-clause-failure generators g_jk=f_j*f_k, optionally with R36 public lift u=z_1*f_8*f_14. Uniform independent a gives L(a) exactly uniform over W. Compute the public RREF basis B_1,...,B_r of W once per bound statement x, with pivots p_1,...,p_r and complement F of size c=M-r. Define:

P(v) = (v - sum_i v[p_i]*B_i)|_F
S(z)[p_i]=0, S(z)[F_j]=z_j.

Then P(W)=0, ker(P)=W, P(S(z))=z, and v-S(P(v)) lies in W. Fix and bind the coefficient monomial ordering, relation identity, claim/UTXO/path, actual SYS/BTC anchors/window/context, native verification key, rank/pivots and capsule version; reject ambiguous/noncanonical field encodings.

CompactBuild(x, K): for every bit mu of the *same precommitted* fixed-path signing capability K and every independently randomized capsule/scope, sample the old M centered independent coefficient noise signs e, but **do not sample a**. Publish Z_mu=P(Delta*mu*1+e). CompactOpen(x,w,Z): compile ORIGINAL witness w to its faithful Boolean assignment z_w, require ORIGINAL R_x(x,w)=1 off chain, and evaluate S(Z_mu) at z_w, then apply the old nearest-center bit decoder. Since every g in W vanishes at genuine w, Ev_w(S(Z_mu))=Ev_w(Delta*mu*1+e). Every valid ORIGINAL witness, including distinct witnesses with distinct internal states, recovers exactly the SAME K, with precisely the old R35/R36 random-noise correctness bound. Open can sum directly over the c free monomial coordinates, without reconstructing M dense coefficients.

## Exact reverse simulator and arbitrary-QPT transfer

The OLD public capsule is C_mu=U_W+Delta*mu*1+e, with U_W uniform over W independent of mu,e, where its compact quotient is Z_mu=P(C_mu). Given ONLY Z, sample independent U'_W uniform over W by uniformly sampling coefficients on the public generators and output Rehydrate(Z)=S(Z)+U'_W.

Conditioned on any Z=z and any fixed mu, the original C_mu is **exactly uniform** on S(z)+W; hence Rehydrate(Z) is identically distributed to C_mu. The conditional law does not use or depend on mu,K or any ORIGINAL witness. P is a deterministic exact left simulation from old to compact; Rehydrate is a classical PPT exact right simulation from compact to old. Thus both directions of transcript distinguishing/recovered-key adversarial games transfer by straight-line public preprocessing with **zero statistical error**, not an assumed LWE/SIS/QPT game. An arbitrary QPT adversary may jointly/coherently process the resulting classical view and independent quantum auxiliary advice; no classical rewinding or random-oracle extraction is used.

For multiple capsules sharing arbitrarily correlated capability bits, independent old mask draws imply a product of these exact conditional fibers. The transformation preserves full public relation/statement, native vk, claim/context, and publicly reproducible CK and related-capsule algorithms. If a LEGACY CK derives from original C, a simulator may rehydrate C then compute that exact old CK; the compact *verifiable* protocol must instead version and bind CK to Z and other declared public fields, and cannot claim its CK bytes match legacy CK bytes. Restrictions: any hidden mask-dependent auxiliary leakage, target secret mask/noise opening, reused/correlated mask draws, malicious setup or arbitrary secret-K_bind-dependent CK is OUTSIDE this exact simulation theorem. Allowed auxiliary state must be independent of original uniform masking coins conditioned on declared K, x and noise; public derived CK transformations are allowed. A coherent non-target opening oracle is allowed only when it can be recreated independently of unopened target masks, not as an unrestricted target randomness oracle.

For R36 certified FALSE F with 1 in W, P(1)=0, so Z_mu=P(e) is EXACTLY independent of mu and shares the previous qualified FALSE full-public zero-bit simulator. For a TRUE x with some w, Ev_w(W)=0 and Ev_w(1)=1 force P(1) nonzero; any publicly computable short dual attack on old raw C also works on Z by rehydration. This does NOT establish arbitrary FALSE security, nor independent hard-TRUE secrecy or an ORIGINAL-witness extractor.

## Executed finite checks, concrete resources and negative claims

The attached exact V8-executed CHECKER.js and captured OUTPUT.json test real 3CNF clauses (not an LWE surrogate) with q=65537, Delta=32768, M=64. R36's 19-clause genuine UNSAT F has 190 product masks plus u, rank 51 and 13 retained field coordinates (64 -> 13, 79.6875% fewer). A genuine TRUE variant obtained by removing original clause index 10 has 18 clauses, 171 product generators, mask rank 49, exactly THREE valid ORIGINAL Boolean witnesses 10,11,43, and 15 retained coefficients (64 -> 15, **76.5625% fewer**). For a 256-bit capability and canonical three-byte F_65537 encoding, this TRUE fixture shrinks raw coefficient bytes 49,152 -> 11,520 (excluding public deterministic basis preprocessing and claim metadata), and avoids 171*256=43,776 q-field mask draws. The independent extended local Python3.13 checker passed **7,214 assertions twice identically**, including 768 identical genuine-witness old/compact openings and an exact 48-case F_3 full-fiber/public-checking-key distribution test. A separate Node22 checker passed **5,164 assertions twice**, with the same ranks, valid witnesses, 768 openings and 48 exact tiny-field cases. All are mathematical checks, not quantum-hardness or 128-bit parameter evidence. An initial local clause-copy mistake was corrected before both successful checks and all publication.

Public RREF preprocessing is polynomial in the explicit M x G matrix but can be expensive; for larger generic NP even d=6 may be wholly impractical, and basis recomputation might outweigh savings for few capsules. The noise remains M signs; compact encoding does not save that randomness. Nothing is claimed about production performance.

## Exact remaining obligation

The security objective remains, for arbitrary genuine ORIGINAL NP/SYS-BTC statement x, classical PPT Build/Open, arbitrary QPT A and the FULL correlated public view:

Pr[A obtains K or accepted native challenge signature]
 <= Pr[Ext^A outputs ACTUAL ORIGINAL w with R_x(x,w)=1]
    + Adv_QPT(independently justified break) + negligible.

The R35/R36 hard-TRUE pseudo-evaluation barrier is unchanged; no independent source-dependent LWE challenge simulator, no arbitrary-FALSE source hiding, no target selective mask openings, no malicious one-honest N-of-N SOURCE setup/abort security, and no deployed native Bitcoin PQ output/signature is supplied. Earlier R39-R44 Regev decryption secrets still do NOT authenticate ORIGINAL SYS/BTC evidence. Next iteration must develop or replace the NONLINEAR witness-gated release, not merely optimize this mask encoding. Bitcoin must not execute ORIGINAL NP/VM/PCP/Kilian/BitVM trace verification; existing R45 conditional pre-funding graph and bounded observer/DA/censorship assumptions are unchanged. No online release authority or unauthorized repository change is introduced.
