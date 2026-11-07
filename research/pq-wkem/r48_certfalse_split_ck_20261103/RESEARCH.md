# R48 — CERTFALSE-SPLIT-CK: ORIGINAL-source secret-correlated CK and exact FALSE native simulator

**Positive, narrow composition advance; generic PQ witness-KEM remains UNSOLVED.** 2026-11-03, offline. Starting syscoin/PVUGC PR #1 draft/open/unmerged, branch research/pq-wkem-validation-20260918 at b27248d6b424531d805764bd22e28786816e864b. Latest substantive ordinary comment 6616351677. Exact-version R47 RESEARCH blob 49a4cd8df2661b4ecbab229b7800bfc83b9614fb; R46 RESEARCH blob 7413e303a4b3b0649e0e9a0ca040d5a23b8b0663; R38 blob 6b5c2584af78bf37378d652dc9326843e1d5a102; R42 blob 8134b7987ae436f5e5017b6d03daf5c062cdc978. No web, literature, PR diff, archive sweep or other repository research.

## One precise missing interface and the delta

R38 proved a certified-FALSE native EUF reduction with checking key reproducible from PUBLIC fields. R42 allowed a K_bind-secret-correlated CK, but only for a surrogate LWE decryption-witness relation. R46 provided an exact quotient ORIGINAL-source release but excluded secret-dependent checking keys from its public-view equivalence statement. Here the ORIGINAL NP Boolean-quotient release is instantiated together with (i) independent K_bind and *full-signature-length* K_pad, (ii) a genuinely K_bind-dependent public CK, (iii) complete DEM/auxiliary correlations, and (iv) an exact FALSE simulator that does not know the native pre-signature, witness or SourceOpen. No LWE challenge or PRG is assumed in this restricted theorem. Its proof uses information-theoretic coupling and an **independent QPT native EUF-CMA assumption**; it does not prove security on TRUE statements.

## Distribution and algorithms (classical PPT for explicit polynomial-size Boolean degree d)

Let R_ORIGINAL(x,w) be a real NP verification predicate; x binds relation identity, concrete claim/UTXO, branch, actual burn or authorization/output, SYS/BTC headers/AuxPoW/coinbase tags/ancestor tags/anchors/window, context and the intended fixed native verification key/path. Compile it faithfully to clause-failure polynomials f_j in the Boolean quotient over F_q, q odd, with the public genuine-witness-vanishing generators g_jk=f_j f_k (and any explicitly justified additional generators). Let M be the number of public squarefree monomials at fixed degree d, W_x=span(g_jk) and P_x:F_q^M -> F_q^(M-r) the deterministic R46 canonical RREF quotient, ker P_x=W_x, with public section S_x. Take Delta=(q-1)/2 and independent centered coefficient errors e in [-B,B]^M, q sufficiently large that M B < Delta/2. Build does not find an ORIGINAL witness.

During honest N-of-N preauthorization, conditionally assume an independently QPT-EUF-secure native signature scheme and no bypass key path. KeyGen(sk_N,vk_N), compute the bound native challenge message m*=M(vk_N,claim,UTXO,path,context), sign sigma*=Sign(sk_N,m*) with an exact canonical fixed-length L-bit encoding, and protect/erase sk_N and unencrypted sigma* before irreversible funding. This step does NOT establish malicious-ceremony safety, source honesty or native Bitcoin deployment; R45's manifest/pre-funding DA assumptions remain separate.

Sample independent K_bind <- {0,1}^k and K_pad <- {0,1}^L, independent of (sk_N,vk_N,sigma*) and each other. Publish D=encode(sigma*) XOR K_pad. For each bit mu of BOTH seeds, each related certified-FALSE target scope, and each independent capsule, publish

  Z_mu = P_x(Delta*mu*1 + e_mu).

Publish CK=F(domain, K_bind, x, vk_N, m*, ctx, D, all Z, declared public related capsules), for any specified classical PPT deterministic F; for concrete use choose H(domain-separated, canonical length-prefixed encoding of those fields). Aux may be independently randomized but is computed only from (public transcript, CK, K_bind, aux coins independent of K_pad, sigma*, sk_N and target SOURCE noise); it may reveal K_bind completely. CK and Aux must NOT additionally depend on K_pad or sigma* except through public D. Declared related capsules may be independent non-target claims (including fully disclosed records for distinct signed messages) or independently masked certified-FALSE target capsules sharing K_pad and sigma*; no target opening or TRUE related capsule sharing target K_pad.

Open(x,w,Z,D,CK): OFF CHAIN verify the faithful ORIGINAL relation R_ORIGINAL(x,w)=1; for both seed families and all capsules decode each bit using centered nearest-Delta/zero decoding of Ev_w(S_x(Z_mu)); reconstruct K_bind,K_pad; check CK and specified Aux; recover sigma=D XOR K_pad, verify native Verify(vk_N,m*,sigma), then submit only that ordinary native fixed-path signature. There is no original NP verifier, PCP/Kilian, trace dispute, or VM step on Bitcoin. Distinct valid ORIGINAL witnesses retain different states and need not share short preimages, common intermediate values, or canonical witnesses.

## Exactly proved TRUE completeness; not TRUE secrecy

For each genuine ORIGINAL w, Ev_w(g)=0 for all g in W_x, and therefore

  Ev_w(S_x(P_x(v))) = Ev_w(v)   for every v.

Hence Ev_w(S_x(Z_mu))=Delta*mu+Ev_w(e_mu), and |Ev_w(e_mu)| <= M B < Delta/2. Every valid ORIGINAL witness recovers BOTH identical precommitted seed strings and exactly the SAME pre-signed native capability, regardless of distinct assignment or internal state. This is deterministic for bounded errors, for all witnesses simultaneously, given an honest Build. It does not protect K_pad on hard-TRUE x from short pseudo-evaluations.

## Exactly proved CERTIFIED-FALSE joint-output secrecy-to-native-EUF composition

Restrict x to FALSE instances with the PUBLIC algebraic certificate 1 in W_x; do not assume this holds for all FALSE NP/SYS-BTC statements (R36 supplies a counterexample). Then P_x(1)=0 and therefore each bit capsule is exactly Z_mu=P_x(e_mu), independent of its encrypted bit, *even conditioned on sigma*, vk_N and K_bind*. All target capsules use fresh e_mu, and the complete product law remains independent of K_pad when several false target scopes share the same K_pad.

Condition on arbitrary fixed native (vk_N,sigma*) and allowed public data. Since K_pad is independent uniform L bits, D=sigma* XOR K_pad is itself independent uniform L bits. Thus the **entire joint classical view**

  V = (R_ORIGINAL,x,vk_N,m*,ctx, all Z_bind and Z_pad, D, CK, Aux, permitted related capsules/openings)

has exactly the same distribution as the straight-line simulator: choose K_bind, generate all FALSE source capsules by sampling e and publishing P_x(e), choose D <- {0,1}^L independently, calculate the exact K_bind-dependent CK and Aux from these sampled public fields, and honestly simulate all independently scoped non-target claims/known-opening tables. The simulator never uses sigma*, native sk_N, target original witness, SourceOpen, source secret, or LWE challenge secret. Crucially CK is **not** publicly reconstructible without K_bind; the simulator nonetheless knows K_bind because it samples that independent seed. It may even reveal K_bind.

Equivalently, couple two arbitrarily different L-bit target signatures sigma0,sigma1 by the bijection K_pad,1 = K_pad,0 XOR sigma0 XOR sigma1. Then D0=D1 and every certified-FALSE target capsule is identical with shared e; all CK, aux, and permitted related views are identical. Zero statistical distance survives arbitrary coherent QPT processing and arbitrary reproducible independent quantum advice. A fixed polynomial non-target opening table may be given through a coherent reversible oracle, since the simulator knows its records. No quantum rewinding, random oracle extraction, adversary-supplied representation or assumed common hidden release primitive is used. Target selective opening, malicious setup, secret-sk/sigma-correlated advice, arbitrary TRUE related capsules sharing target pad, reused secret-dependent source coins, or arbitrary secret-correlated CK outside the defined F are explicitly excluded.

For a predesignated certified-FALSE target message m*=M(vk_N,ctx) distinct from all signing-oracle messages, let arbitrary QPT A output an accepted native signature sigma_A. The EUF reduction B receives vk_N from the native challenger, generates the above entire transcript with simulated uniform D and ZERO target signing queries, obtains only polynomially many signatures for distinct non-target messages if required, and runs A straight-line once. Any Verify(vk_N,m*,sigma_A)=1 is a fresh-message QPT-EUF-CMA forgery, including if sigma_A happened to equal the previously honest sigma*. Therefore

  Pr_real_FALSE[A outputs ANY accepted native signature on m*]
  <= Adv_QPT-EUF-CMA(Sig,B).

Exact recovery of K_pad from this full view yields sigma_A=D XOR K_pad and obeys the SAME bound. The theorem assumes independently specified QPT native EUF-CMA under the actual signature/message distribution; allowing vk-dependent message computation does not require predicting m before vk exists. This reduction does NOT prove IND secrecy of K_pad under a key-challenge game, nor generic hard-TRUE witness extraction.

## Public CK binding and resources

The confidentiality-to-EUF theorem holds for arbitrary efficient F of the **permitted inputs**, even if CK exposes K_bind; it does NOT infer CK authenticity from mere hashing. To claim canonical context/source binding against adversarial tag rewrites, additionally require a genuinely QPT collision-resistant construction with exact length-prefixed serialization; that is a separate property. All claim/UTXO, branch and anchor information must appear in x and the native signed message, not merely in CK. Native SHA/security, a future no-EC-key-path P2MR-like SLH-like verifier and R45's N-of-N graph remain conditional, not deployed.

RAW OTP is L signature bits, so unlike R42's PRG-based small seed it increases off-chain capsule size. At the R46 illustrative TRUE quotient c=15, q=65537 (three-byte coefficients), an 8 KiB native signature alone needs 65,536*15*3=2,949,120 coefficient bytes (~2.81 MiB), excluding K_bind, CK, DEM, basis and metadata. Correctness/source privacy versus resource feasibility is not established for concrete 128-bit parameters. Replacing raw OTP by a QPT-secure PRG seed is a plausible later optimization, but then the PRG hybrid and every full-view correlation require a separate proof; no such extension is claimed here.

## Executed finite checks and exact negative controls

CHECKER.js is the exact twice-executed V8 function with its repeat wrapper; OUTPUT.json is captured from that execution. It passed 91 assertions twice identically, including 192 true-witness seed-bit recoveries for genuine distinct ORIGINAL Boolean assignments 3 and 7 (dummy z2 arbitrary), 64 exact certified-FALSE pad-capsule couplings, and 1,024 exhaustive small-field full public transcript cases per signature. In q=257 with full 3-var squarefree basis M=8 and four genuine CNF clauses forbidding all patterns of (z0,z1), the FALSE W has rank4/codimension4 and P(1)=0. With one clause removed, TRUE W has rank3/codimension5 and its two valid assignments 3 and 7 decode the exact same capability and secret-correlated CK. Exhaustive q=5 toy FALSE with one constrained variable and one dummy yielded 64 distinct joint views and **exactly equal histograms** for two different sigmas even with CK depending on the secret K_bind and two same-pad source capsules. Negative CK=K_pad breaks equality; disclosing a related TRUE capsule sharing K_pad trivially recovers sigma. F is only JSON serialization in the checker (not a cryptographic hash). These checks are finite algebra/distribution validation, never QPT-hardness evidence. The initial local Python/container attempts failed with redis.exceptions.ResponseError; the successfully executed authoritative exact checker was V8 through the connected tool runtime; NO downloadable archive, Python success, native on-chain test, or independent verifier is claimed.

## Unsolved next ORIGINAL-witness reduction

This does NOT establish arbitrary FALSE security, arbitrary TRUE hiding, a genuine LWE SOURCE-opening simulator for x, key recovery to ACTUAL ORIGINAL witness, malicious N-of-N ceremony/abort, adaptive target openings, preauthorization liveness, practical 128-bit security, or a live Bitcoin PQ endpoint. R47's short-public-dual and multiple-decryption-secret failures remain. The indispensable next equation is to find a NEW independent QPT-hard source mechanism where for every hard-TRUE genuine ORIGINAL x and arbitrary QPT A on the **entire** correlated transcript:

  Pr[A obtains K_pad or accepted native signature]
  <= Pr[Ext^A outputs ACTUAL w with R_ORIGINAL(x,w)=1]
      + Adv_QPT(independently instantiated primitive break) + negl(lambda),

with no assumed SOURCE-opening oracle or A-supplied internal representation. The secret CK composition above is reusable if such a source is found; it is NOT itself the missing theorem. This automation must remain enabled.

