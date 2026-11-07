# MINK-SPARSE-SUPPORT-R24 — sparse row projection with exact QPT view equivalence

**Research only, 2026-11-02. NOT a secure generic PQ witness-KEM, a 128-bit QPT parameter set, or a deployable Bitcoin endpoint.**

## Actual predecessor and scope

The exact initial PR #1 head was 1cb6dbc7ce2a67cc23c3b3ee7b030179bb1e4235 on research/pq-wkem-validation-20260918, open/draft/unmerged. The latest substantive ordinary comment was 6589351908. Continued R21's Boolean-quotient SOURCE, R22's authenticated public derivatives, R23's every-ORIGINAL-witness error bound, and R20's **restricted** certified-FALSE native-vk/public-G simulator. Read exact-version R21/R23 and PR metadata/comments only; no web/external literature.

R21 publishes every square-free coefficient row of degree <= d+3, including rows that are identically zero in **all mask columns** and carry only independent sampled noise. R24 gives an explicit shorter release algorithm and a two-way straight-line security-game adapter. It removes redundant data, **not** the known SOURCE attacks.

## Exact Build/Lift

Let x bind the ORIGINAL NP relation/verifier identity, claim/UTXO, branch, anchors/window, challenge path, context and intended native verification key/capability. A witness-preserving 3CNF compiler has n Boolean extension variables and c clauses. Work in A_n=F_q[z_1,...,z_n]/(z_i^2-z_i) over odd q. Let g_j be the polynomial product of clause j's literal-failure factors. R21's full matrix B has rows H={U subset [n]:|U|<=D=min(n,d+3)} and columns coeff(g_j*z_T), |T|<=d. Its full row count is M=sum_{k<=D}binom(n,k), and L=c*sum_{k<=d}binom(n,k).

Compute **publicly and deterministically** I={empty} union {U in H: some B[U,j] !=0 modulo q}. Set J=H\I, m=|I|. Thus B_J=0 and e_empty,J=0 exactly, including after coefficient cancellations. Index/order I canonically in the authenticated descriptor. For each bit mu of the **same precommitted native signing secret K**, honest classical Build samples r uniform in F_q^L and independent centered errors e_I with |e_U|<=eta; it publishes C_I=B_I*r+Delta*mu*e_empty,I+e_I mod q. The honest setup knows/protects/erases K under a **separate**, unfinished one-honest N-of-N ceremony; keyless Build is not claimed.

Every valid ORIGINAL witness w computes a Boolean extension a and evaluation lambda_a[U]=product_{i in U}a_i. Since each g_j(a)=0, lambda_a,I^T B_I=0 and lambda_a,I[empty]=1, so

    lambda_a,I^T C_I = Delta*mu + sum_{U in I,U subset support(a)}e_U  (mod q).

Circularly decode near centers 0 and Delta for every capability bit, verify the intended native vk and sign the exact challenge path off-chain. **Every distinct valid ORIGINAL witness recovers the SAME precommitted capability** except for bounded honest-noise failure; neither a canonical witness nor a common preimage is assumed.

Derived same-scope capsules are exactly C_j,I=C_0,I+B_I*u_j with public authenticated u_j. Their raw witness evaluations equal that of the base. The compact descriptor **must be authenticated before funding**; old signatures binding different full bytes cannot automatically authenticate the compact format.

## Theorem 1: full-joint-view equivalence, including QPT postprocessing

Define Full as the precise R21 independent-row-error distribution with r uniform, all e_H independent of K, source coins and each other, and native vk generated normally. Define Compact as above. Assume that: (i) deleted e_J is fresh and independent even conditional on x, K/vk, retained source coins, past transcript and initial quantum side information; (ii) the public checking-key/context/auxiliary generator G and permitted classical native signing-oracle interface are explicitly specified and reproducible from the relevant canonical view and genuine vk; (iii) each independent base receives fresh errors, while every R22 public derivative shares its base error, and opening records include the corresponding coordinates; (iv) an adversary has no prior quantum register entangled with deleted source errors or private secret-dependent G that the simulator cannot reproduce.

Project(Full) deletes J and publicly regenerates the compact canonical G-fields. Pad(Compact) independently samples e_J **once per independent base**, inserts C_J=e_J, carries those SAME values through every adaptive public derivative of that base, and publicly regenerates the full G-fields (using any permitted classical signing oracle when authorized). Both kernels are classical PPT for fixed d and exactly reproduce the respective joint honest distributions, including R,x,capsules, authentic checking-key data, genuine native vk, contexts, permitted auxiliary and multiple-capsule/selective other-scope opening behavior. These distributions are of DIFFERENT byte formats, not literally equal strings; each format is related to the other by an exact sampling kernel. Every arbitrary QPT recovered-key/forgery/distinguisher attack can be transferred in either direction through the appropriate straight-line classical adapter, with identical success probability in the specified security games. Coherent QPT processing of the public view is permitted; coherent private-opening oracles and arbitrary secret-correlated auxiliary inputs outside G are NOT covered. Neither adapter learns K, a witness or the LWE challenge secret, and neither calls SourceOpen.

Because this is an exact relative security equivalence, the known R19/R21 short-pseudoevaluation FALSE attack and the missing hard-TRUE extraction theorem remain completely unchanged. No new QPT-LWE or signature hardness claim follows. A deterministic public support set cannot hide relation semantics.

## Theorem 2: unchanged certificates and stronger simultaneous correctness

For any t, B*t=e_empty iff B_I*t=e_empty,I, because B_J=e_empty,J=0. Therefore **exactly the same** publicly degree-certified FALSE instances retain R20's honest joint-public simulator: the real correlated vk is taken from the native signing challenger, and, given a public certificate t, the exact change r0=r+Delta*mu*t lets it publish C_I=B_I*r0+e_I without the private tape. A publicly derived checking key, claim/path context, permitted native-oracle auxiliary and all shared-noise derivative capsules couple exactly. This does NOT prove universal adversarial-FALSE security for uncertified x.

For independent centered errors |e_U|<=eta, with ell protected bits, S independent authenticated bases and T=min(Delta,q-Delta)/2, Hoeffding plus a union bound over all Boolean assignments gives:

    Pr[ANY valid ORIGINAL witness fails on any bit/base]
       <= 2^(n+1)*ell*S*exp(-T^2/(2*m*eta^2)).

Public same-base derivatives introduce no extra factor because lambda^T B_I=0 identically. The event is fixed before an arbitrary QPT adversary chooses a witness. This is a **statistical correctness** bound, NOT 128-bit confidentiality.

## Resource checks: actual nonzero supports, not a symbolic estimate

Deterministic seeded proper 3CNF fixtures; illustrative q=65537, Delta=32768, eta=1, ell=256; packed 17-bit field symbols, excluding source computation, native signatures, authentication and manifests:

| n | clauses | d | full rows | retained rows | reduction | full -> compact 256-bit capsule |
|---|---:|---:|---:|---:|---:|---|
| 20 | 40 | 1 | 6,196 | 1,552 | 3.992x | 3.214 -> 0.805 MiB |
| 30 | 60 | 1 | 31,931 | 3,814 | 8.372x | 16.566 -> 1.979 MiB |
| 50 | 100 | 1 | 251,176 | 12,388 | 20.276x | 130.310 -> 6.427 MiB |
| 80 | 160 | 1 | 1,666,981 | 31,686 | 52.609x | 864.828 -> 16.439 MiB |
| 30 | 60 | 2 | 174,437 | 43,570 | 4.004x | 90.498 -> 22.604 MiB |

For n=80,d=1 the prior R23 toy failure bound was weaker than 2^-128; with m=31,686 the same Hoeffding calculation is roughly 2^-6022. This measures **only** reliability. Even 16.4 MiB for 256 bits is impractical; native QPT parameters and real-source performance are unassessed.

## Reproducibility and precise boundaries

The exact published self-contained JavaScript checker in CHECKER.js was executed and yielded OUTPUT.json, 44,451 assertions. The independently authored local Python checker executed **15,778 assertions twice**, byte-identically (SHA256 of checker d35c978fd502640f73511ccd7e8e376bfd51bf85e9b286d775d7a4526c621275; output SHA256 082eecc881e578d3a1aeb24889204ecb3a7720c03d277d1eca3e76b60a17d47a). An independent local Node checker executed **55,531 assertions twice**, byte-identically (checker SHA256 2cd2f691380a836298a2782df320ac39b6f43272799a0da22d493846796c960c; output SHA256 6c7d4d32f61e2a22da7627e53fe482b061ffb239f7742ed93a858c9513983106). The latter extended checkers and outputs are **local-only**, not GitHub blobs. The published checker covers a TRUE 8-variable relation with **136 different** satisfying ORIGINAL witness extensions and a FALSE 7-variable parity-cycle contradiction with an explicit **28-term degree-one** certificate. It verifies same-base noise sharing, honest release and exact public false-capsule simulation. A preliminary independently authored local Node check used an incorrect <10 raw-noise assertion, which was corrected to the valid support-size bound before the two passing executions. No checker tests arbitrary QPT cryptographic hardness.

## Central unmet equation and stopping requirements

We still lack a classical-PPT full-public-output simulator covering **every** adversarial FALSE x and source-dependent checking keys/auxiliary without the challenge secret. We also lack, for arbitrary QPT A returning the final K or a native forgery **without volunteering an internal representation**, an actual ORIGINAL-witness or independently justified QPT-break reduction E satisfying a bound of the form:

    Pr[A succeeds unauthorized on hard TRUE x]
       <= Pr[R_original(x,E^A)=1] + Adv_independent_QPT(E) + negl(kappa).

No ordinary-LWE simulator was instantiated for this structured source. R19's explicit FALSE disclosure still applies; no malicious one-honest N-of-N setup/abort composition, keyless builder, actual native SLH signing implementation, Bitcoin P2MR-like endpoint, pre-funding data availability or deployment is claimed. This is meaningful source-size reduction **without weaker relative security**, not resolution of the PQ witness-KEM.

Provenance: authorized PR #1 branch only, starting SHA 1cb6dbc7ce2a67cc23c3b3ee7b030179bb1e4235. Exact local experiments and the attached archive were performed offline. Do not describe publication as a cryptographic proof or claim independent agents, an external literature search, a review, approval or merge.