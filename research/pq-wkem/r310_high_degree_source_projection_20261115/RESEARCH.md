# R310 — Sparse high-degree SHA-source correction admits a public low-weight extractor (NONQUALIFYING)

## Source continuity and strict scope

Starting syscoin/PVUGC draft PR #1 branch research/pq-wkem-validation-20260918, head a36dd809ab5a2f33230e774c2c21f1f90d098350. Latest R309 blob 5bd8e9baccad2fa6c572d22a9a81a4ab33a71d7f; read exact R308/R307 blob sources 94ed2a7fb10962ed501ec0c583613ddfde464cfb and 82973b1a11326bd82e93b8ac2221a46338013f77. Latest substantive ordinary PR comment R225 #6796383617. Read-only Core PR #609 metadata head c91539de3c34937e57d7f5fda47c7b0502ff33f6. No live source validation, Core test, external literature, or deployment claim.

The intended ORIGINAL evidence remains exactly the approved three OR branches: (1) authenticated, relevant competing BTC history with strictly more exact cumulative work from the *same* anchor; (2) finite authentic refutation/nonmembership or complete bounded authenticated execution for the *specific* asserted burn/withdrawal; (3) qualified Syscoin semantic-ancestor conflict at actual h_rel and required LC depth, or an independently authenticated claim-pinned exact-parent-wrapper tag fault under an expressly adopted maturity policy. Full chain/protocol/claim/UTXO/burn/amount/recipient/baseline, BTC anchor/window, height and predecessor paths, activated contextual modern chain ID, canonical 41-byte SYS tag, distinct merge-mining commitment, deadline/reset, capsule, frozen safe cancel native message/VK stay bound. Defective wrapper cannot borrow LC depth from a valid wrapper of same child; parent certificates for one child alone are not forks. One notary initiates; any witness holder challenges; N-of-N is setup only. R225 native fixed-outpoint activation portability remains independent.

This theorem targets a proposed *compiler* for a full ORIGINAL Boolean verifier, not a live implementation of that verifier. Source authenticity cannot be an after-check applied after secret recovery.

## Actual attempted classical-PPT Build/Open

Let the fully authenticated finite ORIGINAL verifier with source witness and recomputable gate trace z be encoded into polynomially many *public* constant-degree Boolean equations C_i(z)=0 in F_2[z_1,...,z_n]/(z_j²-z_j). SHA Ch/Maj/AND/XOR and bit-level SHA additions can be represented with quadratic gate constraints. Fix degree bound t for C_i. To repair R309's low-degree direct response, sample private independent vector coefficients a_{i,T} for |T|<=r (r a fixed constant), plus polynomially many independent coefficients b_{ij} and positive squarefree monomial supports U_{ij}, each |U_{ij}|>=d>t+r.

Publish only the combined expanded ANF coefficient table for the vector-valued polynomial

    P(z)=S XOR Σ_i C_i(z)[Σ_{|T|<=r} a_{i,T} z_T
                           XOR Σ_{j=1}^K b_{ij} z_{U_ij}].       (1)

S is the ONE frozen claim-safe cancellation capability; no private setup coins or standalone S appear in the public coefficient table. For fixed t,r and polynomial K, constructing and evaluating the sparse ANF is classical PPT. Public Open(C,z) evaluates P on the full original certificate and correct source-verifier trace. For **every** qualified ORIGINAL R(x_W,w)=1, all C_i(z)=0, so Open returns identically S, with no forced canonical witness, and the SOURCE constraints are inside the release polynomial rather than a post-hoc if-check.

That correctness does not imply secrecy. All public raw inputs z also admit evaluation; an adversary need not supply valid source bytes.

## Exact full-public extraction theorem

Write D=t+r, d>D, Q_D={z∈{0,1}^n: HammingWeight(z)<=D}, and B={C_i(z)z_T: |T|<=r}. Assume constant polynomial 1 is NOT in the F_2-linear span of B. This always holds for a TRUE source instance: at any satisfying original certificate+trace, all b∈B vanish, while 1 does not. It also holds on some FALSE instances without degree-r algebraic refutations.

Every multilinear polynomial of degree<=D is uniquely determined by evaluations on Q_D. This follows by Boolean Möbius inversion: a coefficient on monomial z_T equals the XOR of the evaluations on all subset-indicator inputs of T. Therefore linear algebra on the public restriction vectors produces α_z∈F_2 such that

    Σ_{z∈Q_D} α_z = 1
    Σ_{z∈Q_D} α_z C_i(z)z_T = 0   for all i, |T|<=r.         (2)

At every z∈Q_D all high-degree positive monomials z_U vanish, regardless of private supports and coefficients. Substituting (1) into (2) gives the public extractor

    S = XOR_{z∈Q_D, α_z=1} P(z).                             (3)

This is deterministic classical polynomial time for fixed D: |Q_D|=Σ_{k<=D} binom(n,k)=O(n^D), and the number of basis constraints is m Σ_{k<=r} binom(n,k). It uses only publicly available C_i and evaluation of the **full public P**, neither the ORIGINAL source witness nor private setup coins, a supplied representation, query log, or an inversion of SHA. Any QPT adversary can implement this classical attack with arbitrary VK/auxiliary/sibling information. For TRUE instances, even where finding a real challenge history is search-hard, S is recovered without one. For FALSE instances with 1 outside span(B), S is also recovered; native accepted cancellation then follows by using the honest frozen signature rather than forging it. A FALSE instance with 1 in span(B) is a *positive control for the premise*, not a security proof.

The theorem is scoped to this ANF compiler, low-degree multiplier span and positive high-degree monomials. It is NOT an impossibility result for all nonlinear SHA release, arbitrary high-degree schemes, iO, generic witness encryption, or original-source QPT reductions.

## Constructive repair attempts and regressions

1. A public invertible affine change of source variables keeps the local source equations degree<=t, so the low-weight projection still extracts S in the new coordinates. The checker includes an invertibly scrambled SHA Choice gate and recovers S from seven invalid public probes.
2. Including *all* independent degree-0 and degree-1 multiplier coefficients enlarges D to 3 but does not repair TRUE leakage. The checker recovers S from 45 invalid probes on the source-like TRUE fixture and 15 invalid probes on a FALSE quadratic instance without a degree-1 Nullstellensatz refutation. This is a new generalization of the degree-bound failure in R309; it does not depend on knowing the private correction coefficients.
3. A false linear contradiction C=(z0,1+z0) has 1 in span(B), so no α exists. This independent positive control shows the theorem is conditional on its exact algebraic premise.
4. Negated-literal dense high-degree masks can evade the simple low-weight vanishing argument, but expansion of many negated literals into public ANF is potentially exponential; exposing a factored public computation with S or setup seeds in clear is insecure. No polynomial, secret-hiding, source-dependent replacement and full-public QPT reduction is constructed. If r grows with λ, Q_D need not be polynomial; the alternative still needs actual classical-PPT Build/Open and independent QPT security, not an assumed secret evaluator.

## Executed checker and exact limits

Python 3 stdlib checker expands the combined ANF for 16 Boolean variables, 256-bit cancellation surrogates, local SHA256 Choice-like quadratic constraints, 18 high-degree (8–11) masked monomials per equation, and either constant-only (r=0) or all linear (r=1) low-degree secret multipliers. The public extractor receives P and C_i only. The checker exhaustively counts all 2^16 possible assignments for each fixture, checks honest TRUE openings, confirms all extraction probes were invalid, and includes FALSE nonlinearly contradictory and linearly contradictory positive controls. Seven fixtures: r=0 TRUE 64 solutions/9 invalid probes; affine-scrambled TRUE 64/7; r=0 nonlinear FALSE zero solutions/3 probes; r=0 linear FALSE zero solutions/no α; r=1 TRUE 64 solutions/45 probes; r=1 quadratic FALSE zero solutions/15 probes; r=1 linear FALSE zero solutions/no α.

Two independent checker executions: **568 assertions each**, byte-identical JSON SHA256 5979a35813442f111e995664ae107843855acf69ebdda5aa515e043573c1a62a. Executed checker SHA256 616a4a61d81a3c0e5986bf8c396adec2da7713519ddfce60c5777c0883ce17c2. Full local derivation, executable checker, paired output, provenance and archive in R310_high_degree_source_projection_20261115.tar.gz, SHA256 623cca95135dcb303ce6c8e09718fc5662699c936348a6c8c81f7f9d86fcf70b. The archive is a local conversation artifact, NOT a GitHub commit. Fixture source predicates are synthetic, not actual authenticated Bitcoin/Syscoin; S is a surrogate, not a native signature. No quantum simulation, real Core/Bitcoin validation, deployed bridge, or native SLH signing was tested.

## Exact unfinished obligation

Build_inc(x_W,sigma_cancel)->C and public Open_inc(C,w_original)->the SAME frozen safe native capability for EVERY fully authenticated ORIGINAL challenge, while complete-public FALSE and unauthorized hard-TRUE QPT recovery/accepted native forgery straight-line implies an ACTUAL qualifying ORIGINAL certificate or independent PQ hash/native break, including malicious setup, auxiliary correlation, sibling capsules and source-producer retention. The attempted compiler has all-witness correctness but is **provably insecure** on hard-TRUE and some FALSE instances; no reduction or useful source-dependent hidden transition was found. R225's native activation scope remains unsolved. No progress comment, notification, production change, or automation stop is warranted.
