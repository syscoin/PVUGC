# R373 — Global ordered matrix gating: complete-source consistency, but public span search defeats source-work preservation

**NONQUALIFYING; not an ORIGINAL WKEM or an FE implementation.**

## Exact continuation and source boundary
Inspected open/draft syscoin/PVUGC PR #1 at branch research/pq-wkem-validation-20260918, head 62e85204f898ede105596c3e486d1728115511d6 (R372, note blob b545bdab40206a97039dc868a48b771f4e870e16). Relevant issue comments since 2026-11-17 UTC: none. No Core head/source/test reread and no native signing or source certificate. Continue R372's specific unfinished operation: a *single globally consistent serialized public release program*, replacing its bypassable public digest-only label.

The precise new design change from R366 is to mask **one whole ordered path** in a public matrix program rather than expose independent clause readouts whose local accepted assignments have odd-cover leakage. It is a concrete finite-width classical public Build/Open, not a renamed SourceOpen oracle. The global path prevents prescribed-interface clause-splicing. We construct its release and a narrow joint-public FALSE coupling together, then test hard-TRUE source-work security.

## Actual finite-width Build/Open and correctness
For finite field F_q and length-L deterministic read-once matrix program, let public matrices A_i^0,A_i^1 in F_q^(d x d), start row a, terminal column b, with

    f(w) = a (A_1^(w1) ... A_L^(wL)) b in {0,1}

equal to the accepted-word indicator. Build chooses independent uniform R_0,...,R_L in GL_d(F_q), nonzero K in F_q, and scalar test capability S, and publishes:

    u = a R_0
    B_i^c = R_(i-1)^(-1) A_i^c R_i  (c=0,1)
    v = K R_L^(-1) b
    D = S - K
    C = (u, B, v, D).

The public opener evaluates t=u product_i(B_i^(wi)) v and returns D+t if t != 0, otherwise bottom. Telescoping gives t=K f(w), hence **the same S for every accepted whole word**, and bottom for rejected words. Build and Open are polynomial in explicit L,d; no private evaluation service. This tests a scalar release, not an actual native signature or the ORIGINAL OR source predicate.

## Explicit PUBLIC full-word extractor
For each prefix length i define

    V_i = span{ u B_1^(w1) ... B_i^(wi) : w_prefix in {0,1}^i }.

Maintain a basis of V_i using at most d *actual representative prefixes*. For every stored basis row r at step i, multiply r by B_(i+1)^0 and B_(i+1)^1, and retain an independent subset with their representative prefix words. Linearity proves this spans V_(i+1); there are at most d rows throughout. At i=L, any basis row r with r v != 0 supplies an **actual accepted full word** because r v=K f(w) and K != 0. If none has nonzero product, no word is accepted. Finite-field Gaussian elimination gives polynomial complexity O(L d^4) or better, without enumerating 2^L inputs, private gauges, attacker query logs, or a supplied algebraic representation.

Thus a hard-TRUE ORIGINAL source-work predicate encoded faithfully as a polynomial-width ordered public linear program becomes **publicly witness-searchable in polynomial time**. The attack does not exploit an invalid mix of witnesses; it recovers a genuine accepting word. Hence this attempt does not preserve Bitcoin/Syscoin source acquisition work. This is a theorem about *explicit ordered linear programs*, not about general hash-only nonlinear FE or the real source relation.

## Restricted FALSE joint-public simulation
For a specific terminally forced-FALSE family assume b=e_0 and both final matrices have zero first column, A_L^c e_0=0. Set T=diag(K'/K,1,...,1) and R_L'=T R_L. Then A_L^c T=A_L^c, every published B_i^c is unchanged, and

    K' R_L'^(-1) e_0 = K R_L^(-1) e_0.

Set S'=S+(K'-K), making D'=S'-K'=D. This couples the *entire classical public matrix/vector/ciphertext transcript* for two different payloads. For fixed S,S', sample uniform K in F_q^*, and put K'=K+S'-S. Except the at-most-one case K'=0, the above is an exact transcript coupling; the remaining statistical error is at most 1/(q-1). This restricted-classical transcript bound persists under arbitrary quantum post-processing of those **classical bytes**. It does not simulate arbitrary original FALSE claims, setup proofs, correlated native verification keys, siblings, selective opening, or coherent hash interfaces. It is not a hard-TRUE QPT theorem.

## Actual bounded computation and reproducibility
Executed local Python3 standard-library script twice (both exit zero) with byte-identical JSON. Independent 2x2 gauges over F_65537 protect a length-18 exact-match automaton, one accepted word among 2^18. Five thousand random words found none, but the public prefix-span algorithm found the unique exact accepted word and recovered the frozen synthetic S. A separate forced-FALSE automaton had no accepted path and a distinct (K',S') with the exact same published transcript was constructed.

Local-only sources and outputs preserved at /mnt/data/r373_global_matrix/ and archive /mnt/data/R373_global_matrix_20261118.tar.gz (SHA256 ba2d7f3a3ce3c42719a8c1cf0faa60cbd380563086ad205225662cebe546b008). Checker SHA256 520844c5d2fb26776fad60e04c1f2c71aaf0d067029f9ee10b1b7fd430116649; both captured JSON outputs SHA256 bceedd330f21269a091e928501299254f7b7e24b79efc35fa557f8b907bb4cc3. The GitHub research note does not contain the local checker bytes. No real SHA/PoW, Core tests, native Bitcoin signatures, production graph, FE, or quantum experiment.

## Repair attempted, exact open operation
A nonlinearly SHA/ancestry-state-indexed transition would evade the fixed B_i^0/B_i^1 span extractor, *if* publicly evaluable and serialized. Naively publishing independent private-labelled transitions for all future prefixes needs exponential entries; deriving transition labels from a public SHA seed exposes them to arbitrary callers; keeping the seed private leaves source-based public input-label delivery unimplemented. R372 also excludes unrestricted digest-only labels sampled without source preimages. No compressed, nonspliceable, actually source-authenticated nonlinear public evaluator was built here.

Therefore still missing:

    C=Build_orig(x_W,sigma_cancel;rho)
    Open_orig(C,w)=sigma_cancel for EVERY original qualified w,

with full relevant AuxPoW/BTC/burn OR validation inside cryptographic release, one-honest setup and claim-bound native cancellation, plus a reduction from arbitrary full-public unauthorized FALSE/hard-TRUE QPT recovery or native forgery to an **actual qualifying ORIGINAL certificate** or independently established hash/native break. This note is an anti-regression, not the requested missing advance. No PR progress comment or user breakthrough notice; leave the existing automation enabled.