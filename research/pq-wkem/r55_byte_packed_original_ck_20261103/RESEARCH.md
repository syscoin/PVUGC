# R55 — BYTE-PACKED-ORIGINAL-CK: explicit 8-bit release and full-view certified-FALSE coupling

**Run:** R55-BYTE-PACKED-ORIGINAL-CK-20261103. **Status:** a **restricted constructive efficiency advance** for R54's actual ORIGINAL source: source-capsule coefficient bytes fall sixfold at nonzero quotient dimension while every valid ORIGINAL witness still recovers the SAME Build-committed capability and the established certified-FALSE full-public-output simulator still applies. This does **not** repair hard-TRUE secrecy or supply the key-recovery-to-ORIGINAL-witness theorem.

## Pinned continuity and actual provenance

At first read, syscoin/PVUGC PR #1 was open, draft, unmerged on branch research/pq-wkem-validation-20260918 at e5b84f5a6d62611c113da2901148e2ebf0eb8c36. Latest substantive ordinary comment was 6622882397. Exact R54 blobs read: RESEARCH.md b93bbeb71ee065b9e5db28c816701339d0690d34; CHECKER.js d73a52156b81e8e066fcfab0953c177c481b723f; OUTPUT.json 4b5b22ed8bd6e610ed4be2255379b2a4c31972de. Only those exact-version substantive materials and current PR metadata/comments were needed. No PR-wide diff, historical-run sweep, external websites or external literature. The published CHECKER.js and OUTPUT.json are **the exact executed connected V8 source and captured result**. A distinct local Python checker and expanded research manuscript were also independently executed/retained offline; they are not claimed byte-identical to CHECKER.js.

## Release source: BuildByte / OpenByte

Public statement x binds ORIGINAL relation/verifier identity and proof/evidence source, claim/UTXO, SYS/BTC branch, chain/header/AuxPoW/coinbase-tag/ancestor window, authorization, direction, lag, output, intended native verification key/message/challenge path, graph manifest, release/version and canonical byte lengths. It inherits the R54 faithful ORIGINAL predicate; compilation and ORIGINAL checking take place OFF CHAIN. Bitcoin runs neither the original NP verifier, VM, general proof, dispute protocol, nor LWE check; BitVM is covenant plumbing only. Native PQ signatures/no-EC-key-path outputs and R45 N-of-N ceremony, presignature, data availability and enforced timely inclusion remain **conditional**, not deployed.

Let A_q = F_q[z_1,...,z_n]/(z_i^2-z_i), with ORIGINAL clause-failure polynomials f_i and the R54 specified versioned masking subspace:

    W+ = span{ f_i f_j : i<=j } + span{ z_S f_i : |S|<=2 }.

In the public monomial order, P_x is the deterministic canonical RREF quotient projection with kernel W+, and S_x is its zero-pivot public section. This uses an explicit coefficient space of dimension M; for the actual checker M=16 or 64. **No polynomial-size explicit M=2^n construction for arbitrary NP is claimed.** Honest algorithms are classical polynomial time only for the separately supplied polynomial-size efficient compiler family.

The repaired, direct byte release uses an actually checked prime SOURCE field q_s = 16,777,259 = 2^24+43, spacing Delta = 65,536, byte m in {0,...,255}, and fresh per-byte centered noise eta uniformly in {-1,0,1}^M, independent of m and of all cryptographic seeds. Publish

    Z_m := P_x(Delta*m*1 + eta) in F_{q_s}^{M-rank(W+)}.

Canonical encoding is 4 bytes per 25-bit field element, fixed endian, rejection of noncanonical elements and scope-bound lengths; incomplete trailing byte encodings must be checked. R54 had one bit per capsule at q0=65,537 and Delta0=32,768, using 3 bytes per field element. Crucially, increasing q_s rather than merely reducing the spacing keeps the minimum circular symbol distance d_min = min(Delta, q_s-255 Delta) = 65,536. For arbitrary |eta_i|<=B, require d_min > 2 M B; here B=1, M<=64, so 65,536 >128.

OpenByte(x,w,Z) first verifies the actual R_ORIGINAL(x,w)=1 **off chain**. It computes a=Ev_w(S_x(Z)) and nearest codepoint Delta*m mod q_s in circular distance, requiring a unique nearest codepoint within radius MB. Since every valid ORIGINAL w annihilates W+,

    a = Delta*m + Ev_w(eta) (mod q_s),
    |Ev_w(eta)|<=M B.

Thus **all ORIGINAL witnesses, irrespective of their different computation states, recover the same exact Build-selected byte**. Concatenating the bytes recovers exactly R52's originally chosen matrix-expansion root, LWE pad seed/error and independently chosen K_bind; Open regenerates the matrix, checks its intended commitment alpha, computes the distinct-modulus LWE pad Y=A(r0)s+e mod 2^t, unmasks precommitted D=Encode(sigma*) XOR Encode(Y), verifies the ordinary native signature under bound (vk,m*) and returns the signature as the sole public off-chain capability. Build must have generated this signature and all preauthorizations prior to irreversible funding; those graph/ceremony assumptions are NOT repaired here. Optional keyless Build, adversarial coin retention, abort, equivocation and censorship safety remain unproved.

The NEW versioned CK and Aux are computed **after all public target and related byte capsules are normalized**, binding version, q_s, encoding, x, vk, message, A0, alpha, D, Z_target[], related Z[], context, and domain:

    CK = F(K_bind, domain, x, vk, m*, A0, alpha, D, Z_target[], related_Z[], ctx)
    Aux = AuxAlg(K_bind, CK, x, vk, A0, alpha, D, Z_target[], related_Z[], ctx; independent_aux_coins).

F is fixed deterministic classical PPT, genuinely depends on hidden K_bind, with canonical length-prefixed inputs; adversarial re-binding requires a separately justified QPT hash-collision-resistant implementation. Aux may reveal K_bind but cannot leak target matrix/pad seeds, native signature or signing secret, or discarded raw projections. The R54 old CK bytes are **not assumed reusable**. The toy checker uses string CK/Aux only as a distribution-coupling sentinel, not cryptographic verification.

## Exact restricted full-JOINT certified-FALSE theorem and QPT simulation

Consider a predesignated *unopened* certified-FALSE target. Publicly check P_x(1)=0 in this exact SOURCE field and compiler. For **every** byte value, every set of fresh noises, and all target capsules jointly,

    P_x(Delta*m*1+eta) = P_x(eta).

This is exact, not computational or asymptotic. The simulator independently samples all target noises and K_bind without the encrypted matrix root, LWE seed/error or a SourceOpen oracle. It can compute the very same secret-K_bind-correlated CK and permitted Aux from known public capsules, D, x, context, and related independently seeded claims. It samples non-target opened claims only when the specified opening game lets it and when it knows their coins/witnesses; no target opening, same-secret opened related capsule, auxiliary secret leak, or target-secret-correlated quantum advice is allowed. Arbitrary QPT coherent processing of the identical full classical public distribution—and separately preparable independent quantum advice—does not alter equality. Context, original predicate and certificate must remain invariant under the challenged seed/matrix hybrids. Target x binds the claim/path/vk and is fixed before challenges.

Thereafter use **only** the previously *specified* R52 restricted ordinary QPT decisional-LWE binary-tree and pad hybrids with honestly uniform shared A0, independently sampled LWE secrets and bounded noise, known checking-key seed, fresh target native message and QPT native EUF-CMA; the classical-PPT straight-line source simulator introduces no additional assumption. Under precisely those R52 conditions:

    Pr[accepted target native signature]
      <= (2^d-1) Adv_QPT-DLWE_tree
         + Adv_QPT-DLWE_pad
         + Adv_QPT-EUF-CMA_native + negligible.

A QPT commitment/collision break is a separate term when malicious re-binding is in the game. This is a native forgery **bound for certified-FALSE**, not generic arbitrary-FALSE IND secrecy, not hard-TRUE extraction, not proof of concrete 128-bit parameters. It does not use QPT rewinding, oracle programming, generic-group, SIS, iO/WPRF/WE assumptions, or assume an attacker volunteers a representation. Multiple related, permitted openings are limited to independently seeded claims; opening an actually target-secret-correlated capsule is an explicit counterexample.

## Exact fixed fixtures, new nonempty FALSE test and resources

Checked using q_s rather than merely copying R54's ranks: the actual 19-clause n=6 UNSAT ORIGINAL fixture remains rank(W+)=64, quotient 0, no witnesses. Its actual 18-clause TRUE sibling has rank 61, quotient 3, with EXACTLY witnesses 10,11,43. In the new field, each of the 256 possible bytes decoded correctly for every one of the three witnesses (768 successful genuine openings). A 96-byte hidden source ensemble also opened identically for each of those three witnesses. This is all-witness *correctness*, not secrecy.

To test a nonempty certified-FALSE quotient, use a genuine four-variable contradictory 3CNF: (z0 OR z0 OR z0) AND (NOT z0 OR NOT z0 OR NOT z0), leaving the remaining 3 bits free. With the SAME W+ generator rule and q_s, rank is 14 of 16, quotient dimension 2, **P_x(1)=0**, and no genuine witness. The exact executed checker constructs 256 couplings of **four simultaneous target capsules each** with different hidden byte values, identical sampled noise, a fixed independent public D/context/related record, and genuinely chosen secret-K_bind-dependent CK/Aux; each complete transcript matches exactly. This test ensures the FALSE efficiency result is not just a vacuous zero-vector source.

For 256 hidden bits, using field coefficients only and excluding unchanged LWE/public-context overhead:

| Public quotient dimension | R54 per-bit (256 capsules * 3 bytes * dim) | New per-byte (32 capsules * 4 bytes * dim) |
|---:|---:|---:|
| TRUE fixture, 3 | 2,304 bytes | 384 bytes |
| certified-FALSE nonempty fixture, 2 | 1,536 bytes | 256 bytes |
| certified-FALSE 19-clause, 0 | 0 | 0 |

**Sixfold smaller / 83.33% fewer source coefficient bytes** at nonzero quotient dimension. For 96 hidden bytes at quotient 3, capsule coefficients go from 6,912 to 1,152 bytes. This is not a sixfold reduction of *entire* LWE/native graph transaction costs. Hard-TRUE source security was not established in R54 and is not preserved/proved by this field change. The increased decoding distance preserves the proved worst-case noise correctness margin only.

## Execution, provenance, errors, exact next equation

Published CHECKER.js is the **exact connected V8 executed source**, and OUTPUT.json is its captured output: **1,287 successful checks**, 768 true ORIGINAL openings, three complete 96-byte source openings, two original R54 rank/truth checks, and 256 nontrivial four-target-capsule full CK/Aux FALSE couplings. A separately coded local Python checker passed **1,301** finite assertions twice identically after an initial local Python typo (failure to invoke n4.one()) was fixed. An initial V8-only publication staging attempt accidentally transcribed only 16/19 clauses and failed its TRUE rank assertion **before any GitHub write**; it was corrected, then the exact 19-clause version passed and created the published checker/output Git blobs. Neither finite checker establishes QPT hardness or a native signature implementation. No external web/literature or independent agent used.

The actual still missing hard-TRUE, full-joint-public-output theorem is:

    Pr[A_QPT recovers final bound K or forges the accepted native signature]
      <= Pr[Ext^A outputs ACTUAL ORIGINAL w, R_ORIGINAL(x,w)=1]
         + Adv_QPT(breaking an independently instantiated primitive)
         + negl(lambda).

It must cover arbitrary QPT coherent attacks, malicious/adaptive related openings and auxiliary when permitted by the stated security game, and **cannot require A to volunteer an internal dual/representation**. Packing, old padding, public basis changes and marginal LWE hiding are not repairs for this missing reduction. Full arbitrary-FALSE security, hard-TRUE secrecy, malicious N-of-N setup/abort, evidence liveness/DA/censorship, practical parameters, and conditional native PQ Bitcoin endpoint remain unresolved. Keep existing research automation enabled.
