# R53 — GHOST-DUAL-IDEAL-CLOSURE: explicit hard-TRUE source bypass and bounded closure attempt

**Result:** No positive advance toward a practical QPT witness-KEM or the required hard-TRUE arbitrary-recovery-to-ORIGINAL-witness theorem. This is a new, completely checked **negative source result**, followed by one exact algebraic repair attempt that does not establish security. Offline research only; no external papers or web.

## Exact provenance and scope

Started with syscoin/PVUGC PR #1 **open/draft/unmerged**, branch `research/pq-wkem-validation-20260918`, SHA `c7d8c1a63a8a627f55b27e0fb5211645763e04e1`. Read latest substantive ordinary comment 6621268655 and exact-version R52 RESEARCH.md blob 16a8b0125cc62cc17aacf5b005f6e8ff3a7d98e0, R46 RESEARCH.md blob 7413e303a4b3b0649e0e9a0ca040d5a23b8b0663, R48 RESEARCH.md blob d3dce77b15d70b61c1d1e1e1ee2fcbef2f8ee4d2, R35 and R36 introductory records, and R46's exact checker. No PR-wide diff, historical archive sweep, independent agent, external literature or unrelated repository read.

## Target and explicit public bypass

Continue the ORIGINAL-NP quotient source underneath R52's genuine ORIGINAL-witness hidden-matrix LWE-tree release. Let A be the full degree-six Boolean quotient on n=6 variables with M=64 squarefree monomial coefficients and q=65537, Delta=32768. Use exactly R46's TRUE 3CNF obtained by deleting original R36 clause index 10; its genuine ORIGINAL assignments are precisely 10,11,43. Let f_i be actual clause-failure polynomials. The original mask space W2=span{f_i f_j : i<=j}, 18 clauses, 171 generators, has rank 49. Canonical P with ker(P)=W2 and public section S gives the actual per-bit capsule:

    Z_mu = P(Delta*mu*1 + eta_mu), eta_mu coefficients independently bounded in {-1,+1}.

The following PUBLIC **integer functional** on monomial coefficients (index = bitmask of variables) is not any genuine witness evaluation and is not even in the linear span of the three genuine evaluation vectors:

    h(v)=v[0]+v[2]+v[8]+v[10]-v[32]-v[33].

Exact integer arithmetic certifies h(g)=0 for every one of the 171 mask generators, h(1)=1, ||h||_1=6, and rank{Ev_10,Ev_11,Ev_43,h}=4. In particular **the adversary does not need to find, supply or call OPEN with an ORIGINAL witness**. Because h annihilates W2, h(S(Z_mu)) = Delta*mu+h(eta_mu) modulo 65537; |h(eta_mu)|<=6, so the ordinary nearest-center decoder recovers mu with certainty. This applies independently to every hidden R52 root, pad-secret and K_bind bit. The entire seed and the precommitted native capability can therefore be reconstructed directly from public Z, A0, D and canonical context. Revealing K_bind also permits recomputing the secret-K_bind-correlated checking key; published CK cannot stop this extraction. Related capsules do not repair a public per-bit decoding channel. The ordinary off-chain OPEN procedure's ORIGINAL verification is irrelevant to an adversary that directly computes the bound native signature.

The example is a **small easily satisfiable fixture**; it is NOT evidence of breaking a hard-TRUE NP statement or a QPT hardness assumption. The point is precise: R52's full-view certified-FALSE QPT theorem and valid-witness correctness do **not** yield TRUE source confidentiality. This ghost is a *non-Boolean supplied linear functional*, but arbitrary QPT key recovery must be handled without requiring the adversary to volunteer one.

## Attempted constructive repair and exact boundary

Define W2plus = W2 + span{z_S f_i: |S|<=2} using only publicly compiled ORIGINAL clauses and polynomially many explicit generators for fixed source degree. Every ORIGINAL witness annihilates the extra masks; therefore the SAME precommitted-bit correctness identity still holds pointwise. For the exact n=6 fixture, 171+18*(1+6+15)=567 generators have rank **61**, quotient codimension **3**, and the ghost h no longer annihilates W2plus. Indeed the entire full Boolean clause-failure ideal has rank 61 (=64-3). Its annihilator is exactly the span of the THREE genuine ORIGINAL evaluation functionals. This is an exact, locally verified representation lemma, not an unauthorized-key-recovery-to-witness reduction.

The generic full ideal has ambient dimension 2^n and is generally not a practical polynomial-sized public representation; the degree-two truncation need not saturate it for arbitrary NP circuits. A short public dual may still survive the enlarged space. The new capsule is a deterministic public linear transformation of the old capsule, so **capsule-only** distinguishing power cannot increase under fresh identical noise. But that observation does NOT transfer R52's full secret-K_bind-correlated CK/aux/native-output game, because a simulator from the old public view need not know K_bind to recompute a CK that binds the new quotient. Thus NO security-preserving full-public-output theorem for the closure is claimed. No QPT security, practical 128-bit parameters, full arbitrary-FALSE secrecy or native Bitcoin deployed endpoint is established.

## Executed mathematical verification

`CHECKER.js` is the exact function executed in the connected V8 runtime with a Node-compatible output wrapper; `OUTPUT.json` is its captured JSON. The checker verifies the actual 18 clauses and rank, 171 integer mask equations, integer norm and nonrepresentability, all 64 canonical projection coordinate identities, public opening of a complete toy hidden R52 root/pad/binding seed and ordinary masked signature, 64 two-bit control cases across all three real satisfying assignments, and the degree-two/full-ideal closure ranks. A separate local standard-library Python checker ran **twice identically with 945 assertions**, the same exact ghost and closure ranks, and a 36-bit precommitted seed/native-signature recovery. Neither checker tests QPT hardness. The toy signature is a deterministic 16-bit capability, not an actual native PQ signature.

## Exact handoff

The necessary missing statement for arbitrary hard-TRUE ORIGINAL x, with full view (x,relation,Z,A0,D,CK,vk,context,aux,related capsules and admissible openings), is:

    Pr[arbitrary QPT A recovers final K or outputs accepted native target signature]
       <= Pr[straight-line/justified QPT Ext^A outputs genuine w with R_ORIGINAL(x,w)=1]
          + Adv_QPT(independently justified primitive break) + negligible.

No extraction may require A to reveal a pseudo-dual, representation or internal witness. The next useful construction must replace the publicly linearly decodable source with a genuine nonlinear witness gate and instantiate its challenge-secret-independent joint-output simulator. Applying additional low-degree masks or better compression alone does not establish the statement. Preserve classical PPT honest setup, same capability for ALL ORIGINAL witnesses, N-of-N one-honest graph/pre-funding checks, no online release authority, off-chain original verification only, and conditional native SLH/P2MR-like Bitcoin path. R53 is NOT a complete WKEM and MUST NOT stop the ongoing research task.
