# R177 — Claim-relevant fork coverage by one sufficiently advanced authenticated baseline

**Status: constructive, conditional source-relation reduction; NOT a hash-only witness-KEM, QPT release theorem, source-complete Bitcoin/Syscoin verifier, or deployment recommendation.** This pass repairs one overgeneralization from R176 only if the withdrawal's challenge policy is **forks affecting the already-bound claim-relevant source prefix**. If the bridge must veto *any* later fork regardless of claim relevance, R176's two-future-observation witness remains necessary.

## 1. Provenance

`syscoin/PVUGC#1`, draft/open/unmerged; branch `research/pq-wkem-validation-20260918`; original observed head `9c79af61d998afeadf0e5f1b764e8b1ea2bee27d`. Read the exact R176 and R174 construction notes, PR metadata and latest substantive R176 comment. Intermediate `CHECKPOINT_01.md` was published/read back at `9c91796d9c64e1b72c8e3bd2acce126f83834eee`, blob `4b357dbf43f084749eb556cf47dedca1eb922df4`; second intermediate positive claim-scope checkpoint was published/read back at `e3da802d410355fc35cce99d7324f1416c035c61`, blob `5c3ecd6df18474722c24683460f397c3fba787a0`. No web/literature, unrelated repository read, independent agent, production write or quantum experiment.

Pinned implementation assumption (source reviewed in preceding run, not re-fetched here): `syscoin/syscoin@1180dad257fb3cda797187f51ccc519b684e148d`, `CheckContextualAuxPowTag`, where for eligible child height n the reference ancestor height is

    t(n)=10 floor((n-6)/10).

The original user architecture remains: one notary activates a withdrawal; any qualified observer can challenge under R_BTC_more_work OR R_burn_missing_or_invalid OR R_SYS_fork_or_tag_fault; N-of-N preauthorization/erasure constrains the Bitcoin transaction graph but is not a source quorum, online release authority or an NP verifier on Bitcoin. This R177 analysis concerns the *fork inconsistency* subbranch only. Burn/authorization and other two challenges retain their independent source obligations.

## 2. Claim-relevance cutoff and minimal baseline

Freeze a withdrawal statement x_W with an authenticated source history A and define h_rel to be the **last Syscoin height whose history/state influences the exact authorization/PoB, reserve, source-root, interval-tag, and finality commitments actually relied upon by this claim**. It is not necessarily just the burn block's height. A protocol cannot exclude later forks if its own authorization depends on later source history. The source anchor at height a must precede any admissible divergence d, and the claim must bind A, h_rel, its anchor/window, cancel message/VK, native capsule and UTXO.

Let k_LC be the required number of descendant child blocks from the first divergent child, **on both branches for this theorem** (if only the challenger branch needs k_LC, omit the depth term for A). Define

    n_tag(z) = 10 ceil(z/10)+6,
    n_A_min(h_rel,k_LC) = max(n_tag(h_rel), h_rel+k_LC-1).

Fix a *qualified* baseline A with child at n_A>=n_A_min and its exact tag (t_A,H_A(t_A)). This makes t_A>=h_rel and ensures baseline A is k_LC-deep beyond any d<=h_rel. Require the challenger to supply one independently qualified complete history B, from the same authenticated anchor, first diverging at some d with a<d<=h_rel, and extending to an eligible tagged child

    n_B >= max(n_tag(d), d+k_LC-1).

All real contextual AuxPoW, child-header/prev links, parent coinbase/merkle, chain-work, height, lag, tag schedule, relevance, Bitcoin source admission and observation-window rules remain required; toy header checks are not a substitute.

### Source-relation theorem

Under binding child-hash identities (no feasible chosen collisions/rejoins), **one fixed, sufficiently advanced baseline plus ONE new qualified alternate history B is complete for the tag-visible fork relation scoped to d<=h_rel.** No second later baseline observation is needed for such forks. In detail let t_B=t(n_B). Since t_A>=h_rel>=d and t_B>=d, we have min(t_A,t_B)>=d. Two linked branches with first distinct child d cannot share an ancestor block hash at any later common height without a collision/invalid link. Compare the two actual ancestor hashes at min(t_A,t_B), using authenticated predecessor links from the higher tag where their reference heights differ; they are unequal. The verifier can scan bound, linked headers to find first d and verify d<=h_rel and both k depths. This is a deterministic polynomial-time extraction *from the supplied, qualified evidence*, not extraction from a quantum secret-key recoverer.

**Necessity for uniform tag-only coverage:** If t_A<h_rel, choose a possible relevant fork at d=t_A+1<=h_rel. Any later B tagged at/after d shares the baseline ancestor at t_A, so the single old baseline tag cannot contradict it, even though B forks. If n_A-h_rel+1<k_LC, the worst relevant fork at d=h_rel lacks baseline depth. Thus n_A_min above is the tight baseline-height lower bound for all fork heights under this tag-only, both-branch-depth policy, excluding other source qualification/confirmation delays.

**Important overshoot guard:** t_A may lie strictly ABOVE h_rel because tags reference 10-block slots. An alternate fork at h_rel<d<=t_A can produce a genuine tag-hash difference with A yet leave every bound claim-relevant source fact unchanged. So `tagA != tagB` alone may cause false/overbroad cancellation. The full source witness must demonstrate `d<=h_rel` (or another precisely justified claim effect), not merely unequal tags. This comparison of actual linked histories must not be outsourced to a user-chosen `d` label.

### Not an unconditional reversal of R176

R176's counterexample is correct for an **any-future-fork** policy: e.g. fixed baseline n=100 tags h=90; a new fork beginning at d=101 does not contradict h=90, and two later qualified observations are necessary if that late fork itself should veto. This R177 result instead says: if the only security-relevant deviations are d<=h_rel, ensure baseline t(n_A)>=h_rel BEFORE arming the withdrawal and use one alternate B. A fork at d>h_rel is not a qualifying claim-prefix challenge in that policy. The actual bridge must choose its safety semantics; we cannot silently turn the user's any-fork reset condition into a narrower relation. A fork before h_rel may not by itself mean the burn is absent; permitting any such fork as veto is a separately chosen conservative policy with grief/liveness implications.

## 3. Hash-only frozen-key release trial and exact gap

After this relation reduction, an attractive but **invalid** release attempt creates per-slot/bit correction rows

    E_(slot,i,b) = K XOR H("candidate-pad",claim,slot,i,b)

and lets an honest verifier select a row from the divergence of the qualified alternate B from fixed baseline A. Every row recovers the same frozen K, including without any source evidence: an adversary simply invents `(slot,i,b)` and computes the public mask. A source-validity `if` before the raw XOR does not remove this bypass.

A repair that uses `H(full authenticated B evidence)` as its pad binds hashes to actual source bytes, but valid different future B histories yield different pads. A single setup-selected ciphertext will not recover the same K for *all* those witnesses without cross-witness corrections that Build cannot calculate from unknown future evidence. Hashing the fixed public anchor/baseline as the common pad makes it available before any challenge. The source-relation theorem therefore materially reduces the number of **future full source histories** required in a witness, but it does **not** construct the hidden common cross-witness correlation.

The exact unsolved native capability gate remains

    Build_hash(x_W, sigma_cancel) -> C            (classical PPT, pre-event)
    Open_hash(C, B_evidence) = SAME sigma_cancel   for ALL qualified B
    QPT premature recovery / valid target forgery
       -> ACTUAL original qualified challenge evidence OR independent PQ hash/native break.

Full public view includes relation, claim, arbitrary malicious source coins, complete capsule/native VK/checking key, N-of-N setup and manifest, related capsules and auxiliary/selective openings. No assumed online issuer, custom Bitcoin verifier, synthetic Lamport tag signer or lattice/group fallback. No joint full-public simulator, QROM/SHA proof, false-instance or hard-TRUE security proof was obtained.

## 4. Executed checks and exact boundaries

The self-contained `fork_scope.py` uses SHA-256 only to model synthetic collision-resistant linked child identities and enumerates claim-relevance cutoffs 21..55, k_LC values {1,7,12,22}, every relevant divergence between a fixed toy anchor 20 and h_rel, and post-claim divergences in the tag overshoot. It tests one-alternate completeness, exact minimality/needed depth, work-certificate semantic equivalence, later-fork blind spot, overshoot false cancellation and public raw-pad bypass. TWO byte-identical local runs produced `fork_scope_captured.json`. These are **7,398 functional assertions**, not samples demonstrating post-quantum security or real Bitcoin/Syscoin consensus. All synthetic chain-authenticity tests omit AuxPoW, parent headers/coinbase, real work, timestamp, BTC canonical membership and censorship/DA. The recorded source and captured stdout hashes are verifiable; earlier exploratory `checker.py` (1,852 assertions) and `claim_scope_checker.py` (5,010 assertions) and outputs are preserved in the local run bundle but are NOT claimed to be repository files.

The positive claim is the exact tag-schedule source-witness reduction and its proof, conditional on intentional claim-prefix relevance and genuine source authentication. The hash-only Build/Open security construction is **still absent**. Subsequent work should test whether the actual transaction graph/LC policy can safely choose the claim-prefix cutoff rather than an any-future-fork rule; only then search for a source-dependent frozen-key gate against the narrowed ORIGINAL relation. Do not treat source normalization, shorter witnesses, test counts or checkpoint publication as a practical witness-KEM.
