# R176 — Forward-fork tag-visibility correction, source normalization and failed hash-release gate

**Classification:** A constructive **source-relation completeness correction** for the authenticated AuxPoW inconsistency challenge. It is *not* an instantiated witness-KEM, a QPT security theorem, real Bitcoin/Syscoin validation or a practical cancellation key release. The corrected qualification must be incorporated into the actual proof relation before attempting to encrypt cancellation signatures under it.

## Continuity and inputs

Run `PQ-R176-20261109`. `syscoin/PVUGC` PR #1, draft/open/unmerged, branch `research/pq-wkem-validation-20260918`. Verified starting head `7ae45051d5bc2533daabcdff4c0d8cab6a961466`. Latest relevant ordinary comments since 2026-11-09T17:00Z returned `[]`. Exact-version inputs read: `r174_merkle_consistency_gate_20261109/RESEARCH.md`, blob `03d0b4b3087fbbe82d20430892f9e461b51b28fe`, and `three_branch_release_20261109/RESEARCH.md`, blob `56434f3a43b5a2c13d4834a1b4fd53fcc9e69376`. Prior sourced code was pinned `syscoin/syscoin@1180dad257fb3cda797187f51ccc519b684e148d`, `src/validation.cpp` `CheckContextualAuxPowTag`, and `src/auxpow.cpp`. No new web or literature search. All computations here are local standard-library Python; there are no independent agents or quantum simulations.

The original withdrawal model is **one notary initiates, anyone can challenge, N-of-N setup is separate**. The exact combined three-way condition is `R_BTC_more_work OR R_burn_invalid/absent OR R_SYS_qualified_fork/tag_fault`, on the frozen claim/path context. The targeted output remains the **SAME** precommitted cancellation signature/package for EVERY qualifying ORIGINAL challenge witness. Bitcoin must not evaluate the original relation.

## 1. Tag-slot visibility theorem (deterministic consensus arithmetic)

Under the pinned post-Nexus eligible AuxPoW tag code, a child at source height `n` checks the candidate branch ancestor at

    t(n) = 10 floor((n-6)/10).

For a fork whose first different child header is at height `d`, assume two syntactically valid child histories sharing the exact predecessor at `d-1`, with collision-resistant header identity and valid ancestor links. Tagged ancestors on the branches are the same for reference heights `<d`, and distinct for reference heights `>=d` (absent a hash collision or malformed history). Therefore the **first eligible child height** whose tag is necessarily sensitive to the fork is

    t* = 10 ceil(d/10),
    n*(d) = t* + 6,
    n*(d) - d = 6  when d % 10 = 0,
               16-(d % 10) otherwise  (ranges 7..15).

Thus `6 <= n*(d)-d <= 15`. Equivalently, between **7 and 16 child blocks inclusive, counting the fork block**, may be needed before the first contradictory *reference tag* becomes possible. A configured fork-depth threshold of `k_LC` child blocks by itself is sufficient to ensure a conflicting reference tag only when the observed histories extend through

    L_required(d,k_LC) = max(k_LC, n*(d)-d+1).

Example: at `d=101`, the first tag references the divergent ancestor at child `n=116`, requiring 16 child heights including `d`. At `d=110`, `n=116` requires 7 heights. If k_LC=10, the first fork needs six additional heights to establish a **tag-hash** contradiction even though a child-header fork may already be visible. These are *height constraints*, not guaranteed wall-time: both branches must actually produce eligible source children and authenticated parent observations, satisfy window/lag/tag-density and BTC inclusion/admissibility, and arrive before the enforceable challenge deadline. A private miner and Bitcoin censorship can defeat timeliness; no positive hashrate alone gives deterministic liveness.

**Proof.** `t(n)` is a nondecreasing step function, constant on each interval `[10j+6,10j+15]`. The least multiple of ten greater than or equal to `d` is `10 ceil(d/10)`. Its first referencing child is at that reference height plus six. The index arithmetic gives the range above. For a valid fork at `d`, all predecessor pointers below `d` are common; at/after `d`, hash identities along distinct parent-linked branches remain distinct unless a collision allows a merge. Therefore tags comparing ancestors `<d` cannot witness the fork, while qualified tags referencing `>=d` may. No heaviest-branch comparison is part of this statement.

## 2. IMPORTANT correction to the one-sided, fixed-baseline idea

A prior architectural shortcut suggested that because the withdrawal binds an authenticated baseline observation `A`, an alternate observation `B` alone may suffice for every qualifying fork challenge. This is **only complete for a fork that is already visible to the baseline at the comparison height**. It is NOT complete for future forks after the baseline's last committed/tagged height.

A direct counterexample requires no broken hash and no dishonest observer:

- The frozen withdrawal statement contains an authenticated baseline Syscoin child observation at `n_A=100`. Its tag refers to height `t(100)=90`, with ancestor `H_90`.
- A legitimate distinct Syscoin branch starts at `d=101`, so it shares all headers through height 100, including `H_90`.
- A conflicting branch later has a qualified child at `n_B=116`, tagging ancestor height `t(116)=110`, whose hash `H^B_110` differs from that on the competing post-fork branch.
- Comparing the **old** baseline `(90,H_90)` against B's higher observation cannot establish incompatible ancestry: B's proven ancestor at height 90 is exactly `H_90`. The pair is compatible. This is not an invalid witness or cryptographic attack; there simply is no contradictory old baseline fact.
- Two qualified **later** observations `A'=(110,H^A_110)` and `B'=(110,H^B_110)` DO establish inconsistency, provided both source-history/work/window requirements are met.

Therefore, to cover post-assertion forks, the ORIGINAL relation must allow **two later qualified, incompatible observations** relative to the common statement-bound anchor, or explicitly restrict challenge 3 to contradictions with the specific sufficiently advanced asserted source history. The latter restriction must be intentional, documented, and reconciled with the actual light-client safety objective. A fixed old baseline plus arbitrary one alternate history is not a general fork detector. A no-winner-needed dual-observation relation is still existential NP (subject to source qualification), but it changes what information the source compiler must bind and what witnesses must release the same sigma.

More generally, even an earlier divergence at `d=95` is not visible in tag outputs of child `n=100`: both tags reference height 90. The child header identities already disagree at 95, but the tag-based contradiction appears first at n=106. If the protocol accepts **pure child-header fork** as a separate predicate, it must state its own source and depth rules; do not silently call it a reference-tag mismatch.

## 3. Source-outcome equivalence, not source-secret production

For each single valid branch and any children in one tag slot `[10j+6,10j+15]`, every accepted tag is expected to carry the SAME semantic `(10j,H_branch(10j))`. The underlying Bitcoin parent work certificate (`WorkID`), the child height within that interval, and parent coinbase’s unrelated bytes may differ without changing this semantic tagged ancestor. This gives an **efficient certificate normalization** after authentication: `Normalize(P)=(t(n),H_ancestor)`.

This removes spurious work-certificate variation from the comparison relation, but **does not create a hidden secret**. Distinct valid branches can carry arbitrary unequal hashes at a conflicting reference height; a claim scoped to one anchor may admit many distinct heights and fork identities. No premise that they share a secret source label or canonical short preimage has been established.

## 4. Actual attempted hash-only release and its failure

Let A be a known baseline tagged 256-bit hash, K a setup-chosen random 256-bit cancellation-pad key, and c the exact claim/context. The attempt publishes 256 correction rows for opposite tag bits:

    b_i = 1 - bit_i(A),
    E_i = K XOR SHA256(encode("slot-mismatch-pad", c, i, b_i)).

Given an alternate hash B != A, the raw decoder chooses any differing bit i and computes

    K' = E_i XOR SHA256(encode("slot-mismatch-pad", c, i, bit_i(B))).

This algebraically yields exactly K, independent of which alternative tag is used. The raw decoder is, however, **unconditionally unsafe**: an attacker may fabricate `B=A XOR 2^255` and obtain the same K without any Bitcoin parent header, AuxPoW, coinbase, Syscoin child or authenticated fork. The fact that an honest implementation first checks `AuthenticatedSource(B)` is not sufficient—an adversary extracts or reimplements the public raw decoder without that check. The source check is not integrated into key acquisition.

Attempted repair 1: pad by `SHA256(AuthProof(B))`. Setup cannot compute the correction for arbitrary future qualified `B` certificates. Two distinct accepted certificates generally have different proof hashes, so a row for one fails SAME-K correctness for the other. Attempted repair 2: pad only by the public 10-height reference slot; then everyone already knows the pad and immediately recovers K. Attempted repair 3: replace pad with a setup secret token selected by an authenticated source proof. Current Syscoin SHA/AuxPoW evidence contains no such precommitted setup-secret label, and no `SourceToToken`/public compiler was instantiated. No online signer or fake token issuer is accepted as a repair.

This is a **specified normal-form failure**, not a general impossibility theorem for nonblackbox SHA circuits, witness encryption, or other hash-only constructions. No random-oracle/QPT security bound follows from the toy SHA experiments. The central unsolved operation is still

    Build_inc(R_original, x_W, sigma_cancel) -> C  (classical PPT, no future witness)
    Open_inc(C,w) -> SAME sigma_cancel for every R_original(x_W,w)=1,
    QPT recover sigma/accepted native forgery without authorized witness
       -> extract FULL original source witness OR justified PQ hash/native break,

in the full joint view with native VK, N-of-N setup correlations, other capsules and malicious source coins. The corrected `R_original` must include future two-sided qualified forks when required by the application, not silently assume an old baseline suffices.

## 5. Actually executed checks and limitations

The exact `checker.py` source and captured output are committed together with this note. Python standard library SHA-256 is used in **synthetic hash-linked child histories** (no real AuxPoW mining, parent coinbase parsing, Bitcoin consensus, ChainLocks, native signature or QPT). Two byte-identical local executions produced 1,731 functional assertions: 120 fork-height cadence cases, five k_LC values per case, paired toy branch histories, semantic work-certificate normalization, raw forged-tag early release, public-slot direct release, single-proof pad nonconvergence, and explicit fixed-baseline future-fork controls. The output includes a SHA256 of the executed source; captured JSON is a real local execution, not simulation evidence for actual consensus or security.

The only **substantive correctness conclusion** from this pass is the tag-height theorem and the necessary two-sided extension for post-baseline fork completeness. The experiment does not close cryptographic release. No efficiency/packing optimization is authorized before the source-conditioned key gate is secure.

## 6. Next constructively useful question

Decide whether the actual withdrawal LC safety policy requires `R_future` (two later authenticated qualified histories for post-assertion fork) or explicitly covers only inconsistencies with a sufficiently advanced asserted source tip. If `R_future` is included, bind both source observations to the claim anchor/window and k_LC plus `L_required`; then seek a single frozen-capability hash-only release mechanism that is keyed to the **full genuine dual-observation transcript** without being openable by a fabricated second hash. If source changes after setup, neither the bit-selector table nor a proof-hash pad is usable. The future source proof must supply a cryptographic label that Build can commit to ahead of time without knowing which forks will occur; that equation remains entirely open.

No generic-NP WE, lattice, discrete-log group, verifier-on-Bitcoin, DA oracle, assumed post-quantum Bitcoin opcode or new consensus tag format was introduced.
