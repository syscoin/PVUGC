# Bridge-specific challenge target: authenticated AuxPoW tag inconsistency

Status: user-directed scope clarification and source-code review, NOT a new key-release construction, security proof, or breakthrough. General-purpose NP witness encryption is not a prerequisite for attempting this specific bridge challenge relation. A solution for this relation must not be advertised as generic NP WE.

## Continuity and actual sources

Observed syscoin/PVUGC PR #1 head: 44032a05e4362e5831a24084c6154c3266c58988, open/draft/unmerged, branch research/pq-wkem-validation-20260918. Latest-comment query since 2026-11-09T00:00Z returned no new ordinary comments. Current-head R173 authenticated-equivocation research was read; its invented source-signature input and retained-source-secret failure are NOT repaired by narrowing the target.

The user explicitly supplied syscoin/syscoin commit 1180dad257fb3cda797187f51ccc519b684e148d, src/validation.cpp around line 10453, for this question. Read-only source inspection in this pass covered validation.cpp lines 10350-10570 (whole-file Git blob 05e4016e570036453690fb6627cd8b44b48ddb41) and src/auxpow.cpp (blob 656cb66a322b65348c6e2e0cccce16e42f63ade0). These are pinned-code observations, not current deployment claims. No external literature/web search, production write, cryptographic experiment, or independent agent was used.

Source links:
- https://github.com/syscoin/syscoin/blob/1180dad257fb3cda797187f51ccc519b684e148d/src/validation.cpp#L10453
- https://github.com/syscoin/syscoin/blob/1180dad257fb3cda797187f51ccc519b684e148d/src/auxpow.cpp

## The actual architecture to target

One notary may authorize/initiate a withdrawal on an already constrained, delayed, challengeable transaction path. ANYONE with qualifying inconsistency evidence should recover a claim-scoped cancellation capability. No second notary signature or N-of-N source approval may be required to challenge. The N-of-N honest-erasure preauthorization ceremony is separate from the 1-of-N withdrawal initiator and from source/ChainLock thresholds.

This is an existential veto relation. It need not decide which Syscoin fork wins, require the conflicting Syscoin branch to have more work, or prove that no future/unseen fork exists. Timeout controls the normal payout; the challenge is a finite positive certificate. Source authentication, Bitcoin anchoring and timely enforceable inclusion remain necessary. A notary must not be able to bypass the delayed graph or replace its cancellation capsule with an unopenable one.

## Pinned tag semantics

For an AuxPoW child at height n in the active Nexus regime, CheckContextualAuxPowTag uses pindexPrev height n-1, computes nActiveHeight=pindexPrev->nHeight-5, rounds it down to a multiple of 10, and takes pindexPrev->GetAncestor(nActiveHeight). Thus for relevant nonnegative heights:

    h_ref(n) = 10 * floor((n-6)/10),
    n - h_ref(n) in {6,...,15}.

The expected payload serializes that ancestor's block hash followed by its uint32 height. Validation is against the candidate branch's own ancestry, not a global winning-branch decision. The local child-to-reference ancestor subcheck spans 6-15 links; the FULL source authentication/anchor proof is not thereby constant-size. The claimed n itself must be authenticated, not accepted from the challenger unchecked.

The pinned parser searches unspendable parent-coinbase outputs for the Syscoin marker, then searches AFTER that marker for the expected hash-plus-height bytes. It is not simply a strict adjacent tuple decoder. It rejects missing tag, a found marker with no expected bytes later in that output, or marker-bearing additional outputs according to the displayed code. A bridge must explicitly define compatible byte semantics rather than silently classifying some core-accepted encoding as malformed. Before Nexus or for non-AuxPoW headers this particular function returns early; relation scope must account for activation and applicability.

CAuxPow::check separately links the pure child hash through the chain Merkle branch to the parent coinbase commitment and the coinbase through its Merkle branch to the parent header. Those checks authenticate a commitment relative to that header; they do not on their own establish Bitcoin best-chain membership or all Syscoin state transitions. Different parent work certificates for the SAME child/outcome must not automatically count as a fork.

## Fixed withdrawal statement and qualifying observations

Let x_W bind the exact claim/UTXO, withdrawal/assertion digest, relevant baseline/source commitment, source interval and anchors, challenge deadline/reset rules, intended cancellation transaction/message and verification key, and capsule ID. A signed baseline assertion is not automatically an authenticated source observation.

Let Q_x(P) mean the complete parent/coinbase/Merkle/child evidence P is AUTHENTICATED AND RELEVANT under the chosen Bitcoin-anchor, source-height, lag/tag-density, interval, ancestry and observation rules. This is an explicit remaining verifier obligation, not an oracle supplied by the construction. Do not permit a random privately mined header or unrelated old fork merely because it satisfies a hash target.

From qualified observation P derive the semantic tagged ancestor O(P)=(h,H). Keep the full WorkID for authentication, but compare semantic heights/hashes/ancestry for conflicts.

### A. Conflicting valid observations

For h_A=h_B, the conflict condition is H_A != H_B.
For h_A<h_B, the witness provides an authenticated predecessor chain from H_B down to height h_A. If the derived ancestor G differs from H_A, the observations are incompatible. Reverse roles when h_B<h_A. Merely failing to find H_A in an incomplete list is not a non-ancestry proof.

The pair relation is

    R_pair(x_W; P_A,P_B,pi_ancestry)
      = Q_x(P_A) AND Q_x(P_B)
        AND applicable branch/tag validity
        AND positively witnessed semantic incompatibility.

If the baseline P_A is already fixed and authenticated in x_W, it can be public input; the challenger need only supply P_B and the remaining ancestry/inclusion evidence. Completeness still covers every qualifying alternate observation and every qualifying differing slot, not one predetermined challenge witness. The same-height inequality is a small subcheck, not a substitute for Q_x.

### B. Authenticated tag faults

A different branch may deliberately allow an authenticated malformed/missing/wrong-height/wrong-ancestor tag to veto. Its correct shape is

    R_fault(x_W;P) = Q_outer,x(P) AND Relevant_x(P) AND Fault_x(P).

Q_outer authenticates parent inclusion/work, the full coinbase and applicable child commitment; it MUST NOT require the very tag-consistency check that Fault_x is meant to refute. Otherwise a bad tag would make its own challenge witness inadmissible. Absence of a required tag can be demonstrated by the COMPLETE authenticated coinbase, not by a partial output listing. Relevance/required-tag applicability are mandatory: an arbitrary unrelated Bitcoin coinbase without Syscoin participation must not cancel every withdrawal.

Also prevent an unauthenticated or syntactically invalid notary baseline from disabling all challenges: either that assertion cannot arm the payout path, or it has a separately enforceable finite refutation. Requiring both baseline and challenger to be valid histories does not cover an entirely fabricated baseline automatically.

The fault policy and the valid-fork policy must be distinguished rather than pretending every malformed tag certifies a valid Syscoin history. Any-qualifying-inconsistency cancellation is fail-closed and may trade liveness for safety; ordinary irrelevant/transient forks remain governed by the explicit qualification/window policy.

## Key-release target and the unresolved construction

Freeze a claim-specific cancellation signature sigma_cancel (or an equivalently confined capability) before irreversible use. The desired hash-only interface is

    Build_inc(x_W, sigma_cancel) -> C_W,
    Open_inc(C_W,w) = SAME sigma_cancel
        for every w with R_pair(x_W,w) OR R_fault(x_W,w).

The capability must authorize the intended safe cancel/reset/refund path, not an unrestricted spend to the challenger or a different claim. The full public statement, tag/ancestry commitments, checking data, native VK, auxiliary fields, sibling capsules and disclosed earlier challenge evidence are in the security experiment. For arbitrary QPT recovery/forgery, extract an ACTUAL qualifying certificate for this relation or an independently justified hash break. Do not demand an internal representation from the adversary. This remains UNINSTANTIATED.

Two ordinary tag hashes that differ are not two openings of one hash commitment, not necessarily signatures under the same one-time key, and not a cryptographic hash collision. Their authentication establishes evidence; it does not by itself reveal a precommitted secret. R173's paired-label mechanism illustrates a common-capability identity only for invented OTS signatures, and fails when a source signer retains both labels. Requiring another notary to produce the opposite opening would reintroduce the prohibited online authority. The next candidate must bind release to the ACTUAL source evidence, not substitute that synthetic signed-equivocation relation.

Prior generic-NP/statistical or black-box-oracle restrictions must be applied only under their actual hypotheses. They do not justify requiring a general-purpose WE solution before attempting this restricted hash/SHA/AuxPoW relation. Conversely, restricting to this relation is not a security proof or permission to relabel an earlier failed carrier as secure.

## Coverage and next experiment

Tag inconsistency addresses source-history ambiguity/faults. It alone does not prove that an arbitrary withdrawal references a real burn, correct amount or rightful recipient. Those conditions must remain bound/enforced elsewhere or obtain their own challenge predicates; no new assumption that a malicious single notary cannot lie is introduced.

Primary next construction test: with the baseline fixed in x_W, build a hash-only release whose raw public computation remains inaccessible for (i) a changed parent certificate of the same child, (ii) a correctly linked later tag on the same branch, (iii) an unauthenticated or out-of-window alternate branch, and (iv) malformed bytes without authenticated relevant inclusion, while EACH genuinely qualified same-height or ancestry mismatch produces the SAME cancellation capability. The parent-history and tag authentication must be inside the cryptographic release, not a post-hoc if-check. Keep false-instance, hard-TRUE, quantum/coherent, retained-source-coin and related-capsule attacks in scope. Do not resume generic-first detours or restricted-component optimization.

This note records the clarified target and exact source facts only. No new theorem, runtime, executed checker or solved bridge is claimed; no ordinary progress comment is warranted solely for this scope record.
