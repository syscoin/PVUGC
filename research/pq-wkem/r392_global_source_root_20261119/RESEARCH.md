# R392 — Common witness-root coindexing: one explicit release attempt, nonqualifying

## Continuity
Read the live open draft PVUGC #1 at head 412da289b7dd81caa2d25767b40c73439223bf1f on research/pq-wkem-validation-20260918; R391 note blob 0194660289a2f3cc9b1d096b42e415a97a7c2f92, R390 blob a903d41f09899d2e01e80039d4534db7fb0de384, R389 blob 0c6bd14c514d0188f6a0a3c261f6e553642548d5. No new top-level PR comments since 2026-11-18T19:24Z. Core #609 source was not re-read because this test makes no new Core claim. No source witnesses, actual signature, FE, ZK, quantum test or checker was executed. This is an analytical construction/rejection, not a release.

## Precise candidate and what changes from R289/R389
R289 and R389 allowed fragments from distinct inconsistent source traces to form a spurious path. Consider assigning a single global transcript root to all local verification fragments:

    z(w) = SHA256(domain || sid || x_W || canonical_serialization(w)).

Every local claim for source constraint j carries the canonical Merkle opening at the same uniquely named leaf position of the SAME complete witness commitment z. Two incompatible values for the same leaf at one z would yield a Merkle hash collision or second preimage, subject to exact length, domain, index and direction checking. Thus the syntactic mixing of values from two witness assignments under one root cannot succeed merely by reordering local pieces. The full ORIGINAL verifier still authenticates contextual modern AuxPoW, correct tags, actual claim-prefix ancestry, LC depth, the exact burn/recipient/amount and source windows, and the three independent OR grounds. This root binds claimed data; it does not establish their source authenticity or release a secret.

## Attempt to deliver a common frozen terminal key
Builder chooses secret S and terminal key K_star, and publishes:

    D = S XOR SHA256('PAD' || sid || K_star).

For an as-yet-unknown future valid source certificate w with root z(w), a local edge from state K_j might use:

    L_j(z,a) = SHA256('LABEL' || sid || z || j || a)
    T_j(z,a) = K_(j+1) XOR SHA256('EDGE' || sid || K_j || L_j(z,a)).

Correct source release needs every independently qualifying w to reach the SAME K_star, with no fabricated, irrelevant or mixed w able to reach it. The builder does not know future z and cannot publish T_j(z,a) for all possible z in a polynomial table. A tiny public program computing T_j for every arbitrary z,a exposes transitions on malformed input: external software VerifyOriginal and Merkle checks can be bypassed when the attacker processes public bytes directly. Hiding a master secret within that program gives no publicly evaluable classical hash circuit unless an independently secured program-hiding/conditional-delivery primitive is actually instantiated. Keeping the master secret private requires online participation. Replacing each transition with K_(j+1) = SHA256(K_j || z || a) is publicly executable but makes endpoints path-specific, so one frozen D cannot decrypt on EVERY future qualifying w.

One could postulate GateSeal that releases the fixed K_(j+1) only on an original authenticated edge under a globally consistent w, but that is exactly the missing ORIGINAL source-dependent Build/Open obligation. A Merkle root is a collision-binding index, not an independent FE/WE primitive. The root fix is useful ONLY to reject syntax-level splice, not to implement secret delivery.

## Joint-public and security obligations
For a FALSE instance one might attempt to simulate D as a uniform pad jointly with the native VK, manifest, verification parameters, related capsules and all source commitments. There is no defined serialized distribution for the supposed universal T_j, so no such joint simulation or reduction exists. For a hard-TRUE instance, recovering K_star from any arbitrary public manipulation must reduce to an actual qualifying ORIGINAL certificate or a justified independent PQ hash/native break; the Merkle collision assumption alone says nothing about arbitrary recovery. Classical external proof checks do not enforce the private-value release predicate.

Ancillary information-theoretic caution, narrowly scoped: let a qualifying honest-source witness W be sampled independently of S and builder randomness rho given x_W, while C=Build(x_W,S;rho). Then W and S remain conditionally independent given (x_W,C), and H(S | x_W,C,W) = H(S | x_W,C). If perfect Open(C,W)=S, this entropy equals zero. Thus for a TRUE instance such a public capsule cannot be statistically hiding against an unbounded observer: a witness supplies computational help, not new Shannon information about an independently chosen setup secret. This is compatible with computational WE and says NOTHING about arbitrary source-correlated adversarial auxiliary inputs. Do not generalize it to a hash-only impossibility theorem or to FALSE-instance distributions without witnesses.

## Decision
Reject this globally coindexed hash-label candidate before spending further runs on larger trace fixtures. It repairs local root-consistency syntax but DOES NOT implement the source-conditioned release foundation; an apparent cryptographic repair simply renames the absent gate. Current required equation remains:

    C = Build_orig(x_W, sigma_cancel; rho)   [classical PPT, serialized public bytes]
    Open_orig(C,w) = sigma_cancel            for EVERY ORIGINAL R_orig(x_W,w)=1.

Required independent security: full-public FALSE and unauthorized hard-TRUE QPT recovery/native-forgery to actual ORIGINAL certificates or independently justified breaks; one-honest N-of-N setup, malicious source-retained coins, sibling capsules and selected openings; exact claim/outpoint/native message and graph binding. The accepted bridge OR and strict post-PQ source rules are unchanged. No practical algorithm or such theorem was produced. No PR comment, public-progress notification, Core/production edit, transfer, deployment, or automation change.
