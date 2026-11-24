# 2026-11-23 — single-proof alternate-randomness explanation screen (nonqualifying)

## Continuity and selection

Live starting syscoin/PVUGC PR #1: open, draft, unmerged, branch research/pq-wkem-validation-20260918, head 65480baa12c8ed2a9ea1e8a62790793bfe01643b. Read metadata, recent substantive comments including R225, exact head note blob 195d858a36fdf25a60342190d5654e813352787b (instance polarity), preceding native-checked local-read note blob 1f165b8f6225b7fb88e15d6e20314a2e84967b5f, fixed-transcript transfer note at start SHA, and source-Merkle equivocation screen blob 8243daa86133a7faae2ca484f41934ef5951051c. Filtered exact research-tree filenames for alternate-randomness/explanation precedents. No external research, entire PR diff, current Core claim, network observation or deployment. R316 remains a coverage regression only.

Missing ORIGINAL operation: serialized classical-PPT Build_inc(x_W,sigma_cancel) and public Open_inc(C,w) returning the SAME exact safe cancellation capability for EVERY qualifying original certificate w. R is the unchanged three-OR original source predicate with qualified greater exact BTC work, finite authenticated burn authorization refutation, and relevant mature incompatible Syscoin histories or appropriately typed tag/carrier fault. All claim, window, endpoint and full-public security requirements remain in force.

Mathematical delta from the fixed-first-message transfer screen: use no second challenge or opposite challenge response, no special-soundness extractor, and no per-occurrence labels. Instead investigate a single witness-indistinguishable proof of an OR statement. Native cancellation knowledge constructs the proof; a qualifying source witness would allow public explanation of its generation randomness. The key would be a computationally hidden invariant of the explanation fiber. The closest fixed-transcript attack (uncoupled opposite-challenge responses) is not directly applicable since neither response is requested. A further candidate below explicitly relaxes fixed commitment equality to avoid requiring a binding commitment collision. Neither change is assumed to be a primitive.

## Exact construction target

For the frozen native context define N(s) to check the target native signature and (for this candidate) its exact digest. Let Q(b,z) mean (b=0 and N(z)) or (b=1 and R(x_W,z)), using typed padded input lengths. Build knows s=sigma_cancel and chooses honest random tape r0 for a hash-based proof generator P. It generates proof p=P(Q,(0,s);r0). Try to publish

    C = (ctx,p,T,E)
    k = J(ctx,p,(0,s),r0)
    E = s XOR KDF(ctx,k,len(s)).

Here J is a public classical-PPT function and T is serialized auxiliary data computed by Build, not a hidden oracle. Open requires

    Explain(ctx,p,T,w) -> r1
    P(Q,(1,w);r1) = p
    J(ctx,p,(1,w),r1) = J(ctx,p,(0,s),r0).

The second equality is the release operation; the first is the proposed mechanism for generating a globally consistent explanation. Build need not know future w. It must work even when the two witnesses have completely different representations. Neither witness-indistinguishability of P nor a ZK simulator guarantees explanation of an already fixed proof, and equality of proof distributions is not an efficient conditional sampler for their random tapes. Even if Explain exists, the invariant J must remain computationally hidden in the full capsule and native auxiliary distribution without original evidence. A J that can be computed from p alone would trivially break release. A J that simply returns a uniform fresh r1 does not satisfy the required equality.

The intended joint proof, if these algorithms were realized, would first replace the actual secret-dependent E by a fresh pad using a source-hardness reduction for the hidden invariant given (ctx,p,T). The native checking key/message, digest if used, and auxiliary source data would remain correlated with the original s; p and T would also need simulation without giving the reduction the target native signature. A native forgery reduction cannot be obtained just by asserting proof WI: p was generated using s, and the reduction has no oracle for this target message. FALSE and hard-TRUE, arbitrary QPT, related capsules, malicious retained source coins and selective openings all need their own joint simulation. No QROM programming claim is used here.

## Concrete hash-based proof compiler preflight

Take an MPC-in-the-head-style proof with m virtual parties. Use an XOR sharing of the full encoded witness, including b. For each party i commit to the full deterministic view v_i (including its input share), with fresh salt t_i:

    c_i = H_com(ctx,i,encode(v_i),t_i).

The proof p contains all c_i, a public challenge and the selected view openings. Build generates these for branch zero using native s. Suppose Explain returned honest source-mode coins regenerating p. In its virtual execution the shares of b now XOR to 1 rather than 0. Therefore there exists at least one i whose input share of b differs; its canonical full view differs, but the commitment c_i remains identical. Comparing the two honest random tapes gives distinct inputs to H_com with the same output. This does not rely on extracting a QPT attacker's private state. A classical experiment that knows Build's native signing witness and later obtains an efficiently generatable qualifying original source certificate can run honest Build and Explain, recompute both complete views, and output the two inputs. Whenever both required explanations hold it breaks ordinary collision resistance. If legitimate qualifying evidence is not efficiently generatable even in such a joint honest experiment, the implication is conditional rather than a demonstrated collision. Nothing in this argument requires a real fork to itself be a hash collision.

This is not the earlier Merkle equivocation proposal: the source does not need to present colliding source roots. The collision would be in the newly generated proof commitments, forced by alternate explanation of the setup-created transcript. It is also not the fixed-transcript special-soundness proposal: a SINGLE identical proof is required and no additional challenge is requested. But this concrete implementation is rejected before coding: ordinary full-view binding and honest explanation across distinct encoded witness branches are incompatible in the above experiment. Changing salts or number of parties does not help. If some proof commitments are simulated rather than honest, a simulator trapdoor or programmed random oracle that makes them explainable is not a public hash-only construction. In particular a simulator's ability to produce a transcript for one challenge does not supply honest randomness for every later source witness.

## Attempted repair: equality of projected proof rather than committed transcript

To remove the collision requirement, let p0 and p1 contain different full view commitments. Build publishes only a public projection y=Pi(p0), plus T and E. Explain must construct an actual source proof p1 with Pi(p1)=y. The proposed release invariant is

    J(ctx,y,p0,(0,s),r0) = J(ctx,y,p1,(1,w),r1).

This change allows commitments to differ, so the preceding same-commitment collision argument does not apply. It is a new construction requirement, not a proof that the repair works. We screened two explicit projections:

* Pi retains only the public OR statement, challenge and acceptance bit. A source witness can independently generate a valid proof (with an interactive preselected challenge, or using a suitable proof system; the exact Fiat-Shamir challenge is not guaranteed). But Pi has discarded all correlated hidden randomness. If J depends just on these projected bytes, an arbitrary public attacker evaluates it. If J hashes fresh hidden view randomness, two independent genuine explanations have unrelated keys in the independent ideal-hash model. An equality constraint on hidden proof randomness is not supplied by acceptance. Choosing T to encode such a correlation is the exact missing source compiler.
* Pi retains a lambda-bit XOR of domain-separated view-commitment digests. In the simple independent ideal-hash model, after generating all other candidate views, matching a fixed y by the remaining fresh commitment requires its digest to hit one specified lambda-bit target. For at most q fresh classical oracle queries the union bound is q/2^lambda, conditional on a target fixed by Build and previously unqueried inputs. This is not a QROM theorem, and does not cover a non-black-box construction exploiting actual shared source/proof structure. A real source witness lets one compute valid views but does not provide the missing digest preimage. If the projection instead exposes a freely adjustable public correction field to force equality, equality alone holds regardless of source validity; using it as J leaks the invariant, while a J cryptographically dependent on the valid hidden views still needs a separately constructed compiler. This is the familiar independent matching barrier applied to the attempted repair; per selection rule no fixture, hash-placement or parameter sweep follows.

A different projection could preserve a hidden nonlocal invariant while allowing alternate honest proof generation, but it must be concretely sampled from the original statement and native witness and support public explanation from every original certificate. Merely postulating that property would postulate essentially the desired release. No independent hash-based mechanism for it was obtained in this iteration.

## Disposition and handoff

The alternate-randomness route is rejected for ordinary binding full-view commitments, and the relaxed projected-proof attempt does not generate the common hidden invariant. This is an analytic construction preflight, not a general impossibility theorem for WI proofs, hash-only WKEM or original-source computational correlations. No implemented original source evaluator, authentic certificate, native signature, empirical checker, QPT experiment or successful full-public simulation is claimed. Do not repeat this screen with larger proof repetitions, salt changes, randomized wire labels, hash placements or more projection bits.

Next candidate must implement a genuinely source-dependent public explanation or other nonlocal release operation, not just proof acceptance, and prove full-public security from an independent justified assumption. Preserve every-witness correctness, the original three OR grounds, maturity and claim relevance, malicious setup/capsule correctness before funding, slot-global vs activation-specific endpoint scope, accepted same-message forgery and sibling capsule composition. No ordinary PR comment or user notification warranted. The completion condition is unmet.
