# Whole-trace semantic secure-sketch trial — 2026-11-26

Research only; nonqualifying construction/repair iteration. No ordinary PR comment.

Continuity: actual syscoin/PVUGC PR #1 open/draft/unmerged, branch research/pq-wkem-validation-20260918, start ff6e5acf66c798571346a2d42bd3a2fb33ed0c87. Read actual metadata, four latest substantive comments through R225, exact head SOURCE_NATIVE_TREE_GRAFT_20261126.md (blob 78e4ff3e18ab3ccbef33e313a0203023402a35eb), and exact-version SOURCE_GLOBAL_AUTHENTICATED_EVALUATION_20261126.md, SOURCE_REVERSE_KEY_TRANSPORT_20261126.md and relevant SOURCE_SPECIAL_SOUNDNESS_RESPONSE_20261126.md. Rechecked unchanged head and this new path NOT_FOUND / HTTP 404. No new Core claims.

## Selection and attempted actual release

Missing operation: classical PPT Build must serialize a capability encapsulation that every future qualifying complete original certificate opens to the SAME frozen native cancellation contribution S; arbitrary public recovery or accepted native completion must entail qualifying ORIGINAL evidence or independent justified break. Keep all three original OR branches and their complete contextual authentication, relevance, work, maturity and native bindings as R(x,w). Nothing here substitutes a weaker source predicate.

Closest regressions: R289 mixed local labels; R327 low-degree additive invalid-trace evaluation; preceding native graft required a shared source node and allowed a benign opening. Rather than issue independently usable labels, try a whole-vector *unique bounded-distance recovery* gate. The mathematical change is that the source certificate supplies a single noisy view of one enrolled secret, with no independent local correction tokens to splice. This is an attempted secret-release mechanism, not coding or bandwidth optimization. The question is whether enrollment can be computed before the source exists, while preserving the security of the public decoder against arbitrary vector input. Analyze before implementing; if the familiar public source-pad or secret-center obstruction persists, do not scale.

Use any public efficiently encodable code E: {0,1}^lambda -> {0,1}^N with disjoint Hamming balls of radius t and a public bounded-distance decoder Dec. For a native contribution of larger size, encapsulate a lambda-bit K and publish D=S XOR HashStream(ctx,K), with the frozen checking key and message public. Build chooses K uniformly and an enrollment center a, and publishes helper

    h = a XOR E(K).

Candidate honest Open computes a whole-trace feature F(x,w), sets y=h XOR F(x,w), and calls Dec(y). It returns S using decoded K on success. Honest Open may also check R, but security must hold without that optional check. The elementary condition for intended bounded-distance correctness is

    dist(F(x,w),a) <= t

for every qualifying original w. Then y is within t of E(K) and the public decoding is exact. Different w need not have identical features. This code-offset form is classical PPT given an actual efficient enrollment algorithm and feature function. No assumption is made that these can satisfy the missing condition securely. In particular a native signature verifier does not enforce this distance or check that the supplied feature was computed from an original witness.

## Attempt 1: use complete semantic consistency residuals

Take a Boolean verifier circuit for R, and let z be a canonical assignment to all witness and intermediate wires. Define the residual vector b(z) containing all local gate consistency errors, public input mismatches and output-not-one. Let F be the concatenation (z,b(z)), and choose enrollment a=(a_z,0) for any setup-selected a_z. Every actual accepted trace has b(z)=0. The deliberately favorable assumption here is that R can be evaluated and compiled correctly; no original source compiler was implemented.

If the radius is chosen as the full length L of z to accommodate arbitrary accepted traces, every vector (v,0) for v in {0,1}^L is within radius of the enrollment. In particular the public adversary uses v=0^L, regardless of whether a trace with all-zero residual exists. This computes Dec(h XOR (0^L,0)) and obtains the exact K, hence exact S. It never produces a source witness or invokes R. If the code cannot admit radius L, completeness at that radius is unavailable instead. More generally if enrollment selects a public approximate point u within radius t, Dec(h XOR u) suffices: a decoder input is not an authenticated witness. The native VK/message and context can be incorporated in the public feature definition but cannot prevent direct decoding.

This is not the prior local-label splice: no two traces or row keys are combined. The accepting residual string can be supplied as an arbitrary input to the public decoding operation. Hashing the accepting residual or padding it with publicly computable context merely changes the public approximant. The attack applies in FALSE instances as well whenever the capsule is formed by the described enrollment and radius rule. It is straight-line classical, hence defeats the proposed full-public QPT security without quantum assumptions.

## Attempt 2: keep a genuinely hidden enrollment center and use a narrow decoding radius

Take a uniform hidden a in {0,1}^N, chosen independently of the feature map and original source. For a fixed qualifying w independent of a, assume F does not use a-dependent helper data (in particular h). Then the probability that its decoded input lies in the intended correct ball is exactly

    Vol(N,t)/2^N,
    Vol(N,t) = sum_{i=0}^t binom(N,i).

The 2^lambda radius-t balls about distinct E(K) are disjoint subsets of {0,1}^N. Consequently Vol(N,t)/2^N <= 2^-lambda. Thus even for ONE fixed genuine source witness this independent-center version fails intended decoding correctness, regardless of how much larger N is made. For a decoder which refuses outside the radius, this is also the exact probability of recovering K. An arbitrary decoder with a larger, nonuniform decision region requires a different analysis; if K is independently uniform and a uniform, h XOR F is independent of K and the success probability averaged over K remains at most 2^-lambda. This is not an impossibility theorem for correlated-center designs.

Try making F depend on the actual public helper h. The simplest exact correlation is F(x,w,h)=h XOR g(x,w) with g public and independent of h and K. Then y=g(x,w), independent of K, and uniform K again cannot be recovered with probability exceeding 2^-lambda on average. Making a public a-dependent translation that supplies a close vector for any arbitrary v immediately restores the direct-decoding bypass above. If the translation instead cryptographically limits access to a close vector to complete original witnesses, it is precisely the missing source-dependent operation. A secret a selected from one known satisfying trace is also not an available enrollment procedure before arbitrary future certificates, and provides no guarantee of coverage across different original grounds.

Neither the volume argument nor the public-approximant attack applies automatically when the helper enables a nontrivially correlated feature map that cannot be evaluated on arbitrary malformed traces. That is the actual unimplemented case. A hash of the entire source transcript may prevent selecting individual features, but does not itself produce a close vector to the fixed center; in a separated ideal hash domain a uniform independent hash has exactly the independent-center limitation. Programming the oracle on the set of future qualifying transcripts is not serialized classical Build. A public honest-code check before calling the decoder is not a restriction on an adversary operating on the capsule.

## Handoff

The attempted change avoids explicit label reuse by decoding from one vector but fails either at public approximability or correctness with independent enrollment. Do not repeat by varying code family, syndrome basis, error distribution, radius, feature padding or hash placement. The missing equation is an actual correlated enrollment/feature pair with every-OR-source completeness AND a joint public-view simulator that handles arbitrary decoder inputs, not just honest features. It must be obtained without assuming a source-conditioned hidden center oracle. Any proposal based only on residual-zero features, common public baseline bytes, or an independently hidden enrolled value is rejected without implementation. An actual correlated source-dependent feature compiler would need to be evaluated together with its simulator before considering coding details.

No checker executed; the direct decoding and disjoint-ball calculations reject these versions before a parameter experiment. No QPT proof, original source verifier, actual native signature, distributed setup, related-capsule or auxiliary security theorem. No new Core facts, external literature, delegated agents or production action. R316 maturity correction and R225 native endpoint scope unchanged. No qualifying advance; notification gate not met.
