# Signed-weight matching aggregate as a common-key transport — 2026-11-27 UTC

Research only; nonqualifying construction/repair iteration. No practical original-source release or full-public security theorem.

Continuity: actual syscoin/PVUGC PR #1 open/draft/unmerged, branch research/pq-wkem-validation-20260918, start and prewrite head ac683f42e4a4fcc3fe3ee8aad94edefc2f2a781f. Read actual PR metadata, latest returned substantive comments through R225, latest commit filename and exact SOURCE_UNMARKED_OR_TRANSPORT_20261127.md (blob f31b31599f01df4a152de5ab02b78f081e438d6c), SOURCE_COMPLEMENT_TREE_RELEASE_20261127.md, SOURCE_SPECIAL_SOUNDNESS_RESPONSE_20261126.md, SOURCE_NATIVE_PATH_EMBEDDING_20261127.md and SOURCE_FEASIBLE_STATE_MIGRATION_20261126.md. New path returned NOT_FOUND / HTTP 404 at prewrite head. No new Core source claims.

## 1. Selection before construction

Missing operation: offline classical-PPT Build(x,S) must serialize one public capsule such that every qualifying ORIGINAL w recovers identical fixed safe native cancellation contribution S; arbitrary full-public QPT recovery and accepted native forgery require original evidence or an independently justified break. R_x denotes the complete bounded original relation with all three independent OR grounds (strictly greater relevant BTC cumulative work, finite authenticated burn refutation, qualified Syscoin inconsistency/tag fault), contextual authentication, maturity, relevance, and claim/window/native binding. It is not a newly implemented verifier.

The immediately preceding unmarked-OR matching construction permits succinct, globally consistent witness-dependent perfect matchings but no common hidden normalization. Its exact projected isomorphism approach also fails ternary closure. Try a mathematically different normalization: a signed total weight of a succinct exponentially large bipartite matching domain. The key is invariant under ALL perfect matchings, even when their permutations differ and have no group closure. Evaluate the total using only a polynomial list of exceptional edges; all other edge differences must cancel exactly. Neither the dummy-side opener nor source-side opener need supply the other's map or canonicalize a permutation. The entire certificate still drives one global transport, not independent wire labels. The hoped-for construction is a pair of publicly evaluable vertex-weight functions that admit different efficient cancellation covers from the dummy and every original certificate, while their total difference remains hidden from arbitrary public parties. The following tries concrete such weight functions and their repair, without granting a secret evaluator.

## 2. Exact weighted aggregate and initial Build/Open trial

Let Z be fixed-length n-bit names with disjoint tagged source and dummy subsets; padding is canonical. Set N=2^n. Write star for an additional name. In the separated ideal-hash model sample a uniform dummy t from a dummy subset of exponential cardinality and publish y=D(ctx,t), where D outputs 3n bits. Define Q(z) as the tagged original R_x(z) OR tagged dummy D(ctx,z)=y. The planted dummy is unique except with probability at most (N-1)2^-3n. All references to dummy t below are on unique-preimage executions. Public context contains exact relation and capsule/native bindings. This is an idealized synthetic-payload trial, not a native signature distribution.

For explicit or succinct left/right weights L,R on a common finite vertex name set V with values in (F_2)^ell, define

    K = XOR_{v in V} L(v) XOR XOR_{v in V} R(v).
    K = XOR_{v in V} (L(v) XOR R(P(v)))  for every bijection P:V->V.

The second identity follows because P permutes the right summands. For any P with an efficiently generated list E of all mismatching left rows, and efficient evaluation of P at E, one has an actual polynomial aggregate algorithm:

    Aggregate(L,R,P,E) = XOR_{v in E}(L(v) XOR R(P(v))).

The list can include zero-difference rows harmlessly, but it must not omit any nonzero row unless an additional valid cancellation identity is proved. This is a different common-key mechanism from lexicographic map normalization. There is no requirement that P_t=P_w or that the maps form a torsor. If a witness can compute an exception cover for a huge P, it need not enumerate its domain.

Concrete initial weights: V={star} union ({0,1} x Z). Choose public domain-separated hash functions F,G to ell=3n+8 bits, with separate domains from D and the payload-pad stream. Set L(star)=R(star)=0. For all z set

    R(0,z)=R(1,z)=F(ctx,z)
    L(0,z)=F(ctx,z)
    L(1,z)=F(ctx,z) XOR (G(ctx,z) if tagged dummy D(ctx,z)=y else 0).

These are serialized classical-PPT public vertex-weight algorithms (the public input is a vertex name, not a secret evaluation key). On unique-dummy executions K=G(ctx,t) exactly, since every background weight cancels. Build knowing t computes K and E_payload = S XOR ExpandH("signed-matching-pad",ctx,K,|S|). Its complete public weight description depends only on x,y and public domains; no marked dummy map or t is published. In a hypothetical pad challenge the weight description can be generated given x,y without knowing t; E_payload still needs a target-key hybrid, not a proof for arbitrary auxiliary/native correlations.

The identity permutation with exceptional left row (1,t) gives Build a correct polynomial aggregate algorithm. For the source branch, try the prior star-swap matching at the source-tagged w, leaving the dummy rows alone. The resulting mismatches at the star and source rows cancel their own contributions (exactly because the right vertices are only permuted); they do not remove the hidden residual at (1,t). Every original w would need a further transport that routes all nonzero residuals into efficiently accessible exceptional rows. This is a genuinely new missing operation, rather than a failure of common-key equality between two already supplied maps.

## 3. Attempt arbitrary transport, then repair the isolated unmatched weight

Do not restrict the attempted repair to star swaps. Allow ANY bijection P, even one that does not induce the preceding graph pair's matchings. In the stated independent ideal F,G domains, conditioned on F and the planted t, L(1,t)=F(t) XOR G(t) is uniform. The right weights have at most N+1 distinct values. Except with probability at most (N+1)2^-ell, L(1,t) equals none of them. Thus for EVERY P, the row (1,t) is an unavoidable mismatch. This is an exact pointwise obstruction to the proposed explicit exceptional-row cover, irrespective of matching closure and even if the original certificate somehow supplied a very different permutation. An explicit complete E reveals t. This reasoning does not assume a low-degree additive secret evaluator or a mix of labels; it follows from the public multiset of weight values.

Repair that particular obstruction by making the modified left weight equal a right weight by construction, not just by changing the hash domain. Fix a public name z0 distinct from t by dummy sampling domain. Replace the single modification with

    L(1,z)=F(ctx,z0) if tagged dummy D(ctx,z)=y else F(ctx,z).

Now K=F(ctx,t) XOR F(ctx,z0), and Build computes the new pad using that value. The modified value is always in the right multiset. The old unique-unmatched-value argument no longer applies. Try a source-derived transport that cancels the modified row by pairing it with a right copy of z0, and routes the residual to a known source row.

Except with probability at most (N+1)^2 / 2^ell in the ideal domain, F is injective on Z and none of its values is 0. On those executions the right multiset contains two occurrences of F(t), while the left contains exactly one. Consequently ANY bijection P has a mismatching edge whose RIGHT endpoint is one of (0,t),(1,t). Proof: the two distinct right endpoints need two distinct matching left rows of the same value for both edges to cancel, but only one exists. Thus even though the modified left value has a partner, the missing multiplicity creates an unavoidable residual at a hidden right name. An explicit list of exceptional edges reveals t. A list of left endpoints alone plus efficient evaluation of P on those endpoints also reveals t. This includes the intended sparse-cover implementation; it does not require efficient evaluation at all vertices. Arbitrary source-provided permutations, including exponentially large succinct ones, do not change this counting fact.

Try using symbolic edges instead: an edge may designate the unique right dummy by the public predicate D(ctx,z)=y without explicitly outputting z. This is a succinct membership description, not an evaluation of its right weight. The residual edge into that right endpoint needs F(t), or a separate exact aggregate of several such residuals. With only the published weights and y, a public evaluation at the symbolic name is not implemented. If the residual calculation simply receives F(t) it receives the key after XOR with the public F(z0). The exact candidate's entire t-dependent public weight description is generated from y; an original w independent of the separated dummy/weight hash domains supplies no additional correlation to t. Thus the previously established independent-opening/query-recovery screen applies unchanged to this symbolic evaluation. No new oracle-bound experiment is needed.

There is no reason to implement larger domains or another permutation family for these two variants. The repair removed the original unmatched LEFT value but not the hidden residual: in the repaired case it is a deficit of a RIGHT value. That distinction matters for future sparse-cover proposals.

## 4. Why the common-value identity does not yet give Build/Open

The aggregate identity is a real witness-independent normalization and would compose with differing witness transports IF each of them had an actual efficient exception-cover evaluation and the complete weight descriptions were jointly simulatable in the full-public key-recovery game. It is insufficient to have a succinct *existential* matching or a public test for any particular edge. It is also insufficient for Build knowing t to calculate the global XOR; Open needs a different calculation without t. Checking R_x(w) before invoking an independent symbolic weight evaluator is only an honest-code check.

A future repair of this particular route would need a dense jointly generated weight distribution (not a modification localized at the planted dummy) and an actual every-witness aggregate algorithm that can sum the residuals without exposing their hidden endpoints. An explicit polynomial domain with the full public weights is not a repair: the adversary directly computes the total. A dense public weight circuit whose total can be evaluated by public telescoping without the original certificate also fails. A circuit containing S as a readable constant is not a protected weight evaluator. No construction of the necessary dense correlation or simulator was found. The aggregate identity is not an impossibility theorem for arbitrary implicit weighted transports or hash-only release.

No original-source compiler, native signature implementation, arbitrary FALSE/hard-TRUE recovery/forgery reduction, malicious N-of-N setup, or auxiliary/related-capsule proof produced. R225 and R316 scope unchanged. Static derivation only; no checker execution, tests, new Core reads, external literature, or subagents. No ordinary PR comment. Notification gate not met.
