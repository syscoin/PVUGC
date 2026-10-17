# Run 438 — exact forest boundary-pin orbit theorem

Live PR baseline: syscoin/PVUGC#1, draft/open, research/pq-wkem-validation-20260918, head eea775752b1342385c84671fc9adf1b0fa2cc293. Continuation of exact Run 437 proof. This is an information-theoretic restricted-interface result, NOT a PQ witness-KEM, a general local-mixer impossibility, or a CCMR/RIO refutation.

Fix a directed path of reversible S_d gates T_1,...,T_h. Classical honest setup samples independent uniform vertex permutations U_i and publishes G_i=U_i T_i U_(i-1)^(-1), plus named source anchor labels A_i=U_0(a_i) and destination anchor labels B_j=U_h(b_j). Within each endpoint, original labels are distinct. Let T=T_h...T_1 and G=G_h...G_1.

Public invariant: M_ij = [G(A_i)=B_j] = [T(a_i)=b_j]. More strongly, the complete joint transcript distribution depends ONLY on the equality partition of the tuple (a_1,...,a_k,T^(-1)b_1,...,T^(-1)b_l). Equal partitions yield identical distributions; unequal partitions yield disjoint supports. If q distinct points occur, the transcript is uniform on |S_d|^h (d)_q points, each with (d-q)! frame preimages.

Proof: the map (U_0,...,U_h) -> (U_0,G_1,...,G_h) is a bijection. Conditioned on all G_i, U_0 remains uniform. Transporting B_j back through the public path gives G^(-1)B_j=U_0 T^(-1)b_j. Uniformly permuting a fixed labeled tuple reveals exactly its equality partition. This proves both necessity and sufficiency, support count and uniformity.

Positive scope: with anchors on only one endpoint, transcript distributions remain independent of T. Negative scope: even an acyclic path has PUBLIC open-path invariants when both endpoints are pinned. A native public verification key is NOT automatically an output pin: any map from verification key to encoded state must be justified, and this theorem alone reveals neither K nor a signature.

Singleton-output boundary: if witness encoding E is injective for two valid ORIGINAL witnesses and the protected region is one fixed reversible permutation G, their COMPLETE encoded terminal states G(E(w)) cannot agree. All-witness SAME-K semantics then need a many-to-one semantic output projection (with witness-specific garbage), a common input encoding, or an operation outside this restricted permutation model. This does not rule out reversible computation with output projection.

Executed: exact S4 Node.js checker, 55,307 assertions, repeated byte-identical. Supports for identity/same incidence/different incidence/double incidence: 13,824/13,824/13,824/6,912; same patterns have equal full transcript distributions, different patterns disjoint. Independent Python exhaustive checker: 48,544 assertions, repeated byte-identical. Finite checks do not prove cryptographic security.

Attack scope: (1) telescoping path masks, (2) endpoint gauge synchronization, (3) cross-endpoint fingerprints, (4) multiple pin intersections; (5) no oracle needed beyond public tables, but chosen-input encoders add pins; (6) honest uniform frames already leak incidence, malicious retained frames outside equality theorem; (7) UTXO/branch replay untested; (8) checking-key correlation unproven; (9) classical attack applies to QPT but no genuinely quantum-only result.

Auxiliary data must be independent of fresh frames conditional on fixed source configuration for the equal-distribution theorem. This is a formal restriction, not security under arbitrary correlated auxiliary inputs. Source-bound state still does not imply signature-to-ORIGINAL extraction; Run 259 applies only to its accepted complete representations.

Literature: CCMR TCC 2024 local-mixing abstracts and 2026 quantum-local-mixing follow-up provide architectural motivation, not a security theorem for this toy S_d frame scheme. Exact QPT native-forgery security, every-valid-witness SAME-K release, malicious N-of-N setup/erasure, multiple capsules, 128-bit costs and conditional native Bitcoin SLH/P2MR remain UNPROVED. Production unchanged.
