# R372 — Conditional digest-label sampler gate for original-source cancellation (NONQUALIFYING)

## Continuity, decision and closest regression

At this execution's GitHub read, live syscoin/PVUGC PR #1 was open/draft on `research/pq-wkem-validation-20260918`, head `b1be9a350de9eca2ec92bcd6abfef2f34b57af17`, latest R371 note `research/pq-wkem/r371_preauthorized_lateclaim_20261118/RESEARCH.md` blob `07f5b779a72fc3507f60a9eeb07eeaa2c3e90a35`. Checked PR issue comments since 2026-11-18 18:00 UTC: none. No Core source or tests read or run this iteration; no new Core claim is made.

Continue the missing source-dependent release gate, not R371's native preauthorization. Candidate selection: the strongest proposed simplification after the FE analysis is to reduce a qualified ORIGINAL SHA/AuxPoW witness to some digest-labelled attribute and let a publicly evaluable hash-only carrier release the fixed cancellation secret. Unlike the already rejected public target-prefix idea, this assessment handles a **full target-satisfying digest**, and conditional label distributions, not just a few known leading zero bits. The actual mathematical change being tested is whether hiding the missing nonce/preimage *while publishing the full valid SHA digest as the attribute* supplies an unsamplable label. It does not: the digest alone is efficiently samplable without its PoW preimage. Crucially, the result does NOT cover a gate that cryptographically binds the input to an actual original full raw preimage and relevant authenticated ancestry.

## Specific candidate interface and precise conditional-sampling theorem

Fix the complete approved statement x and its native frozen cancellation capability sigma, its public source/claim context I, and a classical-PPT Build output C, which may also contain D=sigma XOR K. Suppose a public, unrestricted label-only evaluator G(C,y) can recover K when fed y=L(w) for a qualifying ORIGINAL witness w, while checking R_x(w) (if done at all) is an **external ordinary software check** whose result is not cryptographically enforced inside G. We do not assume that G reveals its internal coefficients or that attackers volunteer a representation.

Assume there is a classical PPT sampler T(I,C) of labels with joint total-variation distance <=epsilon from L(W), conditional on the full published (I,C), for a specified qualified-source experiment W, and that K is fixed at Build. Then by total variation, with events A(C,y)=[G(C,y)=K],

   Pr[G(C,T(I,C))=K] >= Pr[G(C,L(W))=K] - epsilon.

Therefore an adversary can use the public program and sampler to recover K, then D XOR K, without outputting any qualifying ORIGINAL witness. Its total work is T_T+T_G and does not include the source certificate's PoW-preimage cost. This is unconditional in the stated samplable-label model; it is a *necessary-condition filter*, not a generic hash-only impossibility. The joint conditional distribution condition is indispensable: a marginal-only approximation need not preserve dependencies between labels and the published capsule. Honest independently sampled future RO headers may supply independence; malicious retained source coins and adaptive siblings must be modeled explicitly, not silently granted.

For a Bitcoin-style random-oracle parent header `H(header)` conditioned on `H(header)<=target`, the **output digest** is uniform over the public admissible integer interval, up to conventions for inclusive bounds. An attacker can uniformly sample such a digest by integer sampling in the interval, without finding a header that hashes to it. An arbitrary public function of that digest and public target/claim information remains samplable by composition. This covers any digest-only label whose conditional distribution actually has this form; it does not show that an arbitrary vector of linked header hashes or true best-chain status is independently samplable. Likewise, in an explicitly idealized independent domain-separated random oracle, a label `H_label(serialized original w)` is uniform even conditioned on `H_pow(header)<=target` when not prequeried/correlated, hence its digest-only distribution is also samplable without w. **Neither statement is a concrete-SHA security proof**.

The attack is classical, hence is available to a QPT adversary. It does not need to break SHA or any valid native signature. It fails to apply if G requires the actual original raw preimage/history and refuses fake digests **inside its secret-bearing computation**, rather than trusting an ordinary wrapper. It also does not cover inputs whose joint conditional distribution is unsamplable due to authentic hash-preimage/ancestry constraints.

## Repair attempts within this bounded pass

**External source verifier as an FE front end:** Accepting `R_x(w)=1` in honest caller code, then passing a digest or accepted bit into G, is bypassable. Attackers call G directly with sampled admissible digest or `true`. An NP proof of correct FE *setup* does not turn that wrapper into a cryptographic gate.

**Globally hash the entire source witness:** Let y=H(sid||w), instead of H(parent header), so proof fragments from different witnesses cannot be spliced by the prescribed opener. Build takes place before any future conflicting original w exists. A fixed pad `D=sigma XOR H'(y)` cannot be computed by Build at an unknown y; if the pad is chosen from a common public baseline instead, it is publicly calculable. A polynomial-size *private function* mapping all as-yet-unknown qualifying y to the same K is precisely the missing serialized protected program; merely giving it the label `FE`/garbling or a private online evaluator supplies no construction. This repair avoids a specific fragment-splice syntax but does not instantiate Build/Open or joint public hiding.

**Feed a succinct authenticated proof instead of raw w:** A new Fiat-Shamir transcript or proof hash is similarly unknown at Build. If the protected evaluation accepts only proof-verifier output supplied as an untrusted bit it is bypassable; proof verification must be internal to the secret-bearing public evaluator. Even accepted proof availability need not imply original evidence extraction without an appropriate quantum-compatible argument of knowledge. No such FE verifier or extractor was instantiated.

## Source-faithful limitation and exact remaining construction

The ORIGINAL bridge witness remains
`R_x(w)=R_BTC_greater OR R_specific_burn_fault OR R_qualified_Syscoin_inc_or_tag_fault`,
with strict post-PQ contextual modern ID, sole canonical parent SYS tag, independent AuxPoW child Merkle commitment, actual claim-prefix ancestry and source depth, authenticated outer carrier for a tag fault, relevant BTC anchors/work window, and concrete burn authorization/refutation. A digest sampled under the public parent-work target is NOT an actual authenticated Bitcoin/Syscoin certificate. Branch 3 does not demand greater Syscoin work; source tag-height lag is not LC depth. Different parents for the same child do not alone form a fork. Source knowledge must reside in the release mechanism itself, not a optional software if-check.

The **positive selection criterion** is now sharp: only invest in a proposed classical practical *serialized* hash-only Build/Open that cannot be evaluated on efficiently sampled stand-in digest labels, cryptographically enforces a **single complete relevant raw ORIGINAL certificate** through its secret-bearing computation, and admits an independently grounded *joint-public* recovery-to-original or native-forgery reduction. The next mathematical equation is still:

  C=Build_orig(x,sigma;r); Open_orig(C,w)=sigma for EVERY w with R_x(w)=1,

with a simulator for (x, native VK/message, C, setup proofs, sibling capsules, source coins/auxiliary view), classical first-release and QPT where claimed. No such mechanism or simulator was built here. The lemma is not an independent security foundation, source-work theorem, QROM-to-SHA reduction, or practical bridge solution. It should be used as a fast pre-implementation filter, not as a numbered breakthrough or a replacement for constructing the missing gate.

## Executed actions and disposition

GitHub read-only PR metadata, latest R371 exact file and most recent issue-comment query were actually performed; no new Core test or source replay, local code/test runner, FE implementation or native signature was executed for this mathematical filter. The inequality above follows directly from total variation and does not depend on empirical trials. No user progress comment or notification is warranted; leave the research automation enabled. This note records one bounded, unsuccessful candidate/repair iteration and the precise non-samplable-input boundary for the next proposed release mechanism.
