# Source-assisted opening-fiber release — 2026-11-27

Nonqualifying static construction preflight; no complete WKEM. Original source relation and endpoint unchanged.

## Continuity and selection

Actual PR #1 in syscoin/PVUGC is open/draft/unmerged on research/pq-wkem-validation-20260918, start a607968ba6520e0134979bc6e21306c051963e72. Read PR metadata, last substantive discussion through R225, exact head commit filename and SOURCE_PROPOSAL_DENSITY_RELEASE_20261127.md (blob d060326eabc26d09f989cb0de6591c6dc1fd19f5). Also identified the preceding exact commit 26fbeda152bf904898ca7d6e823302e55453cff6. The new path was absent (NOT_FOUND/404). No new Core source assertion or verifier change.

Missing operation: public classical-PPT recovery of the same precommitted native cancellation capability from ANY independently qualifying ORIGINAL certificate for any of the three grounds, with FALSE and hard-TRUE security for arbitrary QPT attackers and the full correlated native/public view.

Candidate change: instead of composing local wire labels or learning hidden additive coefficients, use the ORIGINAL witness to recover an opening of a SINGLE globally committed sampler output. Different certificates may yield different full opening randomness; only a key invariant of that opening fiber needs to agree. This would avoid the R289 independent-label splice if finding *any* acceptable full opening itself implied actual original evidence or an independent hard problem. The candidate is not another coefficient, rank, source-pad, or label-entropy parameterization. The attempted new operation is witness-assisted inversion of a sampler output, not witness-guided random sampling of terminal trajectories.

## 1. Explicit proposed interface and construction attempt

Let x include the complete original relation and claim/native bindings, let z contain the native public checking information and other allowed auxiliary data. Attempt:

- Build samples classical coins r, evaluates a hash-only sampler F_x(r) = c, and computes k = L_x(r) in a fixed key domain. Use domain-separated random oracle H for an ell-bit mask. Return C = (c,E), E = sigma_cancel XOR H(ctx,c,k). No secret service is retained.
- Open on an ORIGINAL w computes r_w = Inv_x(c,w), checks F_x(r_w)=c and computes k_w=L_x(r_w), then unmasks. It must succeed for every qualifying w, including later source witnesses not known at setup.
- A sufficient (stronger than necessary) correctness condition is that L_x is constant on the relevant opening fiber, including the sampled r. It need not require r_w=r. A public proof of opening consistency would only authenticate the opening; it would not deliver it.

This interface does not assume a constructed Inv. It isolates precisely the operation that must be implemented. It would be insufficient to give Inv an inaccessible secret F key, to give it an extra witness supplied by setup, or to let arbitrary public algorithms sample accepted openings. Public verification of a full opening does not imply the required extraction theorem for arbitrary attackers.

Try to instantiate F using hash commitments to randomized encodings of source traces. Commit to the full randomized encoding with one global binding root; a valid certificate supplies the source trace and lets one translate between its randomized encoding and the setup encoding. Unlike a local per-gate label approach, accept only a full opening of that one root.

For an injective-in-practice hash commitment c=J(ctx,r), two distinct accepted r and r_w give a J collision (if r is known to the builder), regardless of whether w is a valid source certificate. Thus the proposed translation cannot be a general rerandomization of the committed full trace under ordinary binding. The legitimate remaining option is that Inv recovers r itself. That needs a source-dependent trapdoor to invert the independently sampled root; the authentic evidence does not furnish such a trapdoor in this attempted sampler. Do not extend this argument to arbitrary nonbinding or computationally lossy commitments.

Try instead to make F intentionally nonbinding in nuisance randomness: F_x(r)=F'_x(k,u), L_x(r)=k, r=(k,u). If the commitment is key-binding but allows many u, different witnesses can return different u without finding a collision. This is the desired fiber architecture, but the standard public commitment to k is one-way to *all* parties lacking its opening. Making the commitment equivocable in k does not solve this: an algorithm that returns an arbitrary opening might return the wrong k. Public native verification can recognize a successful unmasking, but does not choose the original k cheaply from exponentially many candidates.

A quotient repair would let the invariant k be the quotient class of nuisance-randomized openings. If the class is directly computable from public c, the adversary decodes E immediately. If the public descriptor is only a hash of the class, then one must construct Inv returning that class from actual source evidence. The natural explicit construction of an independent hash commitment to the class has no such evaluator. In particular, a source Merkle opening is not automatically an opening of this separately sampled capsule commitment. The use of source paths in the Open code cannot substitute for a cryptographic correlation between these two opening problems.

## 2. TRUE-side hiding test for the proposed sampler repair (QROM only)

A useful selection check is to distinguish hiding of the exact key from hiding only nuisance opening coins. It differs from the earlier FALSE statistical-hiding/SZK diagnostic: this one is applied to the honest receiver even GIVEN a fixed genuine TRUE witness.

Assume a candidate produces (K,C0,W,Z,Sigma) without querying the independent domain of H used for the final mask. C0 includes all public sampler/helper data, W is a qualifying ORIGINAL witness, Z includes all additional classical auxiliary/native/related data of the tested experiment, and Sigma is the fixed native capability. To make the check conservative, give Sigma to the tested receiver when bounding KEY recovery (not signature recovery). Let A=(C0,W,Z,Sigma,ctx). Suppose the average conditional maximum mass of K is at most 2^(-h):

    E_A max_k Pr[K=k | A] <= 2^(-h).

The independent-mask architecture produces E=Sigma XOR H(ctx,C0,K), taking the address to be an unambiguous encoding. In the comparison experiment take E uniform independent, and use the independent H oracle. Even an arbitrary q-query receiver given A,E has average success recovering K at most 2^(-h), because its entire state in this experiment is independent of K conditional on A. (This diagnostic assumes no unmodeled correlated quantum advice; it is not a general auxiliary-input theorem.)

Couple the real experiment by replacing H at the single address a_K=(ctx,C0,K) with E XOR Sigma. Conditional on A and E this gives the correct programmed distribution, since H was independent of the sampler and E is uniform. For the j-th query state of the UNPROGRAMMED execution, let p_j(K) be its squared projection onto the address a_K. Conditional on A the state is independent of K, so E[p_j(K)] <= E_A max_k Pr[K=k|A] <= 2^(-h). The oracle difference acts only at that address and has operator norm at most 2. A telescoping hybrid, comparing the unprogrammed query states to the programmed execution with unitary suffixes, gives expected final Euclidean distance <= 2 sum_j E sqrt(p_j(K)) <= 2q 2^(-h/2). Measuring any event including exact key recovery changes its probability by at most this bound. Thus

    Pr_real[recover K] <= 2^(-h) + 2q 2^(-h/2).

This is an upper bound for this sampler test, not a tight quantum search estimate. The argument still allows polynomially many adaptive/coherent queries, nonuniform public algorithm code and the full specified classical side information. It does not assume a classical query log or an observed internal trace. It does NOT cover other capsules programmed at correlated addresses, sampler queries into the same mask-oracle domain, quantum side information correlated with K, concrete SHA replacing H, or exact signature recovery in the experiment that deliberately hands over Sigma.

Consequently, making the sampler commitment statistically hiding of K even given the actual qualifying witness cannot supply the required classical Inv through a final hash mask. The entropy deficit required to recover K must come from a genuine source-correlated helper, not from witness-indistinguishable randomness of an otherwise unrelated commitment. Hiding nuisance u is compatible with recovering K; the bound does not apply to u alone. This is not a general impossibility of source-specific computational encryption.

## 3. Concrete disposition

The full-fiber approach does avoid requiring a common *opening* and makes clear where global consistency is checked. But the natural two attempted instantiations (binding hash of the full opening, or a key-binding quotient commitment with freely varying nuisance coins) do not implement the requisite public source-assisted inversion. Independent commitment randomness plus a final native-mask oracle does not create the missing dependence. A generic equivocal commitment interface would at most permit alternative openings; it would not ensure they give the actual sampled key. Neither a stronger hash nor more trace-randomness fixtures addresses that equation.

Do not count this interface, the entropy check, or the global commitment as original source release. No actual public Inv or source-specific key-binding lossy sampler was found, and no code was executed. A next genuine attempt in this family must construct the correlated sampler and source-assisted inversion jointly; give a full-public simulator or reduction in which the sampler output remains hard to invert for unauthorized parties even with malicious source retention, native keys, and sibling capsules. It must also handle accepted-native forgery separately from exact key/signature recovery (ordinary EUF alone is insufficient when same-message alternatives are exposed). Do not use a standalone assumed witness-assisted trapdoor commitment as the foundation.

All three ORIGINAL grounds, claim relevance and maturity, R316 correction, R225 activation-specific/slot-global endpoint choice, one-honest N-of-N setup, pre-funding capsule correctness, and timely admissible evidence and inclusion assumptions remain unchanged. No deployment, no new source semantics, no new security theorem for the bridge, no ordinary PR comment. Static reasoning and authorized continuity reads only; no web, external literature, subagents or tests.
