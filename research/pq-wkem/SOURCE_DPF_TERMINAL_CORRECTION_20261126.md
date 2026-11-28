# Whole-witness distributed-point-function terminal correction trial — 2026-11-26 UTC

Status: static construction/repair attempt, not a qualifying original release advance.

Continuity: actual syscoin/PVUGC PR #1 open/draft/unmerged, branch research/pq-wkem-validation-20260918, start and prewrite head 2182788bd984d1737116941548652a8761078aad. Read actual PR metadata, latest five substantive discussion entries (through R225), head commit file metadata and exact SOURCE_OR_PROOF_COLLISION_SAMPLER_20261126.md (blob 721935dd7ff0e07ecf6514786460bc0aafc58361). The new path returned 404 at the pinned head. No new Core source claims or external research.

## Selection

The missing original operation is a public, offline, hash-only transformation from every qualifying original source certificate w into the same precommitted cancellation contribution S. Retain the complete original relation R_x(w), its three OR grounds, full authenticated relevance, claim/capsule/native-message bindings and maturity/window rules. Neither a digest of the witness nor a verifier result alone is evidence. Encode bounded certificates injectively as fixed-length n-bit strings (including lengths and domain tags).

Instead of the previous attempt's identical OR-proof string or R327's additive private coefficient evaluation, try a pair of GGM/DPF-style seed evolutions indexed by the ENTIRE certificate. Each qualifying w may lead to a different pair of leaf seeds. A terminal difference correction is intended to return S independently of the leaf. The mathematical change is two nonlinear seed evolutions with control-bit-conditioned corrections, not reusable per-wire witness labels, so the R289 splice of local labels is not the immediate failure argument. The issue to investigate is whether a single shared correction schedule can enforce the relation without enumerating certificates or exposing a public chosen-control shortcut. No claim is made that this family is previously unexplored outside the inspected handoff.

## Concrete correction construction

Work over bit strings with XOR; lambda-bit seeds, one control bit per seed. Use an independently domain-separated hash expansion G(ctx,level,s) giving two child seed/control pairs (a^0,b^0),(a^1,b^1). This is a classical algorithm; treating G as a random function on distinct inputs below is an explicit idealization, not a concrete SHA theorem. Build samples independent roots s_0,s_1 and sets t_0=0,t_1=1. Both roots must be available in the public capsule because Open is public and cannot contact the setup parties. For an input prefix p and next bit j, expand both current states. The public correction words (seed word A, per-bit control word B_j) yield

    s_i(pj) = a_i^j XOR (t_i(p) * A)
    t_i(pj) = b_i^j XOR (t_i(p) * B_j).

Here multiplication by a bit means either zero or the whole word. This is the ordinary DPF-style correction algebra; it is not being invoked as a two-public-key privacy theorem. When the current seeds AND controls coincide, all subsequent states coincide under common corrections. When t_0 XOR t_1 = 1,

    s_0(pj) XOR s_1(pj) = a_0^j XOR a_1^j XOR A,
    t_0(pj) XOR t_1(pj) = b_0^j XOR b_1^j XOR B_j.

Consequently for a *single selected parent pair* one can choose A = a_0^ell XOR a_1^ell and B_ell = b_0^ell XOR b_1^ell to coalesce a losing child ell, while choosing the other B bit to continue a control difference. This gives explicit serialized Build/Open for a known singleton index, not the required relation. We are not using that singleton as a fake original witness.

Try the following repair: have one correction pair per level, or one seed correction per child bit per level, and use the verifier to determine which prefixes/children should coalesce. All valid certificates must retain an active pair until the terminal step. False certificates should coalesce or return no release. No evaluator is supposed to know S directly.

At a level with two active distinct parent pairs p,q and a losing child of the same bit j, a shared seed correction A_j must satisfy BOTH

    A_j = a_0^j(p) XOR a_1^j(p)
        = a_0^j(q) XOR a_1^j(q).

Even with two seed words per level this is an exact compatibility equation. Under fresh independent ideal expansion outputs at distinct seed inputs, the equality has probability 2^-lambda; this is a local conditional calculation, NOT a bound on all adaptive setup strategies or correlated choices of seeds. In particular, a common expansion input can defeat the freshness premise; one cannot silently apply the probability to state reuse. More importantly, the standard one-active-prefix generation algorithm has no means of deriving the seed correction at arbitrary new active prefixes from a single level word. Changing just the control-bit correction cannot fix this seed equation.

## Attempted nonlinear terminal repair

Avoid demanding coalescence at each invalid prefix. Leave both states active through all n levels. Let

    U_i(w) = ExpandH("leaf",ctx,s_i(w),|S|)
    delta(w) = t_0(w) XOR t_1(w)
    D(w) = U_0(w) XOR U_1(w)
    OpenRaw(C,w) = D(w) XOR (delta(w) * T),

where T is a public terminal correction word of length |S|. Build must set T so that OpenRaw=S for every original qualifying w with delta=1, without knowing future w. A common terminal word requires D(w)=D(v) for every such pair. For two fixed distinct fresh pairs with all four leaf-domain inputs disjoint, independent uniform leaf outputs give equality probability 2^-|S|. Even if there are only three distinct inputs with one shared seed, equality requires the remaining two outputs to coincide. These statements do not exclude a purposely engineered correlation between seed pairs; they identify the additional correlation that must be engineered. For example, literally reusing the same unordered seed pair across all accepting leaves makes D equal, so independent-leaf analysis would be inapplicable. Such reuse must itself be achieved by actual public corrections rather than assumed.

Try making T depend on w, using the now-public leaf difference to normalize each distinct leaf:

    T(w) = S XOR D(w).

Then correctness is exact if delta(w)=1. However, if T is a public unconditional function of the two publicly evaluable seed states, the caller computes T(w) XOR D(w) for ANY input, even when delta=0, so the entire capability is recovered. If the interface computes T(w) only after R_x(w)=1, an honest-code if-check is not a cryptographic restriction on access to a serialized implementation. This is a chosen-control/counterfactual terminal evaluation, not a low-degree coefficient probe, and does not use label splicing. The result applies to this normalization that makes T(w) directly accessible; it is not a theorem about a cryptographically restricted evaluator.

The intended repair is to remove T(w) from public outputs and let the two seed-side evaluators compute corrected outputs separately:

    V_0(w) = U_0(w) XOR (t_0(w) * T(w))
    V_1(w) = U_1(w) XOR (t_1(w) * T(w)).

But both seeds, both control bits and all code are public in the proposed construction. In the explicit implementation where T(w) is supplied by a common routine and selected by t_i, one can invoke that routine or force the selector; this merely moves the same exposure. To prevent this, a new primitive would need to evaluate the masked outputs from the public capsule without an accessible normalization routine and with inaccessible counterfactual outputs. The PRG expansion itself provides no such operation. Even for delta=0, accepting a forced selector as valid cannot be detected by an optional native check if the recovered S is exact.

An alternative is to put distinct correction words at each prefix (including a terminal word for each qualifying leaf) and encrypt the words with the seed state of that prefix. Honest setup can generate all of these only by generating the relevant states and knowing which branches are live. An arbitrary-source verifier's polynomial running time does not supply a polynomial-size read-once decision diagram or a polynomial-time list of its accepting prefixes. Enumerating the certificate tree or full verifier state graph violates the target practicality; no such implementation or parameter sweep is performed. If one did happen to have a small explicit read-once decision diagram for the complete predicate, reachability in it would give a satisfying input directly; this would not explain hard-TRUE source protection. This is not a claim that every compressed program yields a witness by reachability: repeated variables and succinct transitions invalidate that inference.

## Simulator audit and precise next repair

In the classical two-key DPF setting, hiding from one share holder is a different experiment from publishing BOTH keys. Here the attacker knows both seed roots, corrections, the source predicate, native VK/message and auxiliary data. A hybrid replacing each key independently by a random key discards their joint terminal difference and cannot be justified by single-share PRG security. In particular any public chosen-control implementation of the normalized T(w) permits the straight-line recovery above even on FALSE statements, without a source certificate, hash collision, or native forgery. No hybrid can repair that implementation. Restricting access to the code of one of the evaluators would introduce a private evaluator/online party not present in the original model.

The remaining constructive equation for the whole-index route is a polynomial-size, classical-PPT jointly generated pair of *public serialized evaluators* E0,E1 with

    E0(C,w) XOR E1(C,w) = S for every R_x(w)=1,

whose public representations do not expose either branch-dependent hidden correction or a counterfactual terminal evaluation; arbitrary unauthorized QPT recovery must reduce to an actual qualifying original source certificate or an independently justified break. This equation is only a design obligation, not a primitive assumed to exist. Specifically, a next attempt must supply a nonlinear compressed correction-generation mechanism not requiring enumeration of active seed pairs AND a joint simulator of its public code/keys with native/auxiliary/multi-capsule correlations. Standard single-key DPF privacy, a common terminal word, and public verifier-conditioned normalization do not supply it. Do not retry merely with larger trees, different seed widths, or extra per-level words.

No malicious setup correctness, fixed native contribution, activation-specific binding or native forgery reduction has been established. The original endpoint and LC assumptions remain unchanged (including R316/R225 qualifications). Static derivation only; no code/checker execution, delegated agents, consensus validation, new native signature or QPT theorem. No qualifying result; no ordinary PR comment.
