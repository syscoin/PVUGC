# 2026-11-24 — whole-input two-key DPF release compiler screen (NONQUALIFYING)

## Continuity and selection

Actual syscoin/PVUGC PR #1, open/draft/unmerged, head b64be18d49c2befb31980fedce660d1262f39cf0 on research/pq-wkem-validation-20260918. Read PR metadata, recent substantive comments through R225, the head commit's changed filename and exact-head SOURCE_SPECIAL_SOUNDNESS_RELEASE_20261124.md (blob 63ec2a0b268b7ba369ef9198caf57cb0da0e0b73). That screen found no source-driven fixed-commitment response translator. No external literature/web, whole PR diff or new Core claim.

Missing operation: compile the SAME safe frozen native capability before future ORIGINAL witnesses exist. A complete authentic qualifying input must drive recovery, not a claimed Boolean acceptance bit. Mathematical change from R289 split-mask splicing and R327 private coefficients: try two hash-expanded seed paths addressed by the ENTIRE input in a distributed point/function-sharing (DPF/FSS) style encoder. There are no independently selected occurrence labels. Derive correction words that synchronize the two paths on rejecting inputs and give their fixed secret difference on accepting inputs. Public evaluation is stateless. The attack on locally mixed wire labels does not by itself settle this candidate; both seed keys are public, so the joint view must be analyzed instead of invoking ordinary one-key FSS privacy. Do not assume a general FSS primitive granting the desired joint secrecy.

## Serialized candidate and exact compiler obligations

Let x be the fully bound original withdrawal statement, R_x the ORIGINAL three-ground verifier on injectively encoded length-n evidence (bounded and canonical padding, not a source hash supplied in lieu of its preimage). Let delta be a uniform lambda-bit release key. B = sigma_cancel XOR XOF(domain,context,delta). Include all actual native bindings. Let G(s) be a domain-separated hash expansion into two child seed/control pairs, each (s_b,t_b) in {0,1}^lambda x {0,1}. Root pairs are independently sampled seeds and opposite control bits. Both root pairs, B, and correction description D are public.

At prefix p, for j=0,1, expand the current seed to raw child (u_j,v_j) for next input bit b. The corrected child is

    s'_j = u_j XOR (t_j * a_{p,b})
    t'_j = v_j XOR (t_j * d_{p,b})

where multiplication by a bit means either the indicated vector/bit or zero. A common public correction word is (a,d). Equal parent states remain equal for any common correction. For an unequal-control parent (t_0 XOR t_1 = 1):

    s'_0 XOR s'_1 = u_0 XOR u_1 XOR a_{p,b}
    t'_0 XOR t'_1 = v_0 XOR v_1 XOR d_{p,b}.

Desired Open: evaluate both paths for the complete evidence w and use terminal seed XOR as delta, then unmask B. No optional verifier-only barrier is counted. Thus the terminal invariant must be equality (or an independently justified key-independent distribution) for rejects and difference delta for EVERY accepting original w. The leaf verifier is not assumed to be an inaccessible service.

A literal per-prefix construction could synchronize a dead child by setting a=u_0 XOR u_1 and d=v_0 XOR v_1. An active child must instead retain opposite control bits using d=v_0 XOR v_1 XOR 1, with fresh seed correction. At final leaf the exact common-key correction is

    a_{p,b} = u_0 XOR u_1 XOR (R_x(p||b) * delta).          (1)

This realizes the path invariant with explicit exponential material, but that is already disallowed; no table was built. The attempted constructive compression below concerns only replacing those corrections by a serialized public classical-PPT description.

## Repair 1: shared correction words and prefix pruning

A depth-indexed DPF correction word can synchronize a losing child of one active prefix, but reuse across two distinct active prefixes forces equality of their respective raw seed XOR values. In particular if both children are meant to synchronize,

    a_i = u_0(p,b) XOR u_1(p,b)
        = u_0(q,c) XOR u_1(q,c).

This is an exact constraint, not an assumed rank condition. Standard point-function seed expansion has one active prefix, so it does not supply this equality. Treating raw hash differences as independently uniform would make agreement unlikely, but that heuristic is unnecessary: there is no identity in the specified G interface that enforces it. Choosing correlated seeds to force the equality is a different construction, and exposing a hidden XOR correlation at every internal layer would need the full-public regression analysis.

Try instead prefix-specific corrections computed by the public evaluator, pruning precisely prefixes with no qualifying completion. The missing build computation for pruning is E_x(p)=exists z:R_x(p||z), not merely running the original verifier. Exact public activity is also an explicit witness-search interface: for an active prefix evaluate the two corrected children, choose any with opposite control bits, and after n steps obtain an accepting input (provided active iff a qualifying completion exists). This uses at most two child expansions per bit, not a claim about breaking SHA or the actual relation. It would allow the capsule itself to generate a challenge certificate on a mathematically hard-TRUE statement, rather than waiting for authentic evidence. No efficient independent E_x or safe source acquisition follows from the original verifier. Prefix pruning is not the repair.

## Repair 2: defer the predicate to the terminal step

Keep controls opposite at every internal node, even on dead prefixes. This eliminates the prefix-existence computation and public activity search. Set internal d=v_0 XOR v_1 XOR 1 and choose a from a public domain-separated hash of x, p, b and both current states. These are actual deterministic classical-PPT operations; no private evaluator or precomputed label array. Every complete input now reaches a well-defined pair of raw terminal seeds, and the terminal verifier R_x is polynomial-time.

At the last step compute the known value U=u_0 XOR u_1. The proposed public correction generator must implement equation (1). The mathematical repair fails specifically at serialization: generating it with delta as a literal or public seed discloses delta; omitting delta and using H(x,p,b,U) instead gives arbitrary unrelated terminal differences, not the same key. The honest-code conditional 'if R then use delta' is not cryptographic control: putting delta in the program discloses it outside the branch. For any public description of (1), a caller can compute U independently from public roots and known path, so correction-generator secrecy is precisely secrecy of R_x(w)*delta itself. This identifies the missing function-sharing obligation without appealing to independent-label or one-key DPF privacy.

A public terminal correction table indexed by full inputs can be filled by Build knowing delta and enumerating the original verifier. Its false distribution is independent of delta because every entry equals U; B is then a hash-pad ciphertext under an independent random key (ideal-oracle reasoning would still need native/auxiliary and key-query bounds). But it is exponential. Replacing the table by a public circuit that computes (1) while hiding delta from arbitrary inspection is the original correlated-release problem, not an achieved hash-only FSS construction.

## Repair 3: terminal hash normalization instead of direct seed XOR

Try terminal output Y=H(s_0) XOR H(s_1) XOR (t_0 XOR t_1)*D_f with a single final public correction D_f. For each accepting input w with opposite controls, correctness requires

    D_f = delta XOR H(s_0(w)) XOR H(s_1(w)).

So one D_f works for all accepting inputs only if the raw terminal hash XOR is identical on all accepting paths. Forcing identical terminal seeds makes D_f=delta, exposing it publicly. Forcing only a common hidden hash XOR requires a new correlated seed generator with a proof for the joint public view; independent hash expansion does not give it. Per-leaf D_f brings back the exponential table or an unconstructed function-sharing evaluator. Keeping D_f secret is incompatible with public Open. Reject this repair algebraically; no fixture enlargement, source-pad tests or rank experiments.

## Simulator status and precise next equation

The candidate is correct only with forbidden enumerated corrections or a new succinct conditional generator. Ordinary one-key DPF indistinguishability says nothing about the jointly public pair of roots plus corrections, B, actual native VK/message, source commitments, malicious source coin retention, auxiliary information, sibling capsules and selective openings. A simulator for the finite all-reject correction table could produce the same key-independent entries, but that does not give a PPT simulator for the required public descriptor. Nor is it a full QPT proof for native signature recovery/forgery, random-oracle key search or related instances. No classical rewinding or concrete SHA programming claim.

Remaining operation: a serialized hash-only compiler for the terminal correction family, or a genuinely different path-state relation making its common secret difference emerge only from complete original input without publishing that secret in the descriptor. It must avoid both prefix-existence search and source-independent terminal normalization. Do not introduce a hidden evaluator, treat a point DPF with target 1 as source authentication, or rerun wider/deeper DPF fixtures. The root/correction description has to remain jointly simulatable for false instances and support an arbitrary hard-TRUE recovery/accepted-forgery reduction to ORIGINAL evidence or an independent QPT break. This screen does not establish that such an algorithm is impossible.

Analytical compiler/repair attempt only. No synthetic checker run: the exact terminal and synchronization equations decide these specified variants without parameter trials. No native signing, real source verifier execution or new consensus claim. Preserve all three original grounds and full claim/maturity/carrier relevance, finite burn refutation, actual ancestor comparison, R316 coverage qualification, R225 endpoint scope, one honest N-of-N graph and capsule correctness before funding, DA and inclusion assumptions. NONQUALIFYING; no ordinary PR comment or user notification.
