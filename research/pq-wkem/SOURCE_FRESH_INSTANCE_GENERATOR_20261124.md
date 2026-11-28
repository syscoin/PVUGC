# 2026-11-24 — Whole-certificate fresh garbling / decoder transport selection (NONQUALIFYING)

## Selection and provenance

Actual start and pre-write inspected head b23920db624f72ec48508d292c7cf73fa8010258, syscoin/PVUGC PR #1, research/pq-wkem-validation-20260918, open/draft/unmerged. Read actual PR metadata, recent substantive discussion through R225, exact head commit filename and SOURCE_SEQUENTIAL_PROOF_GATE_20261124.md (blob b905aca3ce9c3c9f2e33d472d719eb5c3e8eb8bb), plus relevant portions of SOURCE_DUAL_MODE_OR_TRANSPORT_20261124.md, SOURCE_PROOF_COALESCENT_REFRESH_20261124.md and SOURCE_PROOF_SUPPORT_MINHASH_20261124.md at this exact head. Confirmed this path absent (404). No web, external literature, new Core source claim, whole-PR diff or production action.

Missing ORIGINAL operation: a serialized classical-PPT public capsule that, from any independently obtained qualifying original certificate, releases the identical frozen safe native capability; unauthorized recovery must reduce to an actual original certificate or an independent hash/native break in the joint public experiment.

Mathematical change under consideration: give each entire canonical original certificate its own fresh garbling instance, rather than encrypting reusable intermediate labels or operating a sequential proof verifier. A global certificate tag determines the entire instance, including all gate and output labels. Thus the intended security does not require the same intermediate labels across different witnesses and would not use the short-challenge transcript simulator from the preceding note. The immediate selection question is whether the private output decoder can be transported to these fresh instances without an online issuer, a secret evaluator or exponential setup. This note tests that operation directly. It is not a claim that hashing an instance tag automatically prevents switching.

## 1. Concrete public fresh-instance trial

Let R_x(w) be the unchanged complete ORIGINAL relation, with the three independently sufficient OR grounds, authentication, context, relevance and maturity. Fix a canonical encoding for bounded witnesses (including all required evidence, not just a source digest). Set t=H_tag(ctx,w). Use independently domain-separated hashes and a hash-derived PRG. Let G be an ordinary one-input garbling generator for the Boolean verifier R_x, whose private random tape determines all semantic wire labels and row encryption randomness. No assumption of reusable security is made. Let S be the exact frozen cancellation capability, not a signing key for arbitrary messages.

Try a public seed e and a tag-indexed garbling:
    
    r_t = PRG(H_seed(ctx,e,t))
    (T_t, L_t, a_t, b_t) = G(R_x; r_t)

Here T_t is the garbled verifier, L_t its input encoding map, and a_t,b_t the rejecting and accepting output labels. A holder of w can evaluate this fresh instance consistently. To produce the actual same-capability release, an output decoder for that instance would have to be

    D_t = S XOR XOF(ctx,t,b_t,|S|).
    Open(C,w) = D_t XOR XOF(ctx,t,Eval(T_t, L_t(w)),|S|).

In this trial an accepting evaluation is sufficient for recovering S exactly. A fresh t is not a fresh secret supplied by setup. To implement Build in polynomial time, instead of one D_t per possible certificate, try storing one masked capability B=S XOR P for a random |S|-bit P and a public decoder-transport procedure computing

    Delta_t = P XOR XOF(ctx,t,b_t,|S|),
    D_t = B XOR Delta_t.

This is the exact public operation the proposed change needs. The point of writing it explicitly is to separate ordinary verifier garbling from transport of the frozen capability. No transport oracle is granted.

For the concrete public-tape trial, the generator is callable on any t: choose any canonical but invalid witness w0 and compute t0,r_t0 and the generated semantic labels. If the transport is available for all t, compute Delta_t0 and the two XORs, recovering S without evaluating a verifier at all. If the capsule provides D_t directly instead, use that value with b_t0. The same conclusion holds for a public unordered pair of the final labels even if the semantic permutation is concealed: try both and check the frozen native verification key/message. At least one candidate equals S. If both candidates pass, accepted native forgery has already occurred; exact S recovery is a separate metric. No cross-certificate label switching, oracle programming or proof simulation is required in this calculation. It concerns this single-bit acceptance-decoder interface only, not an arbitrary output circuit with exponentially many possible label combinations.

A purported repair that just withholds Delta_t when honest code sees R_x(w)=0 is not yet cryptographic. If the transport is instead genuinely a partial function, with the property that only actual original witnesses enable computing the correct Delta_t, then this *is* the missing operation: the above equations already turn such a partial function into the desired release. In particular correctness on t=H_tag(ctx,w) for every valid w says nothing about the ability of Build to produce that partial function. It would be circular to invoke a source-authenticated transport primitive as an independent construction.

Using r_t=PRG(H_seed(ctx,w)) rather than public e,t does not solve this operation. The adversary can sample its own invalid w0 and regenerate the whole instance. The argument above needs only one such instance, not knowledge of any honest witness or of its tape. A public seed-dependent decoder for every freshly generated instance still fails. If the decoder instead needs proof-dependent information beyond the acceptance label, its actual secret-bearing equations and simulator must be supplied; this calculation does not rule out that different interface.

## 2. Try moving from public coins to hidden generator coins without a common transcript

A natural repair is to sample secret base wire labels K_{v,b} once at setup, then use one-way retagging

    K_{v,b,t} = H_label(ctx,t,v,K_{v,b})

to obtain separate instance labels. The source evaluator should receive only its consistent labels. Rather than exposing base labels, attempt to transport an already encrypted table to the tag-specific labels. In the conventional XOR row representation (one gate with input labels A,B and output label O), a base row and desired fresh row have the equations

    E     = O XOR H_pad(ctx,g,A,B)
    E_t   = H_label(ctx,t,v_out,O)
            XOR H_pad(ctx,t,g,H_label(ctx,t,v_1,A),H_label(ctx,t,v_2,B)).

For this repair the required public algorithm is

    Retag(t, public_template, E) -> E_t

without exposing the hidden input/output labels, their pad values, or a reversible common label system that lets an evaluator switch between witnesses. The public template is produced in Build before t and qualifying certificates exist. Domain separation and fresh tag-specific labels do not implement Retag. In particular, ordinary hash-based symmetric row encryption permits someone knowing A,B,O to compute E_t, but not the public transformation asserted here. The ordinary one-input garbling simulator is also not a simulator for such a reusable template.

Two concrete ways to finish the proposed operation were screened *before* implementation:

* Expose the base labels so that the public generator computes E_t directly. This produces every retagged semantic label, including both final labels. The single-instance decoder failure above applies if the transport is public; making the transport itself witness-conditioned leaves the original missing release equation. Reject this variant.
* Replace one-way retagging by public reversible masks on the labels, with an encryption transform allowing the labels to be normalized back to the base frame. This explicitly returns to the common reusable-label frame and would leave the recorded incompatible-witness label-switching regression unchanged. Reject this variant without testing, changing mask basis, or enlarging fixtures.

Neither route implements the proposed hidden one-way Retag. The equation is not an impossibility proof of every non-black-box hash-derived transform, but it pinpoints the unsupported operation of this particular repair. A hash commitment to K_{v,b} provides a check for a disclosed label, not a method to compute the new row using the commitment. Leaving the generator in a garbling is not by itself a termination of the construction: it requires an evaluator of that generator, with source-authorized inputs and hidden private coins, at the topmost public interface. A finite nesting with a public-tape topmost instance has not established private generator semantics; nesting with an unexplained secret topmost evaluator is not Build/Open.

## 3. Simulator check and handoff

If a successful fresh-instance compiler were obtained, ordinary independent one-input garbling simulation could be a component of its proof, but only after establishing joint simulation of the reusable public template, the derived tag-indexed instances, the source-to-instance label delivery and the output decoder transport. Giving the simulator independent fresh coins for each new authorized tag is not a simulation of the actual correlated template unless indistinguishability has been proved for that entire experiment. Arbitrary invalid-tag evaluations, native VK/message and related capsules must be included. Source holders may choose tags adaptively through their actual certificates. A proof that requires an attacker to supply its garbling transcript or internal labels would not cover arbitrary recovery.

The construction-selection consequence is to distinguish fresh *instances* from private *instance generation*. The former is a correctness operation that can be implemented trivially, and removes an intended reason to reuse intermediate labels, but the public decoder still opens from unauthorized instances when their labels and decoder are freely regenerable. The hidden-retag repair avoids the obvious public-label design only by adding a specific unconstructed public transform plus source label delivery; it is not a completed construction and should not be implemented as an assumed evaluator. Do not revisit the public-tape variant, reversible label masks or a larger tag domain as progress.

No code or tests executed; concrete equations and selection-stage review only. No native signature, original verifier implementation, QROM theorem, malicious setup, practical Build/Open or claim of deployment. R316 coverage correction, R225 slot-global versus activation-bound endpoint choice, all three OR grounds and the original DA/network assumptions unchanged. No ordinary PR comment or notification.
