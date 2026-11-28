# Source-conditioned claw to native-chain transfer preflight — 2026-11-27

Nonqualifying construction attempt. No complete WKEM, no source-policy change, no deployment or generic impossibility claim.

## Continuity and selection before implementation

Actual syscoin/PVUGC PR #1 is open/draft/unmerged, head branch research/pq-wkem-validation-20260918, start 32bc67d758e4c7ac74fa177aeffd8710804fedfd. Read metadata, recent substantive comments through R225, exact start commit's file metadata, SOURCE_OR_TRANSCRIPT_TRANSFER_20261127.md (blob deb433b96c52aaac5a1df411b49a6be4034e038b) and SOURCE_OPENING_FIBER_RELEASE_20261127.md (blob b809593d3919f4381a5100376b83780db2d5805d). Rechecked unchanged head, and new path absent (NOT_FOUND/404). No change to original predicate or Core facts, so no fresh Core source assertion.

Missing operation: transfer the SAME frozen native cancel capability to ANY actual qualifying original witness without publishing it or requiring an online participant. Try an instance-dependent two-branch hash claw directly coupled to a native hash-chain preimage, instead of local garbled labels, private additive coefficients, or two independent special-soundness transcripts. The mathematical change relative to R289 is that the sole accepted proof object must be a single global cross-branch claw whose construction checks the entire original predicate; there are no intermediate labels or per-occurrence openings to splice. Unlike the immediately previous OR-transcript attempt, try making the *same hash image* the native verification target, not an independent native proof branch. Preflight the actual evaluation and transfer equations, and reject before implementation if they do not transfer the native preimage.

## 1. Construct the conditional claw without any future source witness

Let R(x,w) be the complete finite bounded ORIGINAL predicate, including all three independently sufficient grounds and their full relevance, maturity and claim binding. Context x includes the claim, capsule and native bindings. Fix unambiguous bounded canonical encodings with length framing and domains. Let H be a collision-resistant hash (QPT collision resistance is an independent assumption for this limited statement, not a proof for SHA).

Define public maps

    F0(t) = H(0 || enc(x,t))
    F1(w,u) = if R(x,w)=1:
                  H(0 || enc(x,u))
              else:
                  H(1 || enc(x,w,u))

Build samples t uniformly and publishes t and a=F0(t). A qualifying original w produces a claw (t;w,t) in classical PPT; no source-dependent secret is assumed, and all honest witnesses can do so even if future witnesses differ. Check a=F0(t)=F1(w,u). For any explicit accepted claw either R(x,w)=1 or the two distinct domain-framed inputs hash to the same a. Thus an algorithm outputting an accepted claw with an invalid source witness directly supplies a collision; no rewinding or representation assumption is needed for that particular output event. Even valid w with u different from t supplies a collision. This is an explicit globally consistent certificate mechanism, but it is intentionally not called encryption. It says nothing about an arbitrary attacker which returns only a native signature or key and no claw.

Important: evaluation of F1 is not a secret evaluator; its acceptance branch is public. An attacker can compute H(0 || enc(x,t)) without R, but cannot label that as an accepted F1 preimage without supplying the source certificate or collision. The distinction is crucial when transferring the result to a native endpoint.

## 2. Try making the claw image itself a native verification target

Use one fixed native hash-chain segment as a deliberately favorable abstraction of a hash-based signature component; the full native signature is more restrictive. For fixed public seed, address and step i, let h_i(z) be the native hash step on a fixed-length z. Let the actual hidden signature component be s at step j, and the relevant public endpoint be y=h_(j+l-1)(...h_j(s)), l>=1. In this thought experiment even give Build freedom to choose s and compute y. Keep the native message, randomizer and chain index fixed. We are not assuming a new native opcode or modified hash function.

First try F0(t)=h_j(t) for l=1, F1(w,u)=h_j(u) on accepted source witnesses, with invalid branch hashing a separate domain. Set y=F0(t). For native cancellation the verifier checks h_j(z)=y, not F1(w,u)=y. There are two choices:

* Publish t as in the claw construction. Then z=t is a native opening immediately, with no evidence or hash break. The R check controls only the certificate wrapper, not recovery of the actual native component. This is a direct endpoint bypass.
* Retain/erase t and publish only y. The original public claw completion (w,t) no longer runs. The genuine witness w does not provide t; the equality F1(w,u)=y is now an inversion problem for h_j. A false-domain hash collision is irrelevant to the receiver's missing inversion.

Try to repair the second choice by giving a public source-to-native map D(T,w) in the capsule, where T is generated by Build knowing t but not w, so that F1(w,D(T,w))=y for every genuine witness. For any explicit accepted native component z different from t, h_j(z)=h_j(t) is a collision. For exact correctness, z=t is already necessary except with negligible probability under QPT collision resistance, for any efficient witness generation/advice independent of the fresh builder secrets and with the actual t available in the reduction. Thus the repair has to implement actual recovery of the hidden t, not an alternative opening of the artificial conditional claw. The original claw construction supplies no such D; no new assumption about source-dependent inversion is allowed. Domain framing also cannot change a native h_j invocation; an artificial invalid branch domain can be used in the proof-side map but is not part of the native verification rule.

Now try allowing different valid witnesses to return different chain values at the SAME fixed index j with the SAME endpoint after l steps. For two unequal starting strings s,z define S_0=s, Z_0=z and S_(a+1)=h_(j+a)(S_a), Z_(a+1)=h_(j+a)(Z_a). If S_l=Z_l, the first convergence index b>=1 has S_(b-1)!=Z_(b-1) but h_(j+b-1)(S_(b-1))=h_(j+b-1)(Z_(b-1)). This directly yields a native step collision with the same fixed public parameters. Different witnesses can have different source claws, but cannot in this way supply different freely chosen native preimages of a fixed chain endpoint without a collision. This argument only covers the indicated fixed-index segment; it does not prove full SLH-like same-message security, alternative randomizers, alternative authentication paths, or recovery of arbitrary native signatures. It does not imply that every hash-only WKEM must reduce to native inversion.

## 3. Test whether keeping the source claw separate fixes the transfer

Keep the original explicit source map F0,F1 and let Build additionally choose independent native component s, endpoint y and E=s XOR H_mask(ctx,k). To keep the native key safe, k cannot be a public function of t or a. Try k=H_k(ctx,t,w) from the claw. Honest openings then give a witness-dependent value, whereas Build lacks w and cannot form E for an arbitrary future w. If using only the common claw image a, k is public. If Build instead computes k from hidden s (or independent hidden t'), then the previously explicit source claw returns neither. Giving the native hash a relation-dependent branch would change the native verifier, which is expressly not allowed. A public hash of the claw proof is not a secret-dependent correlation.

The limited claw security argument simulates the actual public view of this proof-only construction simply by drawing t and evaluating H; the certificate output event reduces to an original witness or hash collision. It does not simulate a native secret-bearing capsule: in the public-t native coupling the simulated view already has the native opening, while the hidden-t coupling has no correct public Open. Adding native checking data, sibling capsules, correlated auxiliary input or malicious source retention cannot repair either missing equation. A full QPT reduction must concern arbitrary key recovery or native forgery, not extraction from a volunteered claw; no such reduction was obtained.

## 4. Disposition and next selection

The globally bound claw is a concrete way to complete an ORIGINAL certificate without setup knowing a witness. But the direct native-chain coupling either discloses the native preimage or loses the explicit claw completion. No Build_inc/Open_inc for the cancellation capability, no QPT full-public simulator and no malicious setup proof were constructed. The proposed repair D was not postulated as a primitive; it remains the missing algorithm. Reject this specific construction before coding, and do not repeat it with different hash domains, longer chains or alternate source certificate encodings. No code/test execution, web, external literature or subagents. Authorized continuity reads and static derivation only. No PR comment or notification.

Future attempt should create source-dependent correlation with the *actual native preimage* (or an independent secret genuinely protecting it), rather than transfer merely equality of two public proof-side images. All original OR grounds, actual authenticated source evidence, claim relevance/depth, R316 coverage correction, R225 slot-global versus activation-bound endpoint, one-honest N-of-N preauthorization, pre-funding correctness/DA, and network/inclusion assumptions remain unchanged. This does not support any change in source requirements or claim a generic hash-only impossibility.
