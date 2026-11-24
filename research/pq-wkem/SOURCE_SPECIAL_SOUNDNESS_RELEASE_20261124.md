# 2026-11-24 — source-driven special-soundness release screen (NONQUALIFYING)

## Continuity and candidate selection

Actual syscoin/PVUGC PR #1: open, draft, unmerged; branch research/pq-wkem-validation-20260918; start e42f5d1f91ea9f43fb605fe58be8b05367e848eb. Read actual PR metadata, recent substantive comments through R225, head commit filename and exact-head SOURCE_LEDGER_LINEAR_CAPABILITY_20261124.md (blob c943e385448bee285fd2d5623e301ab83079bd91). The preceding screen rejected local consume-once authority, not stateless cryptographic source consistency. No web, literature, whole PR diff, or new Core version claim.

Missing operation: before future ORIGINAL evidence exists, compile a public capsule releasing the same exact frozen safe native cancellation capability for every qualifying original witness, without release on fabricated or unauthorized evidence. Mathematical change from R289 and R327: use two-transcript special-soundness extraction on a FIXED native-signature knowledge statement instead of transferable intermediate labels or hidden polynomial coefficients. A successful opening would construct a new response at the same first message and a distinct challenge; splicing accepted responses from unrelated first messages would not meet the extraction premise. Investigate whether ordinary hash-only simulated transcripts and OR challenge rebalancing supply the required source-driven response translator. The translator must work for arbitrary qualifying original witnesses, not setup proof randomness. Do not assume it exists.

## Candidate serialized interface

R(x,w) is the unchanged original OR relation. Let s be the exact canonical serialization of the safe native signature. N(y,s) checks native VK/message and H(domain,ctx,s)=d for binding digest d, included in y with the native context. This is an experimental proof relation, not an opening algorithm. Conditional on collision resistance and canonical parsing, an extracted N witness would give the exact s instead of merely some accepted signature. Grant an abstract classical proof protocol with first message a, challenge e in a finite additive challenge space E, response z, verifier V and special-soundness Ext:

    V(y,a,e0,z0)=V(y,a,e1,z1)=1 and e0 != e1
      => N(y,Ext(y,a,e0,z0,e1,z1))=1.

Build knowing s generates (a_N,e_N0,z_N0) and publishes C containing this transcript, x,y and translation material D. Open(C,w) must compute z_N1 under a distinct e_N1 at the SAME a_N, and return Ext_N. The source must control response generation cryptographically, not via a verifier-only check after recovery. Ext uses explicit public inputs, not adversary internals; nevertheless a full-public proof must also cover unauthorized recovery of s directly or accepted native forgery without any second transcript. Ordinary special soundness alone does not do that. No concrete QPT proof or QROM theorem assumed.

## Attempted compiler: OR proof rebalancing

For protocols for R and N with shared additive challenge space, let e_R+e_N=e. The standard classical OR transcript generator for Build knowing N but not a future w is:

    (a_R,e_R0,z_R0) <- Sim_R(x; chosen e_R0)
    (a_N,r_N) <- First_N(y,s)
    e_N0 := e0-e_R0
    z_N0 := Respond_N(y,s,r_N,e_N0).

Publish a_R,a_N,e0,e_R0,e_N0,z_R0,z_N0. A holder of w can run First_R and Respond_R on fresh coins, and can choose its R challenge in public evaluation. The proposed translator adjusts branch challenges to induce a new native response at fixed a_N. Exhaust the two possibilities:

* Preserve e_N0: reuse z_N0 and set e_R1=e1-e_N0. Even granting an accepting R response for old a_R, both N challenges are identical and Ext_N is inapplicable. If a_R changes, the global first messages differ as well.
* Change e_N1: adjusting e_R1=e1-e_N1 imposes a scalar challenge equation but produces no valid z_N1 for fixed a_N. Respond_N still needs s,r_N or a newly constructed translator. Running Sim_N at e_N1 ordinarily samples a new a_N'; it does not target the old a_N. For high-entropy commitments, rejection sampling is not classical PPT.

If D publishes the second native response or encodes it with a pad derived from the public simulated R transcript, any outsider can perform Ext_N without evidence. This is an explicit full-public attack on that repair. Fiat-Shamir choosing the global challenge does not change the two cases. The OR extractor itself could return w, not s, so its special soundness is insufficient. Ordinary OR simulation does give a compact transcript generator, but no original-source response translation.

## Attempted repair: shared challenge and response-masked transcript

Force both branches to use the same challenge, and have Build compute z_N0,z_N1 with its native randomness. Publish B=z_N1 XOR G(ctx,a_R,e1,z_R1), hoping only a qualifying original witness can obtain z_R1. There are three concrete setup choices.

1. Build simulates R at e1 and publishes a_R,e1,z_R1. Anyone opens B, computes Ext_N, and recovers s.
2. Build simulates R at e1 but withholds z_R1. Open must recover the simulator's exact response or a response with the same pad, not merely produce an accepting proof with w. Ordinary completeness supplies responses to commitments generated with one's own coins, not openings of an arbitrary simulated first message. Even distinct accepted responses at the same challenge need not yield identical pads. Publishing simulator coins makes the pad public; retaining an online secret violates offline release.
3. Build simulates R at e0 and publishes z_R0, hoping the witness holder responds at e1 for fixed a_R. Build does not know z_R1 to encrypt under its hash. Any pad derived solely from z_R0/public data is public. A new response-key projection algorithm is needed. Given a valid new response, Ext_R would yield an original witness under its special-soundness premise, not the pad precomputed by Build.

For hash commitments to simulated proof views, the committed bytes are bound to views chosen by the simulator. Knowing w permits generating new views but does not generally provide openings of those particular commitments. Hash binding supplies no universal translation property. This does not exclude new source-conditioned equivocation/projection mechanisms.

Remaining equation: actual serialized classical-PPT source-driven fixed-commitment response projection. Build knowing s but not w generates D and C; any qualifying original w computes a new N response at fixed a_N under a challenge distinct from e_N0. A joint simulator must cover C,D, checking/native keys, context, source commitments, auxiliary dependencies, sibling capsules/selective openings. Hard-TRUE direct recovery or native forgery must reduce to an actual qualifying ORIGINAL certificate or independent justified QPT hash/native break. No such algorithm or reduction obtained. Do not assume a primitive that grants the desired native response projection; larger challenge spaces or further fixture tests do not supply it.

## Status

Analytical construction/repair screen only. No checker executed because the ordinary interfaces do not supply the required operation even symbolically. No native signature generation, consensus execution, QPT lifting of classical extraction or concrete SHA programming claim. The explicit public attacks are on the stated repairs, not a general impossibility of proof-based/hash-only release. Avoid another OR challenge rebalancing/hash-placement variant; investigate a genuinely new source-dependent correlation instead.

Preserve all three grounds: same-anchor greater exact BTC work, finite authenticated specific burn refutation, relevant mature SYS inconsistency/tag fault without picking a winning SYS fork. Keep independent carrier authentication for malformed tags, R316 as coverage regression, actual ancestor comparison at h_rel, full claim/window/native/capsule binding, one honest N-of-N setup and useful capsule completeness before funding, erased/protected secrets, QPT auxiliary/related capsules/selective openings, exact signature vs accepted forgery, R225 slot-global veto or genuinely activation-bound native message, DA and timely inclusion. No source-version or deployment assertion. NONQUALIFYING; no ordinary PR comment or notification.
