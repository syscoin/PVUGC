# Offline MPC output reconstruction as an original-source conversion — 2026-11-26

Research-only construction screen; no qualifying missing-advance result.

Continuity: syscoin/PVUGC PR #1 open/draft/unmerged; actual branch research/pq-wkem-validation-20260918; start and prewrite head 220602a72eb9eba46fd0e5ba9f6e11a4f7c5123a. Read actual metadata and latest five returned substantive comments through R225; exact SOURCE_CONJUGATED_TRANSITION_LIFT_20261126.md (blob 6693e66ef9590d061f1c693c0cdc26b098352ec0), SOURCE_SPECIAL_SOUNDNESS_RESPONSE_20261126.md and SOURCE_PAIRED_INSTANCE_REDUCTION_20261126.md. New path absent at prewrite head (NOT_FOUND/404). No new Core claim.

## Selection before implementation

Missing operation: offline Build(x,S) serializes data from which EVERY complete qualifying future ORIGINAL w recovers the SAME fixed native cancellation contribution S; arbitrary full-public recovery and accepted forgery must imply original evidence or independently justified break. Write b=R_x(w) for the full bounded relation, all three independently sufficient original grounds with actual authentication, maturity, relevance, claim, window and native binding. No new source compiler is asserted.

Try offline MPC multiplication preprocessing as an output-side conversion, rather than another private-coefficient SOURCE evaluator, independent wire labels or a hidden global-state transition function. The change is to combine a single complete source computation with a globally correlated reconstruction transcript for the native value. A valid trace would furnish the public masked acceptance opening; the native data would remain in offline correlated shares. This is intended to avoid the R289 local-label splice at the release interface, since there is only one complete source acceptance output and a global native response, not separately selectable per-occurrence source labels. Check whether the offline response itself leaks, and whether the masked acceptance opening can actually be derived from original evidence without an online party. Do not grant an ideal secret evaluator.

## 1. Actual offline preprocessing trial

Use a finite field F; initially take F_2 and a vector native contribution S, with scalar multiplication componentwise. For the large-field repair below use a single field element encoding the whole frozen capability injectively. All arithmetic here is only on the output reconstruction, not an assumption that the original SHA/source verifier is algebraically linear.

Build samples a scalar a and native-length mask c independently; forms the Beaver product d=a*c and public v=S-c. A conventional live multiplication of b by S opens u=b-a and v. Reconstruction is

    b*S = d + u*c + a*v + u*v
        = T_u + u*v,
    T_u = a*S + u*c.

The identity holds over any field by expanding b=a+u and S=c+v. An opener with an authentic u for b=1 would recover the exact S, irrespective of which original witness was supplied. The b=0 branch would produce zero if the correct u and response were used. The point of the trial is to remove the live hidden party that normally supplies T_u and the masked input opening.

First attempt: publish both offline responses T_0,T_1 for the binary field, with v. Then T_1-T_0=c and S=v+c, regardless of a and b, including FALSE x. The attacker needs no source or MPC transcript. Even perfectly consistent original proofs, an independently secure MPC protocol with live private parties, and perfect binding commitments do not fix this public data distribution. The attack neither splices local labels nor recovers a private source coefficient.

Second attempt: publish only the response corresponding to the accepting masked input u*=1-a, withholding its index. This preserves pointwise correctness if an honest source holder can compute u*. In F_2, the adversary guesses both possibilities and obtains candidates T and T+v. One equals S. An accepted native candidate suffices for the forgery objective; an exact native-capability recovery experiment can at least select the correct candidate with probability >=1/2 even without a check. Thus the binary reconstruction itself is insecure even if the full-source masked bit evaluator is granted as an ideal operation. Publishing a hash commitment to the masked bit with public opening material does not help; leaving the opening material secret would be another unresolved operation.

Do not implement the binary forms, including repetitions with independently checked binary native pieces. The nearest attack here is on the entire final MPC reconstruction data, not a proposed change to R327's SOURCE polynomial.

## 2. Explicit repair of the output transcript (not of source release)

Replace the scalar bit mask by a uniform element a in a large finite field F of order Q, and encode S as one element. Use e=1-a. Sample v uniformly in F minus {0} and set c=S-v (equivalently resample c until v!=0). Compute the one accepting response T=T_e=S-e*v. Publish exactly (v,T), without e, a, c or d. The exact public algorithms at this layer are

    Prep(S): v <- F*, e <- F; T := S-e*v; return ((v,T), e).
    Recover(v,T,e): return T+e*v.

This is a classical polynomial computation using a binary extension field of sufficiently large degree with publicly specified irreducible polynomial, injective S encoding and standard field operations; no concrete parameter selection or implementation asserted. If S is long, this screen can use a field of degree at least the encoded bit length rather than silently rely on a single scalar to conceal many independent field elements.

Correctness for e is exact. For every fixed S and nonzero v, multiplication by v is bijective, so T is uniform on F for uniform e. A simulator that knows only the public native context (including native checking data) samples v uniformly nonzero and T independently uniformly; for the isolated Prep transcript this is EXACT even conditional on S and arbitrary auxiliary data fixed before the independent v,e. For independently randomized isolated sibling Prep transcripts the same equality holds jointly conditional on their possibly correlated S values and pre-existing public context. This is an elementary distribution identity, not a concrete SHA/QPT source proof. It does not include the required source conversion data. Opening e from the same Prep is not auxiliary independent of the simulator's hidden variables; selective release of a sibling sharing its native S reveals that S and must be modeled as authorized release, not claimed hidden.

The important remaining equation is masked acceptance e=1-a for EVERY authentic original witness. A public verifier returns b but does not have a. Giving a, or e, to the public immediately reveals S. Computing u from b by ordinary public code with a embedded exposes a even if the code is carefully padded. Publishing a proof that T is the correct response to some hidden e does not provide e to a source witness. A proof that b=1 followed by an ordinary public reconstruction program is not cryptographic enforcement.

More precisely for each fixed public transcript (v,T) the mapping e <-> S is a public bijection:

    e=(S-T)/v; S=T+e*v.

Consequently any serialized source conversion D enabling e on every w is also a direct source-dependent release capsule for S, with the same arbitrary hard-TRUE and FALSE recovery problem. Conversely any release of S yields e. A simulator of (v,T) alone cannot generate the jointly correlated D without proving precisely the missing security property. Unlike the binary transcript attack, increasing the masked output entropy does fix this isolated leakage, but does NOT supply the original-source mechanism. A known attack on a source evaluator cannot be evaded by wrapping it in this invertible output transformation.

## 3. Attempted source-controlled masked opening with offline MPC authentication

In an ordinary authenticated MPC, each party holds secret correlated authentication information, and masked input openings can be verified by a live party or jointly with hidden shares. Try replacing the live parties by a public hash commitment h=H("mpc-opening",ctx,e,r) to the masked input e, with independent salt r. Preprocessing is still PPT and can generate this exact commitment, since Build knows e. The intended public opening would be (w,e,r), checked by R_x(w) and by h. But w alone provides neither e nor r; a proof of knowledge of w cannot also be treated as an opening of the independent h. Publishing e,r lets everyone recover S directly; publishing a zero-knowledge proof of existence of e,r leaves honest original holders without Recover's required field element. These are rejected before implementation, not treated as a new construction. Publishing a separate source-dependent hint for e would be a genuine candidate only if that hint has an executable original-source conversion and joint simulator, not merely an authenticated MPC claim. A hidden-key or private online party providing the masked opening is disallowed.

One can derive a instead as H("mpc-mask",ctx,w) to make the honest masked input computable. But Prep's single T was constructed with a fixed independent mask before future w. For two eligible witnesses whose masks differ, using their respective masked input values in the same reconstruction yields different S candidates because v!=0. Requiring a common hidden mask across all original witnesses is the missing source-conditioned operation, not a property of independent hashes. The repair must not reduce the original relation to one canonical witness. No new tag, parent, or maturity assumption is introduced to force such equality.

## 4. Handoff

Offline MPC can provide isolated perfectly simulated high-entropy native output preprocessing, but it cannot on its own transform a public original-source decision into the necessary hidden masked opening. For this exact trial the next equation is a serialized public SourceMask(D,w)=e on the complete R_x, where D and (v,T) must be jointly secure. Since the invertible mapping above makes this equation equivalent to the original release, merely inserting the preprocessing in another source candidate is not progress. Do not rerun with more field elements, different arithmetic, independent Beaver triples, different authentication hash placement or another proof-only wrapper. A different construction would need a nontrivial coupling between source verification and the offline hidden opening, not a conventional live MPC privacy theorem or an implicit private evaluator.

No original source compiler, native signature/checking-key security proof, arbitrary hard-TRUE extraction, joint source conversion simulation, malicious setup or endpoint implemented. R225 endpoint scope and R316 maturity correction unchanged. No external literature, new Core inspection, local checker, delegated agents or ordinary PR comment. Static mathematical screen only; no tests claimed. Notification gate not met.
