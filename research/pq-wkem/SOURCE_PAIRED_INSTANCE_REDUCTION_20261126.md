# Paired proof-search instances as a source-conditioned bit-release trial — 2026-11-26

Research only; static construction/repair screen, not a qualifying advance.

Continuity: actual syscoin/PVUGC PR #1 open/draft/unmerged, branch research/pq-wkem-validation-20260918, start and prewrite 63c7b425b5640b82d5d839f5f1bdf047bce95d98. Read metadata, latest substantive issue discussion through R225, latest commit filename and exact SOURCE_WHOLE_TRACE_SKETCH_20261126.md (blob 5f78a23e9ddb470d81327392a2542a0969e2071e), and relevant existing global-authentication, proof-collision, CSP, challenge-bucket, DPF and transporter notes. This new path was absent (NOT_FOUND/404). No new Core claim.

## Selection

Missing operation: classical offline Build must serialize a capsule for one frozen native cancellation contribution S, opened by every qualifying ORIGINAL certificate w. Retain the complete bounded R_x(w) with all three independently sufficient original grounds, claim and native binding, authentication, relevance, maturity and window rules. No actual source compiler is asserted here.

Instead of asking distinct witnesses to agree on a proof, trace sketch, hidden label or hash preimage as the SAME decryption key, try a paired *proof-search* mechanism. Each valid original certificate should be able to solve exactly one of two public puzzles per key bit; the bit is the identity of the solvable puzzle, not the proof bytes. Both puzzles may be mathematically TRUE, but only the designated one should be efficiently solvable by the original witness. The proof bytes are allowed to be completely different for every source certificate. This change avoids the proof-string collision requirement and local label splice as the immediate correctness obstruction. The question is whether a hash-only compiler can hide which puzzle contains the original-witness shortcut without requiring the original witness to open an independent setup commitment. This is a candidate for the full release mechanism, not a coding or compression improvement.

## 1. Explicit paired-instance shell

Choose K uniformly in {0,1}^lambda; use E=S XOR ExpandH(ctx,K,|S|). For each bit position j, Build constructs two public instances I_j,0 and I_j,1, with public proof/certificate checking algorithm V(I,z). The desired algorithms are:

    (I_j,0,I_j,1) = PairBuild(x,ctx,j,K_j;rho_j)
    z_i = Translate(I_j,i,x,ctx,w)
    b_j = the unique i for which V(I_j,i,z_i)=1.

Open runs both translations on the complete original w, requires exactly one success per bit, and decrypts E. Polynomial size/time follows if PairBuild and Translate are classical PPT. Pointwise uniqueness and existence for every qualifying w would give exact same K with no proof equality requirement. Crucially, an adversary need not run Translate: any algorithm identifying the selected indices or computing K is in scope. The checking algorithm is not security enforcement by itself.

An unhidden prototype can use independent lambda-bit setup preimages t_j,i and public h_j,i=H("pair-preimage",ctx,j,i,t_j,i). For selected side i=K_j use relation

    J_j,i(u) = [u=(0,w) AND R_x(w)] OR
               [u=(1,t) AND H("pair-preimage",ctx,j,i,t)=h_j,i].

For other side use just the second alternative, padded to the same circuit size if desired. Translate returns a tagged original witness. This is an actual polynomial-time construction and correct for every original witness. Both instances have hash witnesses; thus mathematical satisfiability cannot reveal the selected bit. Nevertheless the public description of J includes the branch selector, so the entire K is read from the capsule without solving either puzzle. Even if a succinct proof of J is used instead of raw certificates, the public predicate still exposes which original branch was enabled. Renaming fields, hiding circuit identifiers without a proof of hiding their semantics, or padding size is not a repair. The nearest CSP color-transport screen already rules out small locally exposed decoding gadgets; do not implement another relabeling fixture.

## 2. Attempt a commitment-hidden selector with public certification

Replace the public branch selector with an independent hiding commitment c_j=H("pair-select",ctx,j,b_j,r_j), r_j uniformly lambda-bit. Publish identical-form instances for both i:

    J_j,i(u) =
       [u=(0,w,r) AND R_x(w) AND H("pair-select",ctx,j,i,r)=c_j]
       OR [u=(1,t) AND H("pair-preimage",ctx,j,i,t)=h_j,i].

Each instance still has a setup preimage witness. Honest Build knows openings to both hash witnesses and the one selector commitment. On the designated side, however, possession of the ORIGINAL w does not furnish r_j. In this exact compiler a translated source-mode certificate must include a selector opening; the correct-side hash-mode certificate must instead solve the independent h puzzle. Merely proving existence of r_j at setup does not provide an algorithm to produce that opening. Granting Build a valid source witness would not fix arbitrary future source access.

For the specified ideal-hash synthetic experiment, fix x and any genuine w independently of r_j,t_j,0,t_j,1, choose those three seeds independently uniform, and expose the commitment and puzzle hashes but no seed-dependent hints. A classical q-query algorithm supplied w hits the actual setup seed in any of the three separated domains with probability at most 3(q+1)/2^lambda (a loose union bound). This follows by coupling each digest to an independently programmed random point and counting distinct guesses until a first hit, including a final guessed opening. A different input producing the same digest is a separate preimage/collision event; a direct q-query random-oracle target-guess term of at most 3(q+1)/2^lambda applies to independent fresh inputs, with finite hash-output length lambda in this illustrative experiment. This is not a QROM theorem, nor a bound for arbitrary correlated selector hints. It identifies why this explicit repair cannot offer even intended raw-certificate completeness. A proof of knowledge generated from the original witness alone cannot be assumed to generate a proof for the stronger statement: that would need a real witness translator or an independently justified extraction analysis. Both J instances being true via setup preimages also makes ordinary soundness insufficient for this purpose.

A second repair would let Build publish one proof of the selected commitment opening. If the public proof statement names i, it exposes the bit. If the statement is instead "exists i,r opening c_j", it is common to both instances. A public proof of that existential statement does not by itself give a publicly usable proof that the commitment opens specifically to i. Substituting the existential proof check for the selector-specific opening admits the source branch on BOTH sides, since the same proof can be copied. A proof that a capsule was constructed correctly has a different role from a witness-dependent transformation that unlocks its secret. This is an exact relation-level correctness issue, not a claim against arbitrary zero knowledge systems.

A third repair drops the selector opening completely and uses only a source proof plus the public selector commitment. Both puzzle instances now admit the identical original witness, or its independently randomized proofs; existence no longer distinguishes sides. To filter outputs, add a public per-bit tag d_j=H("bit-check",ctx,j,b_j). The adversary evaluates both bit candidates and obtains b_j (unless there is a hash collision), without any source proof. Salting d_j with public salt changes nothing; private salt is a new missing opening. A public check of the ENTIRE K could reject wrong combinations, but does not tell an honest opener which of the 2^lambda combinations to choose when both sides independently succeed. No polynomial method for that step is supplied. This is a different failure from matching exact proof bytes.

## 3. Necessary compiler and joint simulation

The pointwise release equation would be an executable PairBuild/Translate with a public proof-search predicate satisfying

    for every R_x(w)=1:
      V(I_j,K_j,Translate(I_j,K_j,w))=1
      V(I_j,1-K_j,Translate(I_j,1-K_j,w))=0,

without an independent opening and without a public syntactic bit test. The second equation alone does not imply security against another translation or arbitrary capsule inspection. The paired instances must be jointly simulatable, not merely separately hard to solve. Publishing both with the original x, native VK/message, E, related capsules, and correlated auxiliary input is the actual distribution. Need arbitrary unauthorized key recovery/accepted native forgery -> ORIGINAL certificate or justified hash/native break; no requirement that attacker outputs a proof or discloses its puzzle-solving method. No such compiler or simulator is constructed. An assumption of a source-triggered proof-search shortcut of this precise strength would merely assume the missing operation.

In particular, do not equate the two instances' mathematical satisfiability (both have independently planted setup preimages) with indistinguishability of their public descriptions or with hard-TRUE security. A simulator for a proof transcript does not simulate the full puzzle instances. A public reduction map that itself exposes which source branch is present also defeats the encryption before proof generation.

Handoff: do not retry with longer selector salts, proof-string matching, larger pair tables, per-bit hashes, or graph relabelings that expose the selected branch. A genuinely new paired-instance compiler must hide the shortcut syntactically AND semantically while transferring every ORIGINAL witness to the designated side without an unrelated setup preimage. The allowed hash foundation and full-public arbitrary QPT security remain unmet. No changes to N-of-N offline setup, endpoint safe native capability, R225 slot-global versus activation-bound scope, or R316 maturity correction. No source verifier, native signature, actual QPT reduction, delegated agent or checker executed. The symbolic screens fail before implementation. No ordinary PR comment. Notification gate not met.
