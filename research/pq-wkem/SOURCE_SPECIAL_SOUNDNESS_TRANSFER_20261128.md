# Fixed-transcript source transfer preflight (2026-11-28)

Research-only intermediate handoff; no qualifying advance.

## Selection and provenance

PR #1 in syscoin/PVUGC was read as open, draft, unmerged, on research/pq-wkem-validation-20260918 at 9365515664fa84708f8886e5a08366d29ba56c75. Read recent substantive comments through R225 and the exact head note SOURCE_PAIRED_TREE_CORRECTION_20261128.md, blob b45d80c6d8beddbe610e6201f2d0a1220ce86ce5. Rechecked PR metadata at that head; new note path absent (404). No new consensus claims, external research, agents or executed cryptographic tests.

Missing operation: a future ORIGINAL source witness must change a public capsule into a fixed native cancellation contribution, without setup knowing that witness. Instead of public intermediate labels, private coefficients, or paired terminal seeds, this iteration tries to use a globally binding first message of a hash-based proof and its special-soundness extraction algorithm as the release mechanism. This is a different mathematical change: one complete challenge-response transcript is the unit of transfer, not separately reusable per-wire labels. R289's independently selectable label-splice interface would not be present if the complete transcript were sufficient. Test the actual public response-generation equation before any implementation. All three original grounds remain in V_x; no simplified source is adopted.

## 1. Candidate: extract the frozen secret by changing the challenge

Let S=V_x be the unchanged original relation and P(y,k) a relation for a secret k which the builder samples, with a public commitment y (e.g. y=H(ctx,k)). Encrypt the frozen contribution as E=sigma XOR KDF(ctx,k). Try to use a public two-challenge proof of knowledge for P. Write (a,e,z) for a first message, challenge bit and response, with public Check_P and a special-soundness extractor Ext_P such that two accepting transcripts with the identical a and challenges 0,1 yield a preimage k' satisfying P(y,k'). For use in a KEM we additionally need k'=k except negligible probability; collision resistance could support this if P is a full binding hash commitment and extraction is actually implemented.

Setup samples k, generates a real transcript (a,0,z0), and publishes it, together with E and a source-dependent transfer object U. Open should use a full original witness w to calculate z1=Transfer(U,a,z0,w). The native contribution would then follow from Ext_P(a,0,z0,1,z1). This is an actual candidate release architecture, not a proposed security proof. It avoids requiring an adversarial query log in the *honest* extraction operation. But the key missing operation is the serialization and evaluation of Transfer, and the argument for arbitrary QPT recovery (which need not produce z1) is separate.

An ordinary proof of knowledge alone is not the transfer mechanism: it requires a prover for P, whose secret is precisely k. Need a public conversion from a prover for S, whose witness is w, into the second fixed-a response for P. Test whether ordinary OR composition or hash commitments supply it.

## 2. Explicit OR challenge switching

Assume provisionally a pair of classical binary-challenge special-sound proofs, including simulated transcripts for individually chosen challenges, for S and P. This is a conditional algebraic preflight; no QROM Fiat-Shamir or proof-of-knowledge theorem is assumed. With total challenge e, the OR transcript has

    e_S XOR e_P = e
    Check_S(x,a_S,e_S,z_S) = 1
    Check_P(y,a_P,e_P,z_P) = 1.

Setup knows k and can choose a simulated source transcript for e_S=0 and a real secret transcript for e_P=e. Freeze a_S, a_P and both existing responses. Two possible switches:

* Hold e fixed and change e_S to 1. Then e_P must become e XOR 1. Even supposing a real source witness allows an alternate response z'_S for the *same* a_S, the construction still needs z'_P for the *same* a_P and the other challenge. Computing z'_P is the secret-dependent operation, not a consequence of the OR check.
* Change total e to e XOR 1, leaving e_P unchanged and changing e_S to 1. Even supposing the source response can be made, the pair gives special-soundness extraction on S, not P. It supplies an original source witness (possibly different from the input), but no second P response and no cancellation pad.

If setup simply publishes both P responses, anyone can run Ext_P without source evidence. If it publishes one response masked by a function of the alternate S response, that function must give a fixed mask to every qualifying source witness. There is no such common mask in the OR transcript algebra. Thus ordinary OR proof composition does not implement Transfer, even if source response switching were magically available. It does not matter whether e is a public random bit or a hash of a public transcript. A hash-derived challenge does not manufacture the missing secret response.

## 3. Try to implement the source switch with hash-committed MPC views

The relevant hash-only candidate is a commit-and-open proof with a first message a_S=(c_i) for polynomially many view commitments c_i=H(ctx,i,r_i,v_i). The complete byte encoding includes lengths and domain separation. A response for challenge b opens the required subset I_b of committed views and verifies consistency. Assume for this preflight that the union of the two challenge subsets supplies the complete view tuple from which the source witness is reconstructed; real multi-challenge proof systems need the corresponding extraction collection rather than only two challenges.

The tempting step is to take a simulated transcript from Build, and let any genuine w regenerate all the newly requested views of the same first message. For the concrete proposed implementation where Build creates each c_i by sampling actual opening bytes (r_i,v_i), define

    C_i = H(ctx,i,Encode(r_i,v_i))
    O_i(w) = (r'_i(w),v'_i(w)).
    
If H(ctx,i,Encode(O_i(w)))=C_i, then either O_i(w) is byte-identical to the builder's original input, or those two explicit inputs give a collision. This is an efficient straight-line collision test using known Build coins and a supplied honest witness, not a claim about extraction from an arbitrary QPT adversary. For any polynomial collection of successful honestly generated switches with available witnesses, the same test applies to every opened slot. If collision resistance holds and all views in the extraction collection were committed this way, the reconstruction from those full views is fixed by Build's already sampled view tuple. It cannot provide distinct witness-specific view tuples for arbitrary w without new openings. This observation does NOT require the extractor to return the identical witness supplied to Open, nor does it establish a general impossibility for extracting some common original witness. It limits this specific proposed method of generating switched proof views by re-sharing an arbitrary witness into a frozen hash-committed tuple.

If Build instead simulates a transcript using random digests with no known preimages for unopened views, the above collision test does not cover these slots. But then the proposed public evaluator must explicitly find preimages of those digests encoding consistent missing views from arbitrary future original w. Hash commitments do not implement that operation. A simulator that programs an ideal oracle at new inputs after seeing w is not an honest classical Build/Open using a fixed concrete SHA function. A proof reduction may program its ideal oracle under justified conditions; honest Open cannot do so.

Allowing the source prover to choose a fresh first message avoids the frozen-commitment problem. However, now it produces an ordinary source proof rather than a second response at the precommitted P first message. The two-transcript extraction above no longer supplies k. Publicly verifying that fresh source proof before exposing a P response is only a software if-check unless the proof-dependent response is cryptographically generated by the capsule.

## 4. Decision and next candidate selection

Do not implement or scale this commit-and-open switch. It fails at a concrete honest algorithm step before the joint simulator: the OR split changes a challenge but cannot generate its secret-branch response; ordinary frozen hash-committed view tuples also do not permit the proposed arbitrary-witness re-sharing. This differs from the previous paired-tree terminal-difference preflight, and neither ordinary hash proof verification nor special soundness establishes the missing source correlation.

For this direction the exact next equation would have to be

    (a,z0,U) <- TransferBuild(x,y,k;rho)
    z1 <- TransferOpen(U,w)
    Check_P(y,a,1,z1)=1, Ext_P(a,0,z0,1,z1)=k
      for every V_x(w)=1.

A future construction must give a concrete non-group/non-lattice serialized U with a *new* source-to-response conversion that avoids the frozen-commitment and OR-switch issues, not assume a trapdoor source-dependent equivocal hash commitment or assume TransferOpen as an ideal primitive. Alternatively abandon fixed-transcript transfer. No reason to spend another run changing the number of MPC views, the challenge length, or the Fiat-Shamir hash.

Even if the equation is met, the security goal is full-public FALSE and hard-TRUE recovery/accepted native forgery security, not merely special soundness for explicitly supplied responses. Arbitrary QPT adversaries see E,y,a,z0,U, native VK/message, original source commitments, auxiliary input and sibling capsules, and need not provide a second response or a representation. Same-message native forgery, malicious setup, all-witness completeness for each of the three original grounds, and the frozen graph/activation scope remain outstanding. No generic NP claim, no change to source rules, no positive WKEM claim, no ordinary PR comment.
