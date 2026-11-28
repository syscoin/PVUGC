# Commit-first source-stream release preflight — 2026-11-28 UTC

Research only; nonqualifying. Original source predicate and native cancellation endpoint unchanged.

## Continuity and selection

Actual PR #1 syscoin/PVUGC open/draft/unmerged; branch research/pq-wkem-validation-20260918; start b5ccfea771dda22e3286fbfe8c844656d1ee773d. Read PR metadata and recent substantive comments through R225, exact head commit metadata, SOURCE_HIDDEN_CHALLENGE_DECODE_20261128.md (blob b0fa9d551b217840b30171c061f2526ce579a79c) and SOURCE_OR_TRANSCRIPT_TRANSFER_20261127.md at that head. Rechecked unchanged head and path absence (404 NOT_FOUND). No new Core fact was needed.

Missing original operation: source-dependent public computation of the same frozen cancellation capability from every qualifying complete original certificate, with a simulator of the complete published capsule. Try commit-first authenticated read-once access to a canonical witness memory, rather than the independent proof challenge responses of the last attempt. The mathematical change proposed to avoid R289 is that every secret-bearing transition is keyed by the SAME root of the ENTIRE source certificate, its canonical address and the actual opening path; incompatible occurrences cannot authenticate to the same root absent a Merkle binding break. This needs to hold for decryption, not merely in honest evaluation code. Preflight the actual public byte generation and simulator jointly before constructing a verifier or fixtures.

## 1. Candidate and unmodified source semantics

Let x include the complete fixed claim context and all three independently sufficient grounds. A bounded canonical memory representation W of any original certificate w contains the actual authenticated source objects, their lengths, and any auxiliary verification trace needed for evaluating R(x,w). Distinct genuine witnesses may give different W and different root d = MerkleRoot(W). Commit to canonical addresses, types and lengths; do not assume that source commitments already fix d, or that a Merkle inclusion proof at an address proves validity of the entire source history. The verifier still checks all of the original predicate.

Consider a deterministic step verifier reading addresses i (including repeated reads), with a local state q, an input b and a next-state function delta(q,i,b). The prospective construction first represents this as a bounded transition graph of local states. Treat a polynomial-size graph as a hypothesis of this candidate, not as a property established for actual BTC/SYS verification; the full-state graph may be exponential. No alternate relation is accepted. A single coherent root d and a Merkle opening P at i would constrain each read, including repeated reads of the same address.

For clarity, the underlying hash-locked graph encoding would choose independent random lambda-bit labels L_q for state occurrences (layer included) and an ordinary transition ciphertext

    T[q,i,b] = L_delta(q,i,b) XOR H_edge(ctx,L_q,i,b).

The input-state label is public. A genuine Open follows its trace, and a terminal accepting label decrypts the precommitted sigma_cancel. On a fully explicit exact state graph the receiver can also explore all reachable states using these public bytes and labels. This is not a secure general compiler. In the compressed local graph, incompatible read occurrences can be selected, so the underlying ungated ciphertexts must NOT be present in a secure capsule.

Proposed replacement, with separate hash domains and unambiguous lengths:

    L_q(d) = H_root(ctx,d,L_q)
    T[q,i,b;d,P] =
       L_delta(q,i,b)(d) XOR H_edge2(ctx,L_q(d),d,i,b,P)

where P opens address i to b under d. The terminal wrap must also yield the SAME sigma_cancel for all qualifying roots d. Source membership is now an actual input of the transition pad rather than an external if-check, and the starting and terminal labels are root-specific. This is the intended explicit repair of root/occurrence switching; it only works if Build can serialize those bytes or a safe public computation of them before the future source witnesses exist. We examine both attempted generation methods next.

## 2. Public rekey repair

Build knows all base labels but not the future d or P. Attempt to serialize only base transition T[q,i,b] and a public rekey procedure. Given an available L_q and public T, the following equations are executable with no witness:

    L_next = T[q,i,b] XOR H_edge(ctx,L_q,i,b)
    L_q(d) = H_root(ctx,d,L_q)
    L_next(d) = H_root(ctx,d,L_next)
    T'[q,i,b;d,P] =
       L_next(d) XOR H_edge2(ctx,L_q(d),d,i,b,P).

The last equation evaluates for ANY byte string P, whether or not it authenticates b. Inserting VerifyMerkle before the last equation in Open does not protect the already recovered L_next. Public terminal wraps under the base label likewise bypass all membership checks; a root-specific terminal wrap computed by the same public rekey method inherits that bypass. One can keep the correct Merkle root unchanged throughout this computation; forging its opening is unnecessary. Domain separation does not affect the algebra.

For an explicit false local consistency instance, let a single memory bit u have to satisfy u=1 at the first check and u=0 at the second. The ungated graph admits the local trace (1,0). Choose the Merkle root of either canonical one-bit memory and perform both base transitions, then unmask at the terminal. This violates the intended condition without finding any valid consistent memory, and without a collision or a valid opening for the contradictory occurrence. If the root instead commits to separately chosen occurrence bits, both openings may even be valid while the original relation is false: that is not canonical memory binding. This example diagnoses the serialized rekey operation, not a claim that the actual deployed bridge admits a false source trace. It is the known splice in new notation, so no fixture or performance run is warranted.

A public translator given just a root-specific current label, and not a base label or recoverable base transition, might behave differently. But the above hash rekey procedure cannot compute the next rooted label in that orientation. There is no algebraic identity translating H_root(ctx,d,L_next) from H_root(ctx,d,L_q) and an XOR of base labels. Giving the base labels or reversible translation data recreates the preceding bypass. A hidden keyed translator, or a translator assumed to emit a secret next label ONLY on a valid Merkle opening, is the missing source-conditioned computation, not a constructed hash-only primitive.

## 3. Direct ciphertext repair

Remove all base transitions and base terminal wraps from the publication. Try instead publishing the actual T[q,i,b;d,P] values with the exact root and opening path in their mask, plus per-root wraps. Build can compute such a value for a particular known d,P because it knows the base labels. It cannot enumerate all qualifying future source memories by assumption, and no witness-independent polynomial list of their root/opening pairs was constructed. Source d is not one fixed challenge-independent input to the original statement. In particular, future competing histories can change the canonical memory; treating a known baseline as the entire future witness would drop completeness for original branches.

More generally, even if a procedure can compute d and P from w, Build has no w. In an ideal hash model, hashing (L_q(d),d,i,b,P) at a new unpredictable path-dependent input has no public relationship to the pad for a different path. Correct direct ciphertext bytes for each such input require either the corresponding pad and next label at setup, or a separately constructed compact correlated evaluation operation. A polynomial setup's finite hash query list does not implement the latter. This observation only rejects the direct explicit table and the public rekey method; it is not a black-box lower bound for arbitrary hash constructions or a QROM extraction theorem. Do not program an honest public oracle to make these equations hold. Do not treat a proof of verification of P as a computation of the missing ciphertext.

Another repair is to place d, its verification state, and all path-dependent consistency data INSIDE the exact transition state and generate a table over all such states. Then distinct roots do not share transition labels; with an exact transition graph, reachability corresponds to a coherent accepted input, and the direct splice is absent. But explicit labels for all lambda-bit digest states alone already allow exponentially many states, absent an independent compression theorem. This is the already-rejected full-state graph direction. Dropping root/path state to obtain a small table, with only an honest verification step when evaluating it, restores the same problem. No new complete-state fixture or independent-label theorem is proposed.

## 4. Security and next equation

A simulator would have to generate root/path-correlated secret-bearing transition bytes and terminal wraps with the same joint distribution as actual Build, given x, native VK/message, auxiliary data, sibling capsules and source commitments. It is not sufficient to simulate the unmasked base graph, a single preselected root, or the distribution of labels at an isolated gate. The public rekey repair fails before any QPT proof; the direct repair has no practical Build. No hard-TRUE extraction from arbitrary recovery, FALSE security, same-message forgery proof, or malicious-setup correctness/DA is established.

Do not continue by varying the Merkle tree, hash domains, digest width or number of local checks. Next selection must supply an actual public byte generator for the secret-bearing transition or terminal release with authenticated, future-root-dependent evidence, without exposing an ungated precursor from which the same capability can be recovered. Prefer a different construction if that generator cannot be supplied. This remains a source-conditioned encryption operation; do not label it a standard Merkle primitive. No code or tests run: static preflight detects the known attack before implementing the compressed variant, and the direct variant lacks a PPT Build.

Preserve all original claim binding, all three OR grounds, R316 maturity/coverage correction, R225 explicit slot-global or truly activation-bound native endpoint, one-honest setup versus public challenge distinction, and all source/DA/network constraints. No external web/literature, agents, new source facts, production changes, or ordinary PR comment.
