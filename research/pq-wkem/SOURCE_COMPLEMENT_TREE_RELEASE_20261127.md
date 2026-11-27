# Complement-subtree reconstruction of a full source trace — 2026-11-27 UTC

Research only; nonqualifying construction/repair iteration.

Continuity: syscoin/PVUGC PR #1 open/draft/unmerged, actual branch research/pq-wkem-validation-20260918, start and prewrite head 272019aef9eda66d31188b9d94d3c715af6e8cb7. Read actual metadata and latest returned substantive comments through R225, latest commit filename and exact SOURCE_QUERY_RENDEZVOUS_20261127.md (blob cbcbc746b08e06973d20e4389fda15ee8e304aa1), SOURCE_NATIVE_PATH_EMBEDDING_20261127.md, SOURCE_CONJUGATED_TRANSITION_LIFT_20261126.md, SOURCE_OFFLINE_MPC_RECONSTRUCTION_20261126.md, SOURCE_SPECIAL_SOUNDNESS_RESPONSE_20261126.md, SOURCE_PAIRED_INSTANCE_REDUCTION_20261126.md and SOURCE_FEASIBLE_STATE_MIGRATION_20261126.md. New path returned NOT_FOUND / HTTP 404 at the prewrite head. No new Core source claim.

## Selection before implementation

Missing operation: offline classical PPT Build(x,S) must create one public capsule from which EVERY complete qualifying ORIGINAL certificate w obtains the identical frozen native cancellation contribution S, while arbitrary full-public recovery and accepted forgery are secure on FALSE and unauthorized hard-TRUE statements. R_x denotes the complete bounded original relation: all three independently sufficient BTC greater-work, finite authenticated burn-refutation, and Syscoin history/tag grounds, with actual contextual authentication, relevance, maturity, claim/window and native binding. This notation is not a new source compiler.

Try complement-subtree reconstruction instead of the previous sender/receiver query intersection. The mathematical change is to have each original witness reconstruct the payload using a cover of the *other* leaves of its deterministic computation tree. No setup addresses need to coincide with a verifier's hash-query addresses, and the receiver's reconstructed share is obtained by a capsule-dependent tree computation. A full trace chooses a single path; there is no independent choice of garbled occurrence labels. Investigate whether the determinism of the original verifier suffices to make all complementary subtrees publicly evaluable without making the accepting leaf public. Do not grant secret evaluation of tree labels or a witness-dependent aggregate as a primitive.

## 1. Exact complement identity and proposed algorithms

Fix n witness-input bits and a deterministic bounded Boolean verifier with m additional trace bits in topological order (including its computed acceptance bit). Every input w has one consistent trace z(w). The pair (w,z) qualifies iff all gate constraints hold and the acceptance bit is 1. This is a representation of the full verifier, not a substitute for source admission. No claim that n or m is small or that the actual source verifier has a special tree structure.

For each w consider the depth-m binary tree of possible computation traces. Assign a fixed-length value L(w,z) to every leaf; define A(w,p) as the XOR of all leaf values extending prefix p. For a full trace z=z_1...z_m and empty prefix e, the disjoint decomposition of all other leaves into its sibling subtrees gives

    L(w,z) = A(w,e) XOR XOR_{i=1..m} A(w,z_1...z_{i-1}(1-z_i)).

This identity holds for arbitrary leaf values, since recursively A(w,p)=A(w,p0) XOR A(w,p1). It is a constructive m-step reconstruction, not a sum over exponentially many leaves at Open time, IF the required subtree values have actual efficient access algorithms. The proposed Build would publish root aggregate access plus protected access to aggregates of wrong-branch subtrees. The opener computes z(w) with the full original evidence, requests each complementary aggregate at its actual prefix, and obtains L(w,z(w)). Require L(w,z(w))=S for every accepted w; rejected leaves should not reveal S. A check of the computed acceptance bit is only honest-code behavior and earns no security.

The important structural fact: for each fixed input w, the sibling at the first incorrect deterministic gate is inconsistent for EVERY continuation of that prefix. A proof that one arbitrary trace extending a prefix is invalid would NOT prove this universal statement. In contrast to an unconstrained split-mask splice, the exact path z(w) supplies local first-error information that certifies all these particular sibling subtrees as inconsistent. This is why try the complement rather than the accepting trace's wire labels. The construction still has to cryptographically enforce the actual aggregate values and their joint correlation with S.

In the naive explicit algorithm Build would fill all leaves, aggregate bottom-up, and publish the required sibling values and roots. This is exponential in n+m and is not an algorithm satisfying the practical target. Moreover, a single global tree over w||z instead of a separate computation tree for each w would not preserve the cover argument: siblings diverging in a w bit can contain other valid original witnesses. Multiple accepting witnesses are allowed, not a unique witness assumption.

## 2. Attempt a compact sum-preserving hash tree

To avoid explicitly summing an exponential number of leaves, first consider a binary tree where each node value a_p is both its expansion seed and its subtree aggregate. Define, for an injectively encoded context/address and domain-separated hash expansion,

    a_{p0} = ExpandH("complement-left",ctx,w,p,a_p,ell)
    a_{p1} = a_p XOR a_{p0}.

Every child sum equals its parent, so by induction every node is exactly the aggregate of all its descendant leaves. This is an actual polynomial per-path evaluation algorithm. If Build exposes a root a_e for efficient reconstruction, however, every descendant (not merely an inconsistent sibling) is publicly computable. A constrained root expansion is not implemented just by a source-verifier check. Also an independently initialized tree does not program its unique consistent leaf to S across w. No reason to implement this version, even if a perfectly collision-resistant hash is granted.

Explicit repair: separate the aggregate a_p from a secret expansion key k_p. Let

    k_{pb} = ExpandH("complement-key",ctx,w,p,b,k_p,lambda)
    t_p    = ExpandH("complement-share",ctx,w,p,k_p,ell)
    a_{p0} = t_p
    a_{p1} = a_p XOR t_p.

Publish only an aggregate, NOT its key, at a public root. Root exposure no longer provides a syntactic input to the expansion algorithm. This is a genuine change to the direct seed-exposure attack. Split equality and all subtree identities hold exactly regardless of hash outputs. With hidden keys these are well-defined polynomial algorithms for generating any selected subtree value from the root key and root aggregate, and all reconstruction equations hold for a party possessing the relevant values. No claim that the concrete hash is a proven PRF or that this distribution already gives joint QROM security.

Try giving a wrong-subtree expansion key as a prefix-constrained key. This may allow evaluating descendants of that node; it does not alone give the subtree aggregate a_p, which also depends on shares on the path above the node. Giving the pair (a_p,k_p) allows expansion of that subtree, but Build must deliver the pair for each necessary wrong prefix without supplying the root key or leaking the accepting leaf. A single pair for a common prefix across different witnesses covers all its descendants, including any consistent accepting leaf if one exists there. A pair at a wrong-gate prefix *after fixing w* covers only that particular input and prefix. In the standard explicit prefix-key mechanism, each such nonempty subtree has a distinct address including w; giving keys at their common ancestor before the w bits are fixed does not enforce the claimed constraint. Thus the tree construction alone supplies no polynomial-size compilation of the wrong-subtree access rules. This is not a lower bound against arbitrary constrained PRFs, and no count of real source witnesses is assumed.

The repair also leaves an independent issue: with a fixed root aggregate and independently expanded secret keys, a selected leaf is the corresponding pseudorandom share, not S. For fixed (w,z) with at least one split, its final value includes a fresh mask at its last parent. For a left child it is precisely that mask; for a right child it is the parent aggregate XOR that mask. In the ideal hash experiment with distinct previously unqueried mask-domain inputs along the path, fixing the root aggregate and key generation first, the last mask is uniform and independent of the earlier masks. In particular, an independent S equals the selected leaf with probability 2^-ell, not pointwise every-witness correctness. This is a restricted distribution statement about this exact independent construction. It is not a QPT result or a claim about concrete SHA.

## 3. Try programming the unique consistent leaf without knowing a witness

A useful feature of the deterministic per-w computation tree is that Build need not enumerate its entire 2^m leaves if it knows w: the unique consistent path is computable directly, and a single correction at its final parent suffices.

For a fixed known w, use the repaired split construction to produce the root and all keys on z(w). Let l be the current aggregate of its consistent leaf. If R_x(w)=1, take delta=S XOR l. At the final parent replace BOTH child aggregates by their previous value XOR delta. The parent sum is unchanged, all ancestors remain valid, and the consistent leaf becomes S exactly. Equivalently replace the one final split mask t_p by t_p XOR delta, with unchanged parent aggregate. The opposite leaf is inconsistent with the deterministic gate and absorbs the correction. If R_x(w)=0 no correction is needed for that w. This is actual finite-time leaf programming for a chosen known input, with no source-independent puzzle or forced common witness. It preserves the complement identity. It is not useful to the original target by itself because setup doesn't know future w.

Now try a *single* universal correction rather than per-w programming: publish a common delta and use it at every final parent of a consistent accepting path. This cannot establish the required leaf equation unless all uncorrected accepting leaves are already equal. In the stated independent ideal-hash experiment, two distinct accepted w have different domain-encoded last-parent addresses, and their last masks are independent even conditional on earlier masks and key generation. Hence their uncorrected leaf equality has probability 2^-ell. The shared correction cancels in their difference. Making delta a public function of the exact path can accommodate distinct leaves algebraically, but the required equation is then

    delta(C,w) = S XOR L_original(C,w,z(w)),

where the correction evaluator must be a serialized algorithm that protects S without relying on the public R_x check. Giving the expansion key lets an arbitrary party compute the uncorrected shares; giving a native-secret-containing evaluator as ordinary source code reveals its embedded secret; giving a separate ciphertext for each accepting input returns to witness enumeration. These are rejected forms, not evidence that an arbitrary capsule-dependent function delta is impossible.

There is a second, reverse programming idea: declare the accepting leaf S from the start, assign wrong-subtree shares by independent public hash expansions, and compute the root upward using only m sibling shares. For any qualifying w this is polynomial time if S is known, and the siblings can even be entirely different across w. But the root access requirement now reads

    A(C,w,e) = S XOR XOR_{i=1..m} A(C,w,z_{<i}(1-z_i)).

The left side must be efficiently computable by the public WITHOUT already knowing S. Replacing it with a fixed public constant requires the path mask on the right to be the SAME hidden value for all qualifying w; independent expansions do not establish that equality. Hiding the root generator's secret input in an ordinary program is not a hash-only construction. Publishing a proof that the root equation holds also cannot generate the root share. The reverse programming direction therefore does not solve the original release operation either.

## 4. Joint simulation and handoff

The split-key repair isolates two requirements instead of a local-label mixing condition: (a) a public constrained aggregate-access construction for the full deterministic trace's complementary subtrees, with access tied to actual prefixes and no public root expansion secret, and (b) a correlated leaf-programming construction across all future accepted inputs. Both must be implemented together. In particular, an isolated simulator that replaces the random split masks by independent values is incompatible with (b): the final mask is programmed as a function of the frozen S, its predecessor shares and the accepted trace. Conversely, a simulator that knows S and chooses corrections for already supplied w does not simulate a capsule generated before any future original w is known. Full public verification context, correlated native values, sibling capsules and malicious source-coin retention make these gaps necessary, not optional.

Do not implement larger GGM trees, alternate branching order, independent mask tests, or constrained label fixtures for this family. A further attempt would need an actual compact construction jointly programming the leaf and restricting the complement shares, with arbitrary public recovery analysis rather than an assumption of a hidden aggregate evaluator. This run did not find one. No claim of generic impossibility, new Core behavior, R316 maturity changes, R225 endpoint changes, native signature construction, actual FALSE/hard-TRUE QPT security or malicious setup. Static derivation only: no code execution, tests, external literature or subagents claimed. No ordinary PR comment. Notification gate not met.
