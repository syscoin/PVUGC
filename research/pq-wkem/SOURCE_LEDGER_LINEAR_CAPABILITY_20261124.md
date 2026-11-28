# 2026-11-24 — original-ledger linear-capability compiler screen (NONQUALIFYING)

## Continuity and candidate selection

Actual syscoin/PVUGC PR #1, open/draft/unmerged on the same-repository research/pq-wkem-validation-20260918 branch, start e31dbb9eff30c33123b4e9869312e1758fd9e7d9. Read PR metadata, recent substantive comments through R225, head commit file name, and exact-head SOURCE_MERKLE_GRAFT_COMMON_NODE_20261124.md (blob 2b40111af32479db2ed2ed45d6957e89618845d5). No web, literature, whole PR diff, or new Core source assertion. The previous source-node graft could not join distinct original nodes to a common hidden key with public polynomial sibling/suffix enumeration.

Missing operation: a witness-blind serialized classical-PPT Build_inc(x_W,sigma_cancel) and public Open_inc(C,w) for all qualifying ORIGINAL witnesses, including the original three independently sufficient OR grounds; jointly simulate the full public view on FALSE and reduce arbitrary unauthorized hard-TRUE recovery/native forgery. This iteration considers whether the actual original source ledger can supply *linear use* of secret evaluation capabilities, as opposed to requiring a hidden source-to-common-node map.

Mathematical change proposed before implementation: replace reusable accepting garbled-correction labels (R289 FALSE splice) by source-indexed consume-once tokens, where consuming a token is supposed to advance an authenticated monotone state of the original history. If genuine, linear consumption rather than independent random masks would prevent reusing one intermediate capability at inconsistent positions/branches. Test whether that authority is obtainable in classical public Open from the ORIGINAL finite evidence alone; no new transaction, online issuer, private hardware, stateful Bitcoin trace dispute or external trusted counter may be added.

## Candidate interface

Let w be complete ORIGINAL evidence, containing one or more authenticated histories A and all relation-required paths. Let R(x_W,w) be unchanged; in particular a qualifying SYS inconsistency can involve two incompatible mature histories and does not require picking a winning SYS fork. Treat authenticated history identifier a as a canonical domain-separated commitment to the entire relevant admitted prefix plus source/claim context; not merely a terminal tag. All predicates below are abstract, not claims about a newly implemented consensus checker.

The proposed serializer carries C=(ctx,x_W,VK,M, initial_state, transition_rows, E), with E a masked frozen native capability. Open supplies history evidence, initializes local state (i,L,S,t) where i is transition counter, L a secret-evaluation label available to the current evaluator, S a consumed-nullifier set, t a transcript digest. For each source-backed transition row r with source event identifier e, verify the original authentication/path condition for e against a, derive n=H("consume",ctx,a,e,r), reject if n in S, and update

    S' = S union {n}
    t' = H("tape",ctx,t,a,e,r,n)
    (i',L') = RowEval(C,i,L,e,r,t,S)
    state' = (i',L',S',t').

Final release is intended to be a cryptographic unwrap under the final L, not an optional call to R after plaintext recovery. Honest completeness would require every qualifying w, independently of its particular authentic events, to reach the same native capability.

The missing row compiler must provide all such rows before future events and histories exist. Start by examining linearity itself, granting the proposed row evaluator every other property for this screen.

## Local linearity is not a public resource

Take any serialized public state s and two permitted caller-controlled row inputs u,v for which the transition function is defined. Copy s. Evaluate T(C,s,u) and T(C,s,v) separately (including the source proof and nullifier checks). The updated S_u and S_v can contain the same n without either execution detecting a prior use; the checks only see their common input S. This also holds if S is represented by a collision-resistant persistent Merkle accumulator: both children are valid append-only extensions of the same parent, and the caller can retain both versions. Adding a transcript commitment t gives each branch an authentic digest of its own local computation, not globally exclusive access to s. Randomized classical evaluation does not supply consumption either: the caller can copy serialized state before choosing independent tapes. The adversary is classical PPT and therefore also an allowed QPT adversary. No quantum no-cloning premise is available for classical honest Build/Open.

In particular, any splice whose only newly imposed impediment is a mutable local used-label/nullifier list remains executable from copied inputs. This does not demonstrate that every possible transcript-keyed row compiler admits the R289 splice: if the outgoing secret labels are cryptographically bound to the *entire* path, that is a new cryptographic premise, tested separately below. No source certificates are extracted from this local-state argument.

## Attempted repair: borrow monotonicity from the original ledger

There are two possible nullifier scopes.

1. History-local: n_a=H("consume",ctx,a,e,r). For distinct authenticated histories a,b, the same source event or row can have different nullifiers. A shared pre-divergence event e can appear on both histories without any contradiction in either history. Even if there were a ledger-native mechanism preventing duplicate n_a in history a, it would not prevent use in b. Also repeated off-chain evaluation against a fixed immutable history does not change that history; the ledger rule is not consulted on a new spend.

2. Cross-history: n=H("consume",ctx,e,r), omitting a. A shared event yields a common identifier; uniqueness of the *identifier* is not uniqueness of its use. To reject the second evaluation, an authority must track its use across all accepted history roots. A finite source certificate is immutable and cannot record a later off-chain evaluation. Requiring all accepted evidence to refer to a single canonical spent-state root would change the third original ground when it allows two incompatible authenticated histories without choosing a winner. A shared ledger event after evaluation could enforce inclusion of a new spend only by adding new challenge evidence, online interaction and inclusion/liveness assumptions. These are not original-certificate completeness.

Thus the candidate's claimed monotonic state must either live in the public evaluator (copyable), in an additional authority (forbidden), or in existing source evidence (read-only and history-relative). This is a scope argument about the proposed use-once authority, not an impossibility result for source-dependent cryptographic release generally. The same reasoning does not preclude a real stateless compiler whose labels enforce consistency cryptographically.

## Repair screen: bind row *decryption* to the whole authenticated tape

Remove the claim of non-clonability; instead make copying harmless by using path-specific decryption authority. In a hash-XOR row candidate, let the pad be G(ctx,i,a,t,L,e,r), where G is domain-separated KDF, and publish row ciphertext B before future a,t,e are known. Require an opening to recover next label L_next by

    B XOR G(ctx,i,a,t,L,e,r) = L_next.

The exact missing operation is now the witness-blind generation of B and the correct outgoing secret labels for all ORIGINAL histories, without exposing them to arbitrary callers. A single B with the same fixed L_next for two different accepted path inputs requires equal pads; under independent random-oracle/KDF outputs the equality probability is 2^(-lambda) for lambda-bit pads for a fixed distinct pair. This is the known random-hash collapse regression, not a proposed new larger fixture. Publishing a row for each future tape instead requires an enumeration or succinct correlated evaluator, not supplied by the consume-once mechanism. Allowing distinct L_next per tape avoids the equal-pad equation but leaves the *next* row's ciphertext and final common-capability correlation to be constructed for all such labels. Publishing the ability to compute the tape digest does not publish a secret-dependent row map. Normalizing all labels at each merge without authenticating which complete input tape they came from returns to the R289 consistency problem. Checking the public digest after an otherwise available row decryption does not bind release.

One hypothetical way to avoid this exact equal-pad requirement is a path-tweaked *correction function* B(a,t,e) whose output jointly cancels G to the correct next label only on authenticated full traces. It cannot just be a public formula for G XOR a fixed known label, nor a call to an ideal secret evaluator. Its serialized Build/Open and simulator would be precisely the unresolved source-dependent functionality. No such function constructed here. Do not implement another local nullifier fixture or tune the KDF parameters for this route. A future continuation needs an independent mechanism to establish path-specific secret authority before the future tapes exist; local tape commitments cannot provide it by themselves.

## Security and composition status

No classical-PPT end-to-end release, full-public FALSE simulation, arbitrary hard-TRUE/native forgery extraction, native PQ implementation, source consensus execution, quantum experiment or benchmark was obtained. This is an analytical construction/repair screen only; no local checker was executed because the proposed linear-use authority failed before implementation, and its fixed-pad repair is an already recorded failure family. No new source version claims. The original relation, including strictly greater exact BTC cumulative work from a relevant same anchor, finite authenticated specific burn refutation, and relevant qualified mature SYS history inconsistency/tag fault, is not weakened. Keep independent carrier authentication for malformed tags, R316 as coverage regression, claim and source bindings, native VK/message and exact signature distinction, full auxiliary/related capsule/selective opening dependencies, one-honest N-of-N setup with capsule correctness before funding and erasure, R225 slot-global veto versus genuinely activation-bound native message, offline source evidence, DA and enforceable inclusion. Do not infer source-state secrecy, a global spent-state root across incompatible histories, or any deployment from this analysis. NONQUALIFYING; no ordinary PR comment or notification.
