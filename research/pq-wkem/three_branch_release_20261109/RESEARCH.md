# TRI-CANCEL-20261109: three-way original challenge release and N-of-N setup

**Status: a precise conditional architecture and executable authentication/policy checks, NOT an instantiated secure hash-only key-release gate.** This answers the user's three-condition design question. No general-purpose NP construction is required before attempting this fixed bridge relation. Neither an NP circuit, a ZK proof, an N-of-N setup, nor the conditional composition below is falsely presented as a solution to witness encryption.

## Provenance and exact predecessor

Repository syscoin/PVUGC, PR #1, actual branch research/pq-wkem-validation-20260918. Observed initial head b7a4fbd55030e0fc52a57057824082a0a23d4c40, open/draft/unmerged. Read the exact auxpow_inconsistency_scope_20261109/RELATION_SCOPE.md at that head. A latest ordinary-comment read since 2026-11-09T15:00Z returned no comments. Intermediate CHECKPOINT_01.md was committed as 2ce4b11404ad01d37968f20cba5a1763eaf6c122 using a non-force expected-head update. Its experiment plan did not claim executed results. The present checker was actually executed locally twice with byte-identical output. No outside web/literature, source-code change, independent agent or QPT simulation was used.

## 1. Separate the three functions

The N-of-N preauthorization ceremony restricts the transaction graph with an honest participant excluding bypass signatures and erasing/protecting its keys. One notary/operator subsequently activates an already permitted withdrawal. A watcher supplies finite admissible evidence and must be able to recover the cancellation capability without any setup party returning online. The graph, evidence predicate and cryptographic release have separate security obligations. Bitcoin-chainwork comparison does not itself imply N-of-N signing is mathematically necessary; N-of-N is the covenant-emulation choice for this design.

For one preauthorized withdrawal instance freeze x_W=(protocol version, chain IDs, vault/claim outpoint, burn ID/event index, amount, BTC recipient script, reserve ID, assertion digest, proposed BTC anchor/tip/work, Syscoin baseline/root/height, allowed windows, fork-depth parameter k_LC, relevant tag schedule, exact cancel transaction/message M_W and public keys, capsule ID). Public x_W is authenticated and bound to that instance. It is not filled from attacker-selected witness roots.

The fact that a graph is pre-signed does not automatically allow arbitrary future outpoints/claims/state roots to be inserted without new signatures. Integration must use the actual preauthorized slot/transaction topology. This analysis assumes one bound instance and does not silently add an online N-of-N signing requirement or a dynamic covenant opcode.

## 2. The challenge relation is an OR, not a requirement for ZK

    R_cancel(x_W,j,w) =
       (j=1 AND R_work(x_W,w)) OR
       (j=2 AND R_burn_fault(x_W,w)) OR
       (j=3 AND R_sys_fork_or_tag_fault(x_W,w)).

The selector is explicitly range-checked. Each branch authenticates the roots, scope and evidence it uses. One branch suffices; the challenger does not need evidence for the other two. With bounded witness/header lengths and deterministic verifiers this is one ordinary NP relation/circuit, of size essentially the sum of its branch circuits plus selection. Three conditions are not a reason to require zero knowledge.

Zero knowledge hides a witness; succinctness compresses verification/proofs; knowledge soundness supports witness extraction; a public secret-release algorithm supplies a protected capability. They are different properties. A hash-based transparent argument could be an OPTIONAL off-chain proof representation, but would need stated QPT properties and a knowledge extractor if accepted proofs substitute for original witnesses in a hard-TRUE recovery theorem. The gate must still cryptographically protect the frozen output. A circuit that simply contains a readable secret and checks R before returning it is not secure.

## 3. Exact finite predicates

### Challenge 1: heavier competing Bitcoin history

Validate a candidate header sequence from the SAME authenticated comparison anchor, including all necessary difficulty/retarget, target encoding, proof-of-work, timestamp and predecessor context. Compare exact accumulated target-derived work:

    W(B) = sum over validated headers h of floor(2^256/(Target(h)+1)).

Require that the candidate displaces/contradicts the relevant asserted history and W(B)>W(A). More blocks or unusually small observed hash values do not establish more cumulative work. A normal extension of A is not automatically a refutation, unless a distinct documented reset policy intentionally treats it as one. Header qualification and source anchoring are not implemented by a free Boolean flag in a real system. The checker's qualification flag is explicitly abstract.

An invalid asserted chain is a separate finite fault in the assertion, not necessarily demonstrated by finding a heavier chain. The activation rules must reject such an assertion or ensure another enforceable fault path. No requirement to decide the heaviest of ALL possible private chains is introduced; the positive challenge is existence of this qualifying stronger competitor.

### Challenge 2: no authorized proof of burn for this withdrawal

Do NOT encode this as an unbounded claim that no burn exists on any possible chain or at any future time. The finite target is a missing/incorrect burn in the particular admissible source state/history bound to x_W. The claim must specify burn identifier and authorization details. A burn with a wrong amount, recipient, reserve or replay status is not a valid authorization merely because a burn event exists.

Concrete finite representations are:

1. **Protocol-authenticated burn registry.** An authenticated state root rho at the relevant source height commits a deterministic map from burn ID to exact burn record. A sparse-Merkle proof of the empty leaf at the fixed query ID proves nonmembership. A nonempty leaf with fields incompatible with x_W proves a specific authorization fault. The update rules/root must be consensus authenticated. This note does NOT assert such a map/root currently exists in Syscoin; it is an explicit representation choice.
2. **Refuting the committed positive claim.** Require the assertion to publish its specific burn transaction, index, relevant header/root and inclusion/authorization proof. Recomputing that finite proof can demonstrate it is malformed or inconsistent with the bound root. No proof supplied is invalid ASSERT syntax or a separate disclosure failure; it is not automatically cryptographic proof that no burn exists. A valid proof against an unauthenticated root is not sufficient.
3. **Bounded complete-history evidence.** Complete authenticated block transaction data and deterministic source execution over the required interval can demonstrate absence when no authenticated nonmembership index exists. This can be large and needs data availability; succinct proofs may compress it off chain. It is not ordinary SPV negative inclusion.

An ordinary transaction Merkle root plus failure to find an inclusion path is NOT a nonmembership proof. An outpoint missing from the UTXO set is NOT proof that a historical burn never happened. Withheld data is not mathematical absence; it needs the separately specified DA/abort policy.

The executable sparse-tree subcomponent in checker.py is precise: EMPTY leaf hash has a different domain from OCCUPIED(index,value); internal nodes hash ordered children with another domain. Open verifies an exact-length sibling path against the already bound root. If a true occupied leaf and an accepted empty proof for the same root/index coexisted, taking their first differing leaf/internal hash inputs that map to the same parent would exhibit a hash collision. This is a deterministic reduction for that authenticated tree, valid for any adversary producing such classical outputs. Resistance against QPT requires an independent QPT collision-resistance assumption; this proves a verifier property, NOT key-release security. The tree's state completeness/canonical root authentication is a separate premise.

### Challenge 3: qualified Syscoin fork/tag inconsistency

Require an authenticated incompatible history for the relevant source slot and at least k_LC valid linked descendant Syscoin blocks under the configured light-client rule. k_LC is a protocol parameter bound in x_W, not an invented numeric constant. Do not confuse it with the pinned tag's own 6-15-header ancestor lag.

At equal referenced heights compare the two ancestor hashes. At different heights supply a positively authenticated predecessor path from the higher tagged block to the lower height and compare the resulting hash. Same-child distinct parent-work certificates are not distinct Syscoin forks. Only qualified, in-window, relevant evidence counts. Do not impose greater Syscoin work on this inconsistency branch merely because challenge 1 compares Bitcoin work.

A tag-fault subcase authenticates the outer Bitcoin/header/coinbase/child carrier before demonstrating that an applicable required tag is missing or inconsistent. It must NOT first require the failed tag-validity test to pass. Full coinbase evidence is needed for absence. In all cases claimed height, actual child/header chains, source anchor, ancestor linkage, required interval tags, parser rules and relevant lag/density constraints must be bound to real evidence. A few string inequalities are not the complete source verifier.

## 4. Conditional offline release composition using the existing N-of-N path

To avoid assuming hash-based threshold signing, native signature aggregation, or a coordinator who learns a full secret signing key, let the cancellation path use the already agreed N independent native public keys (pk_i). Participant i prepares ONE frozen native cancellation signature sigma_i on the exact same message M_W. The target capability is the package Sigma_W=(sigma_1,...,sigma_N), not a newly invented aggregated signature. This choice is available only where the agreed endpoint can verify that N-of-N package; it is not a deployment claim about a native PQ opcode.

Participant i publishes an offline capsule:

    C_i = Build_release(R_cancel, x_W, sigma_i; r_i).

The required leaf-capsule property is:

    Open_release(C_i,(j,w)) = sigma_i
       for EVERY accepted ORIGINAL (j,w), for every honest i.

Anyone possessing one valid ORIGINAL challenge computes this for ALL i and broadcasts the same preauthorized safe cancellation package. No live signatures, quorum votes or challenge adjudicator are added. This is AND across participant contributions and OR across challenge reasons:

    AND_i [ R1 OR R2 OR R3 ].

It is NOT R1 AND R2 AND R3. If separate capsules per branch are used, all three for participant i must release its SAME sigma_i and require a joint same-message/correlated-capsule security theorem. Marginal privacy for each branch alone is insufficient. A single combined-OR capsule avoids pretending that correlation theorem is automatic.

### Conditional security projection (not an instantiated theorem of hashes)

Assume for a fixed honest setup participant h that C_h has the requested full-joint arbitrary-QPT security when all other participants' capsules, retained secrets, native public keys, manifests, off-target signatures and auxiliary data are available: accepted recovery of sigma_h OR any alternative valid native signature on the protected message yields ORIGINAL qualifying evidence or an independently justified hash/native security break. The assumption must cover the actual source-dependent construction; it is not supplied here.

Any accepted N-of-N cancellation package contains such a valid h signature. Projecting the adversary's classical output to that component is straight-line and efficient; it requires no rewinding, no requested representation and no automatic classical-to-quantum lifting. Thus this joint leaf property suffices for the package's security. Conversely, N-of-N by itself supplies no such property: corrupted contributors may retain their own signatures, and the honest gate must hide the missing contribution from the complete public view. A publicly derivable gate opening bypasses N-of-N once the other contributions are available.

This conditional projection is just a composition fact. It does NOT solve the leaf Build_release operation. Putting an ideal release oracle in code would not instantiate it.

### Pre-funding audit, abort and acyclic binding

All required cancellations, gates and data must exist and be checked for useful correctness before irreversible funding. A malicious capsule may otherwise be unopenable even on genuine evidence. The honest participant can force abort by withholding its funding-enabling preauthorization, but that only protects safety until funding; it does not by itself prove liveness of an already funded malformed graph. Public audit/zero-knowledge evidence that canonical capsules seal the intended valid signatures could be useful, but requires an actually specified canonical compiler and a suitable QPT-secure proof system, including its joint public correlations. It cannot audit an undefined primitive.

Avoid a fixed-point construction in which the cancel signature signs an ASSERT txid containing a hash of a ciphertext that itself contains that same signature. One acyclic organization, when compatible with the existing graph, is to freeze graph/message/statement first, create signature capsules second, and authenticate their root with a separate setup manifest checked and made available before funding. The manifest binds x_W, the exact graph/message, participant keys, capsule roots and proof parameters. It is not a recursive field inside the signature it protects. The user must receive a path confined to cancel/reset/refund, not an unrestricted key or payment to the challenger. This is an ordering proposal conditional on the already accepted graph, not a hidden new opcode or on-chain manifest verifier.

If the assertion/source statement is chosen only later by one notary, the actual graph/manifest must still bind it correctly. Requiring all N parties to rebuild a capsule for every later dynamic proposal would change the requested one-of-N runtime model. No such online step is assumed solved.

## 5. Why an NP/ZK proof is not the missing release algorithm

A proof system can certify R_cancel(x_W,j,w)=1. Knowledge soundness may permit a reduction to recover ORIGINAL evidence; zero knowledge may conceal it. Neither property guarantees that computing such a proof provides a fixed secret sigma_i known earlier to the builder. H(proof) generally changes with the branch, witness and proof randomness and has no precommitted equality to sigma_i. A proof verifier that returns a secret embedded unprotected in its public code is directly bypassable. A hash garbling with both witness labels public has the previously recorded global-consistency problem. N-of-N setup is not a proof that either candidate is fixed.

A small verifier for an optional transparent argument could be the circuit placed inside the eventual release mechanism, but calling that smaller circuit still leaves Build_release to be constructed. Accepted inner proof without an appropriate QPT ORIGINAL-witness extractor also fails the hard-TRUE target. Bitcoin continues to receive only the intended native cancellation authorization, never the full source proof, original circuit or trace dispute.

## 6. Actual execution and scope

checker.py was executed with Python's standard library twice, producing identical captured.json and rerun.json. It tests three explicit 8-bit sparse-tree maps, membership/absence, altered values, exact path length, alternate-root and adjacent-leaf misuse, exact integer work comparisons, abstract conflict/depth qualification boundaries, all 8 combinations of the three challenge truths and N-of-N Boolean contribution logic. It performs 3,226 assertions. The production sparse-map depth would be a chosen protocol parameter, not eight. The BTC/SYS qualification Booleans are declared ABSTRACT and are not supplied by an implemented consensus verifier. No chain was mined, no actual signature generated, and no witness-encryption gate or QPT attacker was implemented.

The one proof-hash fixture demonstrates only that two specific transcript hashes differ; the mathematical point is that the construction has no identity forcing all accepted proofs to one fixed hidden value. No hash hardness follows from its count.

## Exact next original-source construction obligation

The remaining operation is ONE public hash/SHA-dependent gate for the exact relation R_cancel, with classical-PPT Build and Open, all-original-witness SAME-capability correctness, source authentication inside release, and a joint-public QPT recovery/accepted-signature-to-ORIGINAL-evidence reduction. All three challenge families must be usable; the participant wrapper and sparse-tree verifier cannot stand in for this gate. No lattice, online secret holder, on-chain NP verifier, trace-dispute system, blanket statistical-hiding demand, or arbitrary-NP prerequisite is introduced. Until the gate and its setup/composition are instantiated, there is no secure end-to-end three-condition key-release claim.
