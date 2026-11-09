# TRI-CANCEL-20261109 — three challenge predicates and N-of-N release composition

Status: interactive architecture/construction analysis, NOT an instantiated hash-only witness-KEM or breakthrough. The user asks whether N-of-N covenant emulation plus three challenge conditions can produce permissionless key release, and whether the multiple conditions require ZK. This checkpoint preserves the actual target before policy/absence checks are executed.

## Continuity

syscoin/PVUGC PR #1, research/pq-wkem-validation-20260918, observed start b7a4fbd55030e0fc52a57057824082a0a23d4c40 (open, draft, unmerged). Exact prior scope read: research/pq-wkem/auxpow_inconsistency_scope_20261109/RELATION_SCOPE.md at that commit, previously verified blob cb1337cf67d91e7c0c258d508ab4c351c79e6f7c. Latest ordinary comments since 2026-11-09T15:00Z returned none. No external internet research, production change, independent agent or runtime security test claimed.

## Three independent cancellation grounds, one bound withdrawal instance

x_W must bind claim and vault outpoint, recipient/amount/burn identity, committed assertion, authenticated Bitcoin anchor, source/burn root and height, window/deadline/reset rules, Syscoin fork-depth requirement, exact cancel transaction/message/VK, and capsule identity. These are not attacker-selected witness fields.

R1: a VALID, RELEVANT competing Bitcoin history from the same authenticated comparison anchor that contradicts the asserted history and has strictly greater exact cumulative work. Normal extensions of the asserted history are not automatically counterexamples. Work is sum floor(2^256/(target+1)), with targets/difficulty transitions and contextual header rules validated; length or smaller observed hash values are not substitutes.

R2: the exact authorized burn for this withdrawal is absent/invalid in the BOUND relevant Syscoin state. This must be a finite positive refutation: authenticated nonmembership in a protocol-committed burn registry, or refutation of the claimant's specific committed inclusion/authorization proof, or a bounded fully authenticated execution/history scan. Missing ordinary Merkle inclusion proof or absent UTXO is not proof of absent historical burn. A sparse burn registry is an explicit design choice, not an assertion about current Syscoin state commitments. No need to prove absence on all possible chains or forever. Burn identity, amount, recipient, reserve and replay status matter separately from occurrence.

R3: authenticated AuxPoW/tag observations establish an incompatible Syscoin branch with the configured light-client depth and required source qualifications. Equal referenced height with unequal hashes, or positively proven different ancestor at the lower height, is the semantic contradiction. Different Bitcoin work certificates for the same child do not count. No greater Syscoin-work requirement is added to this branch. Source applicability, full coinbase/tag evidence, ancestor links and BTC anchoring remain mandatory. An optional tag-fault subcase authenticates the outer carrier without requiring the disputed tag check to pass.

Define R_cancel(x_W,j,w) = [j=1 AND R1] OR [j=2 AND R2] OR [j=3 AND R3]. Each selected branch authenticates its own relevant roots and source scope. The other branches need not be true. Three branches do not require zero knowledge; they require correct computation. Succinct proof verification and witness privacy are separate optional layers. A public proof of R_cancel does not by itself decrypt a precommitted secret.

## N-of-N is across setup participants, not across challenge grounds

N-of-N preauthorization constrains the available transaction graph and prevents bypass with one honest key-erasing participant. It does not independently evaluate Bitcoin chainwork or release a hidden key on a true NP predicate. One notary may initiate an allowed withdrawal; every valid challenger should finish with no live setup-party cooperation.

A conditional composition uses N participant-specific preauthorized native cancellation signatures sigma_i on the SAME exact cancellation message M_W. Each participant's offline gate has ALL THREE branches and must release the SAME sigma_i for every valid challenge witness. Bitcoin's conditional native N-of-N cancellation path requires the full vector (sigma_1,...,sigma_N); no threshold-signature aggregation is assumed. This separates source-signing actors from setup participants and avoids assembling the complete secret cancellation signature in a malicious coordinator's memory before funding.

Logical form: AND over i of OR over j of the participant-i gate for Rj. Assigning one challenge type to each participant would wrongly require multiple challenges. Publishing three capsules for the same participant secret additionally needs a JOINT same-message multi-capsule security proof; individual marginal proofs do not imply it. A single OR predicate per participant avoids assuming such a composition for free.

The leaf gate Build_release(R_cancel,x_W,sigma_i) and its public Open remain UNINSTANTIATED. Naming this API is not a construction advance. One valid witness would open every honest gate; N-1 retained private setup signatures would not suffice to cancel alone if the remaining gate truly satisfies the full-public security property. Malicious parties can still sabotage completeness by withholding or publishing malformed capsules, so their construction/signature consistency and data availability must be validated BEFORE irreversible funding. N-of-N gives an abort boundary, not free useful completeness.

## Specific tests and repair to investigate now

Implement a small authenticated sparse burn-map absence verifier and regression tests for claim/root/path substitution. This is a representation of a finite negative claim as positive evidence, not a key-release implementation or a deployment claim. Check the OR/AND composition over all 3-branch truth assignments and participant masks. Check work comparison using targets (longer can be lower-work), ordinary extension rejection, and fork-depth boundary behavior in explicitly abstract policy fixtures.

Also test/dissect the proposed proof-derived-key shortcut: different valid proofs/witnesses generally give different H(proof), so a zero-knowledge proof cannot simply be hashed into a previously fixed cancellation key. A proof-of-knowledge wrapper, even a hash-based one, still needs a source-dependent key-release mechanism and QPT extraction for the ORIGINAL evidence. An offline verifier that returns a secret stored openly in its code is not such a mechanism.

Exact unfinished step: instantiate the hash/SHA/AuxPoW-dependent leaf gate with polynomial classical Build/Open, identical frozen output for all valid witnesses, full-joint FALSE/hard-TRUE QPT security and malicious setup/auxiliary composition, without an online issuer, on-chain source verifier, trace dispute, lattice or disguised witness-encryption assumption. No security or elapsed-time claim is made by this checkpoint.
