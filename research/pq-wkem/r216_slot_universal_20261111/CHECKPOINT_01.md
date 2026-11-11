# R216 checkpoint 01 — fixed-slot universal release and late assertion causality

**Working hypothesis, not proof of witness-KEM.** The exact target is the user's N-of-N preauthorized Bitcoin cancellation graph, where ONE notary later activates a withdrawal and ANY watcher can cancel on qualified R1/R2/R3 evidence. Prior work R191 found a synthetically viable transaction ID / witness ID separation; R215 rejected precomputed SHA256d midstate as a common secret source label. This pass investigates a different outstanding issue: can preauthorization and an adaptively chosen notary assertion coexist without silently assuming online N-of-N capsule regeneration, or making an unmined notary-signed fake assertion sufficient to release the key?

Repository syscoin/PVUGC PR #1, branch research/pq-wkem-validation-20260918, observed initial head 5a05916758906ec097689e9ddc3f716187772c00, tree 43f6c8e572adbc5204f0f0786e47aee92a7ce3a0, open/draft/unmerged; latest ordinary comments since 2026-11-10T12:00Z = []. Read exactly r215_sha_midstate_20261111/RESEARCH.md (blob e4ab8e84b261083f98ab412516df62a1f6b4dbb1). No web, other repositories, proof-mining, production code, or independent agents.

## Named candidate: SLOT-UNIVERSAL precommitted source-dependent gate

At time t0, N-of-N participants bind a fixed Bitcoin cancellation outpoint v, an exact native cancellation message M_v, a one-time setup manifest and one encrypted signature share per participant. At later t1, a notary independently selects an assertion a in a canonical witness encoding of a fixed-txid activation transaction. Witness mutation may alter wtxid, not txid, allowing the preauthorized cancellation to target the fixed outpoint, only under the exact SegWit and native sighash semantics assumed in prior R191. The cancellation signature must only restore/reset the guarded slot, not transfer arbitrary value.

Do NOT pretend Build(x_a,sigma) can run at t0 for unknown a. Instead define one pre-funded relation for all admissible later activations:

    R_slot(v ; (a, receipt, j, evidence)) =
        AuthBTCActivation(v,a,receipt) AND NotaryAuthorized(a,v)
        AND ((j=1 AND GreaterCompetingBTCWork(v,a,evidence))
          OR (j=2 AND AuthenticatedBurnFault(v,a,evidence))
          OR (j=3 AND QualifiedSysPrefixOrTagFault(v,a,evidence))).

The gate target is
    Build_slot(v, sigma_cancel) -> capsule
    Open_slot(capsule, (a,receipt,j,evidence)) -> the SAME sigma_cancel
for EVERY valid ORIGINAL witness and no invalid witness. It is crucial that AuthBTCActivation establish on-chain witness commitment and chain scope, not merely a valid notary signature or a witness chosen from a public mempool. Where the allowed design requires publication before Bitcoin confirmation, replace inclusion by a precisely specified authenticated event/slot with the corresponding censorship/finality assumptions; do not assume unmined signed data authenticates a mined event.

## Causal binding claim to investigate

Assume C is immutable at t0 and assertion a is arbitrary and selected at t1. If no party can produce a new trusted capsule after t0, completeness for every eligible a forces the original C to be a universal release object for the relation existentially quantified over authenticated later a. This is a quantifier/timing observation, NOT cryptographic security. If C instead contains only a fixed a0, one-notary late selection of a != a0 cannot be opened without adding a new authorized Build event or a bounded table of eligible a. A claimed release construction must explicitly choose between preauthorization of fixed claims, a source-universal gate, and a trusted later setup interaction; the last is disallowed for this bridge.

## Attack hypothesis and repair

Naive gate: NotarySignature(a) AND BurnAbsent(a) may be true for a deliberately invented, signed but *unmined* a, enabling early cancellation even though no ORIGINAL on-chain activation exists. A malicious notary controls its signing key. Proposed repair: the release predicate must AND that exact a's wtxid into a fully authenticated, relevant, on-chain witness commitment, with a canonical activation slot bound to txid and v. A real claim with burn defect then qualifies. Merely checking H(a), an unanchored Merkle root, or an arbitrary parent PoW header does not.

## Planned bounded checker

Use Python hashlib to implement exact base/witness transaction double-SHA serialization for one-input synthetic SegWit fixtures; show txid unchanged, wtxid changed when notary evidence changes, and pre-signed cancellation outpoint fixed. Implement a two-leaf synthetic witness Merkle commitment to a fixed mock authenticated Bitcoin root (NOT real header-chain validation), test false unmined notary-signed claims vs an actually anchored defective burn. Prove all source/consensus checks are abstract beyond these bytes. Also test incompatible sibling activation with same txid, invalid Merkle sibling, wrong slot, invalid signature, and disclosure timing. Do not call any fixture deployed or a WKEM.

Independent remaining crypto equation: a classical-PPT public hash/SHA/AuxPoW Build/Open that hides the frozen signature in the complete public view, recovers identical output from every such authentic witness, and reduces arbitrary unauthorized QPT recovery/native forgery to a full ORIGINAL witness or independently justified hash/native break. SLOT-UNIVERSAL supplies the missing *instance-selection timing* specification; it does NOT supply the release algorithm. No notification or PR progress comment for this checkpoint alone.
