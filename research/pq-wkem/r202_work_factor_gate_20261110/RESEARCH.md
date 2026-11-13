# R202 — Work-output-factored release gate (WOF): exact scoped result

**Status:** Research-only unsuccessful ORIGINAL-dependent hash-only release attempt. No end-to-end Build/Open, no full-public QPT security, no actual BTC/SYS validator and **no qualifying breakthrough**. Do not reuse as a bridge security claim.

## Actual continuity and evidence

Repo syscoin/PVUGC PR #1, draft/open/unmerged; branch research/pq-wkem-validation-20260918. Observed starting SHA 3bbdb53e8c2c03d370d29ec8ce0e482807c3124d (tree f03ccfa599354e872490f13713d96d239fb355eb). Read exact prior r201_source_convergent_gate_20261110/RESEARCH.md, blob 27f847536e4e79045a115154b531498373ccfe40; no PR issue comments since 2026-11-10T12:00Z at read. Original local intermediate CHECKPOINT_01.md was written *before* the candidate checker; no external research, web, independent agent, real mining, native PQ signing, on-chain code change or quantum experiment.

## The explicitly named hash/PoW original-dependent attempt

Let x bind the true preauthorized vault/claim/withdrawal, signed activation, relevant BTC anchor/work/window, SYS PoB/burn, exact prefix/tag history, native cancel message and VK, and capsule ID. The ORIGINAL relation is R1 (qualified heavier BTC competing work) OR R2 (admitted finite incorrect/missing burn authorization) OR R3 (qualified SYS prefix fork/tag fault). One notary activates and any witness of one branch should release the SAME precommitted N-of-N cancellation capability, without another live signing committee.

Try to derive a key only from the actual source parent-work output y=SHA256d(parent_header), rather than introducing a separate hash puzzle, invented label, synthetic signer or canonical witness:

    C=(x,E), E = sigma_cancel XOR Pad(x,q(y_setup))
    Open(C,w) = E XOR Pad(x,q(H(parent_header(w)))).

Here Pad and q are public. The setup has no future source header and thus generally cannot know y_setup; tests optimistically grant it knowledge of one valid candidate, which can only make completeness easier. A complete capsule would also have checking key/VK and authenticated source context. This candidate does NOT provide one.

**Exact work digest:** q(y)=y. Distinct qualifying work certificates (including multiple parent WorkIDs for one pure Syscoin child) have different y. Other genuine BTC, PoB and SYS challenges need not have any parent WorkID in common. Therefore Pad(x,y) varies and the same frozen sigma does NOT follow for every ORIGINAL witness. Hashing the whole header, wtxid, source proof, claim-prefix child or first-divergence proof worsens cross-witness variation.

**PoW-range normalization:** q(y)=eligible if y<T, else ineligible. For any qualifying header Pad(x,eligible) is common, but the attacker can compute Pad(x,eligible) directly, or call the raw output-factored expression with y*=0<T. In symbols, if E = sigma XOR Pad(x,eligible), then E XOR Pad(x,q(0)) = sigma. The attacker did not mine a header, prove source membership, find a PoB fault, prove a fork or produce a witness. This is an unconditional classical attack against this precise public pad, hence also a QPT attack.

**Original three-way source test:** In particular, a perfectly valid burn assertion and an incorrectly documented/missing-burn assertion BOTH have ordinary mined Bitcoin parent headers meeting their work targets. The range pad therefore also unlocks on a PoB-VALID activation where R2 is false. Bitcoin work qualification alone does not discriminate burn authorization. R2 might be true with no competing BTC history or SYS fork. Thus a single universal fresh competing-work secret cannot silently stand in for the OR relation.

## Narrow restricted lemma (do NOT generalize)

Assume the pad evaluates solely as Pad(x,q(y)), and there is a *publicly constructible* digest y* with q(y*)=q(y) for every accepted source work digest y. Then E XOR Pad(x,q(y*)) recovers the ciphertext's secret without any source preimage. This is an algebraic identity, not an assumption on SHA, NP, or quantum adversaries. It applies exactly to range normalization q(y)=[y<T] by choosing y*=0. The hypothesis may FAIL for more sophisticated q which distinguishes actual hash images from synthetic below-target values. This does NOT prove a black-box impossibility for arbitrary SHA/source dependent mechanisms. In particular the ability to manufacture a digest y* is not the ability to supply a valid Bitcoin/Syscoin source certificate.

## Executed checker

Python standard-library SHA256 fixture. Synthetic domain-separated 12-leading-zero-bit parent-work targets, 32 seeds, two candidate notary PoB-valid / PoB-missing header types, 32-byte synthetic cancellation secret. No deployed Bitcoin SHA256d header serialization, AuxPoW Merkle paths, source root verification, canonical Bitcoin membership, native PQ signature, real work/security estimate or QPT analysis. Ran checker.py locally twice with byte-identical JSON output. **224 deterministic functional assertions** across seven named groups (32 each): both_valid_toy_work; different_valid_parent_digests; exact_digest_pad_not_common; range_pad_common; fake_digest_opens_range_pad; early_raw_key_recovery; work_pad_does_not_enforce_burn_fault. Checker source SHA256 e00489bf2c77d168c26995a675d222fc46954e561c33ec114e18a48fb070f284 and local captured output SHA256 ef836752bca62a0ceec65cc11ca21605334952c89b489307eefd7d637c61dee5. The local first checkpoint SHA256 47dba792ee28b6036eb6229b732070a4e5af125e14195469dee42d7cb7.

## Repair and security boundary

Putting CheckRealSource(w) outside a raw public pad does not secure it: an adversary is not constrained to invoke honest Open. Requiring the actual preimage inside decryption rather than only the digest defeats arbitrary output substitution, but the preimage/header varies across accepted future certificates and the builder cannot precommit a common pad. A genuine repair requires a cryptographic correlation over the actual SHA/AuxPoW/source-ancestry computation, instantiated jointly with a full-public simulator/extractor. A capsule-root commitment authenticates bytes but does not provide this correlation; retained signer labels, online issuer, arbitrary independent work puzzles, publicly known source anchors, and published garbled wire labels are not repairs.

Open must recover SAME frozen claim/path-scoped native cancel capability for ALL R1/R2/R3 original witnesses. Unconditional raw output recovery, an alternative native signature, or correlated multi-capsule recovery without an ORIGINAL witness must imply a justified QPT hash/native break or extraction of actual ORIGINAL authenticated evidence. Include checking key, native VK, malicious source/setup coins, auxiliary and sibling capsules, selective openings and coherent QROM queries where explicitly idealized. The R201 public garble/input-splicing attack remains a required regression.

This pass does not meet the reporting threshold; no ordinary PR progress comment.
