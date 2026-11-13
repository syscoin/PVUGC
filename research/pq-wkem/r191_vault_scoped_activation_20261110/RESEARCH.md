# R191 — SegWit witness-committed activation with fixed-txid cancellation

**Status: concrete conditional Bitcoin transaction/source-binding construction, NOT an instantiated hash-only witness-KEM or QPT proof.** This construction addresses the temporal mismatch between N-of-N signatures preauthorized before funding and a withdrawal claim chosen later by one notary. The missing secret-release gate is still unsolved.

## Continuity, assumptions, and scope

Repo syscoin/PVUGC PR #1, branch research/pq-wkem-validation-20260918, observed starting head 592123ed31b1d700943ea5459d1089a7b67081f4 (open/draft). The intermediate R191 checkpoint is already present at that head, and the pinned R190 semantic tag-parser note at its parent was read. This write is research-only under research/pq-wkem/. No web search, other repo write, independent researcher, live Bitcoin miner, native PQ signature test, or QPT test. The two long local source-checker scripts and captured results are preserved locally in the active session; the *shorter* published checker and its exact captured stdout are attached here and were rerun byte-identically.

## Constructive transaction-graph mechanism

Fix the vault's outpoint, epoch, ASSERT transaction's nonwitness serialization T, fixed output index o and output script/amount, fee, locktime and sequence. The N-of-N covenant-emulation setup can presign a fixed safe cancellation transaction M_cancel spending (txid(T),o), and place the authorization behind the eventual challenge-release gate. A single notary may later activate T with witness z(a) recording an assertion a, with claim identity, burn, amount, recipient, source commitment and notary authorization. SegWit separates the two hashes:

    txid(T,z) = SHA256d(serialize_nonwitness(T)) = t
    wtxid(T,z) = SHA256d(serialize_witness(T,z))

Thus all eligible future witness variants have the same **child prevout** (t,o), even though the authenticated witness claim and wtxid change. The downstream native cancellation message commits to fixed (t,o) and fixed safe outputs, not to a chosen future wtxid. This is NOT valid if the Bitcoin transaction's nonwitness outputs, input, fee, sequence or locktime depend on a. In particular, a later arbitrary recipient or amount cannot be installed into the nonwitness parent output while keeping t and previously generated signatures; ANYPREVOUT, new covenants or native introspection are not assumed. The fixed script must enforce the existing delayed payout and challengeable cancellation graph. A post-delay unconstrained notary spend to an arbitrary recipient would be unsafe unless beneficiary ownership is separately enforced.

The off-chain relation must authenticate the **actual mined witness**, not just t or an off-chain assertion. An authenticated complete Bitcoin witness observation verifies: (1) T's exact fixed nonwitness serialization; (2) the claimed witness z and its wtxid; (3) witness-Merkle inclusion of wtxid, with the special zero coinbase leaf; (4) the coinbase witness commitment SHA256d(witness_root || coinbase_reserved_value), with the *complete* coinbase and correct commitment-output selection; (5) coinbase txid inclusion under the parent header's normal txid Merkle root; (6) Bitcoin header-chain PoW, difficulty/retarget, ancestry, anchors, work/admissibility and source observation window; (7) a one-notary signature *binding a to this vault, epoch, t and output*. Only then may a branch-specific fault be considered. The synthetic checker does NOT implement the last full Bitcoin/Syscoin qualifications.

Possible claim carriage: an annex (Taproot annex starts with 0x50) is SegWit witness-only. BIP341 Taproot signature hashing commits to the annex when present, but the hypothesized native PQ/P2MR endpoint must explicitly supply equivalent semantics before relying on that fact. Alternatively include an independently publicly verifiable **hash-based** message signature from the same initiating notary on (vault, epoch, t, a, claim nonce) in the witness and verify it off chain. This is one notary's normal activation, NOT an online release authority or a second N-of-N challenge quorum. A malformed, absent or unsigned annotation must itself be a finite enforceable invalid-authorization challenge (part of R2), or an authorized malicious notary could activate an output with no challengeable claim. Full witness data availability must be assured; the witness relay/mining policy and native script semantics require a separate endpoint audit.

The published checker uses deterministic Lamport SHA256 OTS signing of synthetic activation messages for **functionality only**. It deliberately reuses the one-time key for two alternate claims; that is NOT secure, even with SHA, and must never be deployed. Use a suitable hash-based multi-use signing scheme or distinct one-time keys per authorized activation, subject to a separately established QPT security and endpoint specification. No existing EC signature is adopted as the cryptographic foundation.

## Conditional graph-binding lemma

Given fixed T,o and the same native cancellation output/message, any two consensus-accepted witness variants z_A,z_B yield the same signed cancellation message because txid excludes witness. They may have different authenticated claim payloads because their wtxids and corresponding Bitcoin block witness commitments differ. Given an authenticated root/header, a forged different witness against the same authentic commitment requires violating the applicable hash binding. Distinguish fixed-authenticated-root second-preimage resistance from an adversary constructing both colliding variants; SHA256d does NOT imply generic 128-bit quantum collision resistance (generic 256-bit quantum collision search is on the order of 2^(256/3), while fixed-target quantum preimages scale differently). A complete adversarial Bitcoin source and PQ signature theorem is not supplied by this local hash equation.

Multiple simultaneous candidate activations on incompatible qualified histories do not need an unsupported global-uniqueness theorem. Instead define the fail-closed language

    R_v(x_v,a,pi_A,j,w) = QualifiedActivation_v(a,pi_A)
                          AND R_cancel(x_W(x_v,a),j,w)

where j is one of: valid heavier competing BTC work; authenticated missing/invalid exact source burn/authorization; qualified SYS AuxPoW fork/tag inconsistency. Only qualified source histories can supply pi_A; any one activated faulty claim may cancel the **same fixed safe output**, a deliberate liveness tradeoff. Do not count a signed unanchored claim or a self-picked alternative root as QualifiedActivation. An invalid/wrong notary claim does not acquire a source qualification just because some bytes can be hashed. Ineligible competing Bitcoin forks and post-window events cannot qualify.

The first local checker (118 assertions) models a bound vault+epoch claim in an ideal list of authenticated roots, rejects relabeled old epoch/other vault/substituted path, checks existential fail-closed acceptance across two anchored roots, all three challenge alternatives, and confirms changed outpoint/refund changes the cancellation message. Its source-admission root list is an **explicit ideal premise**, not an actual Bitcoin verifier.

The second local checker (29 assertions) models byte-level SegWit serialization, a synthetic coinbase witness commitment and Bitcoin header's txid-Merkle root; claim signatures are toy Lamport OTS. It tests that two different authenticated witness payloads have identical txid but distinct wtxid, tampered coinbase reserved/root/claim fails the corresponding hash equations, and presigned cancellation output identity stays fixed. Synthetic header PoW was never mined or verified.

The *published* minimal checker in this directory (15 assertions) reproduces the crucial fixed-txid/wtxid/witness-commitment and claim-signature binding equations, with exact source and output committed as ordinary Git blobs. All tests are functional; no native script validation, genuine BTC/SYS authentication, final signing/WE implementation, or coherent QPT attack experiment was executed.

## No hidden release theorem follows

This constructs a useful **statement-binding path** for the actual source evidence, not conditional secret release. The unsolved interface is still

    Build_hash(R_v,x_v,sigma_cancel) -> C       [classical PPT]
    PublicOpen(C,a,pi_A,j,w) = same sigma_cancel
        for EVERY valid ORIGINAL three-branch challenge

with whole-public QPT security against FALSE and hard-TRUE unauthorized recovery/accepted native forgery; source history, all auxiliary fields, correlated capsules, malicious N-of-N setup and signature security are in the game. Bitcoin receives only ordinary pre-signed cancellation authorization; no NP/VM/PCP/BitVM trace verifier on chain. Naming an OR circuit, a hash commitment, or a check which hides no key is **not** the missing cryptographic construction. No other optimized restricted carrier is promoted.

## Publication receipts and reproducibility

Starting head 592123ed31b1d700943ea5459d1089a7b67081f4, intermediate note in r191_vault_scoped_activation_20261110/CHECKPOINT_01.md. Published self-contained checker source SHA256 = 826762e921eff67c2f0e0ee710f9c0b929104429f20036e75f459abd1bd35015, captured stdout SHA256 = cfd51c7a1a05521b91ef91b9d409cfdaf4d11bc81caec0df3c9be102a5ee3395. Run: python research/pq-wkem/r191_vault_scoped_activation_20261110/published_checker.py. Rerun stdout was byte-identical. No ordinary PR progress comment is warranted solely by this component: no key-release crypto or QPT proof exists yet.
