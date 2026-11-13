# R182 — Branch-anchored annex identity and source-conditioned cancellation

**Status: source-binding component tested; NOT an instantiated hash-only witness-KEM, native PQ signature or practical bridge solution.** The user retains three challenge predicates, one-of-N notary initiation, N-of-N graph preauthorization, and permissionless offline cancellation using an identical frozen native authorization for every qualifying ORIGINAL witness. This pass does **not** solve the cryptographic release gate.

## Exact continuity and run

Repo syscoin/PVUGC PR #1; observed initial head `426af96e65fa4e48313b2767b561caf16e7f34ee`, existing draft/open branch `research/pq-wkem-validation-20260918`. Read only R181 (blob `4db7da3a002e4e90ca60b6be220be39c742ca796`), R180 (blob `2e87719c294bfd4225fe46fc62da529d9404bda5`) and R179's specific source synopsis (blob `19fc5ad47bd12a2d602c094b1e98835ce55f2aa5`), plus latest relevant ordinary PR comments. Checkpoint `CHECKPOINT_01.md` was saved as an intermediate before this final commit. No web/external literature, independent agent or production-code changes.

The actual locally executed Python checker, `captured.json` and `MANIFEST.json` are archived in `EXECUTED_CHECKER.tar.xz` (xz-compressed tar, Git blob `63df9c6eaee62652dd5f0b4b0b7814ae2c0da585`, SHA256 `32a3f688ab5567de4abf3cd64f29dceabc2cfec9d8af92e2e5efb6d573632ad7`). Extract using `tar -xJf EXECUTED_CHECKER.tar.xz`. The original unarchived source SHA256 `f62d414162d29bc9f8be613497cfb3ecbb17b9438250d63e9f51d9fec9a95668` and output SHA256 `871bda616114e01cf28469e36c14a32bc90bd392d60d45c4c109dbe37e796048` are in the manifest. Two final local runs were byte-identical (640 *functional* assertions, 64 samples). First initial execution failed because the fixture omitted a one-byte CompactSize length before a coinbase output script; fixed offset 8 to 9 before final runs. No QPT experiment, live mined work or real signature verification occurred.

## Candidate: Branch-Anchored Annex Claim (BAAC), source binding only

With a fixed-body two-input Bitcoin activation transaction T, input 0 is an already N-of-N-preauthorized vault spend; input 1 spends an allocated one-of-N notary authorization token. Eligible notary chooses a short claim digest a in **input 1's own annex** and signs that input with a sighash committing to its annex. The canonical withdrawal amount, recipient, outpoints, outputs and cancellation graph remain fixed. It is NOT an arbitrary dynamic-value Bitcoin covenant.

For distinct annexes a and b, holding T's non-witness bytes identical:

    txid(T,a) = txid(T,b) = SHA256d(stripped(T)),
    wtxid(T,a) != wtxid(T,b) unless SHA256d collides.

With BIP341 SIGHASH_DEFAULT, no ANYONECANPAY, and input-0 annex absent, the input-0 native signature digest binds transaction-wide prevouts, amounts, scriptPubKeys, sequences and outputs but only its **OWN** annex. Input-1's annex digest is included in input-1's sighash, not input-0's. Consequently,

    SigMsg_0(T,a) = SigMsg_0(T,b),
    SigMsg_1(T,a) != SigMsg_1(T,b) except hash collision.

Thus one honest N-of-N participant's preauthorization signature cannot by itself restrict which claim digest a malicious eligible notary later signs in input 1. The notary can sign two different annexes for the *same txid*, with two distinct witness transaction IDs. A bare notary signature or txid-level commitment is insufficient to establish which claim was **actually mined** in the relevant Bitcoin history. This is a source-relation issue; N-of-N does not fix it.

## Concrete authenticated repair and conditional collision extraction

For a two-transaction synthetic block (coinbase and activation), let

    witness_root(a) = SHA256d(zeros32 || wtxid(T,a)),
    witness_commit(a) = SHA256d(witness_root(a) || coinbase_reserved32).

The commitment appears in coinbase output script `OP_RETURN 0xaa21a9ed || witness_commit`. Coinbase txid commits to this output; Bitcoin header's ordinary txid Merkle root commits to the coinbase txid and the activation's txid. Therefore distinct annex variants require distinct witness commitments/coinbase txids/header transaction roots (absent a hash collision).

If a valid Bitcoin header, coinbase proof and witness-Merkle opening at a fixed index are qualified and anchored, two different annex/wtxid claims cannot both pass under the SAME anchored parent commitment without a SHA256d collision. Extractor: if wtxids first differ but resulting witness root matches, examine the first Merkle merge where unequal ordered inputs produce the same digest; otherwise if witness root/commitment changes yet two different coinbases produce the same parent txid-Merkle root, extract a collision at coinbase txid/parent Merkle layer. This is straight-line extraction from *classical proof outputs*, including an arbitrary QPT adversary's classical output, under an independently required QPT hash-collision assumption; it is not a QROM proof of WKEM secrecy.

Correct ORIGINAL challenge input is therefore the **actual** `(qualified BTC block hash, tx index, wtxid, annex digest)`, plus signed input-1 claim and relevant window/anchor—not just the pre-signed txid or hypothetical assertion. Challenge 1's competing BTC work can reorg the activation itself; same txid with distinct wtxids on competing chains must be treated as different activated claim evidence, with canonical-history/reset semantics and data availability. Source ancestry/PoB and challenge 3's AuxPoW evidence must bind to THAT activation. No arbitrary private header is promoted to Bitcoin-main-chain membership.

The fixture actually serializes stripped/witness Bitcoin transactions, computes SHA256d txid and wtxid, reconstructs BIP341 key-path **digest only** (not Schnorr signing), coinbase witness commitment, and synthetic header transaction Merkle root. 64 different annex pairs yield exactly the above invariances and cross-commitment rejections. This confirms byte-level dependency only, not Bitcoin consensus inclusion/difficulty, actual Syscoin tags or native PQ-P2MR rules.

## Can this repair cryptographic release?

No. The frozen cancel signature on the fixed-body graph is useful because it can remain the SAME authorization across later annex variants; but the *ciphertext*, built before activation, must still discriminate the actually mined witness against a hypothetical but notary-signed unarmed claim. The dynamic annex broadens the ORIGINAL input domain: the honest N-of-N setup cannot choose one canonical annex later signed by the notary.

Trying `K=E XOR H(wtxid)` changes the derived pad across valid activated claims. One public correction E fitted before activation does not produce the same K for all qualified future variants. Replacing wtxid by the fixed public txid makes the pad publicly computable before any challenge. This is a correctness/secrecy diagnosis for those specified pad forms, not an impossibility theorem for hash-only witness encryption or a full-program QPT attack.

The exact uninstantiated algorithm remains

    Build_hash(x_slot, frozen_sigma_cancel) -> C   [before activation; classical PPT]
    Open_hash(C, activated_BTC_evidence, original_challenge_w)
       = SAME frozen_sigma_cancel for EVERY qualified ORIGINAL challenge
    unauthorized full-public QPT recovery/native forgery
       -> ACTUAL qualified witness for one of 3 original conditions
          OR independently justified QPT hash/native security break.

The FULL public simulator must cover three OR branches, all source commitments, native VK, preauthorization manifest, arbitrary malicious notary coins, sibling capsules, aux input and selective openings. A publicly readable verifier that returns an embedded secret is bypassable. An online notary or source-signer key release, false PoW header, standalone hash puzzle, lattice/group-wrapper or Bitcoin NP/VM/trace verifier is not substituted.

## Actual limits and next work

BIP341 annex/signature semantics are for the *pinned current Bitcoin-like rules* only; a proposed hash-only no-EC-key-path PQ native endpoint must specify equivalent input-local witness commitment behavior and is not presumed deployed. Full source-chain validity, canonical/qualified BTC history, actual child AuxPoW and interval tags, PoB soundness, source observation/reset timing, malicious graph ceremony and pre-funding DA remain open. The checker is a source-binding test, not end-to-end bridge testing.

**Next construction:** invent a classical-PPT hash-only **nonlocal hidden cross-witness release correlation** that authenticates the activated Bitcoin wtxid internally and converges every valid ORIGINAL challenge (heavier conflicting BTC work, invalid/missing bound PoB, or qualified Syscoin AuxPoW history inconsistency) to the frozen native cancellation capability, with a joint-public arbitrary-QPT extractor. The activation-binding lemma is a necessary source statement input, not a replacement for the missing release function.

No ordinary PR progress comment: R182 does not satisfy the constructive-release reporting threshold.