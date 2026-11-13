# R261 — slot-global witness-scope normalization (NONQUALIFYING)

This is a protocol/Bitcoin-endpoint component only, **not** a source-conditioned hash-only WKEM, QPT proof, native Bitcoin PQ implementation, or deployment recommendation. It fixes the R225 creator-witness portability issue **only under an explicit slot-global veto policy**, at an accepted liveness cost. The actual Build/Open security foundation remains absent.

## Source/provenance

PVUGC PR #1 branch `research/pq-wkem-validation-20260918`, checked start head `bdbd8b96d588f757bf0fd8fd7053f3a49ad63786`. Read R260 research note at blob `135232a278a3839d2e9c03ae83812ddf2f705c86` and latest top-level R225 comment `6796383617`. Core #609 metadata at `c91539de3c34937e57d7f5fda47c7b0502ff33f6` was read; **no new contextual validation audit or Core tests**. The user-supplied validated canonical-tag baseline remains in force. No production code changed.

## One frozen Bitcoin outpoint, multiple witness variants

Freeze the complete nonwitness activation transaction B before irreversible setup; t=SHA256d(B), U=(t,j), native safe cancellation transaction T and exact native message M(U,T) signing all protected inputs/outputs, UTXO script/amount and safe destination. SegWit creator witness variants W0 and W1 can have distinct wtxids but the same t, U, output script/amount and native spend-validation view. Thus if source evidence about W1 releases a frozen native sigma on M, that sigma also authorizes cancellation on an admitted W0 history with the same U. Adding wtxid(W1) to an *offchain* capsule cannot make Bitcoin's native verifier distinguish the creator witness. A variant-exclusive policy therefore fails unless a different enforceable Bitcoin spend message/output/commitment exists. This is an identity-of-verification-inputs argument, independent of any WE hardness assumption.

## Constructed policy / fixed statement

Choose the explicitly permitted SLOT_GLOBAL_VETO semantics: a **qualified** fault on *any* independently source-admitted variant for fixed U may cancel U across all histories. This makes portability intended, but a valid W0 payout can be vetoed due to a faulty W1: an explicit griefability/liveness tradeoff, not a proof that W0 is invalid.

Freeze one public statement `x_slot=(protocol/network/chain IDs, B_nonwitness, U and UTXO script/amount, safe native cancel transaction/sighash/VK, original burn/claim/recipient/amount, authenticated baseline claim-prefix anchor, BTCC/Bitcoin anchors/work window, Syscoin reference-height/fork-depth/relevance rules, deadlines/reset, capsule ID, SLOT_GLOBAL_VETO)`. **Do not freeze unknown future activation wtxids.** A witness `w=(branch, optional creator variant v, complete source evidence)` must supply independently qualified original (1) strictly higher competing BTC chainwork, (2) finite claim-bound burn/authorization fault, OR (3) authenticated Syscoin claim-prefix AuxPoW divergence / separately admitted source-assertion tag fault. Any creator variant included must be proven to have the SAME nonwitness B and an admissible source inclusion. All actual SHA256d, AuxPoW, 41-byte tag, modern-ID, contextual history, fork relevance, Bitcoin anchor, deadline and timing checks remain essential. This is one fixed potentially polynomial-time bounded *verification relation* without enumerating future wtxids, not a release algorithm.

Native-portability lemma: If U, UTXO amount/script, signed M and native VK are identical on two admitted histories, the native verifier cannot distinguish W0 from W1; the same sigma spends U in both. Source qualification must not be weakened to a Boolean supplied by an untrusted witness. Arbitrary raw/private work and unrelated faults do not qualify. Safe T must have no unrestricted spend path or loose SIGHASH mode. All native-PQ assumptions remain conditional.

## Cryptographic release remains unsolved

The actual required algorithms are still classical-PPT `Build_slot(x_slot,sigma;r)->C` and publicly executable `Open_slot(C,w)->sigma` for **every** ORIGINAL qualifying w, with complete-public unauthorized arbitrary-QPT exact-sigma recovery/alternative native forgery reducible to an ACTUAL qualifying original source certificate or an independently justified PQ hash/native break, including malicious setup and sibling capsules. No such Build or Open was constructed.

A variant-specific XOR pad using `H(wtxid(v))` cannot be frozen for unknown future v and leaks immediately if the published ciphertext and v are public. A slot-invariant XOR pad using `H(slot_id)` converges for all v but is public at setup, so it leaks immediately. Invoking a hypothetical `WE(R_slot)` does not instantiate it. A software `CheckSource` after raw decryption is not enforcement. Slot-global normalization reduces the *endpoint scope mismatch*, NOT the cryptographic original-source obligation.

## Actually executed limited reproduction

A local Python SHA256/BIP141-style serialization checker ran twice with byte-identical output. Across 128 distinct frozen nonwitness activations, it checked 10 groups each: shared txid, differing wtxid, same abstract native cancellation message, insufficiency of offchain variant isolation, distinct native messages for changed U or safe output, and symbolic admission rejection for irrelevant, late, unqualified and different-slot evidence (1,280 groups). The source predicate uses an explicitly **untrusted Boolean stub** for `source_ok`, not consensus proof verification; the native message is an abstract commitment, NOT a real Taproot/P2MR sighash or PQ signature. No actual BTC/SYS admission, real WOTS+/SHA witness encryption, quantum attack or Bitcoin native PQ opcode test was executed.

Local code SHA256 `46841b1dcdcce852833b8d04809a6d95483d6eee0588238908b862cba4ab84f1`; output SHA256 `3989a17f666f35abef5a9c869e9099024d8b16fff05cdaf8c8ce7872a093a71b`. Initial/intermediate checkpoints SHA256 `2164c752382469ba4129d6f75e13a5e75e39dfc3caaec3ee4db634acf280d882` and `ce98a97fd0356dd086958568619602996a9e4ee4361b8085fd5e804188a9e6da`. Full derivation/checker/result are in the local archive; this note must not be treated as proof those scripts were uploaded.

**Next**: return to source-conditioned cryptographic delivery on this precisely frozen slot-global ORIGINAL relation, not further endpoint optimization. Do not notify for this nonqualifying component.