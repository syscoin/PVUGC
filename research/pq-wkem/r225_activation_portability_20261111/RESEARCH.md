# R225 — Cancellation capability portability across same-txid Bitcoin witness variants

**Disposition: material conditional source/endpoint scope correction, NOT a secure hash-only Build/Open, native PQ implementation or general NP result.** The original challenge relation must decide whether a frozen cancellation signature is intentionally a slot-global veto or is supposed to authorize cancellation of only one later witness-selected assertion.

## Continuity / provenance

syscoin/PVUGC PR #1, open/draft/unmerged, branch research/pq-wkem-validation-20260918, observed initial SHA 94de79d21bda30b57245ce0b6e0cee6c6b5f9525. Read R224's source-labels research blob 5e864459e396c4f200137b6ced04600da9fc7527, related addendum/checkpoint, and R216 slot-universal research at 6da61eaa132ffca1792ed4de44ba36cffc3286d1. PR issue-comment query since 2026-11-10T00:00Z returned []. Intermediate local CHECKPOINT_01.md written BEFORE the local checker and retained here. No external web or literature, independent agent, new production code, real source mining or QPT experiments.

Executed offline Python-stdlib full local checker twice, with byte-identical output: 64 synthetic slot seeds × 8 assertions = 512 checks. Full local checker SHA-256 240d848cf2fc6ca2cf46019be9a34cc35f1b5763679d23be; captured JSON SHA-256 dc03a980e356f33ec87cf9e35bf092fd6563d6f9fa65cca9421c2b73e79cb4d7. The *independently executed, publishable* smaller repro.py also ran twice with byte-identical repro_output.json, 32 seeds × 7 assertions = 224 checks. Source and output are included unchanged below and their Git blob identities should be verified after commit. The short script is explicitly NOT a Bitcoin source or native signature implementation.

## Exact conditional native portability fact

Let an activation's base/nonwitness transaction serialization be B and its later witness be W(a), selected and signed by one authorized notary. SegWit hashes the nonwitness serialization for txid T=SHA256d(B) but the complete serialization for wtxid. Two otherwise valid witness variants W0,W1 on the same B have

  TxID(B,W0) = TxID(B,W1) = T,
  WTxID(B,W0) != WTxID(B,W1) [barring equality/hash collision],
  Output(B,W0) = Output(B,W1) = U=(T,index,value,script).

If a frozen N-of-N cancel path signs a fixed native message M(U,refund-outputs,script-path,...) that does **not** include the creating transaction's witness (the standard UTXO spend model absent new introspection), then M is identical across the two histories. Consequently the same frozen cancellation signature or N-of-N signature package is valid for the UTXO on both histories. The actual Bitcoin blocks can have different witness commitments: authenticating W0 versus W1 does not change U or M. This is a functional identity, not a SHA inversion or forgery.

**Conditional transfer theorem.** Suppose genuine authenticated source histories H0 and H1 include respectively (B,W0) and (B,W1). H0's asserted burn is valid, so no claim-specific R2 fault exists there. H1's activation assertion genuinely lacks the bound authorized burn, and the ORIGINAL source-admission predicate accepts H1 and its finite nonmembership/refutation witness w1. A PERFECT public release gate for the slot relation must output the frozen signature sigma on (H1,W1,w1). That revealed sigma then verifies on H0's identical native cancellation message, even though H0 is fault-free. This is a straight-line consequence that holds with any hash and even an ideal release gate. It is **not** FALSE-instance leakage if the protocol deliberately defines a single fault on any admitted activation as reason to cancel the whole slot.

The premise that H1 is admitted is crucial. A fabricated Bitcoin header, unrelated orphan, invalid coinbase tag, unconfirmed assertion or unmined witness does not qualify. If source rules admit only an activation relevant to the actual anchored withdrawal history, the example does not yield an ORIGINAL witness. If R1 already admits a comparable heavier BTC fork, canceling the old branch is intentional. An indiscriminate 'any apparently mined alternative activation' policy can instead permit griefing through a cheaper competing fork. State root/height, BTC ancestor work/window, burn root, claim, exact UTXO and observation qualification must be original verifier inputs, not attacker-chosen booleans.

## Exact repair alternatives / explicit tradeoff

1. **Slot-global challenge policy.** Explicitly define R_slot(v)=there exists an admitted activation of slot v with an authenticated R1/R2/R3 fault. One valid original witness unlocks a bearer native cancellation authorization reusable wherever the slot's UTXO exists. This is coherent with N-of-N preauthorization and one-of-N runtime notary operation, but malicious-notary cross-fork admission needs stringent economically meaningful source bounds. It does not solve hash-only encryption.
2. **Activation-specific UTXO.** Commit the assertion in nonwitness transaction bytes (e.g. an output), so different assertions yield different txids and cancellation messages. The checker verifies this representation separates the two variants. But unknown later claims now have unknown outpoints; an exact native N-of-N cancel signature cannot be frozen before the claim without constrained preenumeration, a new signing round, or an extra on-chain covenant/introspection facility (disallowed by the current assumptions).
3. **Freeze claim before funding-enabling preauthorization.** If the notary's exact assertion can be fixed at setup, N participants can sign that claim-specific cancel path in advance; this changes the timing of the R191 universal-slot design and may not meet the one-notary later-choice requirement.

Merely including later wtxid in a public capsule root, AEAD associated data, checking key or off-chain original verifier does NOT alter a native signature's post-release verification message. After release, a claim-scoped restriction is enforceable only if the native spend itself is claim-scoped (or if whole-slot veto was intended). The signature can be cryptographically protected before Open and still be transferable after Open.

## Executed bounded reproduction and limits

The published short checker uses correct Bitcoin-like SegWit base vs full transaction serialization for txid and wtxid, and asserts unchanged txid, changed wtxid, identical abstract cancel message, the conditional availability of a genuine R2 witness on alternate branch, exclusion by a stricter source policy, and distinct txids/messages when a claim-dependent nonwitness OP_RETURN output is included. 32 slots × 7 = 224 checks, run twice with byte-identical output.

Source admission flags are **abstract**: no real Bitcoin PoW, best-chain/retarget, coinbase/witness root, Syscoin AuxPoW/tag, actual burn nonmembership, native SLH signing, malicious setup or QPT attacker was implemented. The stronger 512-check local-only checker uses synthetic branch commitments and an HMAC test signature, not native PQ. Tests are regression checks on the scope identity and cannot prove witness encryption.

## Exact next constructive obligation

Choose one explicit policy at pre-funding: if frozen M_v is slot-global, define the full ORIGINAL R_slot quantifiers over all admitted future activations and BTC/SYS histories. Then construct, not merely name,

  Build_hash(R_slot,v,sigma_cancel; coins) -> C_v
  Open_hash(C_v, any ORIGINAL qualified (a,auth,j,w)) = SAME sigma_cancel

for *every* authorized witness, with classical PPT algorithms. Arbitrary QPT unauthorized native signature recovery or forgery from full public C, checking keys, native VK, related capsules and auxiliary source data must lead to ACTUAL R_slot evidence or independently justified PQ hash/native break. The missing source-dependent cryptographic correlation remains uninstantiated; this note only corrects the native endpoint's scope. Source participants retaining their own secrets, externally generated independent PoW, synthetic tags, online label issuers, public-gate labels and ZK proof acceptance without ORIGINAL extraction remain unacceptable.

No routine PR progress comment is warranted solely for regression checks. This may merit a correction notice specifically to R191/R216 if those claims were read as proving activation-specific cancel authorization.
