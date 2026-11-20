# R399 — Claim-ticket activation with fixed N-of-N preauthorization (endpoint-only; NONQUALIFYING)

## Continuity and selection
Read live open/draft syscoin/PVUGC PR #1 on research/pq-wkem-validation-20260918 at 62c96fd4f8cd8ee1d0fe68f3800f65d6f0e6a329 (R398). Exact R398 note blob edc6bf78805accdd6757b218083d95205a08cea6 and R397 note blob f1452084a76c34ccce422d448e333664b00b3509 were read; recent ordinary issue comments since 2026-11-18 returned none. No Core #609 source/tests, live Bitcoin/Syscoin certificate, Bitcoin VM, FE, ZK, or quantum test was executed. This is one indispensable native endpoint/security component, NOT the missing source-conditioned release.

The FE assessment at 69d4a071 described a claim-dependent activation output. A fixed pre-signature over that output cannot then cover unpredictable later claims. R225 separately warns that an off-chain capsule/wtxid label does not limit a native signature already released for a fixed common outpoint. The distinct proposed repair below binds the future claim by changing an attached **input**, keeping the pre-signed **output vector** constant. The preliminary SIGHASH_SINGLE|ANYONECANPAY idea was tightened to **SIGHASH_ALL|ANYONECANPAY** after the adversarial check exposed its unnecessary freedom to append/reorder outputs.

## Selected construction (BIP143; conditional graph, NOT a complete bridge)

Setup knows one immutable native SegWit-v0 vault outpoint u_v with amount V, a P2WSH script that demands both N-of-N preauthorization signatures and an additional authorized one-notary signature on that SAME vault input. It freezes the activation output vector to exactly one output out_0=(V, P2WSH(session_script)). All N participants make signatures on the vault input with sighash byte 0x81 (SIGHASH_ALL | ANYONECANPAY). For this input, BIP143 computes:

  hashPrevouts = 0^256
  hashSequence = 0^256
  hashOutputs = SHA256d(serialize(the ENTIRE fixed output vector))

and additionally binds the vault prevout, witness scriptCode, amount, sequence, tx version and locktime. Because the actual output vector is fixed but the **other inputs are excluded**, those N setup signatures work on a later transaction with a new claim ticket input. Unlike 0x83 SINGLE|ANYONECANPAY, 0x81 rejects all appended/changed outputs. With output0 value exactly V, the added input must fund fees.

At initiation, ONE authorized notary creates a spendable ticket UTXO whose creating transaction has an exact nonwitness output script commitment H(canonical_claim), and then creates the activation:

  input0 = fixed vault outpoint u_v
  input1 = outpoint of this particular claim ticket
  output0 = the fixed (V, session_script) already preauthorized

The notary supplies the additional signature on **vault input0** with SIGHASH_ALL, binding the complete input/output set. A production vault script must enforce N-of-N CHECKMULTISIGVERIFY AND an authorized one-of-M notary signature with no alternative subset/bypass edge. The ticket input also requires its own valid spend witness. Neither native script execution nor 1-of-M code was tested here.

The activation nonwitness txid commits the ticket input outpoint, whose txid commits H(canonical_claim). Therefore two differently committed claims yield distinct activated outpoints u_A=(txid(A),0) and u_B=(txid(B),0) under collision resistance, even though the N frozen activation presignatures are byte-identical. A cancellation native SIGHASH_ALL signature spending u_A is not valid for u_B. The future cancellation message and native signature itself cannot be frozen before u_A is known. Consequently a **dynamic protected signer** or some *explicit fixed slot-global veto* is still required; calling the future signature a previously frozen signature would be incorrect.

## Adversarial requirements and limitations
- The 0x81 preauthorization alone is deliberately reusable for any additional input set, so the **same-vault-input** notary signature gate is essential. A malicious authorized notary may still attach a malformed/missing ticket; a safe whole-UTXO recovery policy must not make this an unchallengeable withdrawal. Authenticating a source fault and permitting cancellation remains the unresolved FE job.
- 0x81 binds ALL outputs, but not the vault input's position among the inputs: moving the vault input to index 1 while leaving the output vector intact retains the setup signature. Off-chain policy/manifest validation must enforce canonical positions and claim-ticket identity, and the notary's SIGHASH_ALL binds the particular assembled transaction. Do not falsely claim native script introspects the other input or enforces its semantic claim.
- Ticket txid commits claim BYTES, not correctness of a burn, reserve, recipient, authorized source baseline, or chain history. A protected signer must check the complete ticket creation/spend, actual activated outpoint, all relevant source anchors and original challenge evidence, rather than trust notary metadata. A missing/fabricated ticket must have a safe finite fault/recovery policy.
- Two competing activation transactions spending the same vault UTXO cannot both confirm. A watcher must bind release to the actual confirmed activation and time window; old cancellation signatures must not authorize another activation.
- The session script requires a safe conditional payout/timeout path; the test only models N-of-N cancellation, not whole-UTXO settlement, BitVM emulation, fee policy, native script stack admissibility, or additional frozen pre-signed descendants. For future activation txids, any descendants with precommitted exact outpoints have the same circularity unless independently repaired. The session owner cannot simply bypass the protected cancellation window.
- Funding must not become irreversible until one-honest setup verifies the graph/manifest, preauthorization, capsule correctness/DA and all bypass edges. No claim that an FE capsule has been built or can be proven well formed is made.

## Executed bounded component check
A Python 3 standard-library BIP143 preimage implementation plus cryptography secp256k1 deterministic low-S ECDSA checked an earlier-recorded published native BIP143 digest vector:
  c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670.

Three PUBLIC TEST-ONLY participant keys and one test notary key, invented vault/ticket transactions, two different claim-committed tickets, and a changed-output variant were used. Two final independent executions exited successfully with identical JSON results. They established:
- Three 0x81 pre-signatures are valid with either claim ticket and have exactly identical BIP143 digests.
- Appending a change output changes the 0x81 digest and invalidates all pre-signatures; reordering input positions can preserve it, confirming the explicit limitation.
- The notary SIGHASH_ALL signature cannot be replayed against the other ticket or changed output.
- The different claim-ticket activations have different txids. Three separate cancellation SIGHASH_ALL signatures for one activation fail verification for the other activation and for an alternate recipient.

An intermediate attempt to insert the BIP143 vector accidentally included a quote in the hex literal, threw ValueError, and generated empty temporary output files. Those runs were corrected and NOT counted. Checker SHA256 d5a7442d99ec871a2cda476cff27f5e9ff9064e1e10899d9cf1b89e6807ce2a4; each final JSON output SHA256 a590f930258844238b2d526d88b913c0e1cf4aeb0da1097479322dc80ac7aec0. The executable checker and paired outputs are **LOCAL ONLY**, not committed; archive R399_claim_ticket_binding_20261120.tar.gz, SHA256 fa1c75736e1cd06c6f69fa59b2d29b045b5ddd9e906ba27304881d9905888e45. A sandbox path is not presumed durable beyond the current execution.

## ORIGINAL-source release remains unsolved
This candidate is not an FE/WKEM instantiation. It makes no progress on public source-dependent hidden key release or the full-public QPT theorem. The still missing independently instantiated classical-PPT operation, for the fixed session and *future* activation, is:

  C_i = Compile_i(x_session, sk_i, agreed_graph; rho_i)
  RestrictedSign_i(C_i, A, T_cancel, w)
    = Sign_i(NativeSighash_ALL(T_cancel))
      iff R_ORIGINAL(x_claim(A), w)=1
          AND A, its ticket and exact safe T_cancel satisfy the precommitted policy.

For any single qualified ORIGINAL witness from the BTC-greater, finite authenticated burn fault, or sufficiently deep authenticated Syscoin inconsistency/tag-fault OR grounds, every valid independent participant capsule must produce the same agreed safe authorization for this activation/message, with no online participant and no signature for an unrelated claim. The full-public FALSE/hard-TRUE QPT reduction must turn arbitrary unauthorized cancellation into an actual qualifying ORIGINAL certificate or independently justified hash/native break, including malicious setup/source mining coins/auxiliary correlated transcripts and sibling openings. No such compiler, security simulator or source-certificate extractor was constructed here. Native ECDSA first-release signatures are not PQ signatures. No Core/production write, deployment, ordinary PR progress comment, or automation change.

**NONQUALIFYING**: endpoint-only checkpoint; no user breakthrough notification. Resume work on the missing hash-only source-release compiler, not transaction-graph optimization.