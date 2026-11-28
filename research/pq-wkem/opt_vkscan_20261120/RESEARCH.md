# OPT-VK — native verification-key scan of opaque terminal pads (NONQUALIFYING)

## Exact continuity / candidate repair

Current draft syscoin/PVUGC PR #1: branch `research/pq-wkem-validation-20260918`, start head `fdcb72776e6c43431df4ab6a0c28495f3702cbdb`; current latest research file `research/pq-wkem/otp_opaque_path_fold_20261120/RESEARCH.md` blob `70c634546e38f23771e69c7f6de94cb683f798ad`. Ordinary comments queried since 2026-11-18T19:24 UTC returned empty. No Core reread, external web, other repos, Core tests or genuine source certificates.

OTP's exact remaining repair was to conceal accepting *semantic status* and terminal-pad identities among hash-opaque rows while keeping a publicly executable polynomial-size finite-state transition compiler. Instead of broadcasting an explicit `Accept_C(t)`, let the terminal row(s) contain an encrypted **native signature** and conceal which row carries the actual cancellation signature. A natural hope is that revealing no acceptance labels defeats public source-free exploration. This note evaluates that exact change, using the actual publicly testable native verification key and fixed cancellation message already included in the original x_W.

## Model and proof: terminal-pad candidate scanner

Let `Step_C(j,t,b)` be a deterministic, publicly executable branch transition for b in {0,1}; t is a copyable opaque byte string. Let B be an upper bound on the total distinct reachable (j,t) pairs; the builder writes polynomially many such labels/transitions. Let the fixed claim/message be (x_W,m_W) and VK_h the native public key for an honest one-of-N setup participant.

For the fixed-cancellation endpoint, suppose public terminal rows i in a set I of polynomial size have serialized pads `D_i`, and prescribed `Open` at a reachable terminal t computes a candidate
`candidate(i,t)=Decode(D_i XOR H("OPT-VK/pad"||sid||i||t))`
with public Decode/Hash. Suppose that for at least one reachable pair (i*,t*) this is a native signature sigma_h accepted by `NativeVerify(VK_h,m_W,sigma_h)`. Rows for nonaccepting terminals may be random; the accepting status/index need not be visible.

**Exact scanner:** starting at the public t0, compute all reachable tokens by branching on both input bits and deduplicate equal (j,t). For every reached terminal token t and every row i, compute candidate(i,t) and run NativeVerify(VK_h,m_W,candidate). Return any accepted signature.

**Correctness and cost:** the OTP equality/closure lemma proves that deterministic public Step reaches every reachable terminal class in at most 2B step calls and O(B) token/edge memory. The new scanner makes at most `|I| * B_L` hash/decode/native-verification attempts, with B_L<=B, so it is polynomial whenever B and |I| are. On the stated completeness premise it returns an accepted native cancellation signature **without producing or processing any ORIGINAL source witness**. Hiding semantic state names, accepting labels, terminal-row IDs, or disguising the winning row does not help. The existing *public* BTC signature checker, rather than a hidden row's semantic meaning, is the acceptance oracle.

The proof does not need the unique frozen signature bytes. If a different candidate verifies and safely spends the same protected outpoint, that is still unauthorized cancellation. For N independent capsules guarded by native N-of-N, colluders may already possess their N-1 signatures; this scanner applied only to the honest participant h suffices for the remaining signature. The theorem is classical and therefore included in the QPT adversary class. It is not an attack on a generic FE scheme, a QROM programming result, or proof that the ORIGINAL relation is easy.

If the source verifier's accepted path is inaccessible to this scanner, some premise must change: e.g. exponentially many distinct reached tokens, an unimplemented non-copyable/source-authenticated transition, or a terminal decryption operation that genuinely requires proof material beyond the public token/row. The latter is **exactly** the missing source-dependent cryptographic release gate and cannot be replaced by a normal VerifyOriginal check outside the protected computation.

## Executed source-free native-key regression

A local standard-library Python + `cryptography` checker built a **synthetic** deterministic 18-layer/7-state opaque-token transition DAG (actual reachable set checked), encrypted a real secp256k1 ECDSA signature for a *fictitious fixed cancellation message* into one of seven shuffled opaque terminal rows, filled other rows with random bytes, and deliberately published no accepting-state flag. The attacker traversed both branches, tried every reached terminal label against every row, and accepted candidates with real ECDSA verification.

Final checker was actually executed twice, returning byte-identical JSON:
`{"candidate_signature_trials":49,"depth":18,"private_semantic_states_used_by_attacker":false,"qid":4,"real_fe":false,"rows_per_layer":7,"source_certificate_used":false,"step_calls":224,"synthetic":true,"terminal_tokens":7,"verified_candidates":1}`.

The first draft of the fixture **failed** because its chosen transition permutation made terminal q=4 unreachable: that failed run is not counted as evidence. The fixture was corrected to a reachable q=4 and then executed twice successfully. Source SHA256 `bd81ff57b95c988e7be943ec38a7ea402fb8ead08e070531875e7f3068930e95`. Each final output SHA256 `0151ac15f5de0f7415113e48ab8ee1dbfacbc04382c42e70190402204ca88975`. Python 3.13.5, cryptography 46.0.4. Local-only archive `/mnt/data/pq_otp_vkscan_20261120.tar.gz`, SHA256 `faf8a70f2232c94698e74a2e99e8e1c8590721781547ee2d9107e181d07db5b1`. Archive contents are **not** committed to GitHub and must not be assumed accessible in a future execution.

No Bitcoin VM test, native network transaction, authentic source inconsistency, FE, quantum test, malicious setup or hard-TRUE source reduction was performed. The synthetically generated ECDSA key is local test material, not a funded key.

## Constructive next decision, not a release claim

A polynomial-output-table / polynomial-reachable-state approach with public candidate generation cannot be repaired merely by concealing terminal accepting bits; the native VK collapses uncertainty over which pad matters. Do not iterate row obfuscation, hidden accept flags or nonce changes in this family. A genuinely new candidate must give an **explicit serialized classical-PPT** public algorithm in which *an actual source certificate* cryptographically controls the production of the honest native signature and cannot be replaced by exhaustive public row/label scanning. It must also preserve one frozen claim-bound capability for every qualifying ORIGINAL witness; separate three OR challenge branches; prove complete-public FALSE and hard-TRUE QPT recovery/forgery-to-ORIGINAL under correlated auxiliary/setup/multi-capsule inputs; and not rely on a private FE evaluator or an online signer.

This is a restricted rejection of one precise OTP repair, **not** a hash-only WE impossibility proof or missing-source-breakthrough advancement. No user breakthrough notification or ordinary PR comment is warranted. No production/Core edits, deployments, funds, or automation changes.
