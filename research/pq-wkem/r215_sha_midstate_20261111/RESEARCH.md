# R215 — genuine SHA256d midstate source-label candidate, bounded construction/repair

**Result: rejected source-label family only. No secure hash-only ORIGINAL Build/Open, no QPT theorem or claimed research breakthrough.**

## Continuity / model
syscoin/PVUGC PR #1, draft/open, branch `research/pq-wkem-validation-20260918`. Initial head `de9eaa91976049a12fd11f245e0cda98c07bbcf0`; prior exact R214 source-label note read, blob `6a44593a4990671777506995f16d7cc0d7ef875d`. Intermediate hypothesis checkpoint published BEFORE tests as `4951e6f7d48a22e2a24c2405638a036f6a99f6dd` and read-only PR comments since 2026-11-10T23:00Z were empty. No web, independent agent, unrelated repository, chain mining, native signature or quantum computation.

Original target unchanged: a single one-notary activation on an N-of-N preauthorized graph; ANY watcher with an actual qualified (R1 contradictory higher BTC work OR R2 authenticated missing/invalid bound PoB OR R3 authenticated, adequately deep claim-prefix Syscoin inconsistency / separately admitted tag fault) witness must recover the SAME previously frozen, claim-/UTXO-/path-specific cancellation authorization OFF CHAIN. Preserve exact BTC source anchoring, real AuxPoW/coinbase/tag/ancestor rules, interval/lag/window, true source claims, full public context, malicious setup and QPT security. These experiments are not the ORIGINAL source witnesses.

## Named candidate: authentic SHA256d source-midstate label

For 80-byte Bitcoin parent-header form `p||n`, with 76-byte template p and 4-byte nonce n, let `D(p,n)=SHA256(SHA256(p||n))`; a valid header has `D(p,n)<Target` alongside contextual consensus rules. Try (i) `L_mid=Compress_SHA256(IV,p[0:64])`, the first-block midstate; (ii) `L_prefix=top_k(D)` at target `2^(256-k)`; (iii) `L_late=D(p,n)` or late SHA internal state. A factorized capsule would seal `E=sigma_cancel XOR H(domain,x_W,L)`, precomputed by Build BEFORE future work, then every genuine Open would derive L from actual source SHA/AuxPoW evidence.

### What the real hash arithmetic establishes

A: For varying nonce n but fixed first 64 bytes of the header, SHA256's first-block compression midstate is fixed. Critically, it is also publicly computable BEFORE any mining from the public bytes `p[0:64]`. Thus a capsule sealed under that common label is immediately decryptable without any ORIGINAL witness. The full local checker computes the genuine 64-round SHA256 compression (verified against `hashlib`) and directly tests this early opening.

B: Under a target `2^(256-k)`, every accepted hash's top k bits are zero by definition; the shared output prefix is public target information. It also decrypts the factorized mask without mining.

C: The full digest or nonce-dependent late trace varies across valid nonce solutions. Build cannot precompute a single mask from one unknown future digest and have it work across arbitrary other future qualified witnesses. The checked sealed key using one solution failed to recover the same sigma using distinct solutions. The finite tests establish examples, not cryptographic collision-resistance bounds or a generic impossibility.

D: For actual AuxPoW, competing child commitments/coinbases can change the parent Merkle root, 28 bytes of which lie in the first SHA256 header block. Therefore the first-block midstate common to nonce solutions for ONE header template need not be common across alternative genuinely qualifying parent templates. Two distinct synthetic Merkle templates gave distinct computed midstates.

E: Adding an honest builder's secret salt s behind a public H(s) in a coinbase commitment does not make its preimage available from ordinary future source work. A miner that knows s can disclose it before a qualifying event; a miner that only sees H(s) cannot generally reveal s in a valid source certificate. An honest participant publishing s only after a challenge would introduce an online release issuer. This is the source-to-secret timing gap R214, not a repaired interface.

F: Requiring a future header to solve an extra secret-dependent setup puzzle would silently replace ORIGINAL evidence with independent work and is outside scope. A public source-authentication *if-check* before factorized decryption does not stop direct public extraction.

## Exact executions / limitations

A local full-checker in Python implements SHA256 compression and 80-byte double SHA256, tests two synthetically constructed header templates, ten nonce solutions each, artificial 12-bit work threshold, 29 assertions, twice with matching output. Local full-checker SHA256 `bff23123474a301a37c06cb05cd2501b0f36ef3a63f1f11cd5da196c5607f7ba`; captured JSON SHA256 `63df0021fd5803302a0338ca8dc757f739eaaf69fab1d8906254cff513e816d0`. A separate smaller self-contained reproduction published below was ACTUALLY executed twice byte-identically: 13 assertions, source SHA256 `ed4709d6c6eab4600c1781408dd197b620614bab158407292eaa1eb0ac1d4e6c`, output SHA256 `5dd076fc5a48ab696c0221df3a323b3b3f2ef20fa97d979624fbeed396d6ac6e`. Synthetic 12-bit headers are not real Bitcoin/Syscoin, authenticated source, consensus work or QPT security tests. Only the full local checker computes SHA256 midstate; the published small repro tests equality of public first-block bytes and actual `hashlib` SHA256d.

## Exact next missing construction

Source evidence can authenticate work, but this factorized attempt's invariant labels are public before work and its variable labels are unknown to Build and fail every-witness common-key correctness. This does NOT exclude a genuinely non-factorized SHA/AuxPoW circuit-dependent public encoding. The next useful candidate must actually specify classical-PPT `Build_inc(x_W,sigma)` and `Open_inc(C,w)=same sigma` for every ORIGINAL qualified witness, with source verification cryptographically indispensable and arbitrary unauthorized full-public QPT recovery/native forgery reducible to an ACTUAL ORIGINAL witness or independent PQ hash/native break. No invented source token, independent PoW puzzle, online issuer, public residual pad, lattice or weakened special-signature relation is a solution. No routine PR progress comment. The task remains enabled.