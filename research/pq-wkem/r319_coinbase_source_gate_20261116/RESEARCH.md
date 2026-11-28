# R319 — Coinbase-preimage source gate: two independent AuxPoW rerandomization axes

**NONQUALIFYING ORIGINAL-foundation iteration.** This continues the exact R317/R318 source-dependent hidden-key question. No practical hash-only witness-KEM Build/Open, joint-public QPT security theorem, native PQ-signature implementation, source network admission, or completion.

## Read-only continuity

At start PVUGC PR #1 was open on `research/pq-wkem-validation-20260918`, head `a6859ac7c78fc60746da79083907810504826ba3`. The relevant latest notes were R317 blob `ff26d166afbc3c52a1838c2ecfae966e7053fc03`, R318 blob `d1fcd7053601d35117c1a61d4d23f0fe2eeaba08`, and R315 source-OTS blob `385f653c0579dca00ba812b08558d78a9381d2cb`. Read-only Core #609 metadata head remained `c91539de3c34937e57d7f5fda47c7b0502ff33f6`, release-disabled. No Core C++ tests were run. The local checker imports the R316 archived synthetic AuxPoW source code; archive SHA256 `405d098ac0a747870731832672ed728196b637c790c23f46c63ab8cfa42e798f`.

The approved relation remains the claim-scoped OR of qualified same-anchor **strictly greater exact Bitcoin work**, finite authenticated **specific missing/invalid burn** evidence, and qualified **actual-ancestor Syscoin inconsistency at LC depth** or independently authenticated exact claim-wrapper tag fault with explicit maturity. The third branch needs no greater Syscoin work; two alternative Bitcoin work certificates for the same child are not a child fork. Require activated contextual modern AuxPoW chain ID, exact canonical 41-byte SYS OP_RETURN tag, separate correctly indexed child Merkle commitment, full authenticated ancestry/interval/depth/window/relevance, exact UTXO/burn/amount/recipient/deadline/reset/native cancel message/VK/capsule binding, independent outer authentication for defective tag wrappers, and the explicit R225 activation/slot veto policy.

## Candidate natural SHA release key

Unlike a raw parent-header SHA256d digest (R317), the **stripped Bitcoin parent coinbase** `CB` contains the real merged-mining commitment and exact SYS tag. In a one-transaction Bitcoin parent its SHA256d is the parent Merkle root. It remains unchanged if a miner re-mines parent header nonce/time while holding that coinbase fixed. Try, with `s` the fixed Syscoin child and `sigma` the frozen safe cancellation capability:

```
K_CB(CB) = SHA256("R319|source-coinbase" || SHA256d(s) || CB)
C_0 = sigma XOR K_CB(CB_0)
Open(C_0,w) = C_0 XOR K_CB(CB(w)).
```

The candidate **generously assumes** honest Build knows some future `CB_0`; actual `Build_inc(x,sigma)` does not receive a future source witness. The normal claim/capsule domain may be included in the SHA input without changing the argument.

**Axis A (parent-header rerandomization):** Many SHA256d-valid 80-byte parent work headers can commit the **same** coinbase txid, same child chain root, canonical tag, child header and Merkle branch. Here `K_CB` is exactly common, so any header re-mining of the fixed coinbase opens the same `sigma`.

**Axis B (coinbase rerandomization):** The miner can instead vary noncommitted-to-child parts of scriptSig (extraNonce), retaining its one correct merged-mining marker, deterministic indexed child root, modern child chain ID and exact canonical SYS tag; then mine a fresh parent satisfying PoW. The coinbase transaction, Merkle root and `K_CB` all change while the Syscoin child is identical. The fixed ciphertext opens to `sigma XOR K_CB(CB_0) XOR K_CB(CB_i)`, not `sigma`, except on a SHA collision. Core's activated rules do not freeze extraNonce. Thus the apparent common SHA preimage **does not meet EVERY-original-witness correctness** where different contextually qualifying carriers may certify the same child. These rerandomized carriers are not themselves conflicting Syscoin histories. The synthetic fixture does not claim they are 64 real simultaneous network-qualified challenge histories.

**Independent FALSE/hard-TRUE leak:** Even in the fixed-coinbase class, `K_CB(CB_0)` is computable from **the coinbase bytes alone**. If those bytes are public (normal published-source scenario), anybody recovers `sigma=C_0 XOR K_CB(CB_0)` without a competing BTC path, specific burn fault, actual child conflict, independent tag-fault relevance or sufficient LC depth. An invalid parent header retaining the exact original coinbase also suffices to compute the pad. Public post-decryption `VerifyOriginal(w)` cannot undo leakage. With full-public native VK, a recovered fixed signature can be used directly or checked via `Verify(VK,M_cancel,sigma)`; this is a classical attack and needs no source-certificate forgery or QROM hybrid. Withheld future coinbase data cannot solve Build's missing future-witness problem, and may violate source DA. A toy SHA verification tag in the checker is **not** a native SLH verifier.

The two-axis result rejects this explicitly described natural-source SHA-key compiler; it is **not** a general impossibility claim for nonlinear hash-only witness encryption. Normalizing to fixed public child/tag bytes trivially exposes the pad, while including future variable parent/coinbase bytes breaks cross-certificate correctness or requires witness-dependent setup. No externally supplied hidden label, arbitrary PoW target-prefix puzzle, source signer or post-hoc authenticity test is substituted for actual source-earned release.

## Executed regression and provenance

A bounded Python3 stdlib checker reused the R316 byte-oriented SHA256d/coinbase/modern-ChainID/AuxPoW depth-5 branch/index/exact SYS-tag fixture. Its target is synthetic `0x207fffff`, **not real BTC work/retarget/best chain or Core admission**. It mined and verified:
- 64 distinct parent-header hashes with one unchanged coinbase, all recovering one frozen synthetic 256-bit secret.
- 64 parent work certificates with different coinbase extraNonce but identical child, indexed chain root and exact SYS tag, with **zero** different-coinbase openings of the same secret.
- One invalid parent header with unchanged coinbase: the public SHA pad nevertheless recovered the frozen secret, including a synthetic VK-like verification positive control.

Two separately executed checker invocations gave byte-identical outputs, **842 assertions each**. Checker SHA256 `6dfa1eb4c922197823481110396667d9708c9a231b35ef3028c7229fbf5bca90`; both JSON SHA256 `1251682b6c9f9b9311fbfda5fa39fb4bfb8acf134587531c6889091e193f3a92`. No real chain membership, full contextual target/retarget, real native signature, honest distributed setup or coherent quantum adversary was executed. A local archive contains the full derivation, exact R316 dependency, checker and paired outputs; GitHub note and local artifact are separate receipts.

## Exact unfinished joint condition

```
Build_inc(x_W,sigma_cancel;rho) -> C, in classical PPT before unknown future witnesses;
forall ORIGINAL-qualified w: Open_inc(C,w) = the SAME frozen safe sigma_cancel;
Adv_QPT[recover sigma or acceptable native cancel without actual R_orig witness]
    <= Adv_QPT[extract genuine ORIGINAL certificate] + Adv_PQ[hash/native break] + negligible.
```

The last inequality must be justified by an independent reduction in the full public distribution of `C,VK,M_cancel,x_W,aux,sibling capsules`, across malicious retained source/coin secrets, selected openings, dishonest setup and coherent oracle access—not by assuming the desired source-release security, a common miner secret, ideal release oracle, or adversarial query logs. **No such algorithm or reduction exists in this iteration.** The next productive target is a genuinely source-certificate-dependent, nonspliceable, **public nonlinear secret-release computation**, with authentication inside the release dependency rather than another public SHA scalar pad.

No PR progress comment, production edit, deployment or automation change.