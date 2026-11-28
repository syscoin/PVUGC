# R323 — whole-witness Merkle-root label binding: finite repair and exponential obstruction (NONQUALIFYING)

**Outcome:** no practical hash-only ORIGINAL Bitcoin/Syscoin witness-KEM, no QPT reduction, no real native signature, and no Core test or network admission. This one bounded offline pass continues R322's precise missing step: deliver globally nonspliceable hash-garbled input labels without a future source signer, and retain the SAME frozen capability across all qualifying witnesses.

## Verified read-only continuity

At start, syscoin/PVUGC PR #1 was open/draft on branch `research/pq-wkem-validation-20260918`, head `c3dd95cb2973656a29970eec5abe1f9cd329cb9c`. Inspected R322 exact note blob `fefc5b0f444dc2ddd5ffb347bc46537fb2e0f042` (public both-label closure), R321 blob `53f6fdbc94c7be9ec8163e78b75dae935d3fac3`, R319 blob `6e6d4310657c2c65733daf72f2b517a218155277`, and R317/R318/R320 for restricted source controls. Read-only syscoin/syscoin Core PR #609 metadata head `c91539de3c34937e57d7f5fda47c7b0502ff33f6`; no Core tests run, public PQ activation remains described as release-disabled/sentinel. R225 native wtxid portability comment 6796383617 remains a distinct endpoint issue. No web or literature retrieval.

The intended ORIGINAL relation remains an independent OR: (1) authenticated same-anchor competing BTC chain of strictly more exact cumulative linked work, (2) finite authenticated fault of the *particular* withdrawal burn/authorization, (3) qualified semantic Syscoin ancestor conflict at h_rel with required linked child LC depth, or an independently outer-authenticated relevant asserted-wrapper tag fault under an explicit maturity rule. Do not count different parent certificates for one Syscoin child as forks. Preserve contextual modern chain ID, separate child commitment and exact canonical 41-byte SYS tag, interval paths, original claim/outpoint/amount/recipient, BTC anchors/window, deadline/reset, capsule/native message/VK, and activation or slot-global native cancellation policy. None of this ORIGINAL source verifier is implemented in the bounded Boolean fixture below.

## A nonspliceable but exponentially enumerated finite construction

For a fixed m-input Boolean verification circuit V_x, **Build enumerates every a in {0,1}^m**. Define a globally binding Merkle root r_a of all m position-tagged input bits. For each a, independently draw two uniform lambda-bit labels L_{a,u}^0,L_{a,u}^1 for *every* input/interior wire u. Let F_a label-garble every gate g of fan-in d by publishing all 2^d rows

```
T_{a,g,b} = L_{a,out(g)}^{g(b)} XOR
            H("gate" || x || r_a || g || concat_i L_{a,in_i}^{b_i}).
```

Publish only one encrypted input label **for the complete assignment a** on this particular root:

```
E_{a,i} = L_{a,i}^{a_i} XOR H("input-pad" || x || r_a || a || i).
Q_{a,u} = {H("commit" || x || r_a || u || L_{a,u}^0),
           H("commit" || x || r_a || u || L_{a,u}^1)}.
D_a = sigma_cancel XOR H("output" || x || r_a || L_{a,root}^1).
```

Also publish the true-root commitment for selecting the terminal TRUE label. Open(C,w) verifies that the requested entry's Merkle root is r_w, derives its **single** designated input label using the complete bytes w, propagates through tables checked by Q, and extracts sigma_cancel only upon obtaining the terminal TRUE label. Honest full-witness consistency is now preserved *within each entry*, and every satisfying w opens **the same setup-frozen sigma_cancel**. Unlike R322's public two-label interface, labels for different assignments are independently sampled and cannot be copied into the same entry, except through a new hash/label break. The statement is about this explicitly enumerated finite circuit, not real ORIGINAL admission or QPT proof.

**Two irreducible defects:** (i) Build and public capsule materialize **2^m full assignment domains**, with Θ(2^m sum_g 2^{fanin(g)}) rows, not classical PPT in the ORIGINAL witness length; for the tested circuit 14 rows per assignment, 112 at m=3, 60,129,542,144 at m=32 and 14·2^256 at m=256. (ii) The builder's enumeration and publicly indexed witness roots outsource the *entire possible source space* to setup, so this is neither an efficient way to handle arbitrary future headers/coinbases nor a hard-TRUE recovery-to-ORIGINAL certificate reduction. In particular, synthetic Boolean inputs are not authenticated Bitcoin/Syscoin certificates. No finite-enumeration observation should be promoted to a practical hash-only bridge or a generic witness-encryption theorem.

## Why the proposed polynomial repairs are not instantiated

A single public root r fixed before future w cannot be the Merkle root of every different witness without opening/collision problems. If public input-label derivation exposes both choices at that root, R322's public closure succeeds **even when every gate pad is salted by that same global Merkle root**. A public per-witness root formula without a table still needs a generator for the correct private output labels, gate rows, and SAME-capability output mask for each previously unknown r. Publishing the generator's private label seed exposes both choices; retaining it privately makes Open an online private evaluator; publishing a generally guarded generator would be the *new cryptographic construction to prove*, not an application of ordinary SHA preimage/collision resistance. Merkle commitments authenticate already chosen bytes, not create unknown source-earned secret labels.

This is a **restricted explicit table-size/closure diagnosis**, not a lower bound for all nonlinear hash-only WE or iO. We have not reduced arbitrary QPT recovery to an ORIGINAL source certificate, and QROM idealization for SHA tables is not concrete-SHA security. Full-public native VK/signature correlations, corrupted setup/retained coins, coherent queries, siblings/selected openings and abort/DA useful-completeness are unresolved. The original relation's independent burn/BTC branches, real AuxPoW admission and endpoint also remain unimplemented in this candidate.

## Executed check and exact next equation

Python3 stdlib checker used SHA256 gate pads, actual 4-leaf SHA Merkle roots, distinct private per-entry labels, public full-assignment input-label pads and checked committed gate outputs. On a 3-bit Ch/NOT/AND **FALSE** circuit, all eight assignment entries failed to open; on a 3-bit Boolean **TRUE** circuit, exactly four of eight entries opened the same frozen synthetic 256-bit secret. For each of the two circuits, all 56 wrong-root assignment requests (8 entries × 7 mismatches) were rejected, and cross-root known labels were additionally injected into each entry's public gate evaluation. Deliberately publishing *both* labels at one FALSE entry gave immediate public inconsistent-fanout recovery of the secret despite its global Merkle salt. Wrong-witness roots were rejected. Two independent executions produced identical JSON and **238 assertions each**. This is not an exhaustive adversarial security search, a quantum experiment, a native PQ test or real consensus admission.

Local checker SHA256 `88f02495670bdc11ab644ac76f6c525928e99cf2134671934575cd25f19927f6`; both outputs SHA256 `b6dcad2ea269172d1d5e9adc64f4f4db8a2a48de836804fa6d5d92392c795af8`. The checker/results remain a separate local reproducibility archive, not GitHub source unless independently published and verified.

**Next exact equation:** provide a classical-PPT compact public `E_x` satisfying `Deliver(E_x,w) ->` one globally nonspliceable set of input labels for **every ORIGINAL-qualified w**, with public `Open_inc` returning the same frozen native cancellation signature and no usable delivery for FALSE or hard-TRUE unauthorized recovery. This must cryptographically bind complete contextual SHA/AuxPoW/source-history relevance *inside* release, not only test it after unmasking. A valid construction needs a joint-public QPT simulator/extractor reducing accepted native cancellation to an *actual* ORIGINAL certificate or independent PQ hash/native break. No such compact source-delivery compiler was produced.

No PR progress comment, production edit, deployment or automation update.