# R209 intermediate: future source Merkle path as hidden release label

Date: 2026-11-10. Observed PR #1 HEAD 10fff30d4dd7becf9205b99ef224d01f8e699087 on research/pq-wkem-validation-20260918. Read R208 exact-version note; latest ordinary PR comments since 2026-11-10 18:00 UTC returned none. No external web/literature.

Hypothesis: Existing authenticated Syscoin/BTC source Merkle paths can supply cryptographically gated labels for an OFF-CHAIN cancellation share, avoiding R208 public quotient leaks. Freeze baseline A at claim setup and key K. Evaluate carrier E_i = K XOR H(label(A,i), label(B,i)) at a first contradictory source position i. Genuine B unknown to Build; distinct qualified B must all recover the SAME frozen K.

Experiments planned:
1. Build preselects candidate B*; check unauthorized early opening by anyone with B* and failure for other future qualifying B.
2. Build substitutes public wildcard value; check key obtained without original source evidence.
3. Build uses a source-derived future label and static E; check same-key correctness across multiple B.
4. Compare Merkle opening of conflicting leaves under the SAME frozen source root versus separate independently authenticated source roots. Test whether a commitment root can make undisclosed future leaf cells available without online issuer or an additional release primitive.

Distinguish synthetic Merkle fixtures from deployed SHA/AuxPoW/Bitcoin best-chain evidence. No instantiated original Build/Open, no QPT claim, and no conclusion yet. Continue repair after failed candidates within this pass.