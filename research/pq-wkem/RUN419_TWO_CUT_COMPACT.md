# Run 419 — fixed-unary lineage does not admit a late ORIGINAL witness

**Live PR source:** syscoin/PVUGC#1, open/draft/unmerged, branch research/pq-wkem-validation-20260918, starting head 49017d18da291d87382803384ccb0c4c753bdf29. Exact predecessor Run 418 blob 67f5db445f48a35aaebb0729e4f50dc0b30cc886; Run 417 blob 368d0e86a4cbead552df856598ac05f3c309493e; CLZ assessment blob c19d9d9cd515140e3ce62eac960cd548c0add622; Run 259 source binding blob c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2. Latest substantive ordinary comment 6067040320.

## Restricted-model theorem (semantic, not a cryptographic impossibility)

Honest classical PPT setup takes the public statement x but not a later-discovered ORIGINAL witness w. It publishes a capability-bearing state C_K, the actual native verification key, all public auxiliaries, and fixed state operations. A watcher independently constructs a witness-bearing C_w. Suppose each allowed transition is **fixed unary**, receiving only one existing state plus fresh coins independent of w. No transition may consume a witness-dependent control argument, a second state, a private per-witness key, or secret-correlated shared state. A fixed output functional also observes only one lineage and public data.

Inductively, every descendant of C_K has only the capability origin; every descendant of C_w has only the witness origin. No state combines the two. Thus a fixed publicly prescribed K-lineage release schedule that succeeds for any valid w can be replayed without w. An independently published w-lineage cannot access hidden K merely by being encrypted under the same public parameters. Correlated public verification keys are still part of the attacker view; no statistical independence or signature unforgeability follows from this data-flow result.

**Escape cases are explicit:** an obfuscated program that hardcodes K and takes w as input, a ciphertext join/packing operation, a witness-controlled transition, or a K-correlated output functional are **additional cross-origin interfaces**, even if their API appears unary. This theorem does not exclude or establish their security. In particular, it does not refute Canetti–Luo–Zhang's real scheme.

## The two application cuts

(A) A protected operation must jointly depend on hidden K and a **source-authenticated** later ORIGINAL witness/representation. A public Join(C_K,C_w) is one potential *interface*, not a proposed secure construction. The joint interaction may instead live inside a single protected release program.

(B) Joint processing must then release one ordinary native credential only on genuine source evidence. Ordinary IND-CPA homomorphic computation of an encrypted (K,accept) does not itself expose K. Conversely, specifying an ideal conditional decryptor which outputs K iff R(x,w)=1 simply restates the missing WE-like functionality; it is **not an assumption to accept**. Run 410's ciphertext-only barrier covers its restricted case, not arbitrary secret-correlated output programs.

**Bare-verdict seam attack:** a correct public verifier computes b=R(x,w), but if the next protected gate can be independently called as Gate(C_K,b), a witness-free attacker supplies b=1 and obtains K. Feeding the Boolean acceptance bit is not cryptographic source binding. This was implicit in Run 418; the new scoped result is the exact *lineage non-interference*, its escape interfaces, and the separate native-declassification obligation.

Run 259 still yields only accepted **complete source representation** -> ORIGINAL witness under its exact residual/fingerprint or SIS hypotheses. Recovery of K or a native signature does not automatically yield that representation. Distinct valid witnesses may keep distinct internal states and must still obtain the same K.

## Security scope and reproducibility

The exact Node checker run419_compact_check.js executed twice with byte-identical output: 4,249,584 assertions, 292,968 fixed-unary root traces, and 256 synthetic two-ORIGINAL-witness/false-source Boolean-seam fixtures. An independent extended Python checker executed 2,274,357 assertions, 384 seam fixtures, and 256 fixed-lineage fixtures. Finite source hashes and an ideal negative control are **not** a KEM, LWE/SIS security, iO, QPT hiding/extraction, or a Bitcoin test.

Attack coverage: direct chosen-input Boolean seam (1,5); source lineage despite public checking keys (8); classical attack automatically available to QPT (9). Not established: resistance to gauge synchronization, distribution fingerprints, multiple capsule correlations, malicious setup/retained coins, cross-UTXO replay, or coherent quantum attacks on a **real mixer** (2,3,4,6,7,9). All such interfaces remain in the security game.

Primary architectural context: Canetti–Luo–Zhang, CRYPTO 2026, DOI 10.1007/978-3-032-35367-2_18; Canetti–Chamon–Mucciolo–Ruckenstein, TCC 2024, DOI 10.1007/978-3-031-78023-3_2. A full updated proof/errata/QPT audit of CLZ was **not** completed here; no concrete PQ assumption is inferred from these papers.

**Handoff:** instantiate actual public late-witness K-interaction and non-circular native release, then prove full-public-output false-instance QPT hiding, true-instance unauthorized recovery/accepted forgery -> accepted complete ORIGINAL representation or standard QPT break, all-witness same-K, malicious N-of-N erasure/abort, multi-capsule binding, and realistic resources. P2MR-like/native SLH remains conditional. The Bitcoin branch verifies only an ordinary native signature, never the NP proof. No production modifications, no practical WKEM yet.
