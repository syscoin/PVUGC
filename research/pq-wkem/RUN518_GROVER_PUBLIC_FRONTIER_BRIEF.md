# Run 518: coherent search of accessible off-source release frontiers

Research-only scoped quantum attack. Starting live draft PR #1 branch research/pq-wkem-validation-20260918 at 9957b754ed22e1c807bc1d5c9f79d5d3e6bfea26. Exact dependencies: Run 517 blob fb0acb35eae848e7fa3b19a5486085d126fcf41f, Run 516 blob fe183bf7b53eb5087e3496d7ae2cdeeef525b979, Run 259 blob c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2.

## Theorem and attack

Fix a fully scoped claim x with no ORIGINAL witness. Suppose a classical-PPT public addressable encoder E_x(s), s in {0,1}^ell, carries the protected seed K from the real target anchor into an opaque frontier state. Suppose h public terminal operations A_i obey

[A_i(E_x(s)) != E_x(s)] = K_i AND [s in T_x]

for every i,s, where T_x is a nonempty set of M off-source accepting states. This functional property is the hypothesis, not a cryptographic assumption. If K != 0, OR over the public terminal fixed-point differences is exactly the membership oracle of T_x. All evaluations can be implemented coherently by an arbitrary QPT attacker holding public classical program code, without inverting the hidden permutation or testing a native verification key. Multiple-solution Grover search finds one accepted s in O(sqrt(2^ell/M)) membership queries, each requiring O(h) terminal calls and polynomial reversible encoding. Once s is found, all K_i are recovered from the fixed-point differences. For uniform h-bit K, K=0 occurs with probability 2^-h. No ORIGINAL witness exists; this is unauthorized key recovery.

The exact success after t Grover iterations and marked density a=M/2^ell is sin^2((2t+1) asin(sqrt(a))). Thus a design relying only on the sparsity of bad accessible states needs ell-log2(M) >= 256 merely to avoid this generic attack below 2^128 coherent oracle queries, ignoring gate overhead and other structure. For ell=192,M=1 or ell=320,M=2^128 the ceiling is 2^96. These are attack upper bounds, NOT security guarantees or recommended parameters. Proper false-instance binding needs no accessible bad marks, or an independently justified COMPLETE-source/SIS extraction consequence.

This extends Run 517's direct acceptance-bit editor to sparse opaque acceptance with an unrestricted public loader. It is a same-claim attack that survives Run 516 sector isolation; it is not Run 510's Simon attack. Run 509's ideal quantum extractor cannot imply ORIGINAL evidence from off-source accepted inputs. Run 259 only applies when its complete representation and exact residual/extractor/SIS hypotheses hold; an arbitrary short acceptance token is outside that scope. If all accepting states supply such complete representations, finding one is not an unauthorized recovery result.

## Security scope and validation

Honest classical-PPT implementation is required but not supplied: the fixture uses an exponentially sized ideal random permutation. Attack is uniform QPT with coherent public program access; independent auxiliary inputs, checking keys and unrelated capsules are unnecessary, not proved harmless in general. Local seam is the addressable acceptance transition; fixed-point fingerprint exposes marks; frame gauge recovery is unnecessary; no malicious setup or cross-UTXO replay is required; no coherent-quantum defense or complete white-box reduction is claimed. Source privacy optional. Native signature and Bitcoin graph enforcement remain separately conditional.

Exact committed JavaScript checker run518_compact_check.js: 56 opaque-frame addressable points, 7 false-target seed recoveries, 98 fixed nonmarked-bit checks, 60 exact multi-mark Grover amplitude checks. Repeated output matched run518_compact_validation.json byte-for-byte. Independent local Python checker: 248 points, 23 recoveries, 675 fixed-bit checks, 150 Grover evolutions. These are finite checks, not QPT security proofs or quantum-hardware experiments.

Quantum-search references: Boyer, Brassard, Hoyer, Tapp, Tight Bounds on Quantum Searching (1998), arXiv:quant-ph/9605034; Brassard, Hoyer, Mosca, Tapp, Quantum Amplitude Amplification and Estimation, arXiv:quant-ph/0005055. No full RIO or Canetti-Luo-Zhang proof audit this run.

## Handoff

Construct a compact, classical-PPT, claim-bound protected admission transition where every reachable accepting state is complete ORIGINAL evidence (or yields the stated SIS break), and whose entire real-versus-null oracle difference support is source-extractable against arbitrary QPT query strategies. Do not treat rarity of unbound accepting states as 128-bit security. Full-public-output QPT hiding, true-instance early capability or accepted signature -> ORIGINAL, malicious N-of-N setup/erasure and abort, multiple-capsule composition, concrete resources, and the conditional P2MR/SLH native Bitcoin authorization graph remain UNPROVED. Production untouched; PR draft/unmerged; WKEM stopping condition unmet.
