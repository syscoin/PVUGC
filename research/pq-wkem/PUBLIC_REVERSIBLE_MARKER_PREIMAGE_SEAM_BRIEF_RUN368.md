# Run 368 — Public inverse of a local release marker bypasses SOURCE

Live starting PR head: `7fec02b8102e49c23bc8e3be798eedbae4423967` on draft/unmerged `research/pq-wkem-validation-20260918`. This is a bounded falsifier of an explicitly restricted candidate; NOT a construction.

## Candidate and exact theorem

Let `P_b:{0,1}^d -> {0,1}^d` be any published classical PPT permutation with a publicly efficient inverse, e.g. an explicit reversible Toffoli/CNOT circuit. For each source branch `b`, let the acceptance marker `a_b` be public. Give the candidate an ideally protected endcap `Gate_K(t,b)` which reveals the same protected native signing seed `K` only if `t=a_b`. Its complete independently callable raw release interface is `Release(b,z)=Gate_K(P_b(z),b)`. The upstream ORIGINAL verifier is ordinary/public, and honest `R(x,w)=1` representations map to `z_w=P_b^{-1}(a_b)`. There may be different branch states `z_0 != z_1`; every valid ORIGINAL witness still releases the identical K.

**Theorem.** An unauthorized classical attacker computes `z_b=P_b^{-1}(a_b)` from public information, calls `Release(b,z_b)` once, and recovers K with probability one. This holds for true and false statements. Each branch has exactly one successful raw d-bit input, so its independent uniform-input success probability is `2^{-d}`, despite the deterministic O(|P_b|)-time attack. The inverse-path attack is substantially faster than the unstructured Grover `O(2^{d/2})` density benchmark in Run 367. It requires no ORIGINAL witness, public-key inversion, path cycles, shared frames, statistical distinguishers or quantum machinery. Consequently it is also a valid QPT attack.

**Essential scope:** Both public inverse computability AND raw-frontier injectability are required. An all-in-one public program that accepts only an ORIGINAL witness and cryptographically enforces the verifier without exposing a raw frontier is OUTSIDE this theorem. So is a forward-only obfuscated permutation whose inverse is not publicly computable. The ideally protected endcap is deliberately an *attacked favorable abstraction*, not an instantiated secrecy assumption or an available cryptographic compiler.

## Run 259, attack taxonomy, and precise failure

Run 259 (exact blob `c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2`) supports `accepted full global representation -> ORIGINAL witness or stated SIS break` under its actual global residual/encoding constraints. The raw state `P_b^{-1}(a_b)` has not passed that acceptance relation. This candidate therefore fails the preceding obligation `unauthorized usable credential -> accepted Run-259 representation`, without contradicting Run 259. Actual native verification-key correlations and per-UTXO/branch context do not prevent this within-claim preimage attack.

Tested relevant attack families: local seam/cancellation (broken), public chosen-input evaluation (broken), public checking-key use (optional success confirmation), branch separation (ineffective against each separate branch), independent setup randomness (ineffective), and classical PPT/QPT attackers (attacked). No gauge recovery, triple-capsule inference, statistical fingerprints, or coherent quantum algorithm is needed. No claim about repaired constructions under such attacks.

## Reproduction and literature

Exact compact checker: `compact_marker_inverse_run368_check.py`. It exhausts invertible local circuits with explicit NOT, CNOT and Toffoli gates at d=4,6,8 for nine deterministic fixtures; proves by enumeration that each marker has a unique invertible preimage; confirms key recovery and the same correlated toy public checking digest; and compares honest TRUE source examples (square roots mod 17) with a FALSE source example for which the public checker rejects all witnesses. Two checker outputs were byte-identical, and Python syntax validation passed. The toy digest is not native SLH-DSA and the sealed gate is not implemented cryptographically.

Canetti--Luo--Zhang, ePrint 2026/1398, https://eprint.iacr.org/2026/1398, studies conditional PKE/FE from obfuscated random reversible circuits via iO/PPRP/SCP. This attack does **not** refute their forward-only obfuscated encryption architecture. The primary abstract/metadata were read; the primary PDF returned HTTP 403, so no proof audit or QPT security instantiation is claimed.

Unproved: source-enforcing protected endcap, full-public-output false-instance QPT hiding, unauthorized true-instance key/accepted signature -> ORIGINAL representation/extraction, N-of-N malicious setup and erasure, multiple capsules, Bitcoin conditional native signature endpoint and graph, practical 128-bit parameters. No complete PQ WKEM; production unchanged.
