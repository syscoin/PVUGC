# Run 429 — coherent-query falsifier for a hidden-XOR-pair release mixer

**Read-first provenance:** \`syscoin/PVUGC#1\`, draft branch \`research/pq-wkem-validation-20260918\`, start head \`6435c709fcb96bec662ea4c4f833f7d433014eae\`. Exact-version Run 428 lower-bound note Git blob \`a82a5a7efbb852462894fc62ac1d910df0e636f2\`, Run 428 provenance \`b515225f7fa8172bd5c8b4e95b080af495ee6557\`, Run 421 note \`ef3c8dbecf476232e267464ba94c4b81eddb3b22\`. Latest substantive PR comment 6067040320.

## Candidate and exact theorem

Consider a narrow public release ingredient indexed by a hidden nonzero n-bit capability seed \`s\` and a hidden bijective label map \`L:{0,1}^n->{0,1}^n\`. Its deterministic public evaluator returns the canonical unordered pair

\`O(z) = canon{L(z), L(z XOR s)}\`.

Even if every label is perfectly secret, injectivity implies the exact two-to-one *Simon promise*:

\`O(z)=O(z') iff z'=z or z'=z XOR s\`.

An arbitrary QPT evaluator can coherently call any published classical circuit computing \`O\`, via \`U_O|z,v>=|z,v XOR O(z)>\`. Starting from uniform superposition, evaluating \`O\`, and Hadamard-transforming the input register yields measurement distribution

\`Pr[y]=2^(-2n) sum_t |sum_{z:O(z)=t} (-1)^(y.dot.z)|^2\`
\`     = 2^(-(n-1)) if y.dot.s=0; 0 otherwise.\`

Each output fibre is exactly \`{z,z XOR s}\`; its Fourier sum is \`(-1)^(y.dot.z)(1+(-1)^(y.dot.s))\`. The n+c independent coherent-query samples span the (n-1)-dimensional orthogonal space except with probability at most \`2^(-c-1)\`. Gaussian elimination recovers the unique nonzero kernel vector **s**, yielding the signing capability without any ORIGINAL witness. For n=256,c=36, 292 oracle queries suffice with failure at most 2^-37 in the ideal coherent model. This is an application of the standard Simon algorithm (Daniel Simon, SIAM J. Computing 26(5), 1997, DOI 10.1137/S0097539796298637), **not a new quantum algorithm**.

## Exact classical/quantum distinction and fatal scope limits

If \`L\` is an *unavailable random bijection* and the adversary only has classical oracle access, a fresh query returns two fresh random labels unless a pair of queries differs by s. For q fixed distinct queries and uniform nonzero s, the matching probability equals the number of distinct pairwise XOR differences divided by (2^n-1), upper bounded by q(q-1)/(2(2^n-1)). Adaptive classical-query attempts satisfy the corresponding birthday-style bound before the first match. The coherent quantum attack is exponential-query faster.

This **does not establish classical white-box security**. If \`L\` or \`s\` is visible in published program bytes, classical extraction may be trivial. A uniformly random permutation table has exponential size; a keyed PRP permits private classical PPT evaluation but publishing its keyed implementation without exposing the key requires an independently proven protection mechanism. **No practical PPT public protected evaluator was constructed.** Even granting ideal program-code secrecy cannot save the *functionality* from the coherent Simon attack. The candidate fails before trying to authenticate witnesses; it does NOT implement all-valid-ORIGINAL SAME-K release. No actual CCMR/RIO/iO scheme or production system is claimed to instantiate this oracle.

## Attack ledger and exact game scope

1. Seam: pair equality survives arbitrary label randomization.
2. Gauge: no labels or masks need to be reconstructed.
3. Fingerprint: identical output pairs encode exact functional periodicity, not marginal gate class.
4. Multi-view: one public evaluator suffices; reused periods worsen composition.
5. Chosen-input: QPT adversary uses coherent public evaluation rather than classical-only oracle calls.
6. Setup: honest nonzero s and any bijection suffice; retained coins/malicious setup are unnecessary for this attack.
7. Context: claim/UTXO/branch-specific s still leaks for that exact branch. No replay is required.
8. Public checking key: vk(s) remains in the attacker's correlated view; reconstruction of s defeats the endpoint.
9. Quantum: Hadamard interference and n-1 independent equations, not Grover-accelerated classical search.

The negative result is information-theoretic **given coherent access** and the exact Simon promise. No QROM programming, quantum rewinding, extraction, or new cryptographic assumption is used. Correlated quantum advice independent of secret setup randomness does not change the attack. Other genuine quantum attacks on surviving local mixers remain open.

## Reproducibility and handoff

Exact published script \`run429_compact_check.js\` checks complete fibre collisions and exact post-Hadamard integer probabilities for 35 small random labelled oracles, n=2..6, 19,600 assertions; output is \`run429_compact_validation.json\`. An independent extended Python script checked 19,695 assertions, including ideal-law rank recovery up to n=256 and eight *non-PQ Ed25519* signature demonstrations. The large cases are sampled from the analytically proved measurement law, **not an exponential-sized quantum-circuit simulation**. Finite tests do not establish practical QPT security.

Run 428's seeded general-NP release -> WE lower bound remains separate. Run 259's accepted-complete-representation -> ORIGINAL theorem cannot repair an attack that directly recovers s without producing such a representation.

**Result:** reject any local release gadget exposing a publicly callable deterministic exact nonzero XOR period equal to the protected credential, even if classical black-box birthday complexity appears high. Missing: any practical all-witness SAME-K release, full-public-output false-instance QPT hiding, unauthorized true-instance recovery -> ORIGINAL or independent QPT break, malicious N-of-N/erasure, multi-capsule composition, practical 128-bit parameters, and conditional native Bitcoin P2MR/SLH endpoint. **No completed PQ WKEM.**
