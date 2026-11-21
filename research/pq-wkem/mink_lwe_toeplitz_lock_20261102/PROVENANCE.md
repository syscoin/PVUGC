# Provenance: MINK-LWE-TOEPLITZ-LOCK-20261102-R14

- Offline, bounded mathematical and local Node/Python iteration on 2026-11-02. No web searches, external literature, independent-agent runs or production actions.
- Actual syscoin/PVUGC PR #1 was open/draft/unmerged on research/pq-wkem-validation-20260918 at 74c368ed278f8dbeb8517a2108d81b6b5e56ce54 before this research. Ordinary comment 6575285376 was the latest substantive comment read.
- Exact prior files read: research/pq-wkem/mink_quad_pack_20261102/RESEARCH.md blob b0e9699402185d9f95684be99f2dd6cd3c49a377; research/pq-wkem/mink_evc_20261102/RESEARCH.md blob a638e32c90a3d0f0d7f7a6089829714b055426f2.
- Published checker.js is the exact independently executed Node version. Two final byte-identical runs: 1,087 assertions each. A separate extended Python checker passed 1,400 assertions twice and is LOCAL ONLY. An incorrect preliminary Python seed-uniqueness test was repaired because binding only requires uniqueness of the message, not its PRG randomness.
- Binding theorem is statistical and self-contained; pre-opening hiding theorem assumes exactly ordinary QPT-decisional-LWE for the specified uniformly sampled public-matrix distribution. Unassessed concrete parameters, no arbitrary joint auxiliary/source simulator, no malicious N-of-N ceremony proof, no full-WKEM solution.
- Only authorized path: research/pq-wkem/mink_lwe_toeplitz_lock_20261102/ on the existing PR #1 branch, and one ordinary top-level PR comment.
