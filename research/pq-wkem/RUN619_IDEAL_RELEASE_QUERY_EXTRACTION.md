# Run 619 — Quantum hybrid extraction for an ideal relation-gated release

Date 2026-10-18. Research only; syscoin/PVUGC#1, branch research/pq-wkem-validation-20260918, start SHA 549649df718d992dfd3b5b62d4aeb71b90ae8f6c. PR draft/unmerged; production unchanged. The user-supplied Run 618 is not on this branch. This is an ideal-oracle proof, NOT a PQ WKEM construction.

## Exact functionality

Fix statement x including the relation, UTXO, branch and anchor/window context. Let Acc_x(z) be a public predicate for a COMPLETE accepted witness-dependent representation; valid z need not be canonical. Honest classical setup chooses a native key K and publishes pk(K), x, Acc_x, and admissible public auxiliary information. The ideal coherent release oracle XORs the nonzero string 1||K into a response register iff Acc_x(z)=1; the no-release oracle is identity. Every accepted representation gets the SAME K. Bitcoin would verify only a separately assumed ordinary native signature, never Acc_x.

An arbitrary QPT attacker A makes at most q >= 1 coherent oracle queries and outputs either exact K or a fresh authorized challenge signature. Let epsilon be success with the real release oracle and p0 success with the no-release oracle, with the SAME public pk and auxiliary distribution. Quantum advice that is not independently preparable for the reduction is outside its simulation guarantee.

## Exact ideal-oracle extraction theorem

Run A with the no-release oracle. Choose one of its q query slots uniformly and measure the query input at that slot. Let p_ext be the probability the measured z satisfies Acc_x(z)=1 (and its query is enabled). Then

p_ext >= max(epsilon - p0, 0)^2 / (4 q^2).

This yields an accepted COMPLETE representation without measuring a final native signature, assuming the ideal-release access model. The extractor is QPT and straight-line, with no quantum rewinding.

Proof: Purify A. Let phi_j^0 be the prequery state with all preceding calls answered by the no-release oracle; Pi projects onto enabled Acc_x-accepted query inputs. Set mu_j=||Pi phi_j^0||^2. Since the two oracles agree off Pi, ||(O1-O0)phi_j^0|| <= 2 sqrt(mu_j). Telescoping oracle substitutions, retaining actual-oracle suffixes and no-release prefixes, bounds final state distance by 2 sum_j sqrt(mu_j) <= 2 sqrt(q sum_j mu_j). Any success-event probability gap is at most that distance. Measuring a uniform no-release query yields p_ext=(sum_j mu_j)/q; rearrange. Average over honest setup with Jensen. QPT coherence and arbitrary intermediary entanglement are INCLUDED. If p0 is non-negligible, this argument instead identifies independent key recovery/forgery from the no-release public view; it does not pretend to extract an ORIGINAL witness.

## Exact Run 259 interface

Choose Acc_x to be precisely the live Run-259 complete-representation predicate, not a local residual or unchecked internal state. For an extracted accepted z, either its residual is zero and the stated public source extractor returns ORIGINAL w, or a nonzero invalid accepted z yields the exact short SIS kernel vector e=Enc(rho_x(z))-Enc(0) satisfying Ae=0 mod q and ||e||_2<=sqrt(L) under Run 259's stated QPT-SIS parameters. Its information-theoretic random-fold alternative instead incurs the explicit bad-setup probability. Therefore, in the IDEAL oracle model, fresh signing or key recovery -> complete accepted z -> ORIGINAL witness or the exact SIS break, unless p0 is independently non-negligible.

## Fatal unproved transfer

Neither two-input FE, a local reversible mixer, a CLZ-style obfuscated program, nor a public source verifier has been proved QPT-equivalent to the ideal relation-gated oracle in the COMPLETE white-box auxiliary-public-output view. One cannot introduce that simulation as a new postulate and label the witness-KEM solved: for generic NP, false-instance secure common-key release is WE-strength (Run 613). A compiled program may leak K without a successful oracle query or admit invalid partial states. Real full-view QPT hiding, malicious N-of-N setup/erasure/abort, multi-capsule correlation, true-instance extraction from actual code, practical 128-bit resources and conditional P2MR/SLH Bitcoin graph remain UNPROVED.

## Attack ledger and executable check

The ideal oracle excludes seam/gauge/fingerprint disclosure by definition; any actual circuit must analyze all three. Other-capsule/related-statement leakage and malicious setup are not handled; they may enlarge p0. Chosen-input public evaluation and genuinely coherent quantum attacks ARE included. Public checking-key correlations enter both experiments. Branch/UTXO replay is excluded only by explicit x/key binding, not by this proof.

The deterministic standard-library checker run619_quantum_oracle_hybrid_check.py simulates complete coherent state vectors for both oracles and prequery measurement probabilities; validation run619_quantum_oracle_hybrid_validation.json records 608 fixtures, 2433 checks, 585 nonzero distinguishing cases and two identical executions. Tests prove no cryptographic security.

Live dependencies: Run-259 GLOBAL_FINGERPRINT_SOURCE_BINDING_RUN259.md blob c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2; Run-615 RUN615_ROBUST_FRONTIER_METRIC_ATTACK.md blob 6e11c2af29aa42329d46dd885e18bdbe7c0aa8ce; CLZ_APPLICABILITY_20261008.md blob c19d9d9cd515140e3ce62eac960cd548c0add622. Relevant established technique: Ambainis-Hamburg-Unruh (CRYPTO 2019) quantum one-way-to-hiding; Czajkowski-Majenz-Schaffner-Zur arXiv:1904.11477v4. No full new literature proof audit is claimed.

STOPPING CONDITION UNMET. No generic NP PQ witness-KEM, endpoint, or bridge release compiler constructed.
