# Run 625 — Joint coherent capsule extraction and related native-key leakage

2026-10-18. New, bounded research only. syscoin/PVUGC#1 draft/unmerged; starting branch research/pq-wkem-validation-20260918 at 11eebf04b96edf7385bcf098e494d067189b9e0a. No production or endpoint change. Builds on live Run 619 ideal-oracle query extraction and Run 259 complete-source-representation binding. This is NOT a concrete PQ witness-KEM, iO/RIO proof, or native signature deployment.

## Joint-oracle theorem (one target disabled, all other capsules live)

Classical PPT setup samples polynomially many precisely bound statements x_i, classical branch credentials K_i and native public checking keys pk_i, together with all public capsules and admissible correlated auxiliary data. Let Acc_i(z) be an efficient predicate for a COMPLETE source representation, not a partial residual. Every valid representation recovers the SAME K_i in the ideal functionality.

The coherent indexed release oracle O acts reversibly on quantum registers (i,z,y): if Acc_i(z)=1, xor the marker-plus-capability 1||K_i into y; otherwise act as identity. Define O_minus_j to be identical except that index j NEVER releases. All other oracles, checking keys, public artifacts, permitted source interfaces, quantum advice and the joint setup/key distribution remain exactly the same.

An arbitrary nonuniform QPT adversary makes Q>=1 coherent indexed calls, possibly in superposition across all capsule indices, and outputs either exact target K_j or a valid fresh native signature checked using pk_j. Let eps and p0 be its target success probabilities with O and O_minus_j, respectively. Run the attacker ONCE under O_minus_j, choose one of its Q query slots uniformly, measure (i,z) immediately before that call, and return z if i=j and Acc_j(z)=1. Then:

Pr[extract COMPLETE accepted target representation] >= abs(eps-p0)^2/(4 Q^2).

Proof: Purify the initial advice and random choices. In the disabled-target execution let psi_t be the prequery state, Pi_j the projector on index j and Acc_j(z)=1, and mu_t=||Pi_j psi_t||^2. The two oracle unitaries differ only on Pi_j, hence ||(O-O_minus_j)psi_t||<=2 sqrt(mu_t). A hybrid telescoping with disabled-prefix/real-suffix circuits gives final-state norm distance <=2 sum_t sqrt(mu_t)<=2 sqrt(Q sum_t mu_t). The probability difference for the same final success test is no larger. Uniformly measuring a disabled-oracle prequery gives p_extract=(sum_t mu_t)/Q. Rearrangement gives the claim; setup averaging follows by Cauchy-Schwarz. This is a genuinely coherent multi-capsule theorem, not Grover-only reasoning. One correlated quantum advice state suffices for the single-run extractor; an external reduction still needs the same legitimately distributed auxiliary state/oracle interfaces, not a hidden ability to recreate challenge-dependent advice. No rewinding, copying, or QROM programming is used.

If Acc_j equals the exact live Run 259 COMPLETE-representation predicate, the extracted object conditionally maps to ORIGINAL evidence or to the stated short QPT-SIS break. That conclusion only applies when p0 is negligible in the entire joint experiment. The theorem does NOT show the public binary representation of a local mixer behaves like its ideal release oracle.

## Strong negative control: native credentials correlated across capsules

Let A be a claim with an available valid ORIGINAL witness and B a false ORIGINAL statement. Honest-looking setup may sample native signing seed s_A uniformly and public Delta uniformly, set s_B=s_A xor Delta, and publish pk_A=PK(s_A), pk_B=PK(s_B), along with Delta. Suppose each capsule has an otherwise perfect ideal source-gated oracle. A legitimately releases s_A. The adversary computes s_B=s_A xor Delta and signs B's native transaction under pk_B WITHOUT a B witness, although O_B never releases anything. Disabling only target B changes nothing: p0_B=1.

This bypass does not reuse local bearer masks as in Run 620: only native credential seeds are correlated. It survives perfect local obfuscation and distinct public checking keys. A single-capsule ideal extraction theorem is therefore insufficient for multi-capsule false-instance secrecy. Independently sampled per-claim credentials eliminate this particular public-XOR attack but are not a proof of general joint QPT security or malicious N-of-N setup. A native verification key does not force the signer to disclose ORIGINAL evidence.

## Exact checker and limitations

The publication checker run625_joint_oracle_check.py uses standard-library five-qubit floating-point statevectors (including an auxiliary qubit), indexed coherent XOR release, H/S/CNOT/X/Z gates, Q=1..4, 320 reproducible circuits at each Q, and tests both norm-hybrid and extraction inequalities. It also checks 400 deterministic 256-bit related-seed derivations using SHA256 as a TOY public checker, NOT native SLH-DSA. Captured stdout and source/provenance are separate planned artifacts. No security inference from tests.

Attack taxonomy: (1) seams, (2) gauge synchronization and (3) fingerprints are NOT analyzed in a real white-box mixer; (4) cross-capsule credential correlation is defeated directly; (5) adaptive quantum chosen inputs included; (6) correlated/malicious setup exposed as a risk but no N-of-N ceremony proven; (7) context replay requires independently confined native credentials; (8) public checking-key correlations included explicitly in p0; (9) coherent superposed indexed queries included by the theorem. Honest setup/evaluation classical PPT, adversary arbitrary QPT with admissible joint quantum advice; no QPT-hardness theorem for an actual compiler is claimed.

CCMR local mixing (ePrint 2024/006) proposes RIO under further pseudorandomness conjectures; Gheorghiu et al. (arXiv:2609.40289v1) adapt it to quantum settings conditionally and do not instantiate the assumptions. These are architecture references, not post-quantum security proofs here.

STATUS: full-public-output false-instance QPT hiding; unauthorized true-instance key recovery or native forgery -> ORIGINAL extraction; malicious one-honest N-of-N setup/erasure; related-capsule composability; practical resources; unrestricted histories; and the conditional P2MR/native-SLH Bitcoin graph are ALL UNPROVED. No completed practical WKEM. Keep PR draft/unmerged, production unchanged, and research automation enabled.
