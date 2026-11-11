# R218 — CIRCUIT-IDEAL-PAD: explicit original-circuit Build/Open is insecure in the full public view

**Disposition: UNSAFE; not a PQ witness-KEM or a constructive solution.** This pass built and tested a polynomial-time explicit source-circuit mask that has same-capability correctness for every satisfying Boolean witness, then derived a deterministic full-public witness-free recovery theorem. This result is scoped ONLY to publicly represented polynomial constraint-span carriers. It neither proves a hash-only impossibility nor authenticates real SHA/AuxPoW evidence.

## Continuity / actual actions

syscoin/PVUGC PR #1, open/draft/unmerged on research/pq-wkem-validation-20260918. Starting head 7dfce7691006423ea442f3ae9e0be18e132057e6, which was the R217 intermediate MONO-RELEASE checkpoint; its full research was not edited. Parent R216 6da61eaa132ffca1792ed4de44ba36cffc3286d1. Read exact R216 universal-slot research blob 9c369aa210cfdb67c6582865b11421d0dd70f999 and R215 SHA-midstate blob e4ab8e84b261083f98ab412516df62a1f6b4dbb1. Ordinary PR comment query since 2026-11-10 returned none. Initial R218 hypothesis committed on the same branch at d33d7c77447712b6de11d8a50408f67b189b3868 before executing local checkers. No web, external sources, production changes, mining, native signing, independent agent or QPT security experiment.

## Actual ORIGINAL requirement

N-of-N one-honest preauthorization freezes a safe Bitcoin cancellation path. A single notary later activates a source-bound claim; any watcher with an admissible ORIGINAL R1 higher contradictory BTC-work, R2 authenticated PoB/burn defect for that *actually admitted* assertion, or R3 depth-qualified authenticated Syscoin claim-prefix fork/tag fault must publicly recover the SAME frozen cancellation authorization, without later online N-of-N help. Real source anchors, BTC admission, witness/wtxid, AuxPoW/coinbase/tag/hash ancestry, lag/window, data availability, malicious coins and full public related capsules remain mandatory. The toy gate checker is NOT an ORIGINAL witness implementation.

## Non-factorized candidate and correctness

Let the ORIGINAL SHA/AuxPoW/PoB/source-verification circuit be expressed through public arithmetic Boolean constraints C_i(z)=0 over F_q. For a fixed bounded mask degree d and publicly indexed coefficient space V containing all m(z)C_i(z), define public S=span{ vec(m C_i): deg(m)<=d }. Classical Build chooses secret field key K, uniformly random low-degree Q_i, and publishes

    vec(P),  P(z)=K + sum_i Q_i(z) C_i(z).

Open evaluates P(w) using an ORIGINAL satisfying assignment w and uses that value as the pad key for an otherwise frozen claim/path-scoped native cancellation signature. All satisfying w have all C_i(w)=0; therefore P(w)=K for EVERY qualified w. This is a genuine same-K *functional identity*, but not secure cryptography.

## Deterministic full-public attack (general theorem for this family)

Assume a TRUE instance has at least one satisfying assignment w, even if computationally hard to find. Evaluation at w is a linear functional on explicit polynomial coefficients with ev_w(vec(1))=1 and ev_w(S)=0. Thus vec(1) is not in public S. Ordinary Gaussian elimination of the PUBLIC generator coefficient matrix finds a linear functional L: V->F_q satisfying L(vec(1))=1 and L(S)=0, WITHOUT FINDING w. Hence for the published capsule

    L(vec(P)) = K.

This attack is polynomial-time whenever the public bounded-degree coordinate space and generators are polynomial-time enumerated. It also defeats D=sigma_cancel XOR H_pad(K) and a public checking key. Sampling Q_i nonlinearly or adding secret correlation among them does not help as long as vec(P)-K*vec(1) lies inside the same known public linear span. The proof is distribution-independent and classical, so also applies against QPT threat models without assuming a quantum random oracle. It is NOT a theorem about other non-linear/hash-obfuscated representations; do not upgrade it to a generic WE impossibility.

## Actually executed bounded checkers

A LOCAL full Python standard-library checker (not published here) used F_257, a 5-variable *SHA-like* AND/XOR gate circuit with Boolean bitness, u=a*b, t=u XOR c and target t=1. It had 56 public monomial coordinates, 48 mask generators, a rank-47 public projection, four satisfying toy inputs, 120 randomized keys, 480 correct same-K evaluations and 120 witness-free public recoveries. It counted 777 functional assertions. The raw constant coefficient differed from K in 119/120 cases, making the projection nontrivial. Two byte-identical runs. Full local checker SHA256 ec42bfde4248bc2c4c7a82f9517a853d78ee8e7b19f78f14f173a214a5c0754a, captured JSON SHA256 8786cd6cbd46f117c70799e64f3d796316c2959804b5217ac0540d79b2223676; neither is claimed published.

The independently executed compact `repro.py` in this directory is a *different* Boolean OR-gate toy with three true assignments, 20 monomial coordinates and 20 public mask generators. Two identical executions: 100 random secrets recover publicly without witnesses and 300 correct evaluations. Git blob identities for published source and captured output are verified separately. No real SHA256 compression, Bitcoin headers, Syscoin authenticated source, native signatures or quantum experiment was run.

## Attempted repairs and next exact subproblem

Hiding each coefficient behind a salted SHA commitment prevents direct application of the projection but also prevents an arbitrary future witness-holder from evaluating P(w); a plain commitment is not a publicly evaluable homomorphic encoding. Revealing all coefficients restores the attack; requiring setup parties to open them later introduces a forbidden online authority. Pre-enumerating openings for every future source witness is not classical-PPT. Publishing both hash-garbled input labels reintroduces the previously documented global occurrence-mixing attack. Source-dependent SHA header labels do not provide Build with a common unpredictable future value: R215 already verified the fixed-public versus varying/unavailable midstate distinction. These are NOT repaired candidates.

The exact missing constructive component is a **nonlinear, compact, hash-based public evaluation encoding** tied to actual SHA/AuxPoW/source-verification constraints which (i) publicly opens from EVERY ORIGINAL source challenge to the SAME frozen signature, (ii) does not expose a low-cost public linear/garbled-circuit closure and (iii) has an independently justified full-public joint QPT simulator/reduction. Merely naming iO/FE/WE/garbling, adding an honest-verifier if-check, or positing a source-held secret is not an instantiated solution.

No routine PR progress comment warranted. Do not report this attack as a breakthrough or as a completed build/open mechanism.