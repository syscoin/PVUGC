# R302 — Parent-source polynomial correction: full-public leakage and unseen-source failure (NONQUALIFYING)

## Provenance

Continuation of R301's exact unfinished SourceEarnedKey equation (R301 file blob `8fda3ac49d8dae43fa3ac0e8cf2ba3a25afb7880`); start syscoin/PVUGC PR #1 at `2f921daf74e02dd95d634969c2308fe949ab68a9`, draft branch `research/pq-wkem-validation-20260918`. Core PR #609 metadata was read-only at `c91539de3c34937e57d7f5fda47c7b0502ff33f6`; ordinary PVUGC R225 comment `6796383617` re-read. No production/Core tests, network verification, quantum computation, or external research.

The actual original target remains all three authenticated, claim-scoped OR challenge branches, with exact modern contextual AuxPoW, canonical 41-byte SYS tag, both child-root and ancestor-tag commitments, relevant semantic ancestor at h_rel (not rounded tag equality alone), certified outer tag-fault carrier, required LC depth, BTC anchors/windows, burn/amount/recipient/replay, deadline/reset, and frozen safe native message/VK/capsule. Different parent certs for the *same child* are not a fork. One notary initiates, anyone with ORIGINAL evidence challenges; N-of-N is preauthorization only. R225 native activation portability remains a separate unresolved issue.

## Named candidate and exact algebra

Try to replace R301's header-specific mask by a precomputed polynomial correction on parent-root-derived public transcript keys. Let F be a prime field and h:F->F a domain-separated SHA-derived public function. Build chooses frozen toy secret K and m known source points z_i, computes unique degree <m polynomial Q satisfying

    Q(z_i) = K - h(z_i) mod |F|.                  (1)

The proposed public Open on a future authenticated ORIGINAL source certificate w computes z=z(w) and

    Open(C,w) = Q(z) + h(z) mod |F|.              (2)

This converges for the m known points but does NOT make future source certificates part of the secret release. The full-public representation discloses K *immediately*:

    K = Q(z_i) + h(z_i) mod |F|,                 (3)

for any publicly known setup point z_i, with no ORIGINAL challenge. An after-recovery AuthSource check cannot retract K. The setup points can be merely distinct outer Bitcoin parents for one unchanged child: no Syscoin inconsistency results.

**Independent random-function correctness lemma (restricted to this evaluator):** Condition on a classical-PPT Build transcript of h queries and on a subsequently sampled, independent z_* not among them. If h is an independent random function F->F, then h(z_*) is uniform conditional on Q and K, hence

    Pr[Q(z_*)+h(z_*)=K] = 1/|F|.                 (4)

For t distinct fresh independent points the joint chance is |F|^{-t}. Thus a published polynomial of sampled correction rows cannot give **every-future-witness completeness**. This is an independent-random-function *correctness* model, not a concrete-SHA/QROM proof. An adversarial future miner selecting z based on h queries alters the sampling premise; the required ALL-witness correctness fails regardless.

Joint-public repair tests: Publishing Q leaks (3). Hash-committing Q hides coefficients but produces no way for an independently arriving source certificate to derive an arbitrary unseen evaluation: a Merkle root authenticates prepared bytes, not a witness-generated opening. Maintaining private coefficients needs online trust, forbidden. A purported public source-specific evaluator with selective access and all-witness convergence is precisely the unconstructed ORIGINAL hash-only witness-encryption primitive. No assumption or hidden issuer is substituted.

## Reproducible executed regression and limits

The Python3 stdlib SHA256d checker (local conversation artifact, NOT in this GitHub note) built 72 *synthetic*, structurally bound 80-byte parents using variable 32-leaf depth-five child-commitment sibling hashes, a coinbase with the exact 41-byte modern SYS tag, a separately verified 4-leaf parent coinbase Merkle path, and toy 4-bit header grinding. Child and semantic ancestor were fixed across all 72 parents; parent Merkle roots and header hashes differed. A fixed child slot of 11 was a **fixture only**: no actual Core deterministic AuxPoW index, modern chain-ID contextual validation, full difficulty, BTC best-chain membership, Syscoin LC depth or native signature was implemented. No fixture is claimed to be an admitted ORIGINAL witness.

Over F_65537, m=5 source points defined a degree-four Q. Public evaluation recovered toy K=40979 without any ORIGINAL challenge; all 67 other newly sampled parent-root keys returned *wrong* K (as anticipated by the ideal-h correctness lemma, not evidence of a real security theorem). Two complete final runs produced byte-identical JSON and 16 assertions each.

Local-only source/results/provenance archive: `R302_parent_interpolation_20261115.tar.gz`, SHA256 `2342d6c74b9b9856e75823714ceb9202bddce617266ef034a88c5a7f14f3e8c4`. `checker.py` SHA256 `b06bcf7f3d0e546ba6b1224e8ecce8c74a43b86c8091d8f0440d1a099405719f`; identical `run1.json`/`run2.json` SHA256 `8e1f8fa988daa9b256b38c89a8fc3231d5ef2ce0d1b675af5907fb748154b79a`. No failed or partial runs counted. The small field/PoW are explicitly toys.

## Exact unfinished step

Construct actual classical-PPT Build_inc(x_W,sigma_cancel) and public Open_inc(C,w) yielding the SAME frozen claim-scoped native-safe capability for EVERY authenticated ORIGINAL challenge, without exposing it for a fabricated or irrelevant certificate. Independently establish joint-public FALSE and unauthorized hard-TRUE QPT recovery/accepted native forgery -> ACTUAL qualifying ORIGINAL certificate or independent PQ hash/native break, with auxiliary VK/context and malicious/related sibling capsules. This iteration supplies **neither** source-authenticated release **nor** that security reduction. No ordinary PR comment, notification, production change, or automation stop warranted.
