# Run 449 — Affine false-residual coset and polynomial-time post-CRS forgery

Live starting draft PR #1: branch `research/pq-wkem-validation-20260918`, SHA `1d5962a12a7f355b3de83778cb75c816db78a579`; latest ordinary substantive comment `6067040320`. Exact dependencies: Run 259 source-binding blob `c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2`, Run 447 `b745265044224d03d101d15331d7064c4cbab41a`, Run 448 `8ac11f6fac32b3cf5fcb27038d698cdca68ee675`.

**New scope (not Run 259's subspace theorem or Run 447's small `(1,z)` fixture):** exact affine-coset existential probability, a constructive classical PPT Gaussian solver, and an essentially tight surplus-fold bound. The ORIGINAL-false statement x is fixed BEFORE fresh honest public CRS. The attacker only chooses the complete representation z AFTER seeing the CRS.

Let the source constraints over F_q require all coordinates of `rho(z)=(1,z_1,...,z_d)` to vanish, with z in F_q^d. This is globally unsatisfiable because of its leading 1. Setup publishes uniform S=[a|B] in F_q^(t x (d+1)). A shortcut release frontier accepts when `S rho(z)=a+Bz=0`. Although for EACH fixed invalid z its acceptance probability is exactly q^-t, an adaptive source forger solves `Bz=-a` after seeing S. Every solution is an invalid ORIGINAL witness representation.

**Exact theorem:** For B of rank r, independent uniform a lies in Im(B) with probability q^(r-t). If N_q(t,d,r) denotes the number of rank-r t-by-d matrices, then

`Pr_S[exists invalid accepted z] = q^(-td) sum_{r=0}^{min(t,d)} N_q(t,d,r) q^(r-t)`;

`N_q(t,d,r) = prod_{i=0}^{r-1}((q^t-q^i)(q^d-q^i))/(prod_{i=0}^{r-1}(q^r-q^i))`.

For t<=d, a classical PPT Gaussian solver succeeds with probability at least `prod_{i=0}^{t-1}(1-q^(i-d))`, since B is then surjective. In particular q=2,d=32,t=16 gives **0.9999847415213746**. This is a constructive efficient attack, not merely an existential/nonuniform bad-setup argument or a quantum-speedup claim.

For t>=d, write s=t-d. Since conditional acceptance is q^(rank(B)-t),

`prod_{i=0}^{d-1}(1-q^(i-t))*q^(-s) <= Pr[bad] <= q^(-s)`.

In binary fields the product at t>=d exceeds 0.288. Thus reducing this affine-example bad-event probability below 2^-128 requires roughly d+127 or more folds; d+128 suffices. This is an **affine coset disjoint from zero**, whereas Run 259's earlier linear-subspace obstruction required a full punctured linear subspace. The theorem extends as a lower bound whenever a false statement's invalid residual image contains any affine d-flat v+U with v not in U.

**Composition boundary:** A public `H(x)`-derived CRS, or merely fixing the UTXO and branch before CRS, does NOT prevent choosing z after CRS. Committing z before independent CRS restores pointwise bounds, but alters late witness admission and needs binding and a genuine QROM analysis if made noninteractive. Run 259's QPT-SIS-compressed route is distinct: an invalid accepted complete z gives SIS, assuming exactly stated QPT SIS hardness. Neither binder proves arbitrary accepted native signature -> accepted complete z. If a protected release independently checks ORIGINAL constraints or uses an independently sound authenticator, this attack does not apply. It defeats only the shortcut that trusts a compact public post-CRS fold as sufficient source authentication.

**QPT/attack ledger:** Setup/evaluation are classical PPT; attack is classical PPT, hence applies to QPT with arbitrary public output/native checking-key correlations. Tested: source-interface seam substitution, adaptive/public evaluation, and folded-source acceptance; other local mask gauge/fingerprint/multi-capsule/coherent-only attacks are not claimed. No new crypto assumption, local-mixing instantiation, native PQ signature, or security theorem is supplied. No complete primary-literature audit this run. Standard proof-system folding's commitment-before-random-challenge ordering is not refuted.

**Executable:** `run449_compact_check.js` enumerates the complete small finite distribution and checks literal accepted false representations. `run449_compact_validation.json` is its captured exact output. Extended proof and 6,053-assertion independent checker are local-only. All-witness SAME-K, false-instance QPT hiding, native-forgery-to-ORIGINAL extraction, malicious N-of-N setup/abort, multi-capsule QPT composition and concrete Bitcoin PQ endpoint remain **UNPROVED**. Draft/unmerged and production unchanged; stopping condition unmet.
