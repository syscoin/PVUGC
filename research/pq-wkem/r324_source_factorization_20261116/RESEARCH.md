# R324 — projected-SHA prefix/GGM source release (REJECTED; NO ORIGINAL FOUNDATION)

This bounded research pass continues R323's missing polynomial public nonspliceable label delivery by replacing its exponential whole-witness table with a hash-only SHA-output constrained-prefix GGM mechanism. **No qualifying ORIGINAL witness-KEM, native PQ endpoint, independent QPT proof, or core test was produced.** Not a generic impossibility statement about hash-only WE.

## Read-only continuity and source scope

PVUGC PR #1 branch research/pq-wkem-validation-20260918 had head f03002ba9e9d26e893d74bf22c775b28a0e0befc, open/draft. Exact R323 note blob 75bb84de7dc1df0d977c5fc5157efbd0d337d3be read. Core #609 read-only metadata head c91539de3c34937e57d7f5fda47c7b0502ff33f6; no Core tests and no claim of PQ activation deployment. The full ORIGINAL source remains the independent OR of qualified stronger same-anchor Bitcoin work, finite authenticated burn/authorization faults, and qualified semantic Syscoin inconsistency or independently outer-authenticated relevant asserted-wrapper fault. Preserve contextual modern child chain ID, canonical exact 41-byte SYS ancestor tag distinct from the child Merkle commitment, h_rel ancestry, LC depth, source relevance, anchors/window/reset, exact withdrawal/outpoint/recipient/amount, capsule ID, native message/VK and slot-global-veto or activation-specific native spend. This fixture authenticates none of those features.

## Candidate and full-public classical attack

Let W_inc(x) be every ORIGINAL qualified source certificate, with projected y(w)=SHA256d(parent_header(w)). Try to replace R323's per-full-witness private label tables with SHA-based GGM prefix keys for the syntactic work set P={ y : first t hash bits zero }. Honest Build freezes one sigma_cancel.

Constant-prefix proposal: reveal prefix key k_p and D_p = sigma_cancel XOR H("mask" || k_p). Every syntactically accepted y opens the SAME sigma_cancel, but anybody reads the public (k_p,D_p) and immediately recovers sigma_cancel. Running public VerifyOriginal(x,w) AFTER computing the signature cannot retract a native bearer capability.

Attempted repair: each y=p||s gets a distinct k_y=GGM(k_p,s), with leaf D_y=sigma_cancel XOR H("leafmask" || k_y). The public capsule must publish D_y for every supported y and a publicly derivable k_y. Attacker chooses a synthetic accepted y (e.g. y=0^256), reads D_y, derives k_y, and recovers sigma_cancel without any SHA preimage or valid parent/chain. Publishing only an index whitelist I subset P avoids some outputs but fails EVERY-witness completeness for eligible y not in I. For a t-bit hash target, full leaf enumeration has 2^(256-t) ciphertext rows; this is a lower bound for THIS leaf-enumeration repair, not arbitrary nonlinear encoders.

Hiding k_p while retaining D_y leaves Open without its key. Deriving k_p from source header bytes yields different future keys and fails SAME frozen capability unless an additional unbuilt public correlation is available. A setup-only retained key amounts to online authority. A Merkle commitment authenticates bytes, not the missing credential.

## Precise restricted lemma and security scope

Suppose the release function is publicly factored as R_C(y), returns the frozen sigma on every y in a publicly efficiently samplable P that contains projected valid-source hashes, and source admission is checked separately. Then the classical attacker samples any y* in P and runs R_C(y*) without an ORIGINAL witness. For the prefix acceptance predicate choose y*=0^256. This directly violates full-public FALSE/hard-TRUE recovery, even in the QPT model, without quantum queries, rewinding or internal-state extraction, regardless of native VK/correlation or sibling capsules. The proof concerns **only** such public-output-factorized schemes; if R_C is not defined to return the key on synthetic P points, this particular argument does not apply.

In an ideal random-function model a uniformly sampled eligible digest belongs to a static whitelist I with probability |I|/|P|, so a polynomial-size static per-leaf whitelist cannot cover every future digest when the output support is exponentially large. That random-function sampling estimate is not a concrete SHA256d/QROM theorem and ignores strategic miner selection; worst-case all-witness correctness already fails for any omitted attainable digest.

## Executed reproducibility

Executed checker.py twice with Python3 stdlib. Byte-identical captured outputs. Source checker SHA256 667b4326512c99b225b9bda1ec14b4c1c3f551680f77e625e83099264fdc36fe; output1.json and output2.json each SHA256 145fde71dc37c03b4b53309570939b0748b196689fc142d2c19f18f32f86f78c. Both exact Python and captured JSON are included beside this note.

Toy SHA256d on synthetic 80-byte headers uses t=4 prefix bits and stipulated parent-identity relevance, NOT real Bitcoin target/admission. Anchored nonce 45 digest 007eb12c91f2f4ad2c3f4487e7d590962f3e8cb6889a664f2550a24600a02fb1; unrelated parent nonce 6 digest 0d8504649cd89b74d040187b9c551e585b8b9f0d465636cbae68070922cfb635. Both satisfy syntactic hash target, only first meets stipulated relevance. Constant and per-leaf GGM proposals open for both and for all-zero digest without a header. 12 anchored accepted samples in nonces 0..255 all open; 256 projected 12-bit GGM leaf rows consume 8192 bytes. Half-leaf whitelist covers 4, omits 8. This is neither native PQ verification nor quantum experimentation, not Bitcoin bestchain membership nor Core tests.

## Exact unfinished source-dependent obligation

Need a classical-PPT public Build_inc(x,sigma_cancel) before future certificates exist, and public Open_inc(C,w) with the source verifier cryptographically *inside the secret-release path*, such that forall qualified ORIGINAL w, Open(C,w) gives the identical frozen safe cancellation signature. Arbitrary QPT unauthorized recovery/accepted native cancellation must imply extraction of an ACTUAL ORIGINAL qualified certificate or an independent demonstrated PQ hash/native break, with the adversary given native checking/VK, auxiliary source correlations, sibling capsules, selective openings, and retained malicious setup information. Need one valid witness to release all fixed N-of-N contributions without online cooperation; preserve pre-funding useful capsule correctness, honest erasure, DA, and native activation binding. None of these requirements were solved here.

No PR progress comment, no production writes, deployment or automation change. This is a nonqualifying negative note, not an improvement in source-dependent release.
