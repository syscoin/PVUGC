# Public noncommutative group-program source gate — screened, NONQUALIFYING (2026-11-23)

## Provenance and exact unfinished step
Open/draft syscoin/PVUGC PR #1, actual branch `research/pq-wkem-validation-20260918`, start SHA `da9ccad8e919b3beea557dd0b515fc98ff351e91`. Read current previous note `research/pq-wkem/r_hidden_reject_matrix_gate_20261123/RESEARCH.md` (blob `1dfbc9719c827c2e4cbdf6bde419e9924c7b0823`), and the directly relevant source path weighted automaton and certificate-ID label notes at blobs `37abc1718fbed8bef0cccbdb587cd4f6edaa020e` and `460917f0d66a4f0cbed93774ff246bf3e502143d`. Checked PR metadata and latest top-level comments; R225 ordinary comment `6796383617` remains relevant. No Core source was reread, no source-authenticated fork certificate was tested, no web/external literature was consulted.

The exact unsolved operation is a publicly serialized *hash-only* classical-PPT `Build_inc(x_W,sigma_cancel)->C` and `Open_inc(C,w)=sigma_cancel` for EVERY original authenticated qualifying challenge under the existing three-branch OR policy, while the COMPLETE public bytes reveal no unauthorized native cancellation unless an actual ORIGINAL witness or independently justified hash/native break exists. The preceding hidden-reject-matrix attempt needed a secret keyed reject map; public SHA-derived reject matrices were eliminated by invalid-only linear equations. We screened one mathematically different serialization, not a further basis/hash-placement variant.

## Candidate: noncommutative group-program target, rather than scalar accepting span
Suppose a publicly described group-program compiler converts an NC1 source-verifier Boolean circuit into a sequence `T_(j,b)` of invertible group elements, reading designated witness bit positions. For every consistent full witness w it outputs `B_x(w)=c` if `R_x(w)=1` and `B_x(w)=e` otherwise, with nonidentity c. This exact polynomial-size compilation for the entire ORIGINAL strict-post-PQ AuxPoW/burn/work verifier was NOT established; standard Barrington length is exponential in formula depth and only polynomial for logarithmic depth. The present candidate is therefore only a structural screen.

Choose private random gauges `G_0,...,G_l`, and publish EACH transition pair:
`M_(j,b)=G_(j-1)^(-1) T_(j,b) G_j`.
A consistent witness yields
`P(w)=product_j M_(j,w_i(j)) = G_0^(-1) B_x(w) G_l`.
Write `P_accept=G_0^(-1)c G_l`, and publish `D=sigma_cancel XOR SHA256(domain||serialize(P_accept))`. Honest every-witness opening (conditional on a nonempty accepted set) produces one same frozen capability from `D XOR SHA256(domain||serialize(P(w)))`. The acceptance group element need not be explicitly public and is not a publicly known SHA-derived per-invalid matrix. Thus the *literal* prior scalar nonzero suffix-span extraction and the exact previous `A P_i=Phi_i B` test do not immediately apply to the semantic interface. That is a mathematical change worth checking.

## Decisive full-public screen: choose transitions per OCCURRENCE
Take the false Boolean formula `f(x)=x AND NOT x`. Let `a=(0 1)`, `b=(1 2)` in the permutation group S3 and `c=a b a^(-1) b^(-1) != e`. The four instruction blocks are:
`T_1(x)=a` if x=1 else e;
`T_2(x)=b` if x=0 else e;
`T_3(x)=a^(-1)` if x=1 else e;
`T_4(x)=b^(-1)` if x=0 else e.
For every ORIGINAL one-bit assignment, the entire product is e:
  - x=0: `e b e b^(-1)=e`;
  - x=1: `a e a^(-1) e=e`.
There is NO satisfying original assignment.

However all four encoded transition PAIRS are public. An adversary is not obliged to call the prescribed `Open(C,w)`; it independently selects `(1,0,1,0)` at the four occurrences and multiplies the published elements:
`M_(1,1) M_(2,0) M_(3,1) M_(4,0) = G_0^(-1) c G_4=P_accept`.
It directly obtains `D XOR SHA256(domain||serialize(P_accept))=sigma_cancel`, with NO consistent x and hence NO original accepted witness. The telescoping proof holds for any group and any independent gauges, including direct products intended to increase key length; increasing group size does not restore cross-occurrence consistency. It requires that the public instruction layout maps each local selection to its occurrence, as in the stated candidate. It is NOT a proof against all conceivable concealed-layout/non-commutative obfuscators.

This is a **full-public FALSE-instance failure**, not an attack on SHA, PoW, AuxPoW, consensus, native signatures or a particular deployed FE. The source verifier itself may be perfectly accurate when called on one full witness. The attack bypasses that call and uses the exposed transitions independently.

## Constructive repair attempted and exact unresolved operation
Make all occurrence choices derive from a single `mu=SHA256(domain||CanonicalOriginalCertificate(w))`, then hash-bind each transition to `mu`. If all frame/transition derivations are public, an adversary may select inconsistent local bits for one chosen mu or compute the public frame corrections between different mu values. A mere certificate-hash tag is not a cryptographically protected input encoder; prior global-certificate-ID and reversible-frame regressions apply. If frames depend on a secret PRF seed, `Open` has no public polynomial-time way to derive the appropriate transitions for EVERY unknown future original witness unless we build a protected evaluator. Publishing seed/frame inverses restores the bypass. Thus do not continue this group-program family with random gauges, S3-to-large-group lifting, hidden-but-publicly-reversible labels, or a changed hash/KDF.

The actual alternative operation would have to be a NEW polynomial-size public `InputEncode(C,w)` that binds ALL consumed local choices to one authentic ORIGINAL w, supplies no independent inconsistent transition access even to an arbitrary adversary reading C, and has a genuine joint-public FALSE/hard-TRUE QPT simulator. That is not instantiated here and cannot be assumed under the name FE, iO, source signer, trusted evaluator, Merkle commitment, or hashed input label. No source-dependent hidden key, common preimage or original-certificate extraction reduction was produced.

## Executed supplementary check and provenance
A Python3 standard-library finite permutation checker was actually invoked. Initial two executions failed on an incorrect Boolean *test assertion* (not a cryptographic finding); the assertion was corrected and two subsequent invocations succeeded with byte-identical output. It verifies the nontrivial S3 commutator, both consistent readouts, independent occurrence spoof, random gauge telescoping and exact recovery of a synthetic 256-bit sealed payload. It uses only deterministic test randomness and fully PUBLIC transitions. This is an algebra regression, not a bridge/security test.

- Final `check.py` SHA256 `45e147166c183138166c622b397cd35847c19607a14c3777e659c1578713b193`.
- Both outputs SHA256 `b03aaa4737d0ddda56eb3a668485c3a3058292f369e0e0333b8fd57f22af447b`.
- Local-only archive `/mnt/data/pq_wkem_group_program_screen_20261123.tar.gz` SHA256 `d52026142f56aec55773b538ed096f4743482855ec93e9b1a9e7a8714c03f5c9`. No sandbox persistence across runs is assumed. The canonical checker and one exact captured output are also retained in this research directory, subject to verified Git readback.

**NONQUALIFYING.** No real source verifier, no original qualifying evidence, no FE/witness-KEM, no independent QPT reduction, no N-of-N malicious-setup theorem, no chain or native cancellation operation. Do not notify the user or post a PR progress comment for this ordinary rejection. Do not stop the existing research automation. Continue ONLY with a mathematically distinct, concretely serialized source-dependent *global* release operation and independently proven public security; not another occurrence basis or group-gauge experiment.
