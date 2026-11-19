# R378 — whole-input-indexed telescoping masks; ideal algebra only (NONQUALIFYING)

## Continuity and exact scope

Started from live syscoin/PVUGC PR #1 branch research/pq-wkem-validation-20260918, head 08bb6e9e1bc06c3ec0c5c77fdd8acfbd02bc21ee (R377). Recent ordinary comments since 2026-11-18T18:00Z: none. Read R377 and its immediate R376 predecessor; did not reread Core #609 source or rerun Core tests. Original three-branch, strict-post-PQ Syscoin/BTC/burn challenge relation, LC depth, relevant ancestry, and safe frozen cancellation endpoint are NOT weakened.

The exact preceding failure was that R376's publicly traversable polynomial-width hashed DAG permits public finding of an acceptance path, while its per-path terminals cannot converge to one common K; R377's signature rekey does not repair this. R366's locally-balanced clause covers recover the frozen K without a common globally consistent witness. This iteration changes the **index of every hidden mask to the entire common witness string**, rather than a clause's local assignment, and jointly analyzes correctness and the full ideal function distribution. This is NOT a serialized hash-only Build/Open for the bridge.

## Explicit ideal operation

For a canonical full Boolean witness w in {0,1}^n, express the verifier as local Boolean constraints c_1(w),...,c_m(w), with their conjunction representing a single accepted source relation (the original OR branches can be compiled into one verifier circuit; a missing branch is NOT silently excluded). Choose uniform K in {0,1}^lambda, independent uniform random functions F_1,...,F_(m-1) on the entire n-bit input domain; set F_0(w)=0 and F_m(w)=K for every w. Publish ciphertext D=S XOR K and an abstract selectively accessible function:

    E_j(w) = F_(j-1)(w) XOR F_j(w), if c_j(w)=1;
             bottom otherwise.

One globally satisfying w yields XOR_{j=1..m} E_j(w)=K, hence D XOR K=S. Every valid w yields the SAME S, without common preimage, same internal state, or canonicalized future parent history. Unlike R366, inputs on distinct full witness strings use independent masks; local cover mixing cannot telescope in this ideal model.

## Exact FALSE joint-table coupling (restricted to ideal functions)

For any FALSE instance, each w violates some gate indexed j(w) (1-based). For any fixed Delta, transform K'=K XOR Delta and S'=S XOR Delta. For 1<=i<m define F'_i(w)=F_i(w) when i<j(w) and F'_i(w)=F_i(w) XOR Delta when i>=j(w). Every available E'_j(w)=E_j(w): for j different from the missing j(w) the two endpoints shift together or not at all; the only affected edge is absent. Also D'=S' XOR K'=D. This is a bijection on independently uniform functions, preserving the ENTIRE ideal output table, including coherent access to that same deterministic function table. It does NOT simulate concrete capsule bytes, auxiliary checking keys/native VK, or maliciously correlated siblings. For TRUE, valid whole-witness telescoping gives the common key.

Graph interpretation: each full input w has nodes (0,w),...,(m,w), with shared fixed node values 0 and K only at its endpoints. Every available local gate gives an edge difference. A FALSE instance has a break in every w-chain; no set of edge XORs spans K, even using multiple locally accepted assignments. This is a linear-algebra fact about ideal labels, not a hard-TRUE extraction theorem and not practical witness encryption.

## Attempted classical hash-only serialization: the point of failure

The public artifact must expose ONLY the correlated XOR difference E_j(w), restricted to inputs passing c_j, without disclosing its constituent F_i values, and do so in polynomial size. A naive GGM/SHA constrained-PRF design exposing separate constituent evaluations is insecure. For m=3, if the second gate's public key permits F_2(w), and the third gate supplies F_2(w) XOR K, then any w satisfying c_2 and c_3 reveals K—even when c_1(w)=0. The FALSE Ch fixture (A: t=Ch(x,y,z), B: t=Ch(x,z,y), C: y!=z) contains four such words: 0010, 0101, 1011, 1100. This is a constructive attack on the attempted serialization, not on the ideal function law.

Publishing a separate ordinary constrained GGM key for each E_j does not automatically preserve the required cross-gate XOR correlation: SHA/GGM child expansion is nonadditive in the seed, so the XOR of parent seeds does not yield the XOR of their child outputs. Individual per-path correction records or output tables may be exponential, and any hidden-key runtime/obfuscated gate would assume the missing cryptographic primitive. A secure, efficiently serializable correlated constrained evaluator was NOT constructed. A universal hash-based FE assumption would merely rename the original research requirement.

## Multi-capsule selective opening regression

Reusing the same hidden F_i across capsules A,B gives E_m^A(w) XOR E_m^B(w)=K_A XOR K_B for any w passing only the final gate. If S_A becomes legitimately known, then K_A=D_A XOR S_A, whence K_B and S_B can be recovered without an ORIGINAL witness for B. Thus independent domain-separated functions per capsule are necessary even in the ideal model; sufficient malicious multi-capsule/QPT security is unproved.

## Actually executed limited checker

A Python 3 standard-library checker evaluated all 16 four-bit assignments for the FALSE triple-Ch fixture and a TRUE variant with C: y==z, checked the full-table FALSE tape coupling for each input, checked same-S opening for all TRUE witnesses, recovered the secret from the four B-and-C-only inputs under naive constituent exposure, and checked sibling reuse leakage. SHA-based child expansion was checked as a nonhomomorphism negative control. The checker was successfully executed twice and outputs were byte-identical. The test has no authentic Bitcoin/Syscoin source certificates, FE compiler, Bitcoin VM validation, native signing or QPT security experiment.

Local checker SHA256: 1c80c800e25fbb2afa53ef7789f8e75b69fded54efd4ddff6d0d20d2f8b63207.
Local captured output SHA256: 8e1dfb95e1990092a7202d803e89b68b6e0631211773fdf90617906feb8b6b15.
Local-only archive R378_whole_input_telescoping_20261119.tar.gz has SHA256 9dd64f14d91ece54bd54e0793607afe8c4e0d8200e93c09da2daa3862e128ae9; the executable and output bytes are NOT claimed GitHub-published.

## Precise unsolved next operation

Actual classical practical serialized Build_inc(x_W,sigma_cancel)->C and public Open_inc(C,w)=sigma_cancel, with EVERY qualified ORIGINAL Bitcoin-greater-work, finite authenticated particular-burn fault, or qualified Syscoin-inconsistency/tag-fault witness yielding one frozen native safe authorization, remains absent. A complete-public FALSE and hard-TRUE QPT accepted-cancel -> actual ORIGINAL certificate or independently justified hash/native break reduction is also absent. Malicious one-honest N-of-N setup, native claim/outpoint/sighash binding, timing, sibling capsules and source-coin retention remain mandatory.

Next candidate must construct a **public correlated constrained evaluator for XORs of secret whole-input functions, admitting only fully typed source-local constraints**, without exposing individual masks, allowing arbitrary public evaluation, or enumerating exponential paths. This is a requested source-dependent operation, NOT a cryptographic assumption that may be counted as already solved. If it cannot be instantiated from independently justified hash primitives, reject/replace the direction rather than repeat the same ideal test.

NONQUALIFYING. No PR progress comment, user breakthrough notification, Core/production edit, deployment or automation change.