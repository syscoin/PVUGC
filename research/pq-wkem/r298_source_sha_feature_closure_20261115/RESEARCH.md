# R298 — SHA-feature affine closure against correction-gadget release (NONQUALIFYING)

## Provenance

Continues R297 `research/pq-wkem/r297_masked_sha_update_20261115/RESEARCH.md`, blob `c5a032f2c4066bd25745dae6834e564f3de9aca1`. Start: open/draft syscoin/PVUGC#1, branch `research/pq-wkem-validation-20260918`, head `bef9b52585c0db6e6f4cfc545b8e01eb2abc81c5`. Core #609 read-only PR head `c91539de3c34937e57d7f5fda47c7b0502ff33f6`; no Core tests, deployment or code changes. No new ordinary issue comments since 2026-11-12. Historical R275 already has the exponential correction-table idea; the oracle-level correctness and secrecy target below are NOT new practical WKEM results.

ORIGINAL context unchanged: one notary initiates; ANY qualifying watcher can challenge through the OR of (i) qualified greater exact cumulative-work BTC competitor, (ii) finite authenticated defect of the particular withdrawal burn, (iii) relevant SYS inconsistency / independently authenticated fault at sufficient LC depth, with all exact claim/UTXO/withdrawal/burn/amount/recipient/BTC anchor/window/h_rel semantic ancestor/modern contextual AuxPoW chain ID/canonical exact 41-byte tag/parent wrapper/merge mining/interval tags/deadline/reset/capsule/VK/native safe cancellation message bound. No greater SYS work or source signer is assumed. This study models only synthetic *locally* satisfiable clauses, not a substituted ORIGINAL relation.

## Attempted shared frozen-capability construction

Let `Phi_x(w)=AND_i C_i(w)`. Sample independent uniform functions `F_i:W->{0,1}^lambda` and `s_i` conditioned `XOR_i s_i=K`. A local restricted evaluator exposes `T_i(w)=s_i XOR F_i(w)` only for `C_i(w)=1`. Publish an all-input global correction `D(w)=XOR_i F_i(w)`. Then EVERY common satisfying witness recovers EXACTLY the same K:

    Open(w) = D(w) XOR T_0(w) XOR ... XOR T_(m-1)(w) = K.           (1)

In the independent full-table model, the *entire* public transcript has EXACTLY the same distribution for any K on every FALSE instance, even after arbitrary QPT computation on its classical bits, provided auxiliary data does not expose/correlate the underlying secrets. Proof: choose deltas on `s_i` whose XOR flips K. For each w shift permitted `F_i(w)` by its share delta; select one index missing at w (exists by FALSE), shift that still-unpublished F coordinate by the XOR of permitted deltas to keep D(w) fixed. This is a bijection of the independent uniform tape preserving all released tokens and all D values. Sibling and quantum oracle dependence outside this precise classical-transcript model are NOT proved secure. The table is exponentially large; this is a correctness/security target, not classical-PPT Build.

## New attempted polynomial SHA-only representation

Use actual PUBLIC SHA256 features `phi(w)=bits(SHA256("R298/phi/SHA256/" || w))` with d=256. Secret 256-bit coefficients `k_(i,p)`, public `k_sum,p=XOR_i k_(i,p)`:

    F_i(w)=XOR_(p:phi_p(w)=1) k_(i,p)
    T_i(w)=s_i XOR F_i(w)          only if C_i(w)=1
    D(w)=XOR_(p:phi_p(w)=1) k_sum,p                         (2)

This has polynomial-size public correction and exact same-key correctness (1). It uses nonlinear real SHA256 features, but is LINEAR in its hidden coefficients. We grant the attacker an IDEAL locally restricted output-only evaluator for every T_i, which releases neither k_i nor s_i and refuses all forbidden local queries. The actual secure local evaluator is NOT implemented: an attack succeeding even under this stronger interface rules out this proposed feature family.

**Exact affine-span extraction lemma:** set `v(w)=(1,phi(w))` in GF(2)^(d+1), and `u_i=(s_i,k_(i,0),...,k_(i,d-1))` where coordinates are lambda-bit strings. An accepted local token is the vector equation `T_i(w)=<v(w),u_i>`. In particular `s_i` is recoverable by XOR of locally accepted tokens iff `e_0=(1,0,...,0)` belongs to the span of their v rows. If locally permitted v vectors span all GF(2)^(d+1), Gaussian elimination obtains every s_i and every k coefficient. This needs no SHA preimage, source witness, internal trace or forbidden query. Nonlinear public input features do not avoid affine closure in hidden coordinates.

Set `C_0(w)=[w[0]&1=0]` and `C_1(w)=[w[0]&1=1]`. Their conjunction is FALSE. Deterministic synthetic 32-byte locally permitted w give rank 257 after 257 C0 and 260 C1 oracle queries on actual SHA256 feature outputs. The adversary reconstructs both secret 256-bit s values and 512 secret 256-bit coefficients and returns the entire frozen K on a FALSE instance. This is a straight-line classical attack, hence also a QPT attack, in the stated synthetic locally restricted oracle model. For TRUE control where both local predicates permit bit0=0, 128 distinct candidate inputs all yield exactly K. None is an actual BTC/SYS challenge.

## Security attempts and exact remaining gap

Replacing phi by any polynomial-dimensional public vector of SHA/SHA256d outputs or SHA trace bits preserves the extraction lemma where the allowed feature rows span its augmented space. Replacing F_i with independent hidden-key SHA256 PRFs avoids that affine interpolation, but then `D(w)=XOR_i SHA256(k_i||w)` is NOT publicly computable from a short hash-only description unless the seeds are exposed (revealing local s_i after an allowed token), the entire table is enumerated (exponential), or an independently constructed hidden-seed public evaluator is supplied. Merely naming obfuscation, key-homomorphic PRF or SourceOpen assumes the missing primitive. Ordinary GGM subtree seeds yield unshifted F_i on locally allowed inputs; combined with T_i they immediately expose s_i.

The R297 opaque source-earned SHA state transition is still MISSING, not repaired. Neither the ideal table nor the broken affine-compressed variant instantiates `Build_inc(x_W,sigma_cancel)` and `Open_inc(C,w)` for every ORIGINAL witness, gives complete-public hard-TRUE QPT extraction, or ensures native-signature/one-of-N endpoint security. Need a polynomial source-conditional noninteractive release mechanism whose complete public joint interface neither permits cross-witness splice nor local-query affine/low-degree closure and whose recovery reduces to an ACTUAL ORIGINAL certificate or independent PQ hash/native forgery. No group/lattice assumptions, invented source labels, online signers, arbitrary private mining or Bitcoin NP checking are inserted.

## Executed checks, reproducibility, error accounting

Python 3 standard-library synthetic checker: 64 exhaustive lambda=1 cases in ideal independent-table FALSE test, with 16 transcript values identical for K=0 and K=1; actual SHA256 feature rank and 256-bit K recovery after 257+260 local queries; 128 successful same-key TRUE candidate openings. Two FINAL executions produced byte-identical output. Earlier first attempted execution raised `NameError: name 'b' is not defined` in the checker; fixed before two successful final runs; it is NOT counted as passing.

Checker SHA256: `8d05ebf480ee6f1a64b7c41fe2b1b5b20efb8e5ffe5aa13bd2613a0ec96778af`; run1/run2 JSON SHA256: `4ac043140b782aa5fe3959b06284e6391b3437f44509712d99810b40be9c985e`. Local complete archive `R298_source_sha_feature_closure_20261115.tar.gz`, SHA256 `1099a137fa608eee1765e0d68e2aee60a7904e8cd4b203a22a99f483394c4b70` (source, derivation, both outputs and manifest); the archive is a conversation artifact, NOT a Git blob. No real chain checks, source membership, native SLH signing or coherent quantum tests occurred. No release or automation completion; no PR comment/notification justified.
