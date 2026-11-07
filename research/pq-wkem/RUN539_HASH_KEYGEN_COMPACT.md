# Run 539 — deterministic hash-native key-generation barrier (scoped)

Research-only. Verified connected-GitHub PR head: `69d112e5255dfd195bfb8255d42ced10e9e615e1`; `syscoin/PVUGC#1`, branch `research/pq-wkem-validation-20260918`, draft/unmerged. No production changes. This tests the proposed hash-based **keyless** signing-key trapdoor, not generic local mixing or honest-erasure N-of-N.

## Exact random-oracle interface and theorem

Idealize native verification-key derivation as `pk=H_sig(s)`, where `H_sig:{0,1}^a->{0,1}^n` is an independently domain-separated random oracle and `s` is a complete deterministic native signing seed. This does NOT assert that SLH-DSA keygen itself is an ideal oracle. The ORIGINAL `(x,w)` distribution, claim/UTXO/branch/window and other classical public source auxiliary data are independent of `H_sig`. Honest classical-PPT `Build^H(x;coins)` outputs a `pk` and public recovery data after `q_B` queries; a malicious **keyless** builder retains every coin, intermediate and oracle query. Honest classical-PPT `Recover^H(x,w,pk;coins)` makes at most `q_R` further `H_sig` queries and outputs a signing seed that must produce `pk`. Give an attacker the complete Build transcript and all public keys/capsules; arbitrary QPT and QROM queries are allowed in the overall game.

Let `E_B` mean some Build query `(s,H_sig(s))` has `H_sig(s)=pk`. On `E_B`, the retained-state builder immediately possesses a usable signing seed. Conditioned on no such query and the whole Build transcript, each **fresh** classical Recover hash query is uniform and independent of the fixed `pk` (since the ORIGINAL source is independent of `H_sig`). An unqueried final output requires one further lucky hash image. Therefore:

`Pr[Recover returns s with H_sig(s)=pk AND NOT E_B] <= (q_R+1) / 2^n`.

If honest correctness is `C`, the malicious builder obtains a usable credential with probability **at least** `C-(q_R+1)/2^n`. This is an information-theoretic classical-honest-algorithm dichotomy, not a QPT hardness theorem. It rules out THIS public random-oracle/hash-native **keyless** interface for independent future SYS/BTC evidence: either Build already knows a signing seed, or polynomial-time witness recovery almost always fails. It does NOT rule out N-of-N setup with an honest eraser, a non-RO native key-generation function, or source statements correlated with this exact oracle.

## A narrow positive exception (not a bridge WKEM)

If an **external party** publishes `y=H_sig(ctx||s*)` while keeping `s*` hidden from Build, define the restricted ORIGINAL relation `R_pre((ctx,y),s)=[H_sig(ctx||s)=y]`. `Build` simply sets native `pk=y`, and a holder of `s` recovers that signing credential directly. For a uniformly sampled a-bit `s*` and n-bit RO output, the probability this image has a unique a-bit preimage is exactly `(1-2^-n)^(2^a-1)` (at a=256,n=512 at least `1-2^-256`). This gives a genuine special-case, preimage-witness **keyless authorization** interface; coherent Grover search over 2^a possible seeds gives only a query-complexity upper bound `O(2^(a/2))`, not native-SLH QPT security.

It fails the actual Syscoin target: authenticated incompatible-fork evidence `e` is not a preimage of a precommitted native public key. Adding `R_fork(x,e)` to the preimage condition leaves a watcher knowing `e` without the signing seed. Supplying the seed to watchers beforehand permits signing without `e`. The false-instance common hidden K game is also absent: a non-image `y` may have no signing seed at all. `ctx` must bind relation/claim/UTXO/branch/anchors/window but binding cannot repair this source-to-seed gap. Run 259 source binding applies only to accepted complete representations under its actual hypotheses, not bare native signatures.

## Attacks, model and remaining work

Tested in this single-hash model: public/adaptive hash queries (#5), malicious builder seed/coin retention (#6), reuse and domain binding (#7), native checking-key equality (#8), and quantum preimage-search **upper bounds** (#9). Neighbor seams, hidden frame gauge, gate fingerprints and opened multi-capsule masking (#1–4) are not present in this toy candidate; no conclusion about them. Full arbitrary-QPT false-instance hiding, true-instance native forgery to ORIGINAL, all-witness same K for the real SYS/BTC relation, actual SLH keygen/sighash, malicious N-of-N/abort, multi-capsule and concrete resources remain UNPROVED.

The compact exact Node checker was executed twice byte-identically and syntax-checked; its captured output verifies finite toy cases only (retained builder, fresh random-hash queries, preimage uniqueness). The separately preserved extended Python checker and proof are local-only. Do not infer cryptographic or quantum security from toy tests. Practical WE-like release remains unsolved; stopping condition unmet.
