# R376 — hashed capability addressing: merge-or-branch repair (NONQUALIFYING)

## Source continuity

Start: syscoin/PVUGC PR #1, branch `research/pq-wkem-validation-20260918`, SHA `b9be93ed745a28a818f0146b0ba4405744c6770d` (R375), note blob `edb4b372c7221402fde8898920cee384e80d6dc9`. Recent ordinary comments since 2026-11-18T19:24:00Z returned an empty array. No Core #609 source/tests or network source evidence was examined or run; no native signature or FE was implemented. Strict activated contextual rules remain as previously documented and public PQ activation is not assumed.

## New concrete operation and attempted repair

R375's public hash-encrypted state graph could be traversed by anyone. This iteration made the next proposed change concrete: hide *all* state IDs using public hash-addressed **predecessor capabilities**, then test a fundamentally different per-path rekeying repair.

For a layered DFA with states `s`, bits `b`, and `delta_i(s,b)`, Build samples a random 256-bit `k_(i,s)` for every layer/state. The only initial public token is `k_(0,s0)`. For each edge publish a record at

`a_(i,s,b) = SHA256("address" || k_(i,s) || b)`

with payload `e_(i,s,b) = k_(i+1,delta_i(s,b)) XOR SHA256("enc" || k_(i,s) || b)` and tag `SHA256("mac" || k_(i,s) || b || e)`. Only the terminal acceptance hash `h=SHA256("target" || k_(L,yes))` and encrypted payload `D=S XOR SHA256("key" || k_(L,yes))` are exposed. `Open(C,w)` traverses the table using the input bits; independent accepted words merge at one terminal capability and return the identical S. Fake intermediate state *names* are not accepted without their predecessor capability.

This is an **actual publicly serialized hash-only restricted Build/Open format** in the checker, not an original-source FE scheme.

## Exact public recovery in the merged case

Hiding state identities does not hide reachable capability tokens. Given the initial public token, a classical adversary tries both outgoing edges at every reached token, authenticates/decrypts the next token, deduplicates equal tokens at each layer, and tests the published terminal hash. If `W_i` is the number of reachable tokens at layer i, this finds an accepted whole input with at most `2 * sum_(i=0)^(L-1) W_i` table lookups. The attacker also derives the pad from the accepted terminal token and gets S.

This is a deterministic argument for a complete edge table, independent of key guessing, unpublished state IDs or proof representations. A polynomial-width version of this *specific model* cannot preserve hard-TRUE source-work cost.

## Attempted repair: per-path SHA capabilities

Replace canonical state tokens with `k_(i+1) = SHA256("per-path" || k_i || b)`. That makes otherwise merging prefixes carry different capabilities, blocking polynomial-width token deduplication. However accepting paths now have unrelated terminal capabilities `k_L(w)`. A single terminal hash or ciphertext cannot accept all of them, except with negligible collisions under an ideal 256-bit random-hash approximation.

A concrete format that publishes a terminal pair `(SHA256("target"||k_L), S XOR SHA256("key"||k_L))` for each accepted path requires **one record per distinct accepted path**; no common frozen pad follows from SHA by itself. Random 256-bit token collisions among `2^L` paths have union-bound probability approximately at most `2^(2L-257)`. An on-demand public transition hash removes the edge-table size but leaves this terminal convergence problem unchanged. Compressing all these records into a secure public global source-conditioned function is exactly the missing FE/WE operation, not a demonstrated fix. The record-count observation is only for this specified format; it is *not* a generic lower bound on arbitrary succinct circuits or hash-based WE.

## Executed bounded validation

A Python 3 standard-library checker was executed successfully once. For a synthetic 12-bit parity DFA with width 2, the fully serialized opaque-address table held 48 entries. Public BFS attempted 46 transitions, reached width 2 at every noninitial layer, found accepted word `000000000000`, and recovered the frozen synthetic payload. A separate per-path hashing fixture of length 12 produced 4096 distinct terminal tokens, with 2048 distinct accepting tokens for a trivial last-bit predicate. Neither fixture is Bitcoin PoW nor ORIGINAL evidence.

- Checker SHA256: `e30be22c0aed72262278451f6479ee1d5c5dcecf13e97c0b031417cef86fb9a7`
- Captured JSON SHA256: `bb3f6b79831dc79b355c2cf547152f53e28fc467dcd675eb93c5129588915d1d`
- Local-only complete note, executable, and output: `/mnt/data/R376_merge_or_branch_20261118.tar.gz`, SHA256 `bbadd2d01be2e8ee7d316efe553d4449e43dd86be32f7f5fdac50af6fa6ccd76`. The executable and output are not represented as GitHub-published bytes.

## Research status / precise next equation

The next source-dependent operation would need **succinct hidden many-to-one merging**: an actual classical-PPT serialized public Build/Open for all relevant ORIGINAL authenticated AuxPoW/BTC/burn-fault witnesses, with common frozen safe native cancellation capability, but without (1) arbitrary state injection, (2) polynomial public search recovering accepted original evidence, or (3) enumerating future accepting labels in Build. Its entire public distribution must admit FALSE and hard-TRUE QPT security and an accepted-native-output-to-ORIGINAL-certificate or justified hash/native-break reduction, with malicious setup and siblings. The original three independent OR grounds, modern contextual tag rules, authenticated relevance and depth, deadline/reset, source/claim/outpoint/cancel bindings remain untouched.

**NONQUALIFYING.** This does not construct that release, a general FE or an independent QPT theorem. No ordinary PR progress comment, user breakthrough notification, production/Core changes, deployment or automation change.
