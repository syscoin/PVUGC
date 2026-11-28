# HSA — prefix-hash state automaton for witness-conditioned cancellation (nonqualifying preflight)

## Provenance and target

Read-only GitHub PR #1 on syscoin/PVUGC, branch `research/pq-wkem-validation-20260918`, start head `45e302bfa642eed28e6bb40fcd1b82b142cfa50b` (R403). Exact R403 note `research/pq-wkem/r403_global_digest_label_20261120/RESEARCH.md`, blob `3d13cabb272634ca127bd9567fe55694f1dc20db`, was read. A narrow issue-comments GET since 2026-11-19T00:00:00Z returned no results. Core #609 only PR metadata was consulted: source and tests were not rerun; release activation not inferred. No other web or literature accessed.

**Objective unchanged:** classical-PPT public `Build_inc(x_W,S)` with `Open_inc(C,w)=S` for every qualifying ORIGINAL witness, and complete-public FALSE and hard-TRUE QPT security against recovery without an actual original certificate or an independent cryptographic break. The ORIGINAL relation remains the independent OR of qualified greater exact BTC work, specific finite authenticated burn fault, and strict-post-PQ relevant Syscoin inconsistency/tag fault at required LC depth; all source, claim, outpoint, deadline, reset, message and capsule binding remains mandatory. A witness cannot be forced to be canonical. No new signing party may be required at challenge time.

## One named candidate: HSA (prefix-hash state automaton)

**Specific change versus R403:** eliminate the need to precompute a table for each *full* source-witness digest by advancing one public, collision-bound, prefix-dependent label at each input step. This is an order-sensitive, no-inverses construction attempt, not another low-degree mask or multiplicative cover.

Fix injective `Encode(x_W,w)=b_1...b_L` and a domain-separated hash `H`. Let

`q_0=H("HSA/start"||sid||x_W)`
`q_j=H("HSA/step"||sid||j||q_(j-1)||b_j)`, for `1<=j<=L`.

An evaluator can compute `q_j` in polynomial time on *any* supplied string without a private key. All q labels are connected to one complete prefix; with an ideal 256-bit SHA compression/function and collision bounds, two distinct encoded prefixes cannot silently share a label except with a collision. A local cut-and-paste of a prefix state into another prefix will not in general preserve the next state. This avoids the *restricted* cross-witness label-splice exposed by unbound per-clause labels. It does not yet authenticate source validity, so a final constraint must gate release.

Try to build `C=(sid,x_W,D,\{terminal rows\})` such that, for the set `A_x=\{q_L(w):R_x(w)=1\}`, the public terminal decoder obeys

`Decode_C(q_L(w))=S` for every `w` with `R_x(w)=1`,
`Decode_C(q_L(w))=bottom` otherwise.

For a fixed terminal row indexed by a valid hash state `q`, the natural hash-only ciphertext is

`D_q=S XOR H("HSA/key"||q)`.

That row is efficiently usable by the holder of the path ending at q. Source authentication and global context checks would have to be included in the covered relation; merely calculating q is insufficient.

## Exact builder/evaluator analysis

1. **Explicit row compilation.** The builder must publish `D_q` for *every* valid terminal q. The builder does not know future authenticated witnesses. The row count is `|A_x|`, potentially exponential. Prefix hashing does not by itself compress the terminal mapping. Under the simplified injective hash idealization, `|A_x|` equals the number of distinct valid encoded witnesses. This is an explicit table-size requirement for this construction, not an impossibility claim for other hash-only schemes.

2. **Public terminal generator.** Suppose `Decode_C(q)` is computed from a polynomial-size public generator. If its generation exposes `S` or permits `S = Decode_C(q)` for a source-invalid q, it leaks the frozen signature on both FALSE and hard-TRUE instances. A public check `if R_x(w) then Decode_C(q)` in a separate wrapper is not binding: the attacker evaluates the terminal generator directly. If instead `Decode_C(q)` hides S and outputs only on certified q, the compiler and the full-public security of that very function are precisely the missing source-release foundation. This is **not** an implementation from ordinary SHA preimage/collision resistance.

3. **Forced convergence.** Replace the many q terminal states with a single accepted label `q_acc`, and set `D=S XOR H("HSA/key"||q_acc)`. If `q_acc` and D are publicly published, S is publicly recovered. If `q_acc` is secret, a public transition from each possible accepted `q_L(w)` to `q_acc` has to be implemented. Explicit transition rows return to item 1; an implicit keyed transition returns to item 2. The apparent convergence is not source-dependent cryptographic release by itself.

4. **Public append/update variant.** Suppose anyone can extend a frozen capsule with `Update(C,w)` after seeing a source certificate. If Update has no access to S or a secret, it cannot simply generate `D_q=S XOR H(q)` for a previously unknown q. If it can somehow do so with only C and w, then `Open'(C,w)=Open(Update(C,w),w)` already implements the original offline Build/Open obligation. Calling the computation an update does not produce a new independent release assumption.

## Concrete bounded-width consequence, not a general lower bound

Suppose at an intermediate position j this particular HSA encoding has `M_j` distinct reachable input prefixes which must remain separately addressable (because prefix-dependent states are not merged). A direct lookup representation needs at least `M_j` rows/keys. In an *ideal independent 256-bit random-function model*, a set of `2^k` distinct length-j prefixes has collision probability bounded by approximately `2^(2k-257)` (union bound; valid for k substantially below 128), hence `M_j=2^k` with overwhelming probability when `k=64`. This calculation pertains to arbitrary distinct prefixes and **does not establish that the ORIGINAL valid-witness language contains 2^64 such prefixes at a given step**; a claim about that source language would require an independent qualification proof. It simply shows that this specific prefix-hash routing method does not create efficient state merging for free. No exponential exact table is acceptable for Build.

## Security and source relevance

The prefix collision argument concerns only consistency of an *already issued* path. It does NOT show that possession of a valid original certificate releases S, that arbitrary processing of the complete C cannot recover S, or that a hard-TRUE attacker must perform original work. The public state computation accepts arbitrary strings; adding a hash of authenticated AuxPoW proofs to the path does not make source authentication cryptographically gate S. The activated Core rules, actual claim-relevant ancestry, qualified depth, original evidence windows, and R225 native signature activation binding remain separate unsatisfied prerequisites.

No joint FALSE simulator exists for the public-terminal generator, and no hard-TRUE QPT reduction to an actual ORIGINAL witness exists. The hash idealization above is an **idealized collision counting exercise**, not a QROM security proof for concrete SHA. No substantive security conclusion is drawn from absence of measured attacks.

## Handoff and actions

The specific HSA change avoids one restricted local-label splice by making the label state depend irreversibly on the full ordered prefix; **the missing public terminal transition has not been constructed**. The next equation cannot be postponed to an external private translator or proof-wrapper:

`Compile(x_W,S;rho)->C` with public `Decode_C(q_L(w))=S` for **every** `R_x(w)=1`, and a complete-public FALSE/hard-TRUE joint simulator/extractor (including source coin retention, native VK/context, sibling capsules and QPT processing).

A viable future candidate must supply a *concrete polynomial-time terminal map* with an independently justified security reduction, not more HSA state indexing, hashes, tables or toy fixtures. The known R289/R327/R366/R403 failure families remain regressions.

This was a symbolic candidate preflight with actual GitHub read-only PR/notes/comments; **no local code or tests, no Core source/test execution, no authentic source certificate, no FE/WE algorithms, no PR comment or user notification**. Nothing here closes the missing ORIGINAL source-dependent release foundation. No main/production/workflow/deployment/automation changes.
