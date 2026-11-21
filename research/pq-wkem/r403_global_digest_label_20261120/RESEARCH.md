# R403 — globally bound Yao labels from future ORIGINAL witnesses (NONQUALIFYING preflight)

## Live continuity / scope

At this execution the open draft syscoin/PVUGC PR #1 on `research/pq-wkem-validation-20260918` had head `d714d8a288bf990df413c4f2714e78185666aa81` (R402; note blob `9876f26c9c3ea915f79ccfd8fbdd2e3c3425d28d`). Read that exact note and R401 at `fffaf156f611ffb869f2d8c150341caa61f36933`. PR issue comments since 2026-11-19 00:00 UTC: none returned. Core #609 was not source-inspected and no Core tests were run. Latest prior FE assessment `69d4a071e0c68fce7c43c5233bd4839b66efb58a` already specifies a conditional protected gate and one-honest setup; the FE compiler remains uninstantiated.

This iteration deliberately tests a different **mechanism** from R401's enumerable public graph and R402's per-future-certificate SHA sink: hash-based Yao garbling with **global witness-digest coherence** at all input and gate-label occurrences. It aims to defeat R289-style *mixing of labels from distinct source witnesses* while supporting every qualified original witness. The original predicate remains the unchanged OR of qualified greater-BTC-work, specific authenticated burn fault, and strict-contextual qualified Syscoin inconsistency/tag fault at required LC depth, with all agreed claim/outpoint/burn/amount/recipient/anchors/deadline/reset/cancel-message/VK/capsule binding. This note DOES NOT implement that verifier.

## Candidate GDL (global digest labels)

Let `d(w)=SHA256("GDL/w" || Encode(x_W,w))` under injective encoding. A garbled circuit for `R_x(w)` carries the fixed secret output `S`. To enforce that every wire label really belongs to ONE complete witness, propose:

`L_(j,b,d)=H("GDL/label" || k || j || b || d)`

where `k` is a fresh builder seed. Each garbled gate table is indexed/tagged by the SAME `d`, and each input translator for witness `w` should provide ONLY `L_(j,w_j,d(w))`. A decoder for the accepting output must yield exactly the same builder-frozen S irrespective of the accepting witness.

This would block the *specific* cross-witness splice in a **restricted label-issuer model**: if an attacker is confined to copies of one honestly issued label vector per witness and all subsequent gate encryptions are collision-resistently bound to its digest, a label from w_A cannot be treated as belonging to w_B at the same digest without either the same encoded witness or a SHA collision. This is a conditional *coherence statement*, not full-public security; it does not say that labels cannot be created in other ways.

## Actual public compilation / evaluation attempt

The builder would have to publish, before knowing any future witness, a polynomial-size `C` from which a watcher can derive its labels and the corresponding consistent gate tables on ANY accepted original source `w`:

`Build_GDL(x_W,S;k)->C`

`Translate(C,w)->(d(w), {L_(j,w_j,d(w))}_j, {T_(g,d(w))}_g)`

`Eval_GDL(C,w)->S` whenever `R_x(w)=1`.

There are exponentially many possible SHA digests d. A polynomial-time Build cannot enumerate a separate full table `T_(g,d)` for each d. A public generator `T_g(d)` therefore needs either to be computed from published key material or to hide the builder key in a publicly evaluable protected program. The latter is precisely the missing serialized source-conditioned FE/WE operation, not an implementation.

**Public-key branch.** Suppose the scheme exposes the required key material `k`, or publishes per-gate public seeds from which BOTH `L_(j,0,d)` and `L_(j,1,d)` are evaluable for an attacker-chosen d. Then the attacker can decode every row of a standard hash-based Yao garbled gate without supplying any original source witness. Inductively, knowing both labels for each input wire gives both output-wire labels for every gate; the accepting output label and its associated S can be reached by public row processing even when the SHA/AuxPoW verification circuit has no accepting input. A SHA digest tag d on each row does not fix this: the adversary uses one arbitrary d throughout. This is a full-public leakage independent of source-work.

**Private-key branch.** Keep k secret and only expose an oracle `Translate_k(w)` that returns one consistent per-witness label vector, alongside a secretly keyed table generator. The source coherence argument may now rule out one cross-witness splice in the prescribed interface, but there is no offline classical-PPT `Translate(C,w)` from public bytes. Calling the oracle a function-hiding FE evaluator or assuming that it hides k is circular. A one-honest participant with erased k cannot serve future source watchers; a retained online signer is forbidden.

**Precomputed branch.** Publish only table rows/label derivations for polynomially many chosen d. This has a potential fixed-signature opener for those chosen transcripts, but *not* all independently generated future qualified ORIGINAL witnesses. It is an invalid restriction of the release relation, not a legitimate efficient implementation.

**Public proof wrapper branch.** An unprotected ZK verifier might certify that `d=H(x,w)` and `R_x(w)=1`, but a public GDL generator can still be called on raw d/bit/row inputs without going through that wrapper. Enforcing those checks inside the hidden-label issuance is the exact missing cryptographic interface.

## Joint-public security assessment

FALSE: with a public k or decoded input-label pairs, there is no S-independent simulator because the arbitrary-gate-row computation exposes the decoded accepting payload regardless of whether R_x is false. Keeping k in an offline private translator makes S appear masked, but breaks public correctness. No full-public FALSE simulator was obtained.

Hard TRUE: a public both-labels implementation allows extraction without finding a qualifying source witness or doing the requisite source work. In the private-translator model there is no concrete capsule to attack or reduce; a conditional oracle that only allows complete witnesses simply assumes source-conditioned release. No hard-TRUE original-certificate extractor is constructed.

QPT: all honest algorithms sought are classical PPT, with adversaries allowed coherent/joint processing of the public bytes, native VK, auxiliary context and siblings. No quantum random oracle programming, extraction or hybrid was used or established. Hash collision resistance supports only the restricted digest-coherence observation, not hiding of a publicly serialized gate.

This is not an attack on actual strict post-PQ AuxPoW, Bitcoin PoW, SHA preimage/collision security, or all possible FE constructions. It is a rejection of this specific candidate before implementing another toy checker.

## Why this is not the missing advance

The globally digested representation is an actual proposed **mathematical change** relative to the historical local label-splice family: honest label vectors for distinct full witnesses cannot be mixed under a fixed digest without collisions. But it does not solve the larger public-source problem. The builder must encode a fixed S once, yet future valid witnesses have independently chosen digests. If the bytes publicly supply all labels the adversary peels the tables; if private keys are necessary no future public opener exists; if finite tables are frozen some legitimate original witnesses cannot open. The positive restricted coherence property therefore does **not** survive full-public composition.

The most useful precise remaining subproblem is **noninteractive, publicly serialized selective global label issuance**:

`C=GDL.Compile(x_W,S;rho)`, and for every qualifying ORIGINAL `w`,
`GDL.Issue(C,w)` yields one globally coherent input-label vector enabling the SAME fixed S, while *arbitrary processing of C* cannot obtain or mix the accepting output without an actual original certificate or independently justified hash/native break.

This is an *obligation*, not an independently instantiated primitive. Defining it cannot count as source release; it is effectively scoped WE unless a new concrete public algorithm and joint simulator are supplied. No further work should be spent on larger garbled SHA circuits, more digest salts, or precomputed future labels without first instantiating that label-issuance step.

## Actions and handoff

Executed GitHub read-only PR metadata, exact R402/R401 notes, and the narrow issue-comments query. This iteration used symbolic reasoning; no local script, Core test, authentic source witness, native signature, source-work budget measurement, quantum proof, or independent agent was invoked. Candidate was rejected at preflight without fictional test outputs. No PR comment or notification, Bitcoin/Core/production edit, workflow, deployment, funds, or automation change is justified. Maintain the research automation until the original comprehensive completion conditions are actually met.

**NONQUALIFYING: no independently instantiated public Build/Open, no full-public FALSE/hard-TRUE QPT theorem and no ORIGINAL bridge solution.**
