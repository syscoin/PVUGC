# R336 — Fork-graph cochain release attempt (NONQUALIFYING)

## Source/provenance
Read the actual open/draft PR #1 head `5fd2e2b7a104b2d0ffc4ef6f8f067865acbff505` on `research/pq-wkem-validation-20260918` and R335 note blob `6a83fe0b185aa6fbfd953e0e4fd28a39b15f26f4`. The recent top-level issue comments include R225, whose native activation-portability limitation remains. No new Core code/tests or other sources were read. All checked graphs are SYNTHETIC: do not interpret them as a valid contextual AuxPoW history, an LC-depth bridge certificate, or a QPT experiment.

**Selection:** Instead of another low-degree SHA polynomial mask (R327) or a secret-bearing source issuer (R333), test whether the *fork topology itself* can support a path-independent common cancellation key with a publicly computable release circuit, for all relevant future conflicts. This explores actual source-history correlations, rather than invented OTS strings. The result is a rejected candidate, not an ORIGINAL-source foundation advance.

## Complete algebraic candidate

Fix the full withdrawal instance `x_W` (chain IDs, claim/outpoint, burn/amount/recipient, authenticated baseline and anchors/window, relevant ancestor height, LC maturity/fork-depth, deadline/reset, native-safe exact cancel message/VK and capsule). For this *algebraic abstraction only*, two qualified child-history paths `P_a,P_b` start at the authenticated common vertex `r` and end at distinct conflicting child vertices `a,b`. A different Bitcoin parent certificate for the SAME child hash is not a child-history conflict.

Builder freezes the claim-scoped native cancellation capability `S`, samples a 256-bit `K` and 256-bit vertex pads `U_v`. For every ordinary edge that will be needed, publish `D(u,v)=U_u XOR U_v`. Hypothesize a special crossing label available for every relevant future fork pair:
`J(a,b)=U_a XOR U_b XOR K`.
Capsule ciphertext is `CT=S XOR K`; `Open` on two properly verified original paths would compute:
`P(P_a)=XOR_{e in P_a} D(e)=U_r XOR U_a`,
`P(P_b)=U_r XOR U_b`,
`K_hat=P(P_a) XOR P(P_b) XOR J(a,b)=K`,
`S_hat=CT XOR K_hat=S`.
The algebra is exact and **every-witness same-output** in the hypothetical finite graph *if the required crossing label exists*. It is not an implementable ORIGINAL `Build/Open` because the future `J` labels have not been constructed from actual source SHA/AuxPoW.

## Public security and repair analysis

1. **Static public crossing labels:** Anyone holding the path labels and one `J(a,b)` computes `K` immediately, before proving an authentic source fork. A post-hoc public `VerifyOriginal` guard in software cannot stop this extraction. If a public label function can be called on arbitrary non-source `a,b`, `J(a,b) XOR U_a XOR U_b=K` for fake values as well. This is a direct hard-TRUE/public-security failure of this representation.
2. **Deferred crossing label:** Publishing `J` only when an ORIGINAL certificate arrives requires a retained secret or online source issuer. Neither exists in normal SHA256d parent headers, canonical 41-byte SYS tags, Merkle links, or original burn/greater-BTC-work evidence. A source claim certificate authenticates bytes; it does not carry builder-selected node pads. Precomputing crossing labels for all arbitrary future header pairs is an exponential state table.
3. **SHA-only local repair:** Making `U_v=SHA256(domain||v)` renders node pads public. A public function for `J` reveals `K` for any input pair. Making `U_v=SHA256(secret||v)` prevents watcher evaluation on unknown future vertices unless a secret-key evaluator is published; a public serializable evaluator with required original-source gating is exactly the missing WE mechanism, not a free repair. Taking `J` from independently mined parent SHA fields cannot in general enforce `J=U_a XOR U_b XOR K` for ALL independently qualified pair choices with one frozen `K`.
4. **Restricted FALSE simulator:** For a *static* finite graph with NO crossing labels, independently uniform vertex pads and `K` yield ordinary edge labels `D` independent of `K`; `CT=S XOR K` is uniform independent of `D` and any fixed `S`. This is an exact classical whole-transcript distribution equality and survives arbitrary subsequent QPT processing of that classical transcript under independent auxiliary/native VK and sibling state. It is NOT the actual full-public ORIGINAL-FALSE simulator; including a callable `J` breaks it.
5. **Sibling capsules:** Reusing `U` across claim-specific keys gives `J_1(a,b) XOR J_2(a,b)=K_1 XOR K_2`; opening one claim opens a sibling on the same pair. Independent per-claim `U_i` removes this *partial-view* XOR correlation, but when each claim's own path-edge tokens and `J_i` are public, each capsule still opens early. Hash-domain separation of `CT_i` cannot conceal a leaked `K_i`.

All genuine proof requirements remain: source authentication inside release and exact relevant semantic ancestry at `h_rel`; qualifying strict-PQ contextual chain ID/canonical tags and complete LC depth; three OR challenges independently usable; no greater Syscoin work/fork winner; malicious N-of-N setup/retained source coins/siblings; FALSE and hard-TRUE arbitrary QPT key recovery to an ACTUAL ORIGINAL certificate or independently justified hash/native break; exact native safe cancellation bound across activations. The R316 stale-tag fixture is not an LC escape: strict history comparison can detect the qualified fork when coverage/maturity is present.

## Executed regression, provenance and handoff

`check.py` uses deterministic Python3 SHA256-linked *synthetic* fork paths, XOR vertex/edge masks and 128 graph fixtures. It asserts exact path telescoping, unauthorized public opening, fabricated crossing opening, shared-pad sibling opening, and independent-pad sibling opening when its own edges are public. **Two actually invoked runs each passed 768 assertions with identical output bytes.** This is not actual Core admission/Bitcoin best-chain verification, native signatures, or a quantum-security test.
Checker SHA256: `1348e5ea6961040a80fa17d0a6f28e2e417ede4d5067e32e151e414adc7370b1`.
Both captured outputs SHA256: `4f3d57b1d5d4ad6a0c0b59a22f979bea180e33e3a2703e1624de2b2da3cbb949`.
Fuller local derivation/checker/paired outputs archive `R336_fork_cochain_20261117.tar.gz`, SHA256 `5e5eb985916c56b4a9d1bac010c8e602d43f35f71c5a56647efdc07909a552a4`, not guaranteed accessible from future runs.

**NONQUALIFYING.** Do not present this as actual source-dependent release or a secure WE. The exact new missing operation in the candidate is a *classical polynomial-size, setup-time, public* source-conditioned crossing token for every future ORIGINAL relevant authenticated fork, without making that token available for invalid/fake values, without an issuer or precomputed exponential table. This is the pre-existing WE gap in a new graph formulation, NOT a reduction or independent assumption. Reject this family until such operation is independently constructed. No progress comment or user notification is warranted.
