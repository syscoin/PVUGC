# Run 258 — local-block enumeration barrier for independent-secret recentering

## Checkpoint

This bounded pass starts from the actual live `syscoin/PVUGC#1` state read through the connected GitHub integration:

- branch: `research/pq-wkem-validation-20260918`
- starting SHA: `0d9435bb72a418345da7b86153852ea558c5e770`
- PR state: open, draft, unmerged
- latest substantive ordinary PR comment: `5945825660`
- exact current-head dependencies:
  - `STAT_DUAL_MODE_SOURCE_HASH_QPT_EXTRACTION_RUN123.md`, blob `2eefa25de7f5a9b9c65abf15a20bb4ae6564702e`
  - `DUAL_MODE_HASH_SECRET_RESAMPLING_BARRIER_RUN126.md`, blob `94d1a6246da77f561ecacd84ce78917d6121dc33`
  - `HAIR_SAHAI_COMMON_KERNEL_DICHOTOMY_RUN251.md`, blob `adf223622a6ed75a1f060706fd7bd522c1c6ede1`

The immediate predecessor is the locally preserved Run-257 checkpoint, `SHARED_SECRET_SECOND_DIFFERENCE_AND_RECENTERING_RUN257.md`. Run 257 showed that the Waters--Wee--Wu shifted-preimage family should **not** share one LWE secret across affine-indexed blocks, because a four-cycle cancels the shared secret, but that independent per-index LWE secrets can be publicly recentered onto one common hidden capability. The unresolved problem was to turn an ORIGINAL NP witness into accepted representations and prove the converse extraction arrow.

This run tests the most obvious next compiler attempt: decompose an NP verifier into polynomially many local gate/consistency relations and attach one independently recentered projective block to each local relation.

The result is negative and unconditional for that decomposition:

> If every local block can be satisfied/search-opened independently in polynomial time and a valid local opening reveals a witness-independent block center, then local enumeration recovers the release value without a globally consistent ORIGINAL witness. Adding wire-consistency checks as more independently projective local blocks does not fix this.

This closes the naive gate-by-gate route from Run 257. It does **not** rule out a genuinely global source-binding representation, a nonseparable cross-block compiler, or witness encryption in general.

No production path is changed.

---

## 1. Abstract local-block model

Fix a global NP relation `R(x,w)` and a public transcript

\[
P=(P_1,\ldots,P_\ell,\mathsf{aux}).
\]

For each block `j`, define a local relation

\[
L_j(x,z_j)\in\{0,1\}
\]

and a public local evaluator `Eval_j` with a **witness-independent block center** `h_j`:

\[
L_j(x,z_j)=1
\quad\Longrightarrow\quad
\mathsf{Eval}_j(P_j,x,z_j)=h_j(P_j,x).
\tag{1}
\]

A global valid witness is mapped to local openings

\[
z_j=\phi_j(x,w)
\]

that satisfy every block. Suppose the protected capability is recovered by a public deterministic combiner

\[
H=\mathsf{Comb}(h_1,\ldots,h_\ell,\mathsf{aux}).
\tag{2}
\]

This includes two natural uses of Run-257 recentering:

1. **same-center blocks:** every block is recentered directly to the same `H`;
2. **share-center blocks:** block `j` is recentered to a share `h_j`, and the shares combine to `H` (e.g. xor or addition).

The model deliberately allows arbitrary statement dependence in the public block descriptions. The attack below does not require those descriptions to look random or be close across statements.

---

## 2. Theorem — independent local search defeats witness-independent centers

Assume there are classical PPT algorithms `Search_j` such that

\[
\Pr[L_j(x,\mathsf{Search}_j(P_j,x))=1]\ge 1-\epsilon_j.
\tag{3}
\]

No compatibility between the independently found local openings is assumed.

### Theorem 1

There is a classical PPT capability-recovery algorithm that outputs `H` with probability at least

\[
\boxed{1-\sum_{j=1}^{\ell}\epsilon_j.}
\tag{4}
\]

### Proof

Run every `Search_j` independently as an algorithmic step (the probability spaces need not be independent), evaluate the successfully opened local block using (1), and apply the public combiner in (2). The only bad event is that at least one required local search fails. By the union bound its probability is at most `sum_j epsilon_j`. The found local openings need not arise from a single global witness because each `h_j` is independent of which local witness opened block `j`. ∎

The attack is classical PPT, and therefore is also available to an arbitrary QPT adversary.

### Deterministic enumerable corollary

If every local witness domain has polynomial size and `L_j` is publicly checkable, exhaustive local search gives `epsilon_j=0`. Thus whenever every local relation is nonempty,

\[
\boxed{\Pr[\widehat H=H]=1,}
\tag{5}
\]

even if the global relation `R(x,\cdot)` has no witness.

For a Boolean gate of constant arity, the local witness domain is constant size: at most 8 assignments for a 3-wire gate and at most 4 assignments for a 2-wire consistency check.

---

## 3. Same-center specialization: one locally satisfiable block already leaks the key

Run 257's strongest algebraic form recentered every accepted representation directly to one common hidden center `H`:

\[
d_i+v_i^T\pi_i = H+\text{small error}.
\tag{6}
\]

If a proposed generic compiler simply assigns one such block to each gate/constraint, then an attacker does **not** need to solve all local relations. One searchable nonempty block is enough to obtain `H` after reconciliation.

Therefore a gate-by-gate realization of (6) is immediately invalid for generic NP: essentially every ordinary Boolean gate relation has at least one trivial satisfying local assignment whether or not the complete circuit has a satisfying global witness.

This is stronger than a consistency failure. The common-center feature itself makes each independently openable local block a complete release oracle.

---

## 4. Secret-sharing the center across blocks still fails if the shares are local-canonical

A natural repair is to choose centers `h_1,...,h_l` with

\[
H=h_1\oplus\cdots\oplus h_\ell
\]

(or the analogous additive relation) and make block `j` release only `h_j`.

Theorem 1 still applies. If the attacker can find **some** valid local witness for every block, it obtains every share and combines them. The local witnesses may be mutually inconsistent.

This distinction matters: a circuit verifier enforces a conjunction of constraints on **one shared assignment**, but the blockwise release layer above enforces only that each constraint relation is nonempty. Those are very different predicates.

---

## 5. Explicit false instance with locally satisfiable gate and consistency blocks

Take Boolean variables `x0,x1` and the three constraints

\[
x_0=0,\qquad x_1=1,\qquad x_0=x_1.
\tag{7}
\]

There is no global assignment satisfying all three. Yet every local relation is nonempty:

- the first is opened by `x0=0`;
- the second by `x1=1`;
- the equality block by either `(0,0)` or `(1,1)`.

If the three block centers over `Z_257` are

\[
(17,91,203),
\]

then the intended additive capability is

\[
H=17+91+203\equiv54\pmod{257}.
\]

Independent local search recovers all three centers and therefore `H=54`, despite the absence of an ORIGINAL witness.

The example also shows why **adding consistency as another independently projective block does not enforce consistency**. The equality relation is itself easy to satisfy locally; the attacker does not need its chosen equality witness to match the local witnesses used for the neighboring blocks.

A gate-level variant is equally small:

\[
x_0=0,\qquad x_1=\neg x_0,\qquad x_1=0.
\tag{8}
\]

Again, the conjunction is false, but every constant-arity local relation is trivially searchable.

---

## 6. Exhaustive finite census

The deterministic checker enumerates Boolean CSPs on three variables built from:

- unary constraints `x_i=0/1`;
- equality constraints `x_i=x_j`;
- inequality constraints `x_i!=x_j`.

It checks every subset of one through four primitive constraints. Among 793 systems, **457 are globally false while every selected local block is nonempty**. The blockwise attacker recovers the intended combined center in all 457/457 false systems.

This is not a cryptographic hardness experiment. It is an exhaustive finite validation of the logical gap between

`all local relations are nonempty`

and

`there exists one globally consistent witness satisfying them all`.

---

## 7. Relation to the current literature

Waters--Wee--Wu's shifted multi-preimage sampler is a genuine multi-block lattice primitive. It samples a **common shift** and correlated short openings and gives perfect somewhere programmability in Construction 4.6; their hidden-bits mode-indistinguishability theorem then uses ordinary LWE one block at a time. That supports Run 257's conclusion that the *hiding/recentering layer* can plausibly be handled without one shared LWE secret. It does not supply the missing ORIGINAL-witness source map. Primary source: ePrint 2024/1401, Construction 4.6 / Theorem 4.7 / Theorem 5.6.

Garg--Hajiabadi--Kolonelos--Kothapalli--Policharla's CRYPTO 2025 framework independently treats the translation from a natural relation to a relation with a linear verifier as a central missing piece, and their framework supplies specialized gadgets to perform that translation. Their slides explicitly state security in the generic-group model. This is useful architectural evidence: one cannot obtain generic NP merely by wiring together independently openable linear blocks. It is not a post-quantum/LWE instantiation for the present target. Primary source: CRYPTO 2025 slides for *A Framework for WE from Linearly Verifiable SNARKs and Applications*.

Bhadauria--Branco--Döttling--Garg--Policharla (ePrint 2026/1079) similarly constructs a WPRF only for the **specific local-opening language** of a vector commitment, under standard pairing assumptions; its own abstract contrasts this with general-purpose WPRFs. A local-opening WPRF therefore does not, by itself, provide the generic NP source-binding compiler required here.

These literature points are supporting context only. Theorem 1 is elementary and unconditional within its stated blockwise model.

---

## 8. What a surviving construction must do

Run 257's independent-secret recentering remains useful only **after** the source compiler has a representation relation whose search is globally source-binding.

A surviving compiler must therefore violate at least one hypothesis of Theorem 1 in a principled way:

1. **Global hard representation.** At least one required accepted representation is as hard to find as an ORIGINAL witness; it cannot be obtained by independently enumerating a constant-size gate language.
2. **Nonseparable cross-block release.** Local outputs cannot be witness-independent centers that a public combiner accepts regardless of compatibility. The cryptographic algebra itself must make inconsistent local choices fail to reconstruct.
3. **ORIGINAL extraction.** Any representation tuple that does reconstruct the capability must yield an ORIGINAL witness (or an independently justified QPT break), not merely a set of locally satisfying assignments.
4. **Standard-QPT hiding.** The complete false-instance public view must still reduce straight-line to an independently justified QPT-hard assumption; the missing global-consistency mechanism cannot simply be renamed as evasive LWE, WE, FE, or an oracle.

Item 2 is the nontrivial one. A naive “add equality blocks” repair is explicitly closed by this run because equality blocks are independently searchable too. The cross-block coupling must be cryptographic, not merely another local predicate.

---

## 9. QPT/security ledger

| Component | Honest model | Adversary model | Assumption | Exact conclusion |
|---|---|---|---|---|
| local-search theorem | classical PPT | classical PPT, hence QPT-capable | none | capability recovery `>=1-sum eps_j` |
| enumerable-gate corollary | classical public checking | deterministic classical PPT | polynomial local domains | false global statement can still release if every local block is nonempty |
| same-center Run-257 specialization | classical local opening | classical PPT | none beyond correctness of local recentering | one searchable block reveals common center |
| share-center specialization | classical local openings | classical PPT | none beyond public combiner | independent local witnesses recover all shares |
| WW&W inner hiding layer | classical PPT | QPT only under explicit QPT-LWE lift | ordinary LWE + sampler properties | supports hiding-layer architecture only; not source binding |
| generic NP ORIGINAL source compiler | classical public/offline | arbitrary QPT | **missing** | must enforce global consistency in the cryptographic representation/release algebra |

No PPT-only theorem is relabeled as QPT security. The attack itself is classical, so any construction satisfying its hypotheses already fails the stronger QPT target.

---

## 10. Reproducible checker

`local_block_enumeration_run258_check.py` is deterministic and standard-library only.

Final validation:

- `py_compile` passed;
- two complete executions were byte-identical;
- **27,693 assertions** per finalized execution;
- core false CSP: 0 global witnesses, 4 candidate tests total, exact capability recovery `54 mod 257`;
- gate counterexample: 0 global witnesses, 4 candidate tests, exact capability recovery `167 mod 257`;
- exhaustive small-CSP census: 793 systems, of which 457 are false but every selected block is locally nonempty; all 457/457 expose the blockwise-combined capability;
- 19,530 finite union-bound grid checks.

The checker validates algebra/combinatorics only. It is not evidence for or against LWE/SIS hardness, a generic quantum extractor, or malicious setup security.

---

## 11. Core handoff

Do **not** try to turn Run 257 into generic NP by assigning one recentered block per Boolean gate and one more block per wire-consistency check. With a common center, one local opening already leaks the capability; with local secret shares, independently enumerable local openings recover every share without a global witness.

The next bounded pass should target a **nonseparable global-consistency representation**: a compact statement-dependent encoding in which capability reconstruction from any accepted representation tuple implies a globally consistent witness, and where that implication can be turned into an arbitrary-QPT ORIGINAL-witness extractor (or a standard-QPT assumption break). If the candidate's consistency mechanism is itself just another independently searchable local relation, reject it immediately by this run.

The practical generic-NP public/offline PQ witness-KEM stopping condition remains **unmet**.

## Sources

- Brent Waters, Hoeteck Wee, David J. Wu, *New Techniques for Preimage Sampling: Improved NIZKs and More from LWE*, ePrint 2024/1401 / EUROCRYPT 2025, https://eprint.iacr.org/2024/1401.pdf .
- Sanjam Garg, Mohammad Hajiabadi, Dimitris Kolonelos, Abhiram Kothapalli, Guru-Vamsi Policharla, *A Framework for Witness Encryption from Linearly Verifiable SNARKs and Applications*, CRYPTO 2025 slides, https://iacr.org/submit/files/slides/2025/crypto/crypto2025/545/545_slides.pdf .
- Rishabh Bhadauria, Pedro Branco, Nico Döttling, Sanjam Garg, Guru-Vamsi Policharla, *Witness Pseudorandom Functions for Vector Commitments and Applications*, ePrint 2026/1079.
- Exact GitHub dependencies listed in the opening checkpoint.
