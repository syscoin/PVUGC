# Referenced missing PQ-WKEM lineage — 2026-10-01

This file records which locally preserved Run-203..Run-221 checkpoints are
actually referenced by later research, versus side branches that can be omitted
from the PR without breaking the current research lineage.

Live PR head when this inventory was made:
`50204dd2857b1cce846bc22dadac19550bed1eca`
on `research/pq-wkem-validation-20260918`.

## A. Dangling references from files that are already on the PR

These are **not throwaway**.  A later branch-published checkpoint explicitly
references them.

| Missing run | Referenced by live PR file | Role | Publication state preserved locally |
|---|---|---|---|
| Run 203 | `QROM_ORIGINAL_WITNESS_BRIDGE_RUN204.md` | Jin/SNARG ORIGINAL-extraction boundary feeding Run 204 | explicit safety denial before branch publication |
| Run 208 | `OFFDIAGONAL_TENSOR_SPECTRUM_RUN209.md` | growing-codimension shared-block theorem feeding Run 209 | explicit safety denial before branch publication |
| Run 210 | `RESPONSE_MINRANK_KERNEL_ATTACK_RUN211.md` | hidden-compression/bad-image coupling checkpoint attacked by Run 211 | note/checker/validation orphan blobs created; provenance write then explicitly safety-denied; no branch commit |
| Run 212 | `HAIR_SAHAI_GENERALIZED_SUPPORT_RUN214.md` | statistical repair/shared-factor channel checkpoint feeding generalized-support pivot | explicit safety denial before branch publication |
| Run 213 | `HAIR_SAHAI_GENERALIZED_SUPPORT_RUN214.md` | generalized column-support formulation immediately preceding Run 214 | partial publication attempt ended in explicit safety denial before branch publication |

Run 209 itself was restored to the branch in commit
`50204dd2857b1cce846bc22dadac19550bed1eca` and is no longer missing.

## B. Side branches / superseded checkpoints in the 203–214 window

These are useful historical experiments, but no later *live branch* checkpoint
depends on them.

- **Run 205** — interactive-to-static public-challenge quantifier barrier.
- **Run 206** — standard-model challenge-binding / encrypt-and-sound-prove branch.
- **Run 207** — online/offline NIZK adaptor-signature boundary.

Run 206 references Run 205, but that 205→206 branch does not feed the currently
published 209/211/214 spine.  Run 207 is likewise a side boundary.  These can be
kept local unless that abandoned branch is revived.

## C. Current unpublished adjoint/generalized-support spine

Later local research moved beyond Run 214.  The current mathematically useful
spine is:

`Run 214 -> Run 219 -> Run 220 -> Run 221`

with the following roles:

- **Run 219** — adjoint dualization of the actual Hair–Sahai generalized-support
  problem; converts the unresolved primal `d_5` question to an exact adjoint
  `e_15` row-support problem.
- **Run 220** — field-closure barriers, including the closure-four exclusion and
  a narrowed `e_15=11` vs `12` target.
- **Run 221** — scalar-core theorem closing the adjoint `GF(16)` closure-five
  class; leaves full closure six as the next unresolved class.

All three have preserved explicit safety-denial receipts for their publication
attempts, so their exact denied payloads are not being retried or rerouted here.

### Earlier local support chain

Runs 215–217 supplied useful finite support/incidence information and are
ancestral to some exploratory work, but the adjoint pivot reconstructs the
needed exact source from Run 214.  They are therefore **historical/supporting,
not required to understand the current 219–221 adjoint spine**.

Run 218 is a support-eight adjacency/field-linear exclusion checkpoint that is
superseded by the adjoint approach for the current handoff.  It is not required
by Runs 219–221.

## D. Minimal research record that should ultimately be present

For a compact non-throwaway PR research record, the desired spine is:

1. existing Run 196;
2. existing Runs 197–198;
3. **Run 208**;
4. restored Run 209;
5. **Run 210**;
6. existing Run 211;
7. **Runs 212–213**;
8. existing Run 214;
9. **Runs 219–221**;
10. Run 203 should also be restored because existing Run 204 explicitly cites
    it, although it is a separate Jin/QROM extraction branch from the current
    Hair–Sahai support spine.

Runs 205–207 and 215–218 can remain local unless their specific side branches
are resumed.

## Publication constraint

This inventory is new metadata, not a retry of any denied research payload.
For every bold missing run above, the preserved receipt records an explicit
OpenAI safety denial at some publication stage.  Under the standing research
publication rule, those exact payloads are excluded from automatic retry,
encoding/splitting, or alternate-action rerouting until that denial is resolved.

