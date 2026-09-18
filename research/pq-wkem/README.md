# PQ witness-KEM research ledger

**Status: incomplete research, not a secure WKEM and not production cryptography.**

This branch was opened at the repository owner's request to make the ongoing
witness-encryption work reviewable in GitHub rather than leaving progress only
inside a chat. It starts from `fcc7929e04a913eca73ae176279d0021f0d88fad`.
Existing Rust code, protocol paths, and repository security claims are not changed.

## Required endpoint

- Statement-only encapsulation: `(header, K) <- Encap(x)` without a witness.
- Every valid witness for the same statement recovers the same key.
- Public, offline decapsulation, with no authority required after setup.
- Security against quantum polynomial-time processing of the entire public view.
- An adversary-based extraction theorem for unauthorized early key recovery,
  distinct from extracting a witness from a submitted low-rank representation.
- Concrete, defensible setup, storage, and decapsulation costs.
- A separately specified distributed setup and same-secret binding to any
  encrypted-signature wrapper.

## Starting evidence and its limits

The preceding conversation supplied a Boolean-moment compiler, rank-metric
correctness tests, and counterexamples for some projection encoders. Its latest
archive is `wkem_one_hour_review.zip`. Prior validation counts are not being
claimed as independently reproduced in this new run.

The rank-one lifting identity and a low-rank-to-witness theorem do not establish
that an arbitrary key-recovery algorithm yields a low-rank representation.
That missing implication must be a proved reduction, not a renamed assumption.

Historical notes in the conversation include claims later withdrawn. They are
not imported as current security claims. Original third-party papers have not
been re-reviewed during this no-web continuation.

## Checkpoint 0 — repository access

- Read repository metadata and the exact `main` head.
- Confirmed there were no open pull requests at this checkpoint.
- Created this isolated research branch; no production source was modified.
- Next: inspect the saved proof package, rerun relevant validations, and record
  exact claims, hypotheses, and failures before adding them here.

## Publication discipline

Only public research notes, mathematical fixtures, and deliberately non-secret
reproducibility data will be committed. No signing keys, live capsules, credentials,
private correspondence, or unrelated user files belong in this branch.

Progress comments describe completed actions. They are not a claim that work
continues after the active session ends, and no fixed-duration uninterrupted run
is promised. The final session checkpoint will explicitly record what remains
unproved. This draft must not be merged as a secure cryptographic implementation.
