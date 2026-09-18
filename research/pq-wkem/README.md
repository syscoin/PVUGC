# PQ witness-KEM research ledger

**Status: a proved semantic compiler component; no completed secure WKEM.**

This draft was opened at the repository owner's request. It records the ongoing
research, actual tests, and unresolved obligations rather than presenting an
unproved encryption primitive as production code. Base inspected:
`fcc7929e04a913eca73ae176279d0021f0d88fad`.

All changes are isolated in this directory. Existing Rust code, protocol paths,
and repository security claims are unchanged.

## What is implemented

`moment_compiler.py` independently implements, using only the Python standard
library, an explicit degree-D Boolean-moment compiler over small prime fields.
It provides:

- Statement-only affine parameterization of all localizing solutions.
- A rank-one lift for every valid Boolean wire assignment.
- An exact extractor for every submitted nonzero solution of rank strictly below D.
- Checks that the extracted atoms are Boolean, satisfy all constraints, and
  reconstruct the submitted moments.

The theorem in [PROOFS.md](PROOFS.md) holds over arbitrary fields. The executable
reference deliberately accepts only primes from 2 through 65537. It is a public
mathematical fixture, not a cryptographic field implementation or security level.

## Run the committed tests

From the repository root, with Python 3.10 or newer:

```sh
python -m unittest discover -s research/pq-wkem/tests -v
python research/pq-wkem/validate.py
```

The second command writes `research/pq-wkem/validation-latest.json`. It does not
overwrite the captured [validation.json](validation.json), which records the
source SHA-256 hashes and actual test interval. There are no network requests or
nonstandard dependencies in these committed scripts.

The captured run passed all six test groups. The exhaustive census checks
14,259 complete small-field moment vectors; 6,942 satisfy the theorem's nonzero
rank bound, and all extract. The census repeats the same unit-test fixtures; it
must not be added to them as distinct coverage. Additional tests cover all small
constrained coefficient vectors, multiple witnesses, the strict rank boundary,
homogeneous inputs with zero constant moment, and malformed inputs.

## What is NOT established

The proved implication is:

    submitted admissible low-rank representation -> valid witness.

The requested missing implication is:

    arbitrary unauthorized key recovery -> a valid witness,

through an actual reduction or a separately justified hardness result. These are
not the same statement. This directory deliberately contains no `Encap` function,
no use of the rejected projection encoders, and no suggested deployment parameters.

A completed design must also establish full public-output QPT hiding, common-key
correctness, concrete practical costs, and a compatible distributed setup. Passing
these semantic tests establishes none of those encryption properties.

## Provenance and checkpoints

[PROVENANCE.json](PROVENANCE.json) identifies the saved conversation archive by
SHA-256 and records exactly which older scripts were rerun. Three completed; a
combined call timed out during a fourth, which is not counted as a passed run.
The independent implementation and tests in this directory were run separately.

Historical conversation drafts include withdrawn claims. They are not imported as
current security claims. No original third-party paper was fetched or re-reviewed;
GitHub access was used for the expressly requested repository work.

Checkpoint comments on the draft PR record completed actions, including the tool
timeout. They do not imply autonomous research after the active session ends.

## Publication boundary

Only public research mathematics, code, and non-secret reproducibility data are
included. No live capsules, signing keys, credentials, private correspondence, or
unrelated files are included. Nothing here claims literature priority or changes
ownership of the research. Do not merge this draft as a secure cryptographic
implementation.
