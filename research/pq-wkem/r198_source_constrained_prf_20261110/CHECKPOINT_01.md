# R198 intermediate checkpoint — source-target constrained hash-key release

Run: R198-SCPRF-20261110 (bounded offline research iteration). This file was created before implementation/testing.

Observed syscoin/PVUGC PR #1 head: ab437d21b56dd81bf032a2e57708ef17840b8e3b, open/draft/unmerged, branch research/pq-wkem-validation-20260918; relevant last file R197 `r197_public_garbling_20261110/RESEARCH.md` read at blob 008919d0d101ab3aa903d8830858448673c17dc0; recent issue comments since 2026-11-10T09:00Z returned empty.

New candidate (not R196 history SHA ratchet or R197 public witness-label garbling): exploit the `H(parent header) < target` comparison as a *union of binary prefixes*. SHA-based GGM constrained PRFs can give a short key for all permitted digest values. Attempt to turn a constrained PRF covering the valid PoW digest interval into a **common frozen cancel key** for any genuine qualified BTC/SYS certificate, while source membership (actual header SHA, AuxPoW coinbase, ancestor tag, claimed burn, provenance) is enforced inside key derivation rather than after it.

Questions to test concretely: (a) a GGM leaf output on separate valid digests normally differs, so does it furnish one precommitted capability? (b) if ciphertexts are published per prefix seed and those seeds are public to evaluators, does arbitrary fabricated digest expose the key without an ORIGINAL witness? (c) can hiding seeds while using the source header as the alleged witness let Build compute the necessary fixed pads for arbitrary future yet-unknown valid headers? (d) do quantum attacks require anything beyond the classical counterexample? (e) can precommitting to an authenticated fixed source root repair future unknown source membership without an iO/WE compiler?

Record exact equations and a local finite checker, then repair or replace within resource budget. None of this asserts an actual WE.
