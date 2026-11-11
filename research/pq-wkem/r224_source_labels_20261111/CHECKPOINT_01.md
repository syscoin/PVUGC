# R224 — source-certificate input-label delivery, intermediate checkpoint

**Status:** candidate under adversarial evaluation, NOT an instantiated hash-only ORIGINAL witness-KEM. No native signature, actual BTC/SYS source verifier, QPT security proof or independent agent.

## Continuity
syscoin/PVUGC PR #1; start head 8aee989b7cc6a3417328d0cedc420be851a9a6be, open/draft, branch research/pq-wkem-validation-20260918. Read R223 target-bucket research at Git blob 50484d122dd10e00bab27790d9294ca821dbf3b4. Latest relevant top-level PR comments since 2026-11-10T00:00Z: none. No web/external literature.

## Proposed source-certified garbled gate
The N-of-N setup contributor precommits a claim-scoped cancellation signature sigma. A hash-garbled circuit for the FULL ORIGINAL R_cancel predicate would carry sigma only in its accepting output. For every future public evidence bit w_i, the challenger must be able to obtain ONLY the matching garbled label L_(i,w_i), and all labels must come from a *single globally consistent, authenticated* actual BTC/SYS certificate.

Candidate variants to test: public bit labels L_(i,b)=H(context,i,b); labels masked by public or secret hash seed; whole-certificate-specific labels L_(i,w_i)=H(context,certificate,i); public source-certificate validation after independent label delivery; fully source-indexed rows.

The exact missing operation is an efficient **offline** source-to-label delivery algorithm that gives every future ORIGINAL witness the necessary correlated labels, but cannot be queried on forged bytes or combined across inconsistent sources. A Merkle commitment to rows, private key retained by source actors, online issuer, independently solved PoW or public postcheck cannot be assumed to provide it.

## Local intermediate results
The first source-input-label checker executed twice with matching outputs: 1,100 checks across 100 deterministic synthetic seeds, showing public-label early recovery, failure of a single prechosen-certificate pad for a second future certificate, secret-seed availability gap, two-source occurrence mixing, and one-honest-signature public-label bypass. No real source mining, cryptography of native signatures or quantum experiment.

Deeper follow-up now targets a **false-instance local hash-garbling counterexample** R(b)=b AND NOT(b), plus repair via whole-certificate consistency and its future-source completeness obligation. Full equations, precise checker sources and actual results to follow. This checkpoint is NOT a progress claim.