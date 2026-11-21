# R219 — HASH-EVAL-ENCODING intermediate checkpoint

Status: exploratory repair attempt, NOT an instantiated secure witness-KEM, original-source compiler, or quantum security theorem.

Repository: syscoin/PVUGC PR #1, research/pq-wkem-validation-20260918. Observed starting head c5ddeb956e3804f0fe9a25fe3f76f3f4258ed3aa. Latest R218 file was read at that exact head; ordinary PR comments since 2026-11-10 returned none. No web or external research.

One named attempted repair: replace the R218 explicit polynomial coefficient vector P(z)=K+sum Q_i(z)C_i(z) with a public evaluator that returns P(z) on Boolean inputs, ideally via a hash-backed representation. This retains the functional identity P(w)=K for all actual satisfying ORIGINAL source witnesses, but has not instantiated a cryptographically protected public evaluator.

Intermediate local tests ran a synthetic 5-bit AND-chain over F257 with polynomial degree <=3, using 26 low-Hamming-weight probes that are all nonsatisfying. Full raw-evaluation attack, 64 random seeds, and a finite-domain rank diagnostic were computed locally; a small separate reproduction is being preserved in the final note. The repair being evaluated is cryptographically *restricted* evaluation on source-authenticated inputs, not mere honest-verifier if-checking.

Initial finding: a raw public oracle for arbitrary Boolean points does not hide K; polynomial interpolation and public constraint-span projection recover K without submitting any satisfying witness. Restricting oracle access may alter leakage, but no noninteractive public hash-only access-control mechanism has been constructed.

The final derivation and executed code/checker provenance are to be preserved separately. No standalone size optimization, native signature, SHA/AuxPoW consensus simulation, quantum experiment, or original release construction is claimed. Do not notify as constructive progress.