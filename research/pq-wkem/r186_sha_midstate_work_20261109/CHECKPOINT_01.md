# R186 — Source-Midstate Common-Token Gate (SMCT), intermediate hypothesis

**Research-only; NOT a working WKEM, PQ security proof, source verifier or deployment.** Continue the exact R185 source-to-key correlation gap. Observed syscoin/PVUGC PR #1 branch `research/pq-wkem-validation-20260918` at `b7f70979ed5ac74205a378ada35f43db278491d0`; read its R185 analysis. No external literature.

For a future parent template P and nonce n, test whether SHA256d(P||LE32(n)) yields a frozen, source-dependent hidden token common to all valid work certificates. Two parent-work solutions for the same Syscoin child MUST be treated as the same semantic child; neither alone establishes a fork. No synthetic nonce makes an ORIGINAL certified source witness without authenticated Bitcoin/Syscoin history.

Candidate A: C_shared = K xor H_pad(SHA_midstate_before_nonce(P)). The midstate is shared, but may be public before work.
Candidate B: C_work = K xor H_pad(SHA256d(P||LE32(n*))) for one future qualifying nonce n*. The work digest is only available after choosing n*, but may not converge across valid nonces.

Test whether correction rows for every valid future nonce are needed, and whether a public work-prefix predicate is a useless common token. Use SHA256d over synthetic 80-byte Bitcoin-shaped headers with a toy target; never claim real BTC difficulty/anchoring, native signatures, QPT security, or an authenticated original witness.

The actual required interface remains classical polynomial-time pre-source Build_hash(x_slot,sigma) and Open_hash(C, authenticated ORIGINAL w)=SAME sigma on ALL R1 OR R2 OR R3 witnesses. Full-public QPT no-witness recovery must imply ORIGINAL qualification or independently justified hash/native break. No online issuer, new Bitcoin verifier, public puzzle substitute or post-hoc validity check.

This checkpoint is recorded before executing the checker. It asserts no test results or successful release.