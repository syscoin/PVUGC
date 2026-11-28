# SAI109 — first-divergence source quotient (NONQUALIFYING)

## Provenance / new mathematical operation
Started from live open/draft syscoin/PVUGC PR #1 at 1db6205c30ace00b55012c2f365c2e688b0a674a on research/pq-wkem-validation-20260918. Read SAI108 note (blob 1ae1d9d3c895c4649fb15e71bee30afc8b034522); scoped comments since 2026-11-20 returned []. No Core #609 code/test was read or run in this iteration.

SAI108's whole-proof-root index has exponentially many possible values. Try a genuinely smaller semantic quotient: for fixed authenticated claim-prefix ancestor hash a at the actual h_rel and a QUALIFIED ORIGINAL branch-3 competing history w, first authenticate its actual ancestor b=b(w) at the SAME h_rel and check b!=a. Define

    i_x(w) = max {j in 0..255: ((a XOR b) >> j) & 1 = 1}.

The first differing bit (in MSB-first order) is unique. Category i has exactly 2^i possible b values, so there are only 256 categories for every possible distinct ancestor hash, even though there are 2^256-1 unequal hashes. Authentication/relevance/maturity must still validate full AuxPoW, canonical active tags, chain ancestry, BTC anchors/window and LC fork depth. Different parent certificates for the same child do not make a child fork. This quotient is not a certificate and must not be confused with h_ref or tag inequality. Tag-fault-only cases and independent BTC-greater/burn-fault OR branches are not classified by this formula.

## Proposed source-dependent release
Build could choose independent pads k_i and publish D_i=sigma_cancel XOR k_i for i=0..255. Correctness would be achieved by

    Open(C,w)=D_{i_x(w)} XOR Unlock_{i_x(w)}(C,w)=same sigma_cancel

if and ONLY if an implemented public Unlock_i(C,w) returned k_i on every qualifying ORIGINAL w of class i and resisted ALL public attacks on invalid and unrelated evidence.

The index compression is valid and cheap but does NOT construct Unlock_i. Any publicly evaluable key selector depending only on i releases k_i to an adversary who supplies a bare i, so S is recovered without evidence. A secret s with k_i=SHA256(s||i) is unhelpful unless a real public protected evaluator releases it ONLY upon validating the original source relation. Hashing an unknown future w as the pad produces different keys for witnesses in the SAME category; Build cannot enumerate the future hashes for every-witness opening. External plaintext Verify(x,w) after exposing a pad or a ZK proof of capsule generation cannot fix the public raw-input bypass.

This differs from SAI108's exponential root-indexing problem only in that 256 class entries suffice. It **does not** reduce the cryptographic source-gating problem. The closest known adversarial regression applies unchanged; do not pursue further category masks or sweeps without an independently instantiated protected evaluator and joint-public simulator.

## Executed bounded local checker
Exhaustively enumerated synthetic 4-, 8- and 12-bit values for fixed a and checked that every b!=a has a unique first-difference class. Class population at index i was precisely 2^i; total was 2^n-1 for every n. Code and outputs were executed in the current container. This is not SHA256/AuxPoW mining, a valid original source certificate, native signing, FE, WE, or a QPT security experiment.

check.py SHA256 df9f0b8712c4f25f29531a324132231a9c9d3786174a962b69f118c1aeb2f10f
output.jsonl SHA256 013365a2a7401877307cac3a76a2384c73380b416dd1eeecb04a5a3812562029
Local detailed note SHA256 53d7cf3953ffb3399fa411dbbcd43e4492ec9676ecd5457229f966205db58220 (local-only; not this file).

## Exact handoff
No new foundation, no public Build/Open of the ORIGINAL three independent OR grounds, no FALSE/hard-TRUE QPT joint simulator or extraction to an actual ORIGINAL certificate, no one-honest malicious-setup theorem, no native PQ release. The next genuine operation must implement source-conditioned public Unlock_i (or abandon this class quotient) in polynomial time without revealing the pad through any public input, while binding the exact native cancellation authorization and related capsules. Simply replacing Unlock_i by FE/WE/ideal-oracle notation is not a construction.

NONQUALIFYING: research-only checkpoint; no progress comment, notification, Core/production edit, deployment or automation change.
