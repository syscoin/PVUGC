# R194 checkpoint — authenticated-source digest-range release hypothesis (not solved)

Run: 2026-11-10, subsequent to R193. Repository syscoin/PVUGC PR #1 on research/pq-wkem-validation-20260918; observed head 3436878b7f8bd39d217a10f64da5911d08d4182c. Only current PR metadata, latest substantive R193 note, and recent ordinary comments were read. No external search. Initial working hypothesis and intended adversarial test recorded before the final result.

## Attempt: source-digest-conditioned release

For fixed withdrawal x and exact R_cancel (BTC heavier competing history OR invalid exact burn OR qualified Syscoin AuxPoW inconsistency), try to exploit PoW target inside hash-only KDF rather than publishing both choices of hash-garbled labels.

A putative witness w contains a real source header B, SHA256d digest y, and a qualified authenticated chain. Consider public KDF F_x(y) where every qualified source witness w must recover the same precommitted K; encrypt fixed cancellation signature as D = sigma_cancel XOR Pad(K,x). As qualified Bitcoin headers satisfy a public target interval y <= target(B), perhaps F can depend only on invariant target-class bits of y while keeping remainder hidden as work entropy.

Hypothesis to test: for a target-defined class, are there any secret digest-only bits common to all acceptable PoW witnesses that Build can use to protect K?

Exact adversarial check: evaluate F_x(y*) at arbitrary constructed numeric y* in the public allowed digest interval WITHOUT a header B whose SHA256d(B)=y*. An arbitrary digest is not authenticated Bitcoin evidence. If this produces K, release invalid regardless of SHA preimage/collision strength.

Candidate repair: tie derivation to the actual SHA256d preimage and authenticated full source history rather than a free digest. This is not automatically sufficient: a public conditional verifier with an ordinary readable constant K can be bypassed. Repair must cryptographically protect the common output for ALL valid evidence and provide full-public QPT simulator, not independent puzzle or posthoc verifier.

Experiment will compare (a) digest-only extraction, (b) per-witness header-secret pads failing same-K correctness, (c) verifier-circuit wrapping exposing a readable constant. Include all context, checking keys, capsules and auxiliary data in full public view.

No Build/Open construction, security theorem, executed test or positive progress is claimed by this checkpoint.
