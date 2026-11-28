# R217 intermediate hypothesis — irreversible key release versus live-chain qualification

Status: intermediate, not a hash-only Build/Open algorithm or a security theorem for the completed bridge. Start: PVUGC PR #1 draft/open, branch research/pq-wkem-validation-20260918, head 6da61eaa132ffca1792ed4de44ba36cffc3286d1. Source continuation: R216 slot-universal note Git blob 9c369aa210cfdb67c6582865b11421d0dd70f999. No external/web lookup.

Named indispensable subproblem: **MONO-RELEASE**, qualifying a challenge as immutable finite historical evidence rather than an ephemeral judgment of the present best chain.

Hypothesis. For an immutable capsule C with public offline Open(C,w)=sigma on challenge evidence w, any release is irreversible. If a time-dependent predicate R_t(x,w) accepts at t and rejects at t'>t following a BTC/SYS reorg, no purely static public verifier can retract the already known native signature sigma. A future ledger-aware checker cannot retract a previously published capability either.

Candidate repair: bind each cancellation signature to a unique preauthorized claim/outpoint/epoch and define a **monotone positive historical certificate** under a frozen, explicitly authenticated source anchor and observation/threshold window. Any admitted inconsistency, bounded nonmembership under a particular committed state root, or fixed-anchor higher-work history is a permanent veto *for that claim*. A reset must retire the old claim outpoint and use a new separate claim/capsule; it cannot revoke an exposed signature on the same still-spendable outpoint.

This is not a claim that any valid PoW header is automatically Bitcoin best-chain membership or authentic publication. Source inclusion is not unconditionally verifiable from a static header alone. Qualification must expressly model the anchor and publication/finality, fork depth, tag validity, required interval data, DA/censorship, timing, and whether private source work qualifies. An on-chain best-tip oracle or unknown future committee must not be smuggled into Build/Open.

Concrete next step in this pass: build and execute a small state-machine checker for reorg after release, expired/stale root, and epoch-specific UTXO retirement; attempt to repair the unsafe trace without assuming an online release authority. Record exact code/output and whether the repaired predicate is actually static and source-authenticated. No Native PQ/BTC implementation or QPT proof is implied.

The missing cryptographic equation persists:
  Build_hash(R_slot,x,sigma) -> C at classical-PPT t0;
  Open_hash(C,w)=the SAME sigma for every qualifying ORIGINAL witness;
  QPT recovery/native forgery -> actual ORIGINAL preexisting admissible witness or independent PQ break,
including full public view, malicious setup and related capsules.
