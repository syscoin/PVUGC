# R201 checkpoint 01 — source-convergent hash gating, exact unfinished equation

**Status:** exploratory construction hypothesis; no operational release gate, no security theorem. Run focus is the ORIGINAL, three-branch claim/vault-scoped BTC/SYS challenge relation. No web or external literature.

## Continuity
PVUGC PR #1, research/pq-wkem-validation-20260918. Observed starting head dce45f27382fc2ee1b79cf4e88e36e364f5a77da. Pinned R200 exact blob e72d39905fe225f48b8fbd0b8340fc756cc45f04 was read; recent top-level comments since 2026-11-10 12:00 UTC: none. This is research only; no source/production changes.

## Concrete candidate SCD (Source-Convergent Decryptor)
The tempting strategy is to use a source fingerprint F_x(w) that is computationally unavailable without a qualified authenticated challenge witness, but gives a single identical value for all valid original witnesses. Freeze a native cancellation signature sigma and set:
  t = SampleSetup(x); E = sigma XOR H_pad(x,t).
  Open(C,w) = E XOR H_pad(x,F_x(w)).
Correctness for arbitrary witnesses would follow if F_x(w)=t for all R_original(x,w)=1.

Test two actual source-history fingerprint definitions instead of inventing hidden labels:
  F^prefix_x(w) = PureChildHash(Ancestor(w,h_rel)), with baseline A fixed in x.
  F^fork_x(w)   = PureChildHash(Ancestor(w,h_rel)) of the qualified alternate chain.

For an inconsistency witness, F^fork differs from baseline by definition. For differing valid alternate branches its value generally differs, violating SAME-output; the baseline F^prefix is already PUBLIC in x and can open any pad built from it without a challenge. Hashing the lowest common ancestor or a normalized shared anchor is similarly already computable from x, or depends on divergence height and fails universal equality.

## Proposed repair to examine
Use a *nonlocal* hash-only computation that checks the entire SHA/AuxPoW/PoB predicate and emits one fixed output without making its internal secret accessible from arbitrary evaluations. Source authentication must be cryptographically upstream of release, not an ordinary public branch check. Try a garbled SHA verification circuit with both public input labels, then explicitly test mixed-occurrence and unrestricted-gate decryption; repair requires source-native secret labels correlated with future authentic headers, or a new computationally secure public gate encoding. The former labels are not present in current BTC/SYS, and no private issuer or online opener may be inserted.

The essential missing cryptographic equation remains an instantiated PPT public C such that Open(C,w)=sigma for every original qualified w, while full-public QPT arbitrary recovery/forgery implies original evidence or independently justified hash/native break. Source-header hashes are ordinary public 256-bit values and cannot be treated as hidden tokens merely because they are PoW-proven.

Next: execute a controlled garbled-circuit/free-input-label test and a two-fork fingerprint correctness regression, then analyze a repair rather than reporting toy success as security.