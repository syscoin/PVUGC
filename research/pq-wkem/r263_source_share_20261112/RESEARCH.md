# R263 — source-certified 2-of-many secret-share transport (NONQUALIFYING)

**No secure ORIGINAL hash-only Build/Open was constructed; no release-security progress claim or PR comment.**

## Source/provenance
At execution start syscoin/PVUGC#1 was open/draft/unmerged at `827d031eece76ae0f2eb003d26257d8f0dc9be63`, branch `research/pq-wkem-validation-20260918`. Read R262 note blob `8d1e3c559a2fbcb182bec273b85f6be822e6cbfe`, R259 note blob `742748dc45c59e6ebb99b978fdb1c7601e97fbb9`, and most recent substantive ordinary comment R225, #6796383617. Core #609 metadata head `c91539de3c34937e57d7f5fda47c7b0502ff33f6`; no new Core code was audited or tests run. No source/deployment claim.

The ORIGINAL x, valid source admission, three independent OR challenge branches, one-notary initiation, any-observer challenge and already frozen slot-global safe Bitcoin cancellation authorization are unchanged. A parent header without authentic work-chain membership, contextual AuxPoW admission, exact current SYS tag, relevant claim ancestry/window/depth and full source checks is not a witness.

## Attempted candidate
Take finite field Fp, p=2^127−1. The preauthorizer has frozen cancellation signature sigma. Sample secret K,a and define f(t)=K+a*t in Fp, publish E=sigma XOR KDF(K,slot). Try to extract source share pairs `(t(w),y(w))` from domain-separated SHA256d digests of future ORIGINAL authenticated parent/child certificate bytes. With a fixed authenticated baseline `(t0,y0)`, set
```
Rec((t0,y0),(t,y)) = (t*y0 - t0*y) * (t-t0)^(-1) mod p.
Open(C,w) = E XOR KDF(Rec(...),slot)  // after full source checks.
```
For **genuine private polynomial shares** `y=f(t)`, any two distinct shares reconstruct exactly the SAME K regardless of which future share was supplied. This is information-theoretic correctness of an ordinary 2-of-many threshold-sharing component, not ORIGINAL-source key release.

**Missing independent instantiation:** A raw future Bitcoin/Syscoin AuxPoW/source certificate does NOT carry the private-polynomial value f(t). Canonical exact SYS tags commit ancestors/heights, not a builder's secret share. Requiring a source signer or miner to receive a and publish f(t) adds retained/source-generated secret and online release dependence; it does not satisfy the ORIGINAL relation. Publishing coefficients (K,a) gives immediate public K, even on FALSE instances. Hiding them prevents computing f(t) from raw SHA evidence. Assuming a public source-gated evaluator which produces f(t) only on qualified ORIGINAL witnesses restates, rather than reduces, the unsolved cryptographic release problem.

## Exact source-hash convergence check
In the explicitly idealized model where independent source labels `y1,y2` are uniform Fp, fix public y0 and distinct indices t0,t1,t2 with t0 != 0. Both `K01=Rec(t0,y0,t1,y1)` and `K02=Rec(t0,y0,t2,y2)` are independent uniform field values: the coefficient of each independent yi is nonzero. Therefore `Pr[K01=K02]=1/p`. If t0=0, the apparent all-witness convergence is simply `Rec=y0`, which is publicly recoverable and insecure. These are exact finite-field statements under stated labels, **not concrete SHA256d QPT theorems**.

Even letting Build choose the line **after seeing one preselected future source label** only gives that source witness correctness: set `a=(y1-K)/t1` and `y0=K+a*t0` (t1 nonzero), so Rec with source1 is K; a second independent future source2 almost always gives a different result. Build must freeze before future sources are known. A post-hoc `CheckSource` never cures raw recovery if the public representation exposes f for arbitrary indices: the adversary simply evaluates f at 17 and 19 and reconstructs K without any source witness.

## Executed offline regression
One Python 3 standard-library checker was actually run twice with byte-identical JSON output. Each run used 256 synthetic sets of SHA256d-based MOCK parent headers and 41-byte canonical-SYS-tag **SHAPES** (no complete coinbase/Merkle/AuxPoW admission). It checked eight classes, 256 each: (1) independent pairwise source labels fail key convergence, (2) private polynomial two-of-many succeeds, (3) public polynomial bypass, (4) arbitrary-index bypass, (5) duplicate abscissa rejected, (6) one preselected future source works, (7) another future source fails, (8) post-hoc validator bypass. All eight counters were 256. Checker SHA256 `15568a3be8dc19193155acaea254776713e1b187cb628df2b62aaffca228f888`; both result SHA256 `d1d2b31556e22ac5fc75934d277b92ebc3f9a1d69c5ec8a8f093b0a80525c0ee`. Full executed checker, results, two genuine intermediate checkpoints and longer derivation are in the local R263 research archive, **not asserted uploaded to GitHub**. Nothing was measured for QPT, real source consensus, actual Bitcoin SLH-like signing or deployed code.

## Unfinished
Still construct classical PPT `Build_inc(x_slot,sigma;r)` and `Open_inc(C,w)=sigma` for EVERY ORIGINAL-qualified AuxPoW/Syscoin or alternate OR witness, without extra share-carriers or post-check-only authentication. Full-public FALSE and unauthorized hard-TRUE QPT recovery/accepted native forgery must straight-line yield an ACTUAL ORIGINAL qualifying source certificate or an independent PQ hash/native break, with malicious setup, siblings, auxiliary information and selective openings. Secret-sharing algebra alone supplies none of this. **Nonqualifying result.** No ordinary PR progress comment; keep research task enabled.
