# Source-qualified work-share release: exact-work and public-evaluation screen (NONQUALIFYING)

## Provenance and target
This bounded offline research pass inspected the actual open/draft syscoin/PVUGC PR #1 head `ef5f8e2a9e35f8b3f6b9c9207b2a4753c91abc63` on `research/pq-wkem-validation-20260918`, and read the exact latest noncommutative boundary note (blob `7e3dae09fee2cef8afb89933492b1c4aa7a29bd3`), the source-ID tree screen and the one-honest all-witness setup note. PR top-level comments since 2026-11-22T00:00Z were empty. No Core source reread, real network certificates, native signing, external literature, FE implementation, or quantum tests occurred.

This is a *different candidate family*, not another algebraic gauge or degree lift: try to make cumulative ORIGINAL Bitcoin-work evidence distribute threshold shares of one setup-frozen decryption key, with each actual source certificate generating a share without online setup actors. The intended cryptographic change is to tie access to original authenticated parent-work certificates themselves, rather than an arbitrary accepted witness assignment.

## Candidate attempted
Fix a claim-scoped statement x, frozen safe native cancellation capability sigma, and a random key K. As a simple starting point, sample a polynomial P over a large finite field of degree t-1 with P(0)=K, and publish D=sigma XOR H("release"||K). For a candidate authenticated parent/work certificate p, let z_p=H("work-share"||x||canonical(p)) be a nonzero point and define an abstract share s_p=P(z_p). A challenger holding t different qualifying certificate points could interpolate K and recover sigma. Different successful sets of t shares yield the same constant P(0); no canonical witness is needed.

The precise missing primitive is **PublicSourceShare(C,p)**: it must return the true P(z_p) only when p belongs to a complete original, relevant, window/anchor-bound witness and is actually qualified; for all other inputs its complete public bytes and evaluations must not expose P(0). Proof checks cannot be an optional wrapper. If it existed with sound all-public security, shares might be a component of a source-specific access structure. It is NOT instantiated here.

## Source-exact completeness defect of the first construction
The actual branch-1 relation requires strictly greater exact cumulative Bitcoin work on a qualified competing history from a common relevant anchor. That predicate is not a cardinality threshold on distinct parent headers. A single sufficiently high-target-difficulty block may carry more exact work than several easy blocks. Merely obtaining t distinct headers can fail for a legitimate qualifying certificate, while t low-work blocks need not beat the asserted baseline. Consequently the proposed polynomial threshold **does not satisfy every-witness correctness** for even branch 1. It also omits the independent burn-fault and Syscoin-inconsistency/tag-fault OR grounds; those cannot be made to require a competing Bitcoin-work threshold. They need their own original-scope access paths to the exact same frozen capability.

One may replace the cardinality threshold with a weighted cumulative-work comparator (binary integer arithmetic and contextual target validation), but then the release condition becomes a full Boolean/circuit predicate, not this elementary polynomial-share threshold. This is a correct functional repair of the *policy*, not an instantiated encrypted evaluator.

## Direct full-public attack on the naive serialization
If P's coefficients are placed in public C, an adversary simply reads P(0)=K. Even a public evaluation interface `EvalPublic(C,z)=P(z)` suffices: an adversary chooses arbitrary t distinct nonzero field points, obtains (z_i,P(z_i)), and interpolates P(0) in O(t^3) field operations. There is no SHA preimage, authenticated parent, sufficient work, original source certificate or source-coin state in this attack. Adding a software predicate `if VerifyOriginal(p)` around public evaluation does not remove access to the raw polynomial or its publicly executable evaluation routine.

Keeping P's coefficients private prevents such arbitrary queries, but a later challenger cannot evaluate its shares from a public capsule without a separately implemented protected input-dependent computation. A ZK proof that P was sampled correctly or that a particular source certificate is valid does not itself release the hidden share. Encrypting P's coefficients under a hash of the candidate certificate gives different keys for different future certificates and does not supply an all-witness common-value correction; publishing a public GGM/ID cover falls into the previously screened source-ID attack.

This screen is an algebraic argument for this explicit representation and its work-count policy, NOT a generic impossibility theorem for hash-only FE or a novel break of SHA. No new large toy test was run because the attack is symbolic and independent of parameters; running more samples would not avoid it.

## Exact possible repair and unresolved equation
To be a real candidate, the work-share concept must simultaneously provide:
1. source-aware crypto-enforced `Share(C,p,context)` whose public serialization cannot be evaluated on unrelated, fabricated, stale or locally recombined parent certificates, even via internal byte manipulation;
2. exact authenticated cumulative-work comparison for branch 1 and independently sufficient burn and Syscoin inconsistency/tag-fault paths, with actual strict contextual post-PQ AuxPoW and correct claim-prefix/LC depth;
3. a common frozen `sigma` for EVERY qualifying original witness, with neither a canonical witness nor guessed future parent hashes;
4. complete-public FALSE and hard-TRUE QPT recovery/native-forgery -> an actual qualifying ORIGINAL witness or an independent hash/native break, including source coins, malicious setup, sibling capsules, selective opening, native VK and message; and
5. one-honest N-of-N preauthorization with robust universal useful completeness, no online notary during challenge and no bitcoin-side source proof verifier.

The unimplemented equation remains
`C=Build_orig(x,sigma;rho)`, `Open_orig(C,w)=sigma` for all `R_orig(x,w)=1`.
A source/work proof is an authentication credential but does not by itself become a private share of an independently setup-chosen secret. A public deterministic hash of an accepted history is not that secret; off-chain original verification is necessary but not a cryptographic share-release mechanism.

## Outcome
NONQUALIFYING screening checkpoint. This pass establishes neither a candidate secure source-dependent Build/Open nor a new security reduction. It is not a completion or progress notification. No PR comment, production or Core edits, deployment, money movement or automation setting change. No tests were run. Do not repeat this polynomial-share/generic-header-count approach without a concrete cryptographically protected ORIGINAL-source share transition that already defeats arbitrary public interpolation and preserves exact-work/OR completeness.
