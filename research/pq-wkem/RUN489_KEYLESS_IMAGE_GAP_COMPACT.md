# Run 489 — joint keyless native-key image completeness gap

Date: 2026-10-13. Verified live start e46dce004be6516b2b68ad5a89c83c9c16b9a11e; `syscoin/PVUGC#1`, `research/pq-wkem-validation-20260918`, draft/unmerged.

## Bounded candidate and falsification

Run 488 suggested jointly deriving both native public key components to avoid fixed-seed chosen-root claws. Test `Build(x;r): S=H_seed(x,r), B=H_root(x,r), vk=(S,B)` with domain-separated public hashes modeled as **independent uniform** outputs, independent of the native root-generation map. The same public coins affect both components; no fixed-seed family need exist. The builder never computes an SLH signing seed.

NIST FIPS 205 (final 2024-08-13), §9.1 Algorithm 18 gives `PK=(PK.seed,PK.root)`, `SK=(SK.seed,SK.prf,PK.seed,PK.root)`, `PK.root=G_{PK.seed}(SK.seed)` where `SK.seed` and `PK.root` are n-byte strings and `SK.prf` does not influence the root. For a *standard key-generation-format signing secret* to exist for (S,B), some z must satisfy `G_S(z)=B`. This is **not** a proof that arbitrary accepted signatures cannot exist under a malformed public key.

In the **explicit ideal model**, put `N=2^h`, sample each `G_s:[N]->[N]` as an independent random function, and choose S,B uniform independently of G. Then

`Pr[no z with G_S(z)=B]=(1-1/N)^N -> e^-1 = 0.36787944117...`.

Thus the independent-uniform **joint** keyless builder fails near-perfect native-key recovery correctness for a constant fraction of public keys *even with unlimited access to a valid ORIGINAL witness*. This does not show actual FIPS 205 root maps behave as independent random functions.

## Exact distribution identity

For a fixed G_s, let `c_y = #{z:G_s(z)=y}`. Compare the native root distribution `D_s(y)=c_y/N` for uniform z with a uniform builder root `U(y)=1/N`. Because c_y is integral and `sum_y c_y=N`,

`TV(D_s,U) = sum_y|c_y-1|/(2N) = #{y:c_y=0}/N`.

This holds for **every equal-domain map**, not only on average. Its expectation under the ideal random-map model is `(1-1/N)^N`. Statistical distance is NOT an efficient PPT/QPT distinguisher: determining whether B is in the image may require exponential work. This is a completeness/existence defect, not a demonstrated efficient security attack.

More generally with `M=2^m` native signing seeds and `N=2^h` roots, missing-root probability is `(1-1/N)^M approximately exp(-2^(m-h))`. Extending the native seed width can suppress nonexistence but is not unchanged FIPS 205, and it does not give public witness recovery a polynomial-time preimage search.

## Proposed repairs and scope

Forcing B into the image via `B=G_S(z)`, where z is public or recoverable from retained public builder coins, **exposes a native signer to a malicious builder** even for a false ORIGINAL claim; it can pick SK.prf. Forcing image membership while somehow hiding z instead presupposes an unconstructed cryptographic builder/release mechanism. Rejection sampling without an efficient native-image membership test does not establish correctness. Honest one-party erasure within an N-of-N ceremony is a different baseline, not refuted.

Attack taxonomy: (1) seam and (2) gauge not instantiated; (3) statistical fingerprint identity does not imply an efficient distinguishability attack; (4) related independent capsules repeat the defect without establishing joint security; (5) chosen input cannot manufacture a nonexistent preimage; (6) retained z breaks the simple forced-image repair; (7) context binding prevents replay but not fresh retained-key signing; (8) native checking pair (S,B) is explicitly public; (9) coherent Grover search can invert reachable ideal roots at exponential cost `O(2^(h/2))`, not a QPT break. Honest algorithms classical PPT, adversary arbitrary QPT. No new WE/iO/RIO/WPRF assumptions or security game asserting the missing goal.

## Executed validation and handoff

Attached compact JavaScript was executed exactly in V8: **265 assertions** covering all 4 maps [2]->[2] and all 256 maps [4]->[4], exact image-TV identity, occupancy expectations 1/4 and 81/256, unreachable-root and retained-seed controls. Independent local Python checker passed **1,286 assertions**, byte-identical twice and syntax validation. Domain-separated truncated SHA-256 toy maps of 8/10/12 bits showed absent-image fractions 0.373779296875/0.3670654296875/0.36546630859375. No real SLH, WE, native forgery, practical local mixer, or quantum implementation was tested.

Primary specification: https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.205.pdf (p.34, Algorithm 18).

Result: a *conditional ideal-model correctness falsifier*, not an impossibility for all keyless builders or actual SLH distribution theorem. A surviving public source-conditioned `Build` must be **in the native KeyGen image without exposing its native seed to any builder retaining all coins**, and valid ORIGINAL witnesses must recover the SAME branch capability. The indispensable native authorization -> accepted COMPLETE source representation -> ORIGINAL witness/independent QPT break remains unproved. Run 259/483 provide only downstream extraction for accepted representations. Also unproved: false-instance full-public-output QPT hiding, malicious N-of-N ceremony/abort/graph, multi-capsule security, concrete >=128-bit costs, conditional P2MR/SLH activation. Production unchanged; draft PR unmerged; no completed WKEM.
