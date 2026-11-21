# R398 — Sigma-simulator-tape source release preflight (NONQUALIFYING)

## Execution continuity and target
Started from the ACTUAL open draft syscoin/PVUGC PR #1 branch `research/pq-wkem-validation-20260918`, head `071fed88460c5db33af938e440d10c1196c3c642` (R397). Read R397 at blob `f1452084a76c34ccce422d448e333664b00b3509` and R396 at blob `b789a25568ac186178c198d87a8420fb090dc67e`; recent ordinary PR comments since 2026-11-19T00:00:00Z returned empty. R397's exact unfinished operation is a compact public source-dependent universal sink for independently generated future evidence, following its failure of publicly invertible noncommuting branch matrices. No Core source or tests were consulted anew and no external literature or web was consulted. No runtime experiment or QPT result is claimed here.

This iteration tests a DIFFERENT cryptographic construction idea before implementation: can a simulated hash-based public-coin proof transcript supply one hidden common release tape, with any valid ORIGINAL certificate acting as a trapdoor to derive it? The goal is a *source-derived* release, not the previous low-degree coefficients, explicit witness tables, publicly invertible gauges, or matrix finite covers. Simulating a proof of the original relation is possible without having a valid source witness in some proof systems; whether it produces the needed secret correlation is the decisive question.

## Named candidate: simulator-tape commitment
Let `R_x(w)` be the ORIGINAL three-OR bridge relation with exact claim, history and activated contextual AuxPoW qualifications. Let a public-coin proof system have an honest-verifier simulator
    Sim(x;c_0,r_0) = (a_0,c_0,z_0)
which outputs an accepting transcript for a chosen challenge, without an ORIGINAL witness. The proposed compiler would sample secret t, derive a public source-independent commitment `y=H("R398/seed"||x_id||t)`, construct a public simulated transcript `a_0,c_0` and a finite hint q, and publish
    C = (x_id,y,a_0,c_0,q,D),  D = sigma_cancel XOR H("R398/pad"||x_id||t).
The desired honest opening is
    Rec(x,w,a_0,c_0,q,y) = t
for EVERY qualified ORIGINAL w, and no unqualified source/user should recover t or a native signature. The compiler must know t so that it can form D, but does NOT know any future w.

This would avoid dependence on a common future *hash* if it were achievable: different original certificates could each invert the SAME setup commitment. To avoid renaming WE, Rec must be an explicit hash-only polynomial-time algorithm, not an assumed original-witness trapdoor oracle.

## Exact sigma-protocol preflight

There are two natural placements of the simulator's secret, and neither supplies Rec:

(A) Take t=H("t"||z_0), with z_0 withheld but a_0,c_0 public. A prover knowing w can create an independent accepting transcript (a_1,c_1,z_1) but that yields unrelated z_1. Special soundness has the direction TWO accepting same-commitment transcripts -> witness; it does NOT say that a witness plus the publicly fixed a_0,c_0 determines the simulator's hidden z_0. Indeed if the public values alone permitted recovering z_0, the secret is public; if a private simulation trapdoor is required, the honest independent witness cannot access it. No candidate Rec was derived.

(B) Publish z_0 and use the simulator's hidden prover randomness r as t. In elementary linear-response notation a real prover has z_0=r+c_0 f_x(w). With fixed public z_0,c_0, the witness can calculate r_w=z_0-c_0 f_x(w). BUT the compiler can construct a prover commitment with known r only if it can form z_0 using f_x(w), which it does not know for future ORIGINAL w. If it instead generates a simulated a_0 from public x,z_0,c_0, it generally does not know the actual opening r_w; with two distinct witnesses w,w' these putative r values need not agree. If f_x(w) is constant and efficiently computable from public x, r is publicly recoverable. If f_x is a hidden witness-uniform invariant not available to the compiler, the compiler cannot form the pad from that r. Thus this placement does not deliver a common builder-known, witness-recoverable secret.

The proof transcript's public *validity* is separate from any hidden simulator tape. A valid proof of x does not by itself yield the particular setup simulation tape. A compiler-generated ZK proof that C was assembled as written would certify the wrong construction perfectly and would not add this missing correlation.

## Independent-tape lemma and its exact scope
Take a deliberately simpler subcase with only public `Y=H(T)`, private `T` sampled independently of source histories conditional on public x, and later qualified evidence W generated from the source without knowledge of T. The joint distribution factors
    p(t,w,y|x) = p(t|x) p(w|x) 1[y=H(t)].
Therefore `T` and `W` are conditionally independent GIVEN `(X,Y)`; equivalently
    I(T;W | X,Y)=0.
This is an exact distributional identity, including if W encodes a real expensive SHA/AuxPoW certificate, and it survives quantum processing of classical W,Y in the absence of other correlations. It does NOT assert that H is one-way against all adversaries; it says a future source witness unrelated to the chosen tape supplies no additional information about that tape. A nonuniform auxiliary string independent of T may improve generic hash-inversion *computation*; that is outside this independence statement and cannot be interpreted as original-source release. The lemma does not extend to arbitrary public C that intentionally correlates T with W through a cryptographic encoding: constructing such an encoding is the unsolved object.

The proposed simulated transcript could in principle induce such a correlation, but cases A/B above fail to show a classical PPT compiler and Rec with it. No reduction from arbitrary QPT recovery of t to an ACTUAL original witness is available.

## ORIGINAL-source relevance
Strict post-activation tag scripts commit exact PUBLIC child ancestor hash/height, and the separate AuxPoW child-root proof authenticates the carried child; neither automatically carries a setup-generated private tape. A qualified Syscoin inconsistency may be witnessed by two independently committed parent certificates and unrelated future ancestor hashes. The original burn-refutation and greater-Bitcoin-work OR branches do not share a mandatory source-secret either. A solution requiring miners/ChainLock authorities to return the hidden simulator response would change the ORIGINAL relation, so is inadmissible.

## Decision and next equation
**Reject simulator-tape publication as an independent hash-only release primitive.** Do not build a large sigma gadget or run toy proof-count experiments: the source-conditioned opening equation itself is missing. The exact next constructive operation remains
    C = Build_orig(x,sigma_cancel;rho)  [classical PPT, serialized public bytes]
    Open_orig(C,w) = sigma_cancel    for ALL w with R_orig(x,w)=1,
jointly with a complete-public FALSE/hard-TRUE QPT argument producing an ACTUAL qualified ORIGINAL certificate or independently justified hash/native break. A ZK verification key or simulated proof must not be substituted for this operation. Any future use of the simulator-tape idea first needs a new explicit `Rec` whose builder-witness correlation is grounded in existing source bytes; merely renaming a witness-dependent inversion oracle does not count.

Preserve N-of-N one-honest setup, distinct fixed safe native spend per activation or explicit slot-global veto, all three ORIGINAL OR grounds, claim-prefix LC maturity, strict modern tags/chain ID, malicious source coins, sibling capsules, and network deadlines. This run did not implement source Build/Open, run native Bitcoin signatures, rerun Core, derive QPT security, edit production, post a PR comment, or alter any automation. **NONQUALIFYING.**
