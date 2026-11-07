# MINK-EVC-20261102: hash-compressed, equivocatable CRS-share commitment

STATUS: **A restricted, explicit setup-commitment component. NOT a generic post-quantum witness-KEM, a source-release construction, or a completed one-honest pre-funding ceremony.**

Continuation: MINK-LWE-PRG-20261102 at PR #1 start SHA 8c1824a28e7dd09b41ce048c89141da6e3750bf4. The signed-XOR SOURCE and QPT-LWE seed generator are unchanged. This iteration instantiates one missing dual-mode commitment building block that a potential straight-line one-honest CRS simulator could use. It does not instantiate SOURCE opening or fix arbitrary key-recovery-to-ORIGINAL-witness extraction.

## Exact real algorithms and distributions

Choose a prime q, integers n,m,k, B0, Q=2B0+1<q, and accepted opening bound B=B0+k. Public real key: independently uniform A in F_q^(n x m) and U in F_q^(n x k). In the concrete instantiation k=384. For a byte message M shorter than 2^64 bytes, compute the 384 LSB-first bits h(M) of SHA-384 of the byte string:

    ASCII("MINK-EVC-v1") || 0x00 || BE64(byte_length(M)) || M.

Sample r uniformly in [-B0,B0]^m over the integers; publish

    c = A*r + U*h(M) (mod q).

Opening is (M,r). The public verifier checks the message framing/type, each |r_i|<=B, and the exact modular equation. All real algorithms are classical polynomial-time in dimension and log(q).

## QPT binding reduction (not an assumption of witness release)

Given two accepted openings (M,r) and (M',r') with M != M', either h(M)=h(M'), producing a SHA-384 collision, or

    v = (r-r', h(M)-h(M')) != 0
    [A | U] * v = 0 (mod q)
    ||v||_2 <= sqrt(4*m*B^2 + k).

For independently uniform [A | U], outputting v is a straight-line reduction to the short-integer-solution (SIS) problem for exactly these parameters. This remains valid for a QPT adversary with independent quantum advice and classical public input/output; there is no rewinding or requested internal representation. Security is **conditional on separately assumed QPT-SIS and QPT SHA-384 collision resistance**, neither verified at concrete parameters. A fixed SHA-384 digest is not an asymptotic collision-resistant family; an asymptotic statement needs a parameterized QPT collision-resistant h_lambda with k(lambda) bits.

## Exact programmable simulation and joint statistical view

A simulator instead samples A uniform, R uniform binary in {0,1}^(m x k), publishes U=A R mod q, and keeps R secret. It can publish c=A r0 with uniformly sampled r0 in [-B0,B0]^m **before learning the eventual fixed message**. After obtaining M, open using

    r_M = r0 - R*h(M).

Then |r_M,i|<=B0+k, and A*r_M+U*h(M)=A*r0=c exactly. This is source-independent: no native signing seed, SOURCE witness, decryption key, or SourceOpen oracle is used.

For a uniform A over prime F_q, the family R_j -> A R_j (R_j uniform binary m-vector) is two-universal. By the leftover hash bound, the simulated public (A,U) differs from independent uniform real (A,U) by at most

    delta_mode <= (k/2)*sqrt(q^n / 2^m).

For each fixed M, uniform cube translation bounds the opened view by

    TV(r0 - R*h(M), r0) <= ||R*h(M)||_1/Q <= m*k/Q.

For T commitments with independent honest masks whose messages are fixed independently of their own commitments (possibly determined by prior authenticated protocol messages), the real-vs-simulated joint classical opened-transcript TV is bounded by delta_mode + T*m*k/Q. Any permitted later classical selective observation is a marginal, hence does not increase TV. Arbitrary coherent QPT processing of these classically sampled views with independent quantum advice obeys the same bound. This does **not** establish adaptive programming when a message may be selected as an arbitrary function of its own earlier commitment, nor maliciously chosen CRS, correlated secret quantum advice, unlimited abort/restart sessions, or dishonest openings.

Real-mode hiding also follows from independent uniform r in [-B0,B0]^m and Q<q:

    TV((A,A*r),(A,uniform in F_q^n)) <= 0.5*sqrt(q^n / Q^m).

The offset U*h(M) does not affect this bound.

## Illustrative (unassessed) resources

Take q=2^255-19 (prime), n=128, m=32940, k=384, B0=2^159 and Q=2^160+1. Then log2(delta_mode) < -142.41 and log2(mk/Q) < -136.40 per commitment. Even 256 commitments keep the simple sum of these statistical errors around/below 2^-128; this is **not a QPT-SIS hardness estimate**. Public A is 134,395,200 bytes at 255-bit fixed encoding; public U is another 1,566,720 bytes; an opening vector is about 0.66 MB. These costs are not practical. SIS hardness at the resulting very loose Euclidean bound beta=sqrt(4*m*B^2+k) is UNASSESSED and may fail.

Hash compression means the commitment binds an arbitrary-length CRS contribution using k=384 message coordinates instead of one public U column per input bit. It invokes the already-present (but unproved) SHA-384 collision assumption in addition to an explicit independent QPT-SIS assumption; the result is not an LWE-only construction.

## Executed evidence and exact remaining gap

The independently stored offline checker ran twice, byte-identically: 11,524 assertions per run. It verifies 160 independently sampled toy A,R keys and all 16 opening targets each, 200 explicit dual-opening -> SIS kernel identities, 64 SHA-384 hash-compressed fixtures with short and 8192-byte messages, an exact one-dimensional cube-translation law, and exhaustive averaging over all 3^7 matrices and 2^7 R masks. Toy statistical distance was 0.03901844231062338, below the 0.07654655446197431 leftover-hash bound. Deterministic fixture randomness is not production randomness; these checks do not test QPT hardness.

**Unfinished composition:** Although a simulator can now equivocate its own committed CRS share, it still must learn or extract the corrupt committed shares *before* setting that share when programming a target QPT-LWE challenge, even if corrupt parties reveal in an adversarial order. An extractable, composable N-of-N ceremony that handles all public commitment/checking-key/proof correlations, selective aborts, and T attempts has not been constructed. This does not furnish generic-NP Build/Lift or the required implication from arbitrary unauthorized hard-TRUE final-key recovery/accepted native forgery to an actual ORIGINAL witness or independent QPT break. The native Bitcoin PQ endpoint remains conditional and undeployed.

All work is offline, research only, with no production or main-branch changes.