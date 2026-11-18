# R368 — private-generator noncommutative release: occurrence-label bypass (NONQUALIFYING)

## Exact continuity and new hypothesis
On 2026-11-18, actual live syscoin/PVUGC PR #1 was open/draft on \`research/pq-wkem-validation-20260918\` at \`d98c2981ff60404f609582d4a2043403e891d12d\` (R367). Read R367's exact note \`research/pq-wkem/global_gauge_endpoint_20261118/RESEARCH.md\`, blob \`de8839deb0be1f813eb8dba2ca81cf7097bd35df\`. Recent issue comments since Nov 17 returned \`[]\`. No syscoin Core read was needed, no Core test or authenticated ORIGINAL source check was run.

R367's actual public extraction uses a known canonical matrix program A(z) and solves X B(z) - A(z)Y=0 to recover an endpoint gauge. This pass tests one mathematical repair R367 explicitly left open: **sample genuinely private generators a,b rather than merely gauging known a,b**, so the attacker's equations lack public A(z). This changes the previous attack's premise. We construct Build/Open AND test the *entire public distribution*, especially mixed local occurrences. We do not assert this is a practical source release.

## Explicit serialized public candidate
Over F_101 let a,b be setup-secret random GL_2 matrices with nontrivial commutator g = a b a^{-1} b^{-1}. The FALSE Boolean source model is the conjunction x AND (NOT x). The four local binary switching layers are:

    A_1(0)=I,       A_1(1)=a
    A_2(0)=b,       A_2(1)=I
    A_3(0)=I,       A_3(1)=a^{-1}
    A_4(0)=b^{-1},  A_4(1)=I.

A *consistent original* assignment x uses the SAME local selector z=(x,x,x,x). Both x=0 and x=1 yield product I; there is no satisfying original witness. The public prescribed opener may check occurrence consistency. Setup independently samples secret invertible P_0,...,P_4, publishes each B_i(v)=P_{i-1}^{-1} A_i(v) P_i, and keeps a,b,P private. It computes C_target=P_0^{-1}g P_4, a uniformly random 256-bit synthetic S, and D=S XOR SHA256("PRIVATE-GENERATOR-BP-TARGET-V1" || serialize(C_target)). The FULL public capsule is the eight B_i(v) and D, not the underlying generators, gauges or target. A fictitious accepting consistent assignment in a related TRUE formula would yield C_target and the same S.

This is **not** merely a different gauge of R367's fixed generators a0=[[1,1],[0,1]] and b0=[[1,0],[1,1]]. At layer 1, a local gauge preserves the conjugacy invariant trace(A_1(0) A_1(1)^{-1})=trace(a^{-1})=trace(a). The canonical fixed a0 has trace 2. Our tested private a have traces 92, 51, 4, none equal to 2. The generator structure was genuinely randomized outside that fixed gauge orbit.

## Exact full-public attack
The illegal local-selector word z*=(1,0,1,0) selects a,b,a^{-1},b^{-1}. Regardless of the hidden generator distribution and endpoint gauges, telescoping gives

    PRODUCT_i B_i(z*_i) = P_0^{-1} (a b a^{-1} b^{-1}) P_4
                         = C_target.

Therefore a classical adversary computes

    S = D XOR SHA256("PRIVATE-GENERATOR-BP-TARGET-V1" || serialize(PRODUCT_i B_i(z*_i))).

This requires no valid globally consistent x (there are none), no private generator, no recovery of P_i, no original AuxPoW/BTC history and no witness-extraction transcript. The private-generator repair removes the *specific known-A linear-system route* from R367 but does NOT enforce the global source relation inside the cryptographic release. A local if-check that rejects z* only in the prescribed Open is bypassable because the B matrices and D are public. The joint FALSE distributions for distinct S are distinguished perfectly, and hence QPT security fails via a classical attack. Randomly permuting or secretly relabeling the two branch values cannot be called a repair unless a **public** opener can recover the intended labels for every unknown future original source witness.

## What an actual new repair would require
To block direct mixed-label access, the public encoding must restrict label availability or product evaluation to a single *authenticated, relevant* original history/certificate, while remaining offline, succinct, noninteractive, and independent of which future qualifying witness is found. A secret fixed label permutation without a publicly reconstructible map breaks honest opening. Publicly revealing that permutation restores mixed access. Deriving new selector permutations directly from arbitrary SHA(history) does not help by itself: the builder cannot precommit one common target for all future unpredictable qualifying histories, and freely computable SHA on fabricated histories does not authenticate them. Encrypting each branch under a witness-derived key would require a *known* encryption key at Build or an independently instantiated constrained release mechanism. An online source signer, secret source-generation coin, invented preimage label or public verifier wrapped around already extractable matrices would violate the original requirement.

The exact constructive step still missing is NOT another permutation/matrix-width experiment, but a public, polynomial-time source-conditioned evaluator whose accepted-witness dependence is cryptographic and whose **whole public representation** has an unauthorized-output -> ORIGINAL source certificate or independent hash/native-break reduction. Its joint simulator must cover false and hard-true instances, VK/capsule correlations, malformed source evidence, sibling selective openings and malicious setup. This test is a negative gate on one non-gauge private-generator attempt; not a generic impossibility for hash-only witness encryption.

## Executed bounded synthetic checker
Python3 standard-library checker \`check.py\` constructed full public B matrices and D for three independently seeded private generator pairs, checked both original consistent assignments yield only P_0^{-1}P_4, checked illegal z* gives C_target and recovers the same 256-bit S, and recorded differing private generator traces. Two actual checker executions produced byte-identical \`output.json\` bytes.

    check.py SHA256: 927078e07e110be7eb4a13b1ab28803a4bc057c539d19255238075e235b29614
    output.json SHA256: 22bb79344b1c5bfe8c4fb7bffe65baf72d364d6cba17597bd27dc9ba42a95a26

This is only a synthetic GL2 model of Boolean *occurrence consistency*, NOT SHA256/AuxPoW, Bitcoin best-chain, ORIGINAL OR challenge certificates, native signing, actual FE or independent QPT testing. The matrices are NOT claimed quantum secure. No progress/notification comment, Core edit, deployment or automation change. The research-only note/checker/output are evidence of a screened failed candidate, not evidence that the missing breakthrough was achieved.
