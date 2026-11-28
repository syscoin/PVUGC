# R393 — Ordered-matrix source joins: an exact linear-state bound (NONQUALIFYING)

## Continuity
Read live open/draft syscoin/PVUGC#1 at a561277d50100c9ee512de52e0d5bbe154b267bc on research/pq-wkem-validation-20260918. Read R392 note blob 6f4e31fe4d6b8d291120c57aed83fd2c3d8b9fa4. Recent top-level PR comments after 2026-11-18T19:24:28Z were empty. No new Core source claim or Core tests. Approved ORIGINAL bridge OR relation and active strict contextual AuxPoW assumptions remain unchanged.

## Candidate and mathematical change from R366
R366's commutative locally revealed tensor supports secret extraction by finite balanced covers. Test the mathematically different repair of ordered NONCOMMUTING public matrix transitions, using one common terminal secret K and exact agreement between two separated n-bit source-history fields. This is a global-consistency subtask of a particular separated-input sequential-matrix architecture, not the complete ORIGINAL verification relation.

Let x,y range over all n-bit strings and K be a nonzero element of a field. The desired readout is f_K(x,y)=K if x=y, and zero otherwise. A public d-dimensional weighted matrix program receiving all x bits before y bits has output:

  f_K(x,y) = a^T * M(1,x1) * ... * M(n,xn) * M(n+1,y1) * ... * M(2n,yn) * b.

These matrices may be arbitrary and NONCOMMUTING. Split the product at the input boundary. A_x is the 1-by-d row before the cut and B_y is the d-by-1 column after the cut. The matrix F of all 2^n by 2^n readouts factors as F=AB, so rank(F) <= d. The exact target matrix is K times the 2^n-dimensional identity, of rank 2^n. Hence d >= 2^n. Noncommutativity, gauge randomization, field-order tricks, or 2-torsion cannot evade this rank bound for this exact linear-state, separated-input representation. A smaller d necessarily miscomputes some valid or invalid pair.

This is NOT an impossibility for arbitrary hash-only FE, for interleaved-input representations, nonlinear state machines, high-order tensor networks, or the actual Syscoin source language. SHA/byte equality can be publicly checked with polynomial storage. The theorem concerns the specifically attempted compact linear representation.

## Candidate repair and joint public security
A nonlinear hash-state transition storing a digest of x at the cut and comparing with y can efficiently enforce exact consistency and bypass the rank premise. But the plain public program that returns K on equality embeds K in public bytes. Keeping K inside an unpublished hash/FE evaluator eliminates public Build/Open. Merely encrypting the key under a hypothesized private program reintroduces R392's unresolved witness-conditioned release. Thus the nonlinear repair has no constructed public secret-delivery distribution, and no independent joint-public FALSE or hard-TRUE simulator. This run rejected the candidate instead of implementing another basis/hash-placement variation.

## Executed checker and measured scope
Actually executed Python standard-library checker twice over F_257 with byte-identical successful output. For n=1 through 6 the target K*I_(2^n) has rank 2^n, while a deterministically constructed public factorized matrix of inner dimension 2^(n-1) has rank at most that dimension, and never equals the exact target. The checker models no Bitcoin headers, actual SHA traces, FE evaluation, native signatures, or QPT adversary.
Local checker SHA256: f96bb0bb22640dd68f3f878c7be5744ced7a1ab37ea45e5bad69febbd75d54c2.
Both complete locally captured outputs SHA256: 81359a23d415cca05559a09c0cfa020d72546904617d8cb7038495c48b219186.
The committed readout.json is a compact transcription of these checked quantities, not a byte-for-byte copy of the complete local captures.

## Exact remaining obligation
The attempted public matrix serialization does not satisfy polynomial-time exact release correctness, so there is no legitimate security theorem for that candidate. An actual solution still needs classical-PPT public serialized Build_orig(x_W,sigma_cancel;rho)=C and public Open_orig(C,w)=the SAME frozen safe sigma_cancel for EVERY qualifying ORIGINAL witness, with independent full-public FALSE/hard-TRUE QPT recovery/native-forgery reduction to authenticated ORIGINAL source certificates or justified independent breaks. Include one-honest N-of-N setup, malicious source coins, sibling capsules and claim-bound native endpoint. A root digest or public verifier cannot itself deliver an encrypted private value.

NONQUALIFYING: no breakthrough claim, no PR progress comment, no Core/production edit, transfer, deployment or automation change.
