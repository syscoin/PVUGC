# SAI115 — Global ordered noncommutative release screening (NONQUALIFYING)

## Continuity
Read live draft syscoin/PVUGC#1 branch research/pq-wkem-validation-20260918 at start head 1fbf6c53cfbd6b31a12c1688c4076553370c9d7b; tree e78c1973db63445fca23356417e311c849a8195e. SAI114 note blob b208a894a0d6df4221bc1b4be2d66a136f06aa5a and SAI113 note blob fc538c1d5fc3cca3de5ba53bb89c2b05f87644ed were read. Querying PR issue comments since Nov 20 returned none. No Core tests, source admission, or production edits.

## Construction attempt
The attempted change from R327/R366 is a SINGLE globally ordered noncommutative matrix word for the SHA/AuxPoW verifier, not a commutative independent-clause mask, arbitrary hash range, or public invalid-trace pad. The missing source operation is consistent repeated-bit selection inside a public serialized object.

For known invertible instruction matrices P[j,b] for each bit value b, choose independent secret gauges R[0..L] and publish BOTH public transitions:

    X[j,b] = R[j-1] * P[j,b] * inverse(R[j]).

A prescribed whole-witness evaluator selects the same witness bit at all occurrences of a variable:

    W(w) = product_j X[j,w[v(j)]]
         = R[0] * (product_j P[j,w[v(j)]]) * inverse(R[L]).

If an accepting source verifier has abstract target G, the builder can compute

    T = R[0] * G * inverse(R[L])
    K = SHA256(domain || serialize(T))
    D = S XOR K.

For a globally accepting witness W(w)=T, prescribed Open recovers one frozen S. The description is polynomial-size, classical and serializable for a synthetic branching-program relation, but security depends on the ENTIRE public distribution. It is not a working witness-KEM.

## Exact full-public FALSE-instance bypass
Even noncommutativity cannot force repeated occurrences to use the same bit. Over F_101 choose genuinely noncommuting

    A=[[1,1],[0,1]], B=[[1,0],[1,1]].

A single variable x is read at instructions 1 and 3. Instruction 2 is fixed:

    P[1,0]=A; P[1,1]=I;
    P[2,0]=P[2,1]=B;
    P[3,0]=inverse(B);
    P[3,1]=inverse(A)*inverse(B).

Set G=I. The only two CONSISTENT inputs give P(0)=A != I, P(1)=B*inverse(A)*inverse(B) != I. The synthetic statement is FALSE. Nevertheless an attacker reads public transitions with inconsistent local choices 1 at instruction 1, 0 at instruction 3:

    X[1,1] * X[2,0] * X[3,0]
      = R[0] * I * B * inverse(B) * inverse(R[3])
      = R[0] * I * inverse(R[3]) = T.

Thus the public object reveals K and S with no satisfying whole witness, independently of gauge secrecy. Ordered multiplication and noncommuting A/B do not repair R289-style occurrence splicing. This is not a claimed attack against concrete SHA, Core AuxPoW, or arbitrary function-hiding FE; it precisely disqualifies this candidate.

## Repair screened
A single per-variable hidden token tau[v,b], used at all occurrences, would constrain the choices only if a public caller could not obtain both tau[v,0] and tau[v,1]. A merely public token-selection routine can be invoked twice. A routine requiring authentic whole ORIGINAL source evidence to release the tokens is the still-unimplemented source-conditioned cryptographic release operation itself. A public whole-witness SHA commitment or ordinary external consistency check is bypassed by direct processing of published transitions. A new candidate must implement this protected global token interface or an equivalent nonblackbox protected verifier, with actual classical PPT compilation and full-public security; it must not name Token as an ideal oracle.

## Executed bounded checker
Python3 standard-library check.py was run twice with successful status, producing byte-identical output.json and output2.json. It constructs 12 deterministic seeded random invertible gauge sets, publishes the masked transitions, confirms the relation is FALSE on both consistent inputs, and confirms public inconsistent products recover a synthetic 256-bit S. SHA256 check.py from executed local file: e829233752240a87f6a1e845a5b58432c3b19a51fba2b6149e32a10a39b2edf2. SHA256 output.json and output2.json: d141452c7508bd19486706f82b968b42c81a024c0923a5e2c01321d82d339243. Test scope is toy finite-field algebra only: no original Bitcoin/Syscoin evidence, FE, native signatures, malicious setup or quantum experiment.

## ORIGINAL continuation
No practical hash-only source-dependent Build_inc(x_W,S)->C / public Open_inc(C,w)=S for EVERY qualifying original Bitcoin greater-work, exact burn-fault or qualified Syscoin inconsistency/tag-fault witness is supplied. There is no complete-public FALSE/hard-TRUE QPT unauthorized release/forgery to actual ORIGINAL certificate reduction, no one-honest setup composition and no source-work theorem. The earlier FE architecture is conditional, not instantiated. Further attempts using public transitions with per-occurrence bit choices should be rejected before scaling. Need an actual nonspliceable globally source-bound protected input interface, not a wrapper, extra algebraic degree or another matrix group.

NONQUALIFYING: research checkpoint only. No PR progress comment, user notification, production/Core edit, deployment or automation modification.
