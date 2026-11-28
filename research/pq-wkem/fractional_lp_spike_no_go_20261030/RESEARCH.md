# Unsatisfiable 2-CNF fractional SOURCE opening: additive-noise repair rejected

STATUS: NO POSITIVE NP-WKEM CONSTRUCTION ADVANCE. This is a reproducible exact counterexample to a particular ORIGINAL-to-LWE-SOURCE compiler, not a generic cryptographic impossibility proof or a QPT-secure candidate.

## Provenance
Run fractional_lp_spike_no_go_20261030; authorized syscoin/PVUGC draft/unmerged PR #1, branch research/pq-wkem-validation-20260918, starting observed SHA 43fc999a5b742d90f86587c997a9c988bab53f9f. The latest substantive comment inspected was 6522825693. Exact predecessor files: xor_packet_amplification_rejected_20261030/RESEARCH.md (blob feb15d4cec85a03c027517e3803372fb914eaa4e) and uniform_target_batched_lwe_20261030/RESEARCH.md (blob d1bc72cf6b2692ee73783d086931014917631859). No internet research, full PR diff, archival sweep or independent agent.

The unfinished step tested here was repairing a PUBLIC FALSE-instance pseudodecryption using noise rather than a nonlocal, source-dependent proof. Earlier signed-unit AND linearization admitted an invalid -3 coordinate. A proposed denser-LWE-plus-random-sparse-spike error distribution was intended to make an invalid coefficient sometimes corrupt decryption, then XOR-share the protected secret across polynomially many independent packets. Its dense independent LWE component was retained to avoid the earlier one-sparse-error inversion attack. The new fractional counterexample defeats any such additive-noise-only repair that keeps the stated worst-case correct-decoding margin.

## ORIGINAL relation and SOURCE compiler
Fix the ORIGINAL Boolean claim

    F(a,b)=(a OR b) AND (a OR NOT b) AND (NOT a OR b) AND (NOT a OR NOT b).

Every one of the four Boolean assignments falsifies exactly one clause. Thus the fixed ORIGINAL statement is FALSE. Bind it, as usual, to relation identity, claim/UTXO, branch, authenticated anchors/window/context, native checking key, challenge path, and any same-scope capsules; this binding cannot make an algebraic FALSE-instance leak disappear.

For each two-literal clause whose signs (s,t) are, respectively, (++),(+-),(-+),(--), introduce one Boolean slack u = literal1+literal2-1. Clause satisfaction exactly requires u in {0,1}. Signed coordinates z_a=2a-1, z_b=2b-1, z_j=2u_j-1 satisfy

    s*z_a + t*z_b - z_j = 1.

Let A have the four rows (s,t,-unit_j) and U=(1,1,1,1). For any Boolean ORIGINAL satisfying W, the signed vector z(W) is in {-1,+1}^6 and satisfies A*z(W)=U, supporting a public release that need not choose a canonical W. For this FALSE formula there is no such accepted vector.

But the publicly computable fractional vector

    z_bad=(0,0,-1,-1,-1,-1)

satisfies A*z_bad=U exactly over the integers and any odd-prime field, even though it is NOT an ORIGINAL W nor an accepted signed SOURCE opening. Its first entries encode a=b=1/2. Exhaustive enumeration of 3^6 signed small-cube vectors shows z_bad is the UNIQUE cube solution. In particular, every coordinate has absolute value at most 1, unlike the previous invalid -3 opening.

## Concrete noisy release and theorem
For prime q, public relation-conditioned A,U, protected bit k, hidden r, and errors, publish

    c = A^T*r + eta                 (mod q)
    d = U^T*r + eta_d + g*k         (mod q).

The proposed repair uses eta = eta_dense + S, where S is a random-position, random-sign high-magnitude spike independent of standard dense-LWE coins. For any z satisfying A*z=U, including invalid algebraic z,

    d - z^T*c = g*k + eta_d - z^T*eta (mod q).

Suppose the honest decryption guarantee for all valid signed-unit W and all supported error realizations uses the public deterministic bound

    |eta_d| + sum_i |eta_i| < g/2,

and q is large enough to avoid wraparound into a competing plaintext center. Since |z_bad,i|<=1 for every i,

    |eta_d-z_bad^T*eta|
       <= |eta_d|+sum_i |eta_i| < g/2

for EVERY supported realization, regardless of its correlations, spike position, sign or amplitude. Thus the invalid z_bad deterministically decodes the actual protected bit, and similarly every XOR packet, every bit of the REAL native signing secret, and each related capsule. The attack is a constant-time source computation followed by classical polynomial-time public arithmetic. The fake vector need not be submitted to or accepted by any SOURCE verifier. Once the genuine serialized signing secret is recovered, its genuine pk correlation does not save the construction.

This theorem rejects additive-noise-only repairs with that global deterministic legitimate-release margin. It does NOT assert that all noisy or nonlinear witnesses must be insecure, nor does it transfer to the predecessor's genuinely UNIFORM random-source LWE distribution. The honest random uniform matrix is a different distribution and has no ORIGINAL-W Lift.

## Repair attempt: parity-integrality extension
Augment the source with t_i and z_i-2*t_i=1 (mod q), one equation per signed coordinate. Every legitimate z_i=+1 uses t_i=0, and z_i=-1 uses t_i=-1, so true-witness short-opening correctness survives. The fractional z_i=0 requires t_i=-1/2 mod odd q, with centered integer magnitude (q-1)/2, and so the simple small fractional opening is excluded by a shortness requirement. This is a real algebraic repair of THAT individual pseudo-opening.

But the unsatisfiable formula still has, for every one of the four Boolean a,b pairs, a public integral linear solution in which exactly one clause slack z_j=-3 and t_j=-2. These are NOT valid ORIGINAL witnesses. The extended matrix has deterministic systematic structure, not uniform LWE. The parity lemma is a supplied-representation property, not security of complete-public key recovery, and does not establish a QPT reduction or a secure one-honest setup.

## Independently justified boundaries and exact remaining problem
A real uniform-matrix decisional-LWE sample remains decisional-LWE-secure after INDEPENDENT randomized addition of an error spike: any QPT distinguisher for spiked real-versus-uniform distributions can be simulated by sampling S and adding it to its ordinary-LWE challenge. For J independent capsules, a sequential J-challenge hybrid preserves the genuine scope and checking-key correlations under legitimate classical signing-oracle simulation. This elementary postprocessing fact holds only for the precise uniform-matrix source and simulatable auxiliary inputs. It is NOT a proof for the structured A above.

The experiment supplies no assumption about a verifier who must be honest last, no SourceOpen oracle, no fake native checking key, no QPT rewinding, no extractor for arbitrary attackers, and no special Bitcoin opcode. A full solution still requires classical-PPT witness-free Comp(R_original,x,context,pk) and publicly executable Release(D,W) such that EVERY valid ORIGINAL W obtains the SAME precommitted native sk, every fixed FALSE x hides sk in the complete classical public view (pk, context, arbitrary permitted auxiliary data, related capsules and one-honest malicious setup transcripts) against arbitrary nonuniform QPT adversaries, and unauthorized hard-TRUE native signature/key recovery yields an actual ORIGINAL W or independent QPT break without asking for a supplied representation. The source-conditioned opening distribution and QPT challenge simulator must be instantiated jointly, not inferred from marginal LWE hiding.

Malicious unknown-one-honest N-of-N graph/abort/data availability, SYS/BTC authenticated fork qualification with finite evidence and censorship/reorg assumptions, and a hypothetical no-EC PQ-native Bitcoin output remain unproved. This is NOT a deployment or automation-completion result.

## Executed evidence
Exact standalone Node-compatible check.js was executed twice in the connected V8 runtime with byte-identical outputs, 3617 assertions each; OUTPUT.json is that exact output. It checks the four false assignments, exact unique fractional cube solution, all 24 spike/sign/dense configurations crossed with 64 signed legal vectors, two distinct TRUE witnesses, two independently randomized related capsules per protected bit (256 bits), 512 FALSE packet recoveries, exact residual identities and the parity equations. Independent local Python check.py was also executed twice, 3,620 assertions per run, with byte-identical local output. These finite checks are not QPT hardness experiments, a genuine native post-quantum signature or a deployed Bitcoin transaction. No other GitHub write destination is authorized.
