# MINK-IVEC: independent verifier challenges for MINK-BHC setup consistency

Run MINK-IVEC-2026-11-01-T17. This is a RESTRICTED constructive soundness improvement, NOT a generic post-quantum witness-KEM, a QPT ZK proof, or a deployment recommendation. No external research.

Source: syscoin/PVUGC#1 branch research/pq-wkem-validation-20260918 at starting head c9eea4022a412fc5949c529c51a3ba4124955965. Exact predecessor: research/pq-wkem/mink_lwe_beacon_20261101/RESEARCH.md at blob ec9a93e99d946b34f110b081b58e1c2685265783.

## Unfinished predecessor and why a naive coin flip is insufficient

MINK-BHC uses color commitments Com_A(b;s,e)=A^T s+e+floor(q/3)*b*e1 mod q, with classical PPT samples s uniform in Fq^n and e from chi^m supported on [-B,B]^m, public A uniform in Fq^(n x m), q odd prime, q>12B+12, m>n. Its claimed global cross-color-binding bad-A probability is at most delta_A=6(q^n-1)((4B+1)/q)^m. Its color-hiding reduction is to decisional QPT-LWE for that exact error distribution, with polynomial loss for multiple fresh commitments. This is not a concrete 128-bit hardness estimate.

The predecessor assumes an externally honest, unpredictable and independent post-commit edge beacon to soundly test a 3-color proof. A simple multi-party seed XOR is NOT a secure instantiation using these commitments alone. A corrupt party can copy a commitment to the honest seed, and after honest reveal copy its exact opening coins and seed. The two identical seeds XOR to zero; ordinary LWE hiding and cross-color binding are not nonmalleability or proof-of-knowledge of pre-reveal opening. This is a public-interface attack under the proposed coin-flip schedule, not a claim against a different independently nonmalleable protocol.

## Actual finite IVEC procedure

Set N>=2 registered pre-funding participants and a fixed, authenticated unique session sid. Freeze the exact statement X: ORIGINAL relation identity and compiler, intended claim and UTXO, branch, anchor and observation window, challenge-path native verification key and intended capability, every related capsule, manifest, auxiliary public data and exact KeyGen/Build identities. The MINK-BHC setup relation L_setup(X) asserts existence of native keygen and capsule-generation coins consistent with the actual vk and ALL capsules. Its classical polynomial circuit-to-3-coloring compiler gives G_X=(V,E), d=|E|>=1; no original source witness is substituted for that setup witness. The predecessor's checker does not implement the full KeyGen/Build-to-3COL compilation, and this iteration does not either.

For each proving participant i and every OTHER verifier participant j, repeat ell independent rounds r:

1. The honest prover freshly uniformly permutes a proper coloring for this (i,j,r), independently commits every vertex color using fresh LWE coins, then freezes an authenticated commitment-root manifest signed and bound to (sid, digest(X), i, j, r). The verifier has no advance view of its own future challenge.
2. Only after the entire commitment batch is immutable, verifier j samples ONE uniform edge from E using fresh classical local coins and sends the authenticated edge challenge for the exact tuple. No shared challenge beacon or XOR seed is used.
3. The prover opens just the two challenged vertex commitments, including actual (color,s,e), and the verifier checks equality of LWE ciphertexts and distinct colors.
4. Accept this prover's setup proof only if every mandatory verifier j and each repetition r passes. An absent, aborted, replayed, retagged or mismatched transcript fails. Never reuse the same vertex-color commitment with another verifier or in another round.

For a malicious proving signer i there is, by the preexisting one-honest N-of-N premise, an honest other participant j, so its random challenges alone enforce soundness independently of all corrupt verifiers. Their adaptive or copied challenges cannot cancel this challenge. When all signers' setup proofs are complete, funding STILL requires N-of-N preauthorizations, all path pre-signatures and the DA/inclusion conditions; neither a checker nor quorum members may create bypass spending edges. A malicious pre-funding abort sacrifices liveness, not one-shot safety.

## Proof of restricted full-context QPT setup-statement soundness

Condition on a uniform A from an independently honest generation and the complement of its global cross-color-binding bad event. Every classical vertex commitment has at most one OPENABLE color, even against an unbounded adversary; use an arbitrary color for an unopenable commitment. If X is FALSE, G_X is non-3-colorable; that induced assignment violates at least one edge, or an edge touching an unopenable commitment fails opening. Consequently for each immutable graph commitment batch there exists at least one of the d edges on which acceptance is impossible.

Let a malicious prover and other corrupt participants have arbitrary QPT internal states, QPT auxiliary advice, native vk, context, all related capsules, other protocol transcripts and prior challenge outcomes. They must output classical vertex commitments before the honest verifier samples its uniform edge; conditional on any such prefix, the fresh edge is independent. Success for that repetition is at most 1-1/d. Each repetition has fresh independent edge randomness and fresh immutable graph commitments; conditional chaining yields

  Pr[false setup statement accepted in one attempted session]
     <= delta_A + (1-1/d)^ell.

All QPT coherent processing of the public CLASSICAL transcript and quantum-generated classical commitments is allowed; no quantum-superposition opening/challenge query or honest-randomness leak is assumed. The proof does NOT rewind the adversary, and does NOT assume the adversary supplies a private representation.

An attacker can abort after unfavorable honest challenges; if abort is failure for the funded event, the joint probability of accepted fraudulent funding cannot increase. Conditioning only on non-aborted sessions would be misleading. Across at most T authenticated adaptively chosen pre-funding attempts with independent fresh honest verifier edges, same fixed good A and strict no-replay, the bound is delta_A+T*(1-1/d)^ell. With a fresh A for each attempt use T times the corresponding delta_A. Unlimited retries invalidate a finite-target claim. The event definition includes statement and digest binding; changing relation, vk, branch, capsule or claim after first commitments rejects.

This is a SOUNDNESS proof for the finite 3-color setup checker, NOT proof that a fake source capsule hides the native signing key and NOT a full-public-output SOURCE simulator. Quantum security of commitment hiding remains an independent QPT-LWE assumption, not used to establish this one-honest verifier soundness result.

## Completeness and expense

For every TRUE setup statement with an actual KeyGen/Build witness, every fresh permutation of its proper coloring remains proper. Every chosen edge has different endpoints, so the prover opens successfully for any honest or adversarial classical challenge. Distinct valid ORIGINAL witnesses may retain distinct internal evidence states; this setup proof neither canonicalizes them nor establishes common-capability release. It only checks consistency of a claimed native key/capsule setup.

The cost is N(N-1)*ell*|V| independent color commitments over ALL signers, plus 2*N(N-1)*ell openings, without authentication overhead. For target error eta across at most T attempts, choose ell >= ln(T/eta)/(-ln(1-1/d)), approximately d ln(T/eta). Large setup circuits can make this impractical. Combining multiple verifiers against the same permuted coloring is NOT an acceptable optimization without a new privacy proof: combined edge openings may reveal a large fraction of the coloring and hence sensitive setup information.

## Remaining hard security boundary

If a prover is HONEST but verifiers are malicious QPT, their chosen edges may depend on prior public commitments and auxiliary data. MINK-BHC's simulator chooses the challenged edge BEFORE fabricating commitments under its independent honest-beacon premise. IVEC does not supply an equivocal commitment, a malicious-verifier QPT-ZK simulator, or a full selective-opening hiding theorem. The exact missing simulation is a classical-PPT or QPT efficient simulator that, without the honest native sk or Build randomness, produces the joint distribution of genuine vk, source, all capsules, context, authentication, maliciously adaptive edge challenges, actual opening coins, aborts and related sessions, computationally indistinguishable to arbitrary QPT verifiers, with independently justified assumptions. No simulator is assumed or proved here.

A is still assumed honestly uniformly generated; malicious distributed A generation is unproved. The full circuit-to-3COL compiler, practical post-quantum proof parameters, generic-NP finite Build/Lift, false-instance full-public hiding, unauthorized hard-TRUE final-key recovery/native forgery -> actual ORIGINAL witness or independent QPT break, N-of-N robust ceremony and the conditional no-EC-key-path Bitcoin/PQ endpoint are all uncompleted. In particular, this soundness-only improvement is insufficient to authorize funding.

## Reproduction and limitations

The exact published self-contained checker.js was executed twice as JavaScript, yielding identical JSON with 448 assertion events per run: all 3^4=81 color assignments of K4 have at least one bad edge; exact 5^ell/6^ell honest-challenge counts for ell=1,2,3,4; 72 independently tagged honest TRUE proof instances for four participants and six rounds using actual toy LWE color-commitment equations; malformed color openings reject. These toy values q=101,n=1,m=7,B=1 are cryptographically insecure. No QPT test or real KeyGen/Build circuit ran.

A separate Python checker, included in the local evidence archive, was also executed twice with byte-identical results (457 assertion events per run). It adds explicit abort-as-failure accounting. The local note carries the extended proof and exact Python outputs. The published JS checker and its JSON are independently executed, not borrowed assertion counts. No external research or any production or main branch changes.
