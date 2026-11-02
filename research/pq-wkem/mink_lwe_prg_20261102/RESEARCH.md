# MINK-LWE-PRG-20261102-T20 — ordinary-QPT-LWE stretch for a restricted same-capability release

**Status.** New finite, classical-PPT component. The SHAKE256 PRG *assumption* in the preceding MINK-SLSEED variant is replaced by an explicitly instantiated matrix-LWE pseudorandom generator and a straight-line QPT decisional-LWE hybrid. Valid ORIGINAL **signed-XOR** witnesses recover one identical precommitted seed. This does **not** give a generic-NP witness-KEM, an honest-secret setup-proof simulator, or hard-TRUE recovery-to-ORIGINAL-witness extraction. It is restricted to the same easily solvable signed-XOR SOURCE and one-time Lamport prototype as the predecessor.

## Exact public and secret distributions

Parameters for the finite executable example: q=2^16=65536, n=256, m=4096, a=10. Honest public A is independent uniform in Z_q^(m x n), encoded in 2,097,152 bytes. Its generation/erasure/abort transcript must be authenticated. One-honest malicious N-of-N CRS generation is **not instantiated** by this result.

Draw S uniformly from {0,1}^L where L=16n+am=45,056 bits (5,632 bytes). Parse the first 4,096 bits as n independent little-endian 16-bit elements s_j of Z_q. Parse the remaining 40,960 bits as m independent 10-bit unsigned integers u_i. Let e_i=u_i-512, uniformly and independently distributed over [-512,511]. Define

    G_A(S) = LE16(A s + e mod q) in {0,1}^O, O=16m=65,536.

The joint distribution (A,G_A(U_L)) is exactly **decisional LWE with uniform s and independent bounded errors** for these parameters, not an additional ad-hoc seeded-hash assumption. Its quantum hardness and any 128-bit concrete security estimate remain unverified. The QPT assumption is explicitly:

    |Pr[D(A, A s+e)] - Pr[D(A, U(Z_q^m))]| <= eps_DLWE

for all allowed nonuniform QPT D with independent quantum advice, A uniform, s uniform and e as just specified. There is no worst-case-lattice hardness proof or automatic QPT lift claimed for this parameter tuple.

At each generator step, retain the first L output bits as the next state and emit the remaining O-L=20,480 bits. Iterate 15 steps with the **same A**, concatenate outputs, and truncate to 294,912 bits = 36,864 bytes. Parse as 768 consecutive 48-byte Lamport private leaves u_(i,b), 384 message-digest positions with b in {0,1}. Publish the genuine 768 SHA384 leaf images vk_(i,b)=SHA384(u_(i,b)). One one-time native-style signature reveals one 48-byte private leaf per SHA384 digest bit. This is off-chain experimental signing, not Bitcoin native functionality.

The bound typed manifest includes ORIGINAL relation identity and source rows, claim/UTXO, challenge branch and intended credential, source anchors/window, A digest, actual SOURCE capsule digest, and genuine vk digest. The Python implementation checks the real SHA384 signature, a tampered manifest and an incorrect challenge message. Bitcoin does not verify the ORIGINAL NP relation in this proposal.

## QPT hybrid: repeated use of a single public matrix

Define hybrids H_j for j=0..t with the first j complete G outputs replaced by independent uniform O-bit strings. Their L-bit prefixes become the subsequent seeds; all later stages compute G_A honestly. H_0 is actual iteration, H_t emits independent uniform blocks. At stage j of H_j, the seed is exactly uniform and independent of A and earlier uniform emitted tails. To distinguish H_j and H_(j+1), an ordinary LWE reducer receives (A,b) with b either As+e or uniform, inserts all O bits of b as this stage's output and computes subsequent stages deterministically. This is a straight-line black-box QPT reduction, uses no rewinding, and does **not** require new independent A at each stage. Public post-processing, including generation of real correlated vk, manifest, related FALSE source capsules and one classical Lamport signing response, is performed by the reduction.

Thus, for t polynomial and publicly generated allowed auxiliary inputs,

    Adv_iterated_G(t) <= t * eps_DLWE.

For this sample t=15. For polynomially many independently seeded claims sharing A, hybridize one claim/iteration at a time; bound grows by sum of their iteration counts. Multiple FALSE capsules sharing **one seed** are generated from fresh, independent SOURCE mask coins; they do not require independent G outputs. This is for arbitrary coherent QPT processing of a joint **classical public sample**, with nonuniform advice independent of the fresh secrets. It does not prove anything for arbitrarily secret-correlated/entangled auxiliary quantum states, coherent signing/source-opening oracle queries, or malformed malicious setup.

Statistically, G_A has seed support at most 2^L inside 2^O outputs: the result is **not** information-theoretic pseudorandomness. It is computational solely under the precisely stated QPT decisional-LWE distribution.

## ORIGINAL SOURCE correctness and exact restricted FALSE-source simulation

Let x be a signed-XOR relation on variables z, and A_src its F2 signed incidence matrix with each constraint row (b,e_u+e_v). A valid ORIGINAL witness z gives t=(1,z) and A_src t=0.

For every bit S_i of the precommitted L-bit seed, sample independent uniform m_(i,0),m_(i,1) and set m_(i,2)=S_i+m_(i,0)+m_(i,1). Independently choose r_(i,j) uniform F2^E; publish

    C_(i,j)=A_src^T r_(i,j) + m_(i,j) e0.

For **every** satisfying ORIGINAL z, t^T C_(i,j)=m_(i,j); summing the three lane evaluations gives the **identical** S_i. The original witnesses need not share intermediate projection vectors or canonical witnesses. The full seed expands through G_A into the same bound native signing key and verification key.

For FALSE signed-XOR, public elimination yields delta with A_src^T delta=e0, proving unsatisfiability of the ORIGINAL signed-XOR equations. Since

    A_src^T r + m e0 = A_src^T (r + m delta),

C is uniform in Image(A_src^T) independently of m or the seed. A straight-line simulator samples r0 uniformly and publishes C=A_src^T r0. To open up to two lane shares for a given seed bit, choose independently uniform revealed m and supply real opening coins r=r0+m delta. The third lane remains unopened. This is an **exact joint classical distribution identity even conditioned on the actual genuine vk** and any efficiently generated native signing transcript; related FALSE capsules reuse the same seed with independent SOURCE masks. The simulator needs neither the initial seed nor a SOURCE-opening oracle. The executed toy checker exhausts the visible distribution for all three possible pairs of opened lanes and both possible secret bits.

Allowed SOURCE openings are adaptive but classical and reveal **at most two of three** lanes per seed bit/capsule. A third opening, a related TRUE capsule releasing the seed, secret-dependent unbounded auxiliary leakage, a coherent opening oracle, or a non-honest setup lie outside this theorem.

## Restricted native-forgery implication and exact missing ORIGINAL reduction

In the full specified restricted FALSE SOURCE subview, replace the 15-stage output by uniform Lamport leaves using the QPT-LWE hybrid above, while the simulated SOURCE capsule and revealed coins remain genuine and joint with vk/manifest. For a fresh accepted one-time SHA384 Lamport signature on a distinct 384-bit digest, at least one previously unopened leaf is revealed. Embedding a uniformly chosen SHA384 preimage challenge in one of 768 vk entries gives a straight-line quantum-adversary reduction with loss <=768. A distinct message giving the same signed digest instead contradicts QPT SHA384 collision resistance. A scoped bound is

    Pr[fresh accepted false-source native forgery]
      <= 15 eps_DLWE + 768 eps_SHA384-preimage(QPT)
           + eps_SHA384-collision(QPT) + eps_binding.

The final binding term includes preauthorization graph and proper proof of capsule-to-native-key consistency and is **not established**. This result does not provide the setup proof/its checking key or a simulator for that entire required public distribution. It does not prove hard-TRUE arbitrary key recovery/native forgery => ORIGINAL witness or independently justified PQ break. It does not treat an accepted inner SNARG as an ORIGINAL witness. Generic-NP Build/Lift remains the central missing primitive, and arbitrary adversaries never have to volunteer their internal representation.

## Reproducibility and resource accounting

The exact executed published standalone Node JS checker validates a small exact LWE generator and exhaustive 2-of-3 FALSE-source distributions: 7,354 assertions, two byte-identical runs. The separately executed, downloadable Python-standard-library full-size checker performs all 15 q=65536 matrix-vector stages, actual SHA384 signing/verification, 45,056-bit capsule generation, two distinct ORIGINAL witnesses recovering the same seed, genuine native-key recomputation, authenticated context/capsule binding, 90,112 simulated openings and exhaustive FALSE one-bit distribution comparisons. It passed 1,216,696 assertion events **twice with byte-identical output**. A public deterministic SHAKE test fixture is used to make both checkers reproducible; **not** a secure sampling claim. See the offline archive for full-size Python source, both original results, complete detailed derivation and hashes.

Exact illustrative bytes: seed 5,632; SOURCE capsule V=3, bitpacked 67,584; independently generated 768-leaf SOURCE capsule 442,368; public A 2,097,152; native vk 36,864; one-time signature 18,432. SOURCE capsule alone is 6.545x smaller than independent leaves, but the public A dominates a single claim: **there is no total single-claim public-footprint improvement**. Sharing an honestly sampled A across at least six independent claims can amortize that cost, conditional on multi-instance QPT-LWE security and the missing malicious CRS ceremony. The earlier SHAKE-seeded capsule was far smaller (384 bytes) but required an additional unproved SHAKE256 PRG assumption. This variant replaces that with the standard decisional-QPT-LWE assumption, not with an unconditional security proof.

## Open obligations: do not deploy or fund

The ORIGINAL generic-NP requirement remains

    for all w satisfying R(x,w), Lift(x,Build(x,K),w)=K,

with a proven full joint simulator and an arbitrary-QPT unauthorized key-recovery or accepted-native-forgery => ORIGINAL witness or **independently justified** QPT break. The full public view must include relation/statement, capsules, genuine native checking key, setup checking key and setup proof, context, arbitrary admissible auxiliary input, related capsules and classical selective openings. No source-opening oracle, adversary-volunteered representation, fixed probes, local masks, or easy relation may substitute for this.

Also unproved: one-honest N-of-N malicious preauthorization/CRS generation, selective-abort and multi-attempt composition, witness consistency proof before funding, actual generic SOURCE evidence for Bitcoin/Syscoin including AuxPoW, headers, ancestor/tag interval/direction/windows, data availability and censorship assumptions, and the conditional native no-EC-key-path PQ Bitcoin endpoint. There is no 128-bit QPT parameter validation or deployment claim. No external literature or internet research was used.
