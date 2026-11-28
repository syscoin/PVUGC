# Quadratic-factor affine-normalized Fourier gate groups

Research record: affine-quadratic-star-20261027-turn6. Repository syscoin/PVUGC, draft PR #1, branch research/pq-wkem-validation-20260918. Starting parent 02f2783d8eef49e05746dd471d0ddaa0c64451ee. Exact predecessor: research/pq-wkem/pow_star_polar_20261027/PROOF.md, Git blob 2e9e3477a39eca0a03d3d234f1c0bdd3dd260bd6. This is an offline continuation, not a deployment or a generic-NP WKEM.

## Construction and exact compiler criterion

Each original nonlinear Boolean gate is c_i=(u_i AND v_i) XOR nu_i, with nu_i=0 for AND and 1 for NAND. The input wires u_i,v_i are affine forms in the public source's global GF(2) variable vector xi after exact XOR/NOT elimination. Write U_i,V_i for their linear-part coefficient vectors. If these vectors are independent, the Boolean quadratic part of u_i*v_i is the alternating two-form U_i wedge V_i. Its factor plane is span(U_i,V_i), with exactly three nonzero vectors U_i,V_i,U_i XOR V_i.

For a candidate gate group G having disjoint original assignment-label blocks, select a nonzero a in the intersection of those factor planes. For every i, choose b_i independent of a in its plane. The change of input basis has determinant 1 over GF(2); hence the degree-two components of u_i*v_i and A*B_i coincide. Here A,B_i are arbitrary affine lifts of those linear parts, with A selected as the SAME global affine form for the whole group. Therefore the Boolean polynomial

  ell_i = (u_i*v_i) XOR (A*B_i)

is affine. It is expressible as an affine function of the original local u_i,v_i and a constant. Define the VIRTUAL output C'_i=c_i XOR nu_i XOR ell_i. Then the ORIGINAL gate equation is equivalent, for every assignment, to C'_i=A*B_i. The input transformation (u_i,v_i) to (A,B_i) is invertible affine; the output adjustment is affine. All identities can be certified by the four local assignments and the original exact affine SOURCE equations. No new nonlinear gate, canonical witness, common preimage, secret setup state or source-opening oracle is introduced.

A polynomial greedy compiler enumerates the at most three nonzero factors of each eligible gate plane, selects a factor covering the most remaining disjoint gates and groups those gates. After removing those blocks it repeats, leaving ungrouped gates as singleton filters. It verifies each product identity symbolically and adds the needed exact affine consistency rows if not already present. Source compilation remains classical polynomial time in circuit size. The grouping is not claimed globally optimal.

Strict nonliteral example: original gate inputs u_i=x XOR y_i and v_i=y_i, with separate y_i. No two original gates share a literal input wire, yet each factor plane is span(x,y_i) and all share the quadratic factor x. Their gate equation c_i=(x XOR y_i)*y_i becomes c_i XOR y_i=x*y_i. This example is missed by literal shared-input grouping but accepted by the new compiler.

## Fresh physical assignment-label mask

Retain the same public homogeneous GF(2) SOURCE matrix C_x and full row basis B of ker(C_x). Each original gate's four allowed assignment labels correspond to the original (u_i,v_i) pairs (00,01,10,11), not invented transformed labels. For a group of h gates draw independent eta in GF(2), lambda in GF(2)^h; reject exactly eta=1,lambda=0; then draw independent uniform beta. On the ORIGINAL gate label e, evaluate the publicly compiled affine virtual values A(e),B_i(e),C'_i(e), using the allowed original output c_i(e)=u_i(e)*v_i(e) XOR nu_i. Place the bit

  E_i[e] = lambda_i*(C'_i(e) XOR beta*B_i(e))
           XOR (i==first ? eta*(A(e) XOR beta) : 0)

at that gate's ORIGINAL label coordinate. Every other physical error coordinate is zero. Error draws are independent among disjoint groups and across release columns.

For every normalized complete SOURCE kernel state, exact affine consistency forces all gate-local values of A to coincide. Because the mask enters only linearly through original label coordinates, its phase is exactly

  <E,v> = eta*(A XOR beta) XOR sum_i lambda_i*(C'_i XOR beta*B_i).

For fixed beta, averaging eta and lambda before rejection yields indicator(A=beta and all C'_i=beta*B_i). Average beta: the unconditioned Fourier signal is 1/2 on EVERY locally valid normalized state and zero on EVERY invalid normalized state. The rejected eta=1,lambda=0 event has cancelling beta phases (-1)^A and (-1)^(A+1) for every state; its probability is 2^(-(h+1)). Conditioning yields the exact common valid-state bias

  rho_h = (1/2)/(1-2^(-(h+1))) = 2^h/(2^(h+1)-1),

and zero invalid signal. The prior equal-signal local Fourier L1 certificate proves local optimality only under those exact-support constraints, not generic global optimality. Each group needs O(h) random bits per admitted draw and O(h) assignment-label work. A classical polynomial worst-case Build caps attempts at T per group and aborts BEFORE funding. Across N release columns its honest cap-abort probability is at most N times sum_groups 2^(-(h_i+1)*T_i). Conditional on no abort, the admitted law is exact.

## Full quotient identity, SAME key and QPT scope

Let b=B*e_0, define P_z as the COMPLETE probability law of Q=B E+b*z, with the independent grouped errors. Write rho=product_groups rho_(h_i), including singleton rho_1=2/3. For any Fourier index a, the corresponding SOURCE state is v=a^T B. If its constant bit v_0=0, the b-shift changes no character. If v_0=1, the product of the exact group filters is rho precisely when v is a normalized one-hot ORIGINAL witness satisfying every affine pin and nonlinear gate, and zero otherwise. Therefore

  Fourier(P_1)(a)-Fourier(P_0)(a) =
    -2*rho  for ORIGINAL accepted normalized one-hot SOURCE indices;
     0      for every other index.

This is a WHOLE-distribution identity, not a probe. For EVERY false ORIGINAL statement x the witness-index set is empty, so P_0=P_1 exactly, including the entire output law.

Use the previously published public-dither polar release without changing its output semantics. Honest Build generates one k-bit native seed K and the real public checking key pk(K), samples independent public uniform S, polar encodes U=K XOR S as length-N c, and publishes independent Q_j=B E_j+b*c_j. The full public view includes relation and x, source matrix, public grouping, N/code parameters, S, all Q_j, native pk, claim/UTXO/branch/anchor/window and intended challenge-path context, allowed auxiliary data and related capsules. For any valid ORIGINAL witness w, its own state v_w gives alpha_w*B=v_w^T and observations alpha_w Q_j=c_j XOR <v_w,E_j>. Per fixed witness this is a memoryless BSC with bias rho. The fixed public polar decoder therefore recovers U, then the SAME precommitted K=U XOR S, whenever decoding succeeds, even if witnesses have different intermediate states. Native pk checks the candidate. Honest setup/evaluation remain classical and polynomial in the ACTUALLY emitted capsule length; this is not polynomial generic-NP completeness.

With the predecessor's public upward-rounded dyadic polar certificate, t_eff noise-class bound and correctness lambda, simultaneous all-witness failure is at most 2^-lambda conditional on Build success; add the explicit honest cap-abort probability. In the h=4 nonliteral example, the new rho=16/31 versus the independent 16/81. Recalculated at k=128,t_eff=64,lambda=64, the accepted column counts are 8192 versus 65536: 8x fewer, a COMPLETENESS/payload comparison only. Generic many-group rho remains exponentially small.

For false x the complete joint Q vector has distribution P_0^N independent of K, even given REAL pk(K), S and independently simulatable context and auxiliary material; the simulator does not know native K. This exact classical joint-distribution theorem survives QPT postprocessing with independent allowed quantum advice. No arbitrary setup-coin-correlated advice or correlated selective opening is proved.

For hard TRUE x, the previously established coherent-adversary-code/inverse-access Fourier reflection extractor applies because the SAME whole-character support identity holds. For actual final-seed recovery or a genuine new-message authorized-path native signature forgery (under the correctly simulated native signing challenge), the inherited conditional inequality is

  p_real <= p_native + N*rho*sqrt(s_x*p_extract).

The extractor does not ask the attacker to output an intermediate representation and uses one copy of properly independent quantum advice. Its computational and coherent-access costs, checking-key correlations and auxiliary simulations are included in the resource budget. This is NOT a standard-LWE theorem. A true claim-bound PoW/NP relation would permit projection of a verified ORIGINAL witness onto its work evidence, but NO quantitative QPT work-search bound for actual public 100-block BTC/SYS history is derived. Large s_x and exponential N may make the inequality vacuous. Once work evidence is public the corresponding fresh-work hardness can vanish.

Several independent-claim, independent-key, independent-noise capsules can be treated in joint hybrids when auxiliary material is simulatable; target-correlated key reuse, retained masks, adaptive selective opening, malicious N-of-N ceremony/abort, Bitcoin preauthorization graph, one-of-N watcher inclusion, SHA/AuxPoW tag/window evidence, or native PQ Bitcoin scripts/signatures have NOT been proved. The Bitcoin endpoint would still need only a native signature, not on-chain NP verification.

## Executed checks and exact remaining gap

An independent local Python checker and full derivation were executed twice with byte-identical output (3620 assertions per execution). Tests include h=1..5 exact mask distributions and physical ranks, GL2/affine-offset/NAND remappings, real 2-gate homogeneous GF(2) kernel quotient distributions for true (five accepted modes) and false (none) original statements, entire false-view equality, and exact dyadic polar length certificates. The accompanying shorter executable JS checker checks the same nonliteral factor criterion and exact local phase distributions. Finite checks are NOT QPT hardness tests, mining benchmarks, or proof of the unrestricted theorem by experiment.

The missing practical inequality is to make N*rho*sqrt(s_x*delta_work(B*, public history, full pk/context/aux/capsules)) negligible while achieving negligible all-ORIGINAL-witness decoding error with polynomial-sized honest capsules. This iteration improves which circuits may be efficiently grouped; it does not establish that inequality for actual SHA-256/Bitcoin/Syscoin or provide the generic structured-LWE SOURCE embedding.