# PoW projection plus optimal star-filtered polar release

Research checkpoint: 2026-10-27, one bounded offline iteration. Source PR #1, branch research/pq-wkem-validation-20260918, starting head b4e2eaa4062e68e53a488e066f75de83fb24c45d. Exact published predecessor: polar_coded_fourier_20261027/PROOF.md, Git blob 039e2706200aaf8cb6cf0a2bd9e0d730684abda5. The earlier optimized shared-input sampler was locally derived and checked but NOT previously published on this branch. Full longer notes and Python checker exist in the separately delivered local archive. No external SecMine paper or internet research was consulted.

## 1. Actual release algorithm

Fix ORIGINAL deterministic Boolean verification circuit R_x(w). Its public x includes the relation identity, claim/UTXO, branch, burn/authorization/outputs, authenticated anchor/window and intended native public key. Every legitimate ORIGINAL witness has its own normalized one-hot SOURCE state v_w with constant coordinate 1 in the public homogeneous GF(2) kernel ker C_x. Let B be a public full row basis of ker C_x and b=B e_0. Public linear algebra gives alpha_w satisfying alpha_w B = v_w^T; no canonical witness or common intermediate state is needed.

Partition nonlinear AND/NAND gates into disjoint *gate-label-coordinate* groups. All gates within a group share one input a, although different groups may share wires. For each gate i of a group with h gates, define the other input b_i and c_i=output for AND, c_i=1+output for NAND, so correctness means c_i=a*b_i. Align the four allowed labels by input pair (00,01,10,11).

For one group draw uniform eta in GF(2) and lambda in GF(2)^h, rejecting the single event eta=1 and lambda=0. Upon acceptance draw uniform beta. In first gate's four-label error block set E_1=(0,0,eta,eta+lambda_1) if beta=0 and E_1=(eta,eta+lambda_1,0,0) if beta=1. In each later gate i>1 set E_i=(0,0,0,lambda_i) if beta=0 and E_i=(0,lambda_i,0,0) if beta=1. All other coordinates are zero. Use independent group coins and independent fresh errors across columns. Ungrouped gates retain the preceding singleton law with bias 2/3. Cap rejected trials at T_i per group/column, and abort before funding if exhausted. For N columns the probability of an honest bounded-time setup abort is at most N*sum_i 2^(-(h_i+1)*T_i), which can be made negligible with polynomial T_i. Conditioned on no abort, the admitted masks have precisely the original exact distribution. Malicious participant abort control is not proved.

Let rho_i=2^{h_i}/(2^{h_i+1}-1), rho=product_i rho_i*(2/3)^u where u counts independent leftover gates. Generate fresh uniform native seed K (k bits) and real native checking key pk(K), independent of release coins and relation. Generate a PUBLIC uniform k-bit dither S, form U=K xor S, and polar-encode U into a length-N codeword c with public information set I and frozen zeros. For each j publish Q_j=B E_j+b*c_j. Full public view is relation,x,C_x/B,group definitions,N,I,rho,S,all Q_j,actual pk(K),bound context,permitted auxiliary information and related capsules. Setup must erase/protect native seed and noise after N-of-N preauthorization, and does not leave an online release authority. Only off-chain witness decoding and an ordinary native signature are intended; no onchain NP or trace verification.

For any valid ORIGINAL w, compute y_j=alpha_w Q_j=c_j+v_w^T E_j, SC-decode Uhat, and output Khat=Uhat xor S. Whenever the decoding succeeds it is exactly the SAME precommitted K for every valid ORIGINAL witness. The actual public pk checks any purported seed, subject to native-key assumptions; no equality between arbitrary seeds sharing a pk is silently postulated.

## 2. Full Fourier support and exact false-instance simulation

For every normalized kernel state with gate variables (a,b_i,c_i), the four allowed-label coordinates of gate i are (1+a+b_i+c_i,b_i+c_i,a+c_i,c_i). The stated physical error mask has parity phase

  <E,v> = eta*(a+beta) + sum_i lambda_i*(c_i+beta*b_i).

Before rejection, averaging eta,lambda conditional on beta equals the indicator that a=beta AND c_i=beta*b_i for every gate. Averaging beta gives one-half on each valid group state and zero on invalid normalized states. The rejected eta=1,lambda=0 event contributes a cancelling pair of phases a and a+1 for the two beta values, identically zero for ALL normalized states. It had probability 2^(-h-1). Therefore after rejection

  E[(-1)^<E,v>] = [1/(2-2^(-h))] * 1[all gates in this group valid].

The Fourier L1 norm of f(a,b,c)=1[c=a*b] over all generic normalized group states is exactly 2-2^(-h). For any affine-phase probability sampler having uniform positive valid-state signal rho and exact zero invalid-state signal, its signed Fourier measure has total variation >=rho*(2-2^(-h)) and at most one. Thus rho<=1/(2-2^(-h)); our rejection law achieves it. This is a LOCAL optimality statement, not a global lower bound on generic witness encryption.

Every normalized SOURCE kernel state either satisfies all affine constraints and all nonlinear gates, thus describes a valid ORIGINAL witness with coefficient rho, or violates a gate and its group's coefficient is zero. The groups' noises are independent even if their wires overlap. For Fourier mode a of the FULL quotient, aB is the SOURCE state. If its constant bit is zero, shifting Q by b does not affect its character. Thus

  Fourier(P_1)(a)-Fourier(P_0)(a) =
     -2*rho  if aB is an accepted ORIGINAL witness state;
     0       otherwise,

where P_z is the full law of Q=B E+b*z, not one hand-selected projection. On FALSE ORIGINAL x there are no such modes, hence P_0=P_1 EXACTLY. The entire public polar-coded Q^N distribution is then P_0^N even when the hidden codeword bits are correlated. Given the actual native pk and permitted simulatable challenge context, the false public capsule can be sampled WITHOUT knowing K. This exact classical-distribution statement is stable under arbitrary QPT postprocessing with independent quantum advice, but not arbitrary advice entangled with unrevealed setup coins. Cross-capsule target-correlated openings or malicious retained setup state are not covered.

## 3. Concrete all-witness polar certificate and correlated-noise rank

For any fixed valid w, group parity errors are independent across release columns and have the same BSC bit-error probability (1-rho)/2. Correlations between different witnesses on one column do NOT invalidate the union bound. The public S makes U uniformly distributed over the dither-generation experiment for any fixed K, including its public-key correlations. Use the predecessor's root-first even/odd SC decoder and the conservative integer Z recursion.

Set D=2^P with P=t_eff+lambda+128. Start z0=ceil(D sqrt(1-rho^2)). On each polar split use z_minus=min(D,2z-floor(z^2/D)) and z_plus=min(D,ceil(z^2/D)); recurse root-first and select the k smallest leaves as I. Accept the length only when

  2^(t_eff+lambda) * sum_(i in I) z_i <= D.

Then conditional on successful Build, the probability that ANY accepted ORIGINAL witness decodes incorrectly is <=2^-lambda. A safe t_eff is the witness input-bit length t. A stronger public bound is t_eff=min(t,r_E), where r_E is the GF(2) rank of the projections B E for all possible physical noise masks; witnesses having the same function on this error span see the same noise sequence. The physical optimized h-gate mask span has rank 2h+2 instead of the 4h independent-gate label coordinates; after applying B the rank can only decrease. This improves the public union-class upper bound without enumerating witnesses or choosing a canonical witness. Overall abort and decoder failure probabilities add.

## 4. Full-transcript QPT reduction and PoW as a restricted independent hardness invariant

The pinned coherent Fourier extraction reduction only uses the exact witness-supported Fourier identity. It therefore applies to this new explicit sampler and polar code without claiming a new extraction theorem. For complete public-view arbitrary QPT native-seed recovery or eligible fresh-message native-signature forgery:

  p_real <= p_native + N*rho*sqrt(s_x*p_extract),

where s_x counts accepted SOURCE modes, p_native is the success of the actual native challenge simulator retaining real pk, signing interfaces and permitted aux, and p_extract is the probability of the predecessor's coherent circuit/inverse-access SOURCE witness extractor. It needs one copy of relevant independent quantum advice, reversible circuit access, all computation/oracle resources and checking material represented correctly. The loss through s_x can be catastrophic. This is not a standard-QPT-LWE reduction, a black-box classical rewind, or a proven Bitcoin hardness bound.

To ATTACH PoW and general NP, specify ONE ORIGINAL source relation

  R*_x(z,u)=Chain_100(x,z) AND NPVerify_x(z,u).

Chain_100 must verify claim-bound anchor, all 100 appropriately counted linked headers, actual targets/work and branch/direction, relevant tags and Merkle proofs, and SYS AuxPoW authenticated commitments. It cannot equate valid AuxPoW parent headers with canonical Bitcoin best-chain membership. The general NP predicate remains cryptographically enforced: even if a qualifying chain exists, a false NP statement gives no key-sensitive Fourier modes. Qualified broken-tag/incompatible-fork veto branches may use their own correctly scoped source without imposing an arbitrary 100-block additional work burden.

The deterministic projection (z,u)->z means any *verified ORIGINAL witness extractor* also wins the corresponding chain-evidence work-search game. If an independently justified **matching QPT** work-game bound is delta_work(B*) (with same public network feed, correlated context, precomputation, quantum queries, history and expanded coherent extraction budget), then the formal consequence is

  p_real <= p_native + N*rho*sqrt(s_x*delta_work(B*)).

This is a genuine projection lemma, NOT a derived practical 100-BTC-block work bound. Once qualifying chain evidence is publicly available, delta_work may be one. Standard Bitcoin confirmation/reorg security is distinct from a fresh claim-bound private work-finding oracle game. No real Bitcoin/Syscoin circuit, tag-window model, PoW theorem or economic work bound is compiled here. More importantly, N remains exponential in the number of independently filtered nonlinear groups, and huge s_x may make the reduction vacuous. Neither a publicly computed future tip hash nor publicly checking NP before a PoW-only hashlock gives generic WE for a precommitted same K. A named SecMine construction was NOT externally verified, under the offline restriction.

## 5. Resource certificate and executed validation

For illustrative k=128, conservative t_eff=64, lambda=64, with group size h=4: one optimized star has rho=16/31 and an exact upward-rounded polar certificate at N=8192, versus rho=(2/3)^4=16/81 and N=65536 for independently masked gates: **8x fewer certified columns**. Two such stars (eight gates) certify N=32768; the independent-gate baseline was not certified by N=262144. Three stars certify N=131072, likewise with no independent certificate within 262144. These are correctness/payload illustrations, NOT 128-bit QPT-security parameter sets or Bitcoin sizes. Each quotient column has dim(ker C_x) public bits. With p nontrivial groups rho is still approximately 2^-p, so generic cost remains exponential.

An independent local Python checker executed twice byte identically with 2781 assertions: exact h=1..5 local laws, physical noise ranks, whole true/false homogeneous SOURCE quotient laws, integer polar certificates and a structural-only synthetic claim/NP projection. The separately published JavaScript checker was executed twice identically with 2913 exact checks, including public whole-quotient law and polar sizing. An initial checker comparison incorrectly used insertion-order Maps; corrected canonical-map comparison before the final two passes. These are bounded mathematical fixtures, not SHA-256 mining, QPT hardness evidence, external SecMine validation, malicious ceremony proof, selective-opening proof or native Bitcoin endpoint verification.

## 6. Exact unfinished obligation

A polynomial-cost source-dependent release and a tight resource-matched extraction/work bound remain missing. The desired full-joint security needs an actual compiled SYS/BTC claim verifier, source-noise or LWE challenge simulator for the *complete* pk/context/capsule/auxiliary/related-capsule distribution, a nonvacuous quantitative quantum work term, and real N-of-N preauthorization, abort, graph and native PQ script/signature composition. The present result is a verified, strictly scoped sampler + decoder efficiency advance, not an actual practical generic-PQ witness-KEM.
