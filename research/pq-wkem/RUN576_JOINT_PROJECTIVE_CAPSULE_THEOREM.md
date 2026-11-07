# Run 576: joint-projection closure in projective witness release

2026-10-16. Draft research only, syscoin/PVUGC#1, branch research/pq-wkem-validation-20260918; initial verified head d09bd472a6b840ead693da943cab74cbe2c18890. A bounded mathematical theorem and explicit false/false multi-capsule attack, NOT a practical PQ WKEM.

## Constructive testbed and exact limitation

Smooth projective hash functions (SPHFs) are a concrete family of restricted-language late-witness release interfaces. To isolate the algebra, let q be prime, A in F_q^(m x n), y in F_q^m, and t independent hash coordinates. Classical setup samples secret H uniformly in F_q^(m x t), publishes P=A^T H and protects K=y^T H. A later ORIGINAL witness satisfying Aw=y releases w^T P=K. Every valid witness recovers exactly the SAME K even if witnesses differ. This is a positive restricted-language correctness property, not new cryptography.

For the unrestricted linear relation, there is an exact dichotomy. If y is in the column image of A, a public Gaussian solver finds w and K=w^T P; true statements have no key-hiding property. If y lies outside the image, K is perfectly uniform conditional on P. Proof: each fiber of A^T H is a translate of ker A^T; the linear functional y is nonzero on that kernel iff y is not in the column image. This perfect conditional claim holds against any QPT processing only the specified classical view; NOT against arbitrary extra leakage such as a public signing-check key.

Do not substitute the NP-hard short-witness ORIGINAL relation for the unrestricted relation. Over F_5, A=[1,1], y=3, and w in {0,1}^2, ORIGINAL is false. Yet the unrestricted w=(3,0) solves Aw=y and recovers K from the public projector. This instantiates the previously disqualified linear-closure barrier; it is not a proposed generic NP compiler.

## NEW: exact multi-capsule closure theorem

Suppose s capsules reuse the same H but publish separate projectors P_i=A_i^T H and protect K_i=y_i^T H. Write B=[A_1|...|A_s], P=B^T H. For each target j:

(a) If y_j belongs to Col(B), the attacker computes K_j from PUBLIC P by solving Bc=y_j and returning c^T P. This can happen even if y_j is outside Col(A_j), in which case the capsule was perfectly smooth in isolation.

(b) If y_j is outside Col(B), K_j is exactly uniform in F_q^t conditional on ALL these projections.

(c) More generally, for a target matrix Y, conditional on P, the vector Y^T H is uniform on an affine subspace of dimension t * (rank([B|Y])-rank B). Therefore individual false-instance smoothness does not imply joint independence or composable security.

Proof. Condition on B^T H=P. Each column of H is uniform on an affine coset of ker B^T. Applying Y^T maps this fiber uniformly to an affine image of rank rank([B|Y])-rank B by linear duality; independent H columns multiply the dimension by t. In case (a) y_j=Bc makes K_j=c^T P deterministically public. In case (b) the target functional is surjective on the fiber and gives a uniform field element in each coordinate.

Explicit classical false/false break: q=5, m=2, A_1=e_1, y_1=e_2, A_2=e_2, y_2=e_1, where e_i are unit columns. Both source statements are false relative to their respective linear image, and K_i is individually uniform given P_i. With one reused H=(h_1,h_2), published P_1=h_1 and P_2=h_2, yet K_1=h_2=P_2 and K_2=h_1=P_1. ALL protected capabilities are recovered from public projections without any ORIGINAL witness. Distinct native signing seeds do not prevent this failure: unlike Run 573 it exploits reuse of the HASH secret. Context labels in a downstream KDF cannot conceal an already recovered K_i. Independent hash secrets per UTXO/branch avoid this specific attack, but need independent setup/composition proofs.

## Attack surface, literature and boundaries

The attack covers seam cancellation, global frame synchronization via rank(B), related-capsule elimination, chosen public evaluation and checking-key correlations; malicious retained H only worsens it. Replays must be prevented by actual relation/claim/UTXO/branch binding, absent here. Statistical smoothness for targets outside Col(B) is exact, not heuristic. The break is classical PPT, hence also feasible for arbitrary QPT; no claim is made about the behavior of a real lattice SPHF against coherent attacks. The theorem assumes honest uniform H and contains no full-public native verification key, malicious N-of-N setup, or sign-only extraction. Run 259 source binding only applies after a complete accepted source representation, which this gadget does not produce.

Primary literature: Katz and Vaikuntanathan, Smooth Projective Hashing and Password-Based Authenticated Key Exchange from Lattices (Asiacrypt 2009), https://www.cs.toronto.edu/~vinodv/KV-PAKE.pdf, defines APPROXIMATE correctness on an honest ciphertext subset. Bettaieb et al., Post-Quantum OT from SPHFs with Grey Zone (2022), https://arxiv.org/pdf/2209.04149, explicitly has a third grey zone without correctness/smoothness guarantees. Benhamouda et al., Hash Proof Systems over Lattices Revisited (PKC 2018), https://eprint.iacr.org/2017/997, advertises a relaxed WE application in the abstract, but its full proof was not retrievable here (403). No exact theorem from that inaccessible section is asserted. None is shown to compile arbitrary Syscoin ORIGINAL-false statements entirely into a smooth class, enforce SAME capability for all ORIGINAL witnesses, or extract an ORIGINAL witness from an arbitrary native signature.

The exact executed Node checker exhausts 322,996 assertions on joint-projection conditional distributions plus two-false-capsule attacks. An independent longer Python checker passed 367,140 assertions. Neither implements encryption, LWE, SLH-DSA, a Bitcoin graph, or QPT security. Literature is architectural guidance, not an instantiation. The minimum next constructive task is a genuinely nonlinear source-authenticated projector for a restricted Syscoin evidence language with total false-instance coverage, independently scoped keys, and public checking-key-inclusive QPT source extraction. All practical 128-bit/ceremony/Bitcoin endpoint obligations remain UNPROVED. Stopping condition unmet; keep the PR draft/unmerged and automation enabled.
