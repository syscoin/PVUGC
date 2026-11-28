# Run 567 — SIS-folded source binding does not preserve false-instance emptiness

Research-only checkpoint from draft syscoin/PVUGC#1, starting head `f2cdd54649131a180de77c4b3e434ac6614cef2d`, branch `research/pq-wkem-validation-20260918`. Exact dependencies checked at this head: Run 259 `GLOBAL_FINGERPRINT_SOURCE_BINDING_RUN259.md` blob `c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2`; Run 566 `RUN566_AFFINE_HYPERPLANE_BARRIER.md` blob `7e21c5fbb9d7a872b91a9415da52d15e60f2efa7`. Latest ordinary substantive PR comment at start: 6067040320.

## Scope and new application

Run 259's short-SIS residual compression establishes **computational binding**: efficiently generating a complete invalid folded-accepted source representation directly yields a short SIS solution. It does not establish that **no such representation exists**. A small explicit ORIGINAL relation demonstrates that ordinary witness encryption instantiated for the folded NP language does **not** inherit false-instance hiding for the ORIGINAL language. This is a language-composition failure, NOT a cryptanalytic SIS break or a new primitive.

## Exact relation

Let q be prime and let A be a uniform public n-by-L matrix over F_q. Encode binary vectors in F_q^L. Define ORIGINAL relation R(b,z)=[b=1 and z=0^L], with b a public bit and z in {0,1}^L. Define a public complete-source residual:
- rho_b(z)=z when z != 0;
- rho_1(0)=0;
- rho_0(0)=e_1.

Therefore rho_b(z)=0 iff R(b,z)=1. The public ORIGINAL extractor from any zero-residual complete representation simply returns z. For b=0 the ORIGINAL instance is false, yet the residual image contains **every nonzero binary vector**. Let FoldAccept(A,b,z)=[A rho_b(z)=0]. The folded language is L_fold={(A,b): exists z FoldAccept(A,b,z)}.

An accepted invalid z yields e=rho_b(z) in {0,1}^L\{0}, Ae=0, ||e||_2 <= sqrt(L). This is precisely a straight-line reduction to the exact ordinary SIS distribution assumed hard in Run 259. No proof of SIS hardness at any parameters is made here.

## Theorem 1 — pairwise-independent binary-kernel census

Put M=2^L-1, X_A=#{e in {0,1}^L\{0}:Ae=0} and mu=M/q^n. For uniform A,

E[X_A]=mu, Var(X_A)=mu(1-q^{-n}).

Proof: Each nonzero binary e has Pr[Ae=0]=q^{-n}. Distinct nonzero binary vectors are linearly independent over F_q: a nonzero scalar multiple remaining binary must use scalar 1 and be identical. Hence their kernel indicators are pairwise independent. Their sum has the claimed moments. Chebyshev gives Pr[X_A=0] <= q^n/(2^L-1). If 2^L-1 >= 2^kappa q^n, then with probability at least 1-2^{-kappa} the false ORIGINAL statement b=0 is nevertheless **true in L_fold**.

These are existence probabilities over honest classical-PPT setup. They do not grant a QPT algorithm an efficiently found SIS vector.

## Theorem 2 — a deterministic zero-sum threshold

If L>n(q-1), then for **every** A there is a nonzero binary e with Ae=0, so L_fold contains every (A,0). Proof (Chevalley–Warning): introduce u_1,...,u_L in F_q, and F_i(u)=sum_j A_ij u_j^(q-1), i=1,...,n. The all-zero u solves all F_i=0. The number N of common zeros modulo q equals sum_{u in F_q^L} product_i (1-F_i(u)^(q-1)). The polynomial in the summand has degree <=n(q-1)^2<L(q-1). Every monomial of degree less than L(q-1) has some variable of exponent less than q-1, so its full field sum vanishes modulo q. Thus N=0 mod q. Since u=0 is one solution, another nonzero solution exists; e_j=u_j^(q-1) is nonzero binary and Ae=0. QED.

This classical theorem does **not** furnish an efficient general algorithm for finding e. The deterministic threshold is a sufficient bound, often far larger than the typical-existence threshold L ~ n log_2(q). Literature attribution: Chevalley–Warning is classical; see Clark–Genao–Saia (2021), https://doi.org/10.1016/j.exmath.2021.03.005, Theorem 1.1.

## Security consequence

For b=0 there is no ORIGINAL witness. But when X_A>0, (A,0) is a *satisfiable folded-language instance*. Standard WE false-instance IND for L_fold has **no hiding conclusion at this input**, even if recovering an invalid accepted z would violate QPT-SIS. Existence and efficient findability are different quantifiers. Run 259's **computational** source binding cannot silently replace Run 259's alternative **information-theoretic** sufficiently-high-codimension binding in a reduction that needs mathematically unsatisfiable false instances.

This refutes only the composition: computational-SIS source binding -> regard FoldAccept as an ordinary NP language -> use ordinary false-instance WE-IND on that folded language to claim false-ORIGINAL hiding. A different construction with a directly proven hard-to-find-witness hiding game might survive; it must not simply assume the desired WKEM or generic WE as a new "local mixer."

## Quantum query interface and attacks

The predicate Ae=0 is public and can be evaluated coherently by arbitrary QPT attackers. When mu is large, Pr[X_A<mu/2] <=4/mu. On its complement, Grover/amplitude amplification finds a nonzero binary kernel vector in O(sqrt(2^L/mu))=O(q^(n/2)) coherent evaluations, generally exponential rather than QPT. This is neither a QPT SIS break nor a 128-bit estimate for any actual parameter set.

Attack taxonomy: no local seam, gauge recovery or statistical-fingerprint attack is needed; the flaw is existential language drift caused by public source folding. A classical attacker that **does** produce an accepted invalid representation still solves SIS straight-line. Multi-capsule/auxiliary-key correlation, retained malicious setup secrets, source-relation replay and a real native signing verification key are not protected by this toy reduction. These omissions cannot repair an invalid false-instance WE premise. Witness privacy is not required.

## Reproduction, scope and core handoff

The independent finite Python checker was executed locally on 13 grids, with 263,603 assertions and 87,453 matrices, and independently spotchecked. The exact **committed JavaScript checker** performs an exhaustive integer second-moment census, checks all deterministic-threshold grids and binary-vector independence, and produces the committed machine-readable output. Finite checks do not prove security or either theorem.

Run 259 remains valuable once a **complete accepted source representation is actually obtained**. It does not supply either the secret release or a key-recovery-to-accepted-representation extractor. Future constructions must prove false-instance hiding under the **ORIGINAL** relation and arbitrary QPT public-output/auxiliary access, as well as unauthorized true-instance recovery/native-signature forgery -> ORIGINAL evidence or an independent QPT break. No safe practical local mixer, malicious N-of-N setup/erasure, multi-capsule proof, 128-bit parameters, or conditional Bitcoin P2MR/SLH deployment is established. All-valid-ORIGINAL-witness SAME-key off-chain release remains unimplemented. Production unchanged; PR draft/unmerged; stopping criterion unmet.
