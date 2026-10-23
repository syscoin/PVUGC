# Sampled off-domain Frobenius-QAP: a statistically sound, smaller SOURCE carrier

**Checkpoint:** sampled-frobenius-qap-20261023. **Status:** one proved compiler/efficiency improvement, NOT a PQ witness-KEM security construction. Do not use these matrix capsules to authorize funds.

## Dependency and delta

Continue "syscoin/PVUGC#1", draft branch "research/pq-wkem-validation-20260918", from the live checked checkpoint "9d662e07c8031135db8d0c797a1d89e59e722e05" (Frobenius-quotient QAP). Its full proof's blob SHA1 was "90853783859418ef4fc42da70832f270d638bbf0"; exact code "frobenius_qap.py" was blob "d5b35ae77076e0e6bbf927a41b819130ac84fead", SHA256 "6da9e9519c1f9b21d00b736679ba498cb56a7518e9610abc7934ec3aacf66d9a". That version used **L=2m-1** deterministic off-domain tests to force a polynomial identity and thus projective soundness. Its all-witness K-eigenvalue correctness and supplied-source extractor were already proved; arbitrary public-operator QPT security was NOT.

**New delta:** keep the first **m-1** off-domain tests deterministic and choose only **r further distinct tests uniformly at random** after the entire ORIGINAL relation and context have been fixed. Use the *same* Frobenius-quotient coefficient forms, four-by-four alternating rank gate, independent two-sided outer factors and spectral recovery. With an exact setup-failure bound, the new gate count **L=m-1+r** may be strictly smaller than 2m-1, without adding variables or changing the release-interface semantics. This is an honest-setup statistical soundness substitution for the former perfect polynomial-identity condition, not a QPT hiding claim or a change in adversary computation power.

## 1. Setup / Build and original-source contract

Let F=GF(q), q=2^kappa, with a fixed irreducible modulus, and let a complete Boolean R1CS have m>=2 homogeneous rows and n free original coordinates: r_i(z)=(A_i z)(B_i z)+z0(C_i z), z in F^(n+1). Explicit rows "z_j^2=z0*z_j" for every free coordinate guarantee that every nonzero projective ORIGINAL solution has z0!=0 and hence its normalized free wires are Boolean. This is a checkable sufficient prerequisite. The relation includes the actual claimed context, input binding and acceptance conditions; example fixtures here are not Syscoin grammar. An arbitrary odd-prime-field program cannot be ported to GF(2^kappa) without preserving its Boolean/arithmetic semantics.

Build interpolates A_z(T), B_z(T), C_z(T), each of degree<m, on fixed distinct gate nodes t_1,...,t_m; write Z(T)=prod_i(T-t_i). Fix **m-1 public base nodes** u_1,...,u_(m-1), all distinct from t_i. Once the COMPLETE R1CS and claim/branch/UTXO/context are bound, choose r further distinct nodes e_1,...,e_r uniformly without replacement from F excluding the gate and base nodes. They are PUBLIC, not secret. The honest sampler can use uniformly random kappa-bit draws with rejection; real setup needs a CSPRNG/coin-tossed randomness. The reference code's Python "random.Random" is for deterministic reproducibility only. Require q>=2m-1+r, preferably ample slack for practical sampling.

Define the Frobenius quotient H_rho(T)=sum_(j=0)^(m-2) rho_j^2*T^j, and at every L=m-1+r node v impose

    A_z(v)*B_z(v) + z0*C_z(v) + Z(v)*H_rho(v) = 0.    (1)

Write S_v(rho)=sum_j sqrt(Z(v)*v^j)*rho_j; then (1) has the five-linear-form equation ab+dc+s^2=0. Exactly reuse predecessor gate

    P(a,b,c,d,s) = [[0,a,d,s],[a,0,s,c],[d,s,0,b],[s,c,b,0]],
    det(P) = (ab+dc+s^2)^2.

Choose independent honest outer L_v in F^(N x 4), R_v in F^(4 x N), N=2L+1. Set M(y)=sum_v L_v P_v(y) R_v, where y=(z,rho) has k=n+m coordinates. Publish all k coefficient matrices of the affine/public operator C(y)=M(y)+z0*K*I_N; also publish q, public node sequence, full relation/context, intended native checking key, and any justified selector material. Only the honest erasure-based N-of-N setup is contemplated; malicious/abort-secure setup and keyless retained-coin security are NOT established. None of the secret outer factors or the key may be included in the public package.

**Encode(w):** construct full normalized valid z=(1,w). Perform polynomial division of A_z B_z+C_z by Z; remainder=0 and unique quotient degree<=m-2. Set each rho_j to the unique field square root of its quotient coefficient. This is the SAME encoding as the predecessor. Every valid ORIGINAL witness has its own accepted y; no common witness state or preimage is imposed.

**Recover(w):** evaluate public C(y) and apply the predecessor field-eigenvalue decoder with the scoped public checking-key selector. Since every valid gate has rank exactly 2, rank M(y)<=2L<N, so **the same K is an eigenvalue** for every accepted ORIGINAL witness. The demonstration uses public field roots and a synthetic context-bound tag, not an actual native Bitcoin signing key.

**SuppliedSourceExtract(y):** check all L source equations; on the "GoodNodes" setup event proved below, every nonzero accepted y has z0!=0. Normalize by z0 and return the accepted ORIGINAL assignment via the existing source extractor. This does NOT extract a source from an arbitrary bare recovered K or native forgery.

## 2. Exact global statistical soundness proof

Let E(T)=prod_(j=1)^(m-1)(T-u_j). For any fixed nonzero ORIGINAL projective source vector z, the first m-1 constraints determine **exactly one** quotient polynomial H_z of degree<=m-2: evaluate H_z(u_j)=(A_z(u_j)B_z(u_j)+z0*C_z(u_j))/Z(u_j), and interpolate. Squaring is a bijection on GF(2^kappa), so the corresponding rho is also unique. This is true even for an invalid z.

Let F_z(T)=A_z(T)B_z(T)+z0*C_z(T)+Z(T)H_z(T). We know deg F_z<=2m-2, and F_z(u_j)=0 for all m-1 base nodes. Therefore E divides F_z, with quotient

    P_z(T)=F_z(T)/E(T),     deg P_z<=m-1.              (2)

At each ORIGINAL gate node t_i, Z(t_i)=0 and E(t_i)!=0, so

    P_z(t_i) = r_i(z)/E(t_i).                           (3)

Thus P_z is **exactly the degree-<m interpolant of the ORIGINAL residuals rescaled at the fixed gate nodes**. It is identically zero iff all ORIGINAL R1CS rows hold. This establishes an explicit global residual-binding identity rather than merely asserting that random tests are independent.

For every invalid projective z, P_z is nonzero of degree<=m-1. The r sampled tail nodes, chosen *after* fixing the source and distinct from gate/base nodes, must all be zeros of this one nonzero polynomial if an extended SOURCE is to be accepted. Sequential uniform sampling without replacement gives

    Pr[all r tail tests accept this invalid z]
      <= product_(j=1)^r (m-1)/(q-2m+2-j).           (4)

There are exactly (q^(n+1)-1)/(q-1) nonzero projective z classes. A union bound yields

    eps_nodes <= min{ 1,
      ((q^(n+1)-1)/(q-1)) * product_(j=1)^r
                    ((m-1)/(q-2m+2-j)) }.            (5)

This bound is **independent of the attacker's computations, auxiliary data and whether it examines the public nodes adaptively**, for a fixed, honestly committed SOURCE sampled before the tail nodes. On the complementary setup event, EVERY extended nonzero accepted y projects to an ORIGINAL projective solution. Explicit Booleanity rules out a nonzero ORIGINAL solution at z0=0. The remaining case z=0,rho!=0 is **deterministically impossible** already after the m-1 base tests, since Z(u_j)!=0 and a degree<=m-2 polynomial H_rho cannot have m-1 distinct roots. Consequently, on the same event all nonzero accepted y normalize to an ORIGINAL witness. Conversely, every true original z has the unique true quotient making F_z identically zero, so is accepted for EVERY node sample. QED.

The bound is per **fixed complete relation** with independent honest node sampling. When adaptively chosen new statements are permitted, each statement must be committed before fresh nodes are sampled. For polynomially many capsules, a union bound on their per-capsule eps applies under fresh sampling; correlations of native keys, actual ciphertext hiding and joint QPT attacks remain wholly unproved. A malicious setup participant choosing the nodes after seeing the relation can intentionally defeat (5); an N-of-N coin-toss and abort/security proof remains missing. The statistical theorem contains no classical rewinding, QROM, extraction oracle or computational assumption.

## 3. Preserved coefficient-direction support

For any nonzero coefficient direction eta in F^(n+m), the predecessor's exact argument applies to any L distinct nodes. If eta0!=0, the d-form is nonzero in all gates. Otherwise if any original wire direction is nonzero, explicit Booleanity rows guarantee A or B is a nonzero polynomial of degree<=m-1, hence at least L-m+1=r gates have a nonzero tuple. A quotient-only direction has a nonzero S polynomial of degree<=m-2 at at least r+1 gates. Every nonzero four-by-four alternating tuple has rank>=2. Thus the block diagonal source rank is at least 2r for **every** nonzero eta.

Conditioned on nodes, the earlier independent full-uniform outer-factor projection lemma gives, for integer a>=0,

    Pr[exists eta!=0: rank(sum_v L_v P_v(eta) R_v)<2r-2a]
      <= min(1,8*(q^(n+m)-1)*q^(-(a+1)^2)).

This property is only about SOURCE-direction rank, not a hardness assumption for arbitrary matrix processing or private-key hiding. The auxiliary node-good event and this outer-factor event can be union-bounded. Neither alone nor together proves the full release security game.

## 4. Actual efficiency and honest setup parameters

The old certificate used L_old=2m-1, N_old=4m-1, and (n+m)*N_old^2 field elements. The new source uses L_new=m-1+r, N_new=2L_new+1, **the same number k=n+m of SOURCE coefficient matrices** and k*N_new^2 elements. The new sampling randomness is r public field elements; this is metadata, not secret factor seeds.

An **exact integer** evaluation of (5) for q=2^256, n=11,000, m=16,000 proves that **r=11,636** is the smallest r satisfying eps_nodes<=2^-128 under that specific union bound. At r=11,635 the exact integer inequality fails; at r=11,636 it holds. This is computed using integer products with no floating point estimate. Hence L drops from 31,999 to **27,635**, N from 63,999 to **55,271**, and the dense field-element payload from 110,588,544,027,000 to **82,481,852,907,000**, a **25.415553995%** reduction. The large payload is still roughly **2.64 petabytes at 32 bytes/field element** and therefore NOT practical. The 128-bit figure here is solely the compiler's sampled-source soundness error and says nothing about PQ key-hiding security.

A small GF(256) fixture with n=1, m=6, r=3 has L=8 rather than 11 and N=17 rather than 23. Its exact projective setup-failure upper bound is 6,425/2,905,308 (about 0.00221147), not a cryptographic parameter. The fixture's true source has two different original witnesses; the false source is contradictory.

## 5. Reproducibility

"sampled_qap.py" reuses the predecessor's **exact SHA256-pinned** "frobenius_qap.py" rather than copying or modifying it. "check_sampled.py" exercises the exact public compiler and source checker. Commands from "research/pq-wkem/sampled_frobenius_qap_20261023/":

    OPENBLAS_NUM_THREADS=1 python -m py_compile sampled_qap.py check_sampled.py
    OPENBLAS_NUM_THREADS=1 python check_sampled.py > rerun.json

The captured "validation.json" is from two executions with byte-identical JSON stdout (therefore only one file is committed). The current checkpoint passed **5,380 exact assertions**. It checked both true/false original-source sets exhaustively over all 257 nonzero projective classes for ten independent honest node samples per source, and compared the explicit residual interpolant P_z with compressed tail verification for selected source vectors. There were no invalid accepted classes in these bounded fixtures. This is not the proof; (2)-(5) provide the global result.

Six honest spectral recoveries used two distinct ORIGINAL witnesses and three independent setups, each yielding one same key through two different public evaluation matrices. The checker also verified exact integer inequalities at adjacent r=11,635 and 11,636 for the large hypothetical example. Every honest code/test path is classical. The toy table field restricts examples to <=GF(256), whereas the mathematical algorithm supports arbitrary binary extension fields with practical polynomial-basis field arithmetic.

## 6. Full-public-output adversary and next indispensable step

The user-facing PQ WKEM **remains unsolved**. The attacker's target view includes every coefficient matrix, source and sampled nodes, intended native verification key/public exact-selector material, any auxiliary input, multiple related capsules and statements, and coherent QPT processing of the public description. Recovering K or forging a native signature need not expose any accepted SOURCE. No computational assumption, hardness reduction, malicious setup/abort theorem, multi-capsule hiding proof, native-SLH deployment or Bitcoin covenant implementation is claimed.

The prior Run706 constant-mask and Run695 original unmasked sparse carriers remain broken in their exact scopes. The current binary-field alternating QAP carrier has a **different** full-public-output distribution and still requires analysis of public tensor decomposition, quotient-coordinate subpencils and global gauge/fingerprint attacks. Its algebraic normalizer and improved sampled soundness are reusable independently if this specific public carrier is replaced.

**Next missing implication**: for this exact full-public operator plus checking key, show arbitrary unauthorized key recovery or accepted native forgery -> a release-accepted representation satisfying the complete sampled SOURCE (on GoodNodes), or an independently motivated QPT hardness break. Only THEN does supplied-source extraction, and where its exact scope applies Run259 SOURCE binding, yield the ORIGINAL witness. The source-binding theorem does not itself establish ciphertext hiding.

No production files, workflow files, PR state or automation are to change in this checkpoint.
