# Exact row-shift SOURCE release: a public decision algorithm obstruction

**2026-10-27 | offline continuation of PR #1 | status: NO qualified constructive WKEM advance.**

## Prior exact component and bounded repair tested

The latest PR head inspected before this calculation was `61d884952ff29eb3c9dde06f657885116ced69de`. The exact-version file `research/pq-wkem/even_mod_refutation_20261027/check.js` establishes a concrete 4-XOR parity SOURCE where a degree-four moment matrix has an integer certificate `M_false^T c = 2 e_anchor`. Choosing even q and even g, or an odd prime field and dividing 2, gives a direct shift of uniform SOURCE opening randomness. That *correctly* yields exact public ciphertext equality in this particular false instance. This note examines the **generic-NP extension** of that mechanism, rather than the independent, uniform-random-B transverse-LWE reference.

Fix a public statement `x`, a source-dependent, polynomial-time computable matrix `M_x ∈ F_q^{r×n}`, a designated anchor vector `e ∈ F_q^n`, and `0≠g∈F_q`. Consider the proposed release for digit `t`:

    p_t = M_x^T u + ε + g t e,
    u <- uniform F_q^r,
    ε <- χ^n, independent of t,u.

For a valid **ORIGINAL** witness `W`, the public opening computes a vector `z_x(W)` with

    M_x z_x(W)=0,        e^T z_x(W)=1,
    z_x(W)^T p_t = gt+z_x(W)^T ε.

The intended same-capability release then decodes a single protected pad `Z`, and recovers one **precommitted** native signing key `K` using a shared native verification key `pk(K)`. Different accepted witnesses can use different `z_x(W)`; they always aim at the same pad/key. This algebra alone does not establish ORIGINAL witness extraction from final key recovery.

The attempted **exact false-SOURCE repair** is to construct `M_x` such that *whenever x is false*, there is a public row coefficient `c_x` with

    M_x^T c_x = g e.                 (SHIFT)

Then `u' = u+t c_x` is uniform and satisfies `M_x^T u'+ε = p_t` pointwise. Because this coupling preserves the whole vector p, it preserves any independent context, bound `pk(K)`, and unrelated auxiliary data. For multiple independently randomized capsules, apply the shift separately to each column. In the predecessor two-share construction, choose independent uniform `U,Z ∈ {0,1}^k`, let `D=U XOR Z`, `V=K XOR U`, and let `t_j` be the (possibly correlated) radix digits of Z. After the columnwise shifts `u'_j=u_j+t_j c_x`, the whole `p` array is independent of `(U,Z,K)` conditional on M and source-independent error sampling. Conditional on fixed K and its **real native** `pk(K)`, `(D,V)` is exactly a uniform independent pair. Hence `(p,D,V,pk(K))` admits an **exact** joint null coupling for this false source; independent related capsules and contexts may be included. However, side information revealing or correlating with the target's `U`, `Z` or `u_j` is NOT covered by this coupling, and arbitrary auxiliary-input security is still missing. (SHIFT) is **a sufficient** simulator, not the only way to achieve computational or statistical hiding.

## New necessary-condition theorem: universal exact shift implies SAT in P

**Theorem.** Suppose a deterministic classical polynomial-time SOURCE compiler maps every 3CNF statement `x` to `(M_x,e_x,g_x)` over efficiently representable finite fields, with `g_x ≠ 0`, and simultaneously satisfies:

1. **ORIGINAL completeness:** for every satisfiable `x` and every ORIGINAL valid witness `W`, a `z_x(W)` exists with `M_x z_x(W)=0` and `e_x^T z_x(W)=1`;
2. **Universal exact false shift:** for every unsatisfiable `x`, `g_x e_x∈im(M_x^T)`.

Then 3SAT lies in P. If the randomized compiler satisfies the premises with sufficiently high success probability per statement, the same membership test gives a randomized polynomial-time decision procedure under the corresponding completeness/soundness error bounds.

**Proof.** On input x, compute the public source and test via Gaussian elimination whether `g_x e_x` belongs to the column span of `M_x^T`. If x is false, membership holds by premise 2. If x is true, choose any ORIGINAL W and its normalized z from premise 1. Membership would supply `c` with `M_x^T c=g_x e_x`, whence

    0 = (M_x z)^T c = z^T M_x^T c = g_x e_x^T z = g_x ≠ 0,

an impossibility. Therefore the public polynomial-time test decides 3SAT correctly. QED.

This is an **unconditional implication**, not a proof that P differs from NP. It rules out using a universal, efficiently checkable exact row-span SHIFT certificate as a black-box substitute for missing SOURCE security unless that consequence is accepted. It does **not** rule out computational-QPT false hiding when SHIFT is false, hidden or unavailable, nor noisy/approximate simulation, nor hard instances whose row-space membership is not the soundness criterion. Over `Z/2^k`, membership can be tested via modular linear algebra/Smith form; the field statement above avoids torsion ambiguities. In particular, `2a=0 (mod 2^k)` must not be divided by two.

## Exact finite check (not hardness evidence)

`check.py`, pure Python standard library, constructs all 57 degree-≤4 parity moments on six variables and the 200 product equations for each of four triples `S=(7,25,42,52)`. For signs `(1,1,1,1)` it verifies eight distinct ORIGINAL satisfying witnesses, rank 49 and absence of anchor in the source row span. For `(1,1,1,-1)` it verifies zero ORIGINAL witnesses, rank 57 and membership of anchor in row span over `F_101`. It builds and validates the four-row **integer** certificate yielding `2 e_anchor`, then converts it to a `g e_anchor` shift in `F_101` using the inverse of 2.

The checker exhausts all 16 parity sign systems and checks that public row-span membership agrees exactly with ORIGINAL truth. It also verifies 120 seeded pointwise real/null ciphertext couplings with actual independent error vectors; a fixed arbitrary checking key and auxiliary data do not change this pointwise equality. Two executions produced exactly identical captured output: **1,766 finite assertions per execution**. This is neither a QPT hardness test nor a general-NP sampler.

## Repair assessed, outcome, and handoff

A degree-four parity closure with a false row certificate **does** instantiate exact false-source simulation for this special XOR family. But universalizing that *same kind of exact row shift* to arbitrary 3SAT would make decision public and polynomial, as above. Worse, the previous degree-three SOURCE has concrete short false-statement openings; degree lifts do not automatically close every such direction. No full-joint ordinary-QPT-LWE simulator exists here for the structured SOURCE `M_x`, and arbitrary final native-key recovery/native forgery is NOT reduced to any ORIGINAL witness or independent QPT break. A native signing key and checking-key correlations do not fill this reduction.

The next precise construction obligation must **depart from universal exact shift** while retaining same precommitted `K` for every valid ORIGINAL W:

    (A) for every valid W, Dec(x,C,W) = K except negligible setup/decoder failure;
    (B) real [x,C,pk(K),ctx,aux,related capsules]
        ≈_QPT sim [x,C_null,pk(K),ctx,aux,related capsules]
        jointly for all false x, without a SOURCE-secret oracle;
    (C) Pr[A outputs K or native forges]
        ≤ Adv_independent_QPT(B) + Pr[Ext^A outputs ORIGINAL W] + negl,

where Ext is concrete, works with arbitrary coherent QPT A and its advice, and never requires A to give a representation. For true instances that are hard to witness, (B) cannot be justified merely by assuming the public source is uniform-LWE: the current `M_x` is structured and its public row space is explicitly testable. The earlier pivot-SL2 supplied-representation result and independently sampled uniform-B reference remain separately conditional/restricted.

Other required work—generic NP polynomial honest cost, QPT Bitcoin work bound with authenticated fork/tag semantics, malicious N-of-N graph/abort/pre-signature and availability proofs, and native PQ Bitcoin endpoint—is unchanged. There is no claimed 128-bit parameterization or deployment. This is a **diagnostic no-go implication**, not constructive WKEM success.
