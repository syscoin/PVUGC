# Generic ORIGINAL NAND-to-source compiler: exact completeness, failed false-source release

Research record: nand-original-kernel-20261028-turn11. Offline work only. On syscoin/PVUGC draft PR #1, research/pq-wkem-validation-20260918, starting head b002f8497fc809c9e168eec424c26407a57444a6. Exact predecessor: research/pq-wkem/half_orbit_projected_source_20261028/README.md, Git blob a9f1dc22e66b3516e2f2128232778520fff96f97. Latest substantive ordinary PR comment inspected: 6464632442. No web/literature research. **NO QUALIFIED POSITIVE GENERIC-NP WKEM ADVANCE**: an exact general-NP completeness compiler is instantiated, but its linear projected-source release is shown insecure on a fixed false ORIGINAL instance.

## 1. Concrete polynomial-time compiler, with ORIGINAL statement binding

For a polynomial-time uniform Boolean NAND verifier V(x,W), let P be the number of public input bits, T the private ORIGINAL witness input bits, G the NAND gates, and v=P+T+G the number of wires. The public x bits are fixed in explicit rows; the last wire is the accepting output. Each NAND gate uses only earlier wires as inputs. This represents any fixed polynomial-time NP verifier by a polynomial circuit encoding. The construction is not a special signature-only or random-kernel relation.

Choose a prime q>4, m=1+2v+4G, and introduce an anchor coordinate z_*=1, two one-hot Boolean coordinates u_i^0,u_i^1 per wire, and four Boolean coordinates t_g^00,t_g^01,t_g^10,t_g^11 per NAND gate g. Define a sparse public source matrix C_x by the following homogeneous rows, understood modulo q:

    u_i^0 + u_i^1 - z_* = 0                        each wire
    t_g^00 + t_g^01 + t_g^10 + t_g^11 - z_* = 0      each gate
    t_g^10 + t_g^11 - u_a^1 = 0                    gate input a
    t_g^01 + t_g^11 - u_b^1 = 0                    gate input b
    t_g^00 + t_g^01 + t_g^10 - u_c^1 = 0           gate NAND output c
    u_i^1 - x_i*z_* = 0                             every public statement input bit
    u_final^1 - z_* = 0                             actual verifier must accept

The row count is r=v+4G+P+1, source vector length m=1+2v+4G, and every accepted Boolean opening has Hamming weight h=1+v+G. All compiler operations and the witness-lifting algorithm are classical polynomial-time, with a sparse representation of C_x. Public x must include, in the actual NP verification relation, relation identity, claim/UTXO, challenge path, anchors and window, authorization/output rules, and native checking-key identity; the present executable checker uses only small abstract NAND predicates, not Bitcoin parsing.

For every valid ORIGINAL W, evaluate V(x,W) and create the anchored one-hot vector z=f_x(W) by setting the actual wire values and NAND truth-table positions. Then z is binary, C_x*z=0, z_*=1, and its weight is h. The different ORIGINAL witnesses remain different vectors; no canonical witness or common intermediate state is imposed.

Conversely, every accepted binary z with C_x*z=0, z_*=1, and weight h determines one wire value and one gate row per gate. Since at most four binary entries are summed, q>4 ensures that congruence to 1 forces ordinary integer sum 1. Input/output/gate rows enforce every real NAND relation and public bit. Thus extracting the T witness-input bits gives an ORIGINAL W for which V(x,W)=1. It is a bijection between accepted binary openings and accepted ORIGINAL witness bitstrings.

**Important boundary:** This establishes accepted representation -> ORIGINAL witness, not arbitrary recovered K/native forgery -> accepted representation or QPT break. An adversary need not volunteer a vector or invoke the honest off-chain Release.

## 2. Explicit source-dependent Build, off-chain Release and standard LWE challenge embedding

Set e=(1,0,...,0), source ternary noise eps_i uniform on {-1,0,1}, deterministic error radius E=h, digit spacing g0=2h+1, and radix b=floor(q/g0)>=2. Encode an arbitrary 256-bit Z into ell=ceil(256/log2(b)) radix-b columns. For clarity, q is a prime parameter chosen sufficiently large for the verifier size, not a certified concrete post-quantum hardness parameter.

Classical honest Build samples a uniformly random precommitted 256-bit native master signing seed K and genuine native verifying key pk=NativeKeyGen(K).pk, as a conditional native seed-based signature API. It samples independent uniform 256-bit U,Z and publishes D=U XOR Z and V=K XOR U, together with C_x, R, x, pk, context, auxiliary data and related capsules. For each digit a_j:

    A_j <- uniform F_q^(n x r),   s_j <- uniform F_q^n
    eta_j <- chi^r,               eps_j <- uniform {-1,0,1}^m
    y_j = A_j^T*s_j + eta_j        (HIDDEN)
    p_j = C_x^T*y_j + eps_j + g0*a_j*e   (PUBLIC, mod q)

The public source ciphertext is (A_j,p_j); do not publish y_j. Release(x,W) first validates the actual ORIGINAL verifier, builds z=f_x(W), then obtains

    z^T*p_j = g0*a_j + z^T*eps_j  mod q.

Since z has exactly h ones and eps_i are ternary, the centered noise is in [-h,h] for every draw. Cyclic centers 0,g0,...,(b-1)g0 have gaps at least 2h+1, including wraparound, so every valid ORIGINAL W deterministically decodes the SAME original a_j, Z, and finally K=V XOR D XOR Z. Each witness can have different projected errors; that does not affect the released capability.

For every fixed public source C_x, a standard decisional-LWE challenger supplying (A_j,y_j) can be embedded by publicly constructing p_j=C_x^T*y_j+eps_j+g0*a_j*e. The LWE branch exactly reproduces the real source-dependent capsule, while uniform y_j reproduces the corresponding intermediate hybrid. This is a straight-line challenge simulator without SourceOpen or the LWE secret; source, actual checking key, context, XOR shares and independent sibling capsules can be sampled with their real correlations while the reduction knows K. This algebraic embedding is **not** an all-false SOURCE hiding theorem and does not justify an eventual native-checking-key-only simulator on hard-true statements.

This candidate retains only the baseline classical-PPT Build/Eval assumption and allows arbitrary QPT postprocessing of the fully public classical output. No independent QPT hardness proof is supplied for the source-dependent residual, native signature, or multi-capsule setting. The checker uses a mock hash-based key equality check rather than actual SLH or native signing.

## 3. Exact fixed-false attack on the generic linear projected release

The short false ORIGINAL verifier has one witness input a and three NAND gates:

    n0 = NAND(a,a)       = NOT a
    n1 = NAND(a,n0)      = 1
    out = NAND(n1,n1)    = 0.

The ORIGINAL relation requires out=1. There are no valid ORIGINAL witnesses or accepted binary source openings. With q=257 the compiler has v=4,G=3,m=21,h=8,r=17. However, select the honest wire assignments for a=0 except set final output to 1. For each gate with Boolean wire input values A,B and chosen (possibly false) output value Y, the following signed truth-table entries satisfy ALL the linear rows:

    t00=2-A-B-Y,
    t01=B+Y-1,
    t10=A+Y-1,
    t11=1-Y.

The last invalid gate has t=(-1,1,1,0), while the others remain legal one-hot. This yields an **easily computable**, normalized integer pseudo-opening z_fake with C_x*z_fake=0, z_fake^T*e=1 and L1 norm h+2=10. It is not an ORIGINAL witness and the honest Release would reject it, but the attacker ignores Release and directly calculates the PUBLIC linear projection

    z_fake^T*p_j = g0*a_j + z_fake^T*eps_j.

The LWE component cancels identically, regardless of the choice of standard LWE parameters, secret s, or any coherent-QPT computational power. For q=257, h=8, g0=17, radix b=15 and ell=66, the projected noise is a sum of ten independent ternary variables (sign reversals preserve the distribution). Exact convolution counts:

    Pr[ |z_fake^T*eps_j| <= 8 ] = 59027/59049.

These digit events are independent across columns. The attacker therefore obtains the entire Z and the genuine target K=V XOR D XOR Z on the FALSE ORIGINAL instance with exact probability

    (59027/59049)^66 = 0.9757056468873536...

This is a classical false-source key-recovery attack, hence also a QPT attack. It violates the intended false-instance full-public security even though accepted ORIGINAL representation soundness is exact. Larger LWE parameters, ordinary LWE hybrids, or public basis changes do not stop this projection. The previous half-orbit theorem for its specific fixed false-source family is NOT invalidated: its kernel and noise distribution differ.

## 4. Reproducibility, conclusions and exact next missing equation

The self-contained check_pub.py, executed twice offline with byte-identical output_pub1.json and output_pub2.json, verifies 3,869 assertions: exhaustive accepted opening-to-ORIGINAL equality on the true and false small NAND circuits; three distinct ORIGINAL witnesses; 16 full 256-bit SAME-K legitimate release trials; the signed public false pseudo-opening; and the exact finite ternary attack probability. An additional extended local-only check.py passed 19,245 assertions per run and observed 63/64 complete secret-seed recoveries on independently generated false-source capsules (analytic success ~97.57%). These are algebraic and statistical tests only, not quantum-security experiments.

**No qualified positive security advance**. The generic-NP NAND opening compiler and its all-valid-witness correctness proof can be reused, but this attempt to combine it with the existing projected-source linear release FAILS even for a fixed false ORIGINAL relation. This illustrates the prior affine/low-degree closure test; it must not be treated as a repaired hard-true or false-source construction. In particular, do not replace the ORIGINAL relation with the easier kernel relation, and never claim that a supplied accepted representation gives an extractor for arbitrary recovered final K.

The next exact unsolved construction obligation is an efficient **global/nonlinear source release**, not a local linear one-hot mask, that simultaneously supports all valid ORIGINAL W with the identical bound K; a no-SourceOpen source-dependent QPT challenge simulator for the FULL joint statement/capsule/pk/context/aux/siblings output; false-instance key hiding for every x; and a straight-line or otherwise QPT-valid unauthorized hard-true native key-recovery/forgery reduction to ORIGINAL W or an independently justified PQ break **without requiring A to disclose any internal vector**. No such construction or proof is present.

Malicious N-of-N ceremony, abort/erasure, pre-signatures/DA, one-honest-watcher inclusion, BTC PoW best-chain versus AuxPoW, header and interval-tag verification, conditional no-EC-key-path native PQ endpoint, concrete 128-bit QPT parameters and native Bitcoin transaction-graph composition remain outside this local algebraic checkpoint. No production/deployment claim.

**Authority/provenance:** All additions restricted to research/pq-wkem/nand_original_source_checkpoint_20261028/ on actual PR #1 branch, with a separate ordinary PR comment only if commit succeeds and verifies; no main/workflows, reviews, approvals, merges or force pushes.
