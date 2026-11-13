## Material security qualification / R149 equivalence — REJECTED as a security advance

This source is **NOT a surviving construction and NOT positive progress toward generic-NP WKEM security**. Its exact ordinary-LWE joint simulator below is mathematically correct but is security-neutral: when the challenge g is replaced with uniform, (B,p)=(T_x^T g+e,b_x^T g+ΔK+eta) is IDENTICAL in law to the ALREADY REJECTED R149 structured scalar-source (c,p) obtained by choosing its source secret s uniformly over F_q^t. The extra public A in this hybrid is independent and changes nothing. Ordinary decisional QPT-LWE shows the real R152 distribution is computationally indistinguishable from this rejected uniform-source distribution (under precisely the independently simulatable auxiliary restrictions stated below). Every efficient R149 public rational/denominator projector attack therefore applies to R152 REAL whenever the corresponding q,Δ,noise and denominator-distance conditions hold, with at most the ordinary LWE distinguishing advantage loss. It is not a new safe source or a fix to R149. This must remain an INTERNAL negative/equivalence checkpoint, not a user notification milestone.

The Fourier law below precisely characterizes the uniform-g SOURCE's remaining leakage and the finite checker confirms an explicit FALSE shortness failure (TV=11/27). Neither an LWE generator wrapper nor a joint simulator alone supplies generic SOURCE soundness, hard-TRUE extraction or native-security composition. Do NOT further optimize, extend or market this rejected affine family absent a fundamentally different non-affine ORIGINAL-dependent correlation.

# R152: quotient-compatible ordinary-LWE joint source — partial construction, NOT a generic WKEM

STATUS: The joint source-dependent LWE sampling and a straight-line challenge simulator are instantiated for arbitrary *public affine* relation representations. This is a bona fide security-foundation component, but generic ORIGINAL-NP representation soundness, false-instance hiding, arbitrary hard-TRUE extraction, malicious setup, native composition and security parameters remain UNSOLVED. No efficiency work. Offline derivation only; no external research.

Continuity: syscoin/PVUGC#1 open/draft/unmerged, branch research/pq-wkem-validation-20260918, starting head 8ade0f3ea429975305fab931c2268e5494aab8f1. Read R151 blob ad44ac4889410f858f839765616086201c72ff3c, R150 blob 1c747a7984339bc001e11a151fcb2f3d54875476, R149 blob a898438d6b223c5bcdd60acaa696a1f0703116a9, R147 blob 669cdee1514b5490071759379aba42a25717c7ed. Latest substantive ordinary PR comment 6698876958. This does not restart the rejected exposed-coefficient ideal-mask or rational-projector models.

## Explicit candidate

Choose odd prime q and polynomial n,t,m. A still-MISSING public classical-PPT compiler for arbitrary ORIGINAL NP (R,x) must output T_x ∈ F_q^(t×m), b_x ∈ F_q^t and a classical-PPT representation Rep(x,w) ∈ Z^m, with T_x Rep(x,w)=b_x mod q for EVERY ORIGINAL-valid witness, and a uniform bound ||Rep(x,w)||_1≤L. x must contain the ORIGINAL relation identity, real claim/UTXO, branch/challenge path, anchors/window, context and native VK/capability binding. Distinct valid witnesses can generate distinct representation vectors. Neither this compiler nor an accepted-representation-to-ORIGINAL extractor is constructed here.

The ACTUAL source sampler draws A uniform F_q^(n×t), s uniform F_q^n, epsilon←chi^t, and g=A^T s+epsilon mod q: ordinary scalar decisional LWE. Independently sample e←xi^m, eta←zeta and a uniformly chosen capability bit K. Publish A,T_x,b_x and the CORRELATED pair

    B=T_x^T g+e,     p=b_x^T g + Δ K + eta (mod q).

No SourceOpen oracle is needed. Off-chain Open first verifies the ACTUAL ORIGINAL relation R(x,w), obtains v=Rep(x,w), and computes

    p-v^T B = ΔK+eta-v^T e (mod q).

For supported error magnitudes |eta|≤β and |e_i|≤E_i, the circular distance d_q(0,Δ)>2(β+sum_i E_i|v_i|) for every valid v gives perfect all-witness SAME-K correctness. For a frozen intended native signature σ, repeat with independent K_i per native signature bit and publicly provide D_i=σ_i XOR K_i. This is a source/capability wiring sketch, not an accepted native signature security reduction, setup protocol, deployment or Bitcoin opcode claim. Bitcoin executes no original NP verification.

## Exact QPT-LWE challenge simulator — instantiated, no hidden correlated source oracle

Given ONE ordinary scalar decisional-LWE challenge (A,g), either honest g=A^T s+epsilon or independent uniform g, a straight-line classical reduction samples the real e,eta and makes the ACTUAL full correlated outputs B=T_x^Tg+e and p=b_x^Tg+ΔK+eta. It never needs the challenge s, epsilon, a source-opening key or an ORIGINAL witness. Any public CK/J/Aux/context computed via a specified PPT function of the ACTUAL bytes and independent sampled coins can be recomputed from that same challenge; independently sampled native signer/VK and frozen native signature are simulatable when the hybrid reduction chooses K and σ. Related capsules whose g' is independently sampled are generated honestly; shared-g related outputs must be built from the SAME challenge g. Classical adaptive off-chain Open of supplied original witnesses is public computation. Disclosure of the target challenge s/epsilon or secret-dependent CK/Aux without independent simulation is NOT covered.

Thus for EACH fixed known K, a nonuniform arbitrary-QPT distinguisher (including independently permitted quantum advice) between the real and uniform-g FULL PUBLIC VIEW gives a straight-line decisional-QPT-LWE distinguisher of the same advantage. Independent challenge vectors can be replaced by sequential hybrids; there is no rewinding or classical-to-QPT lift. This is a real joint challenge simulator unlike R149's unembedded structured matrix or R151's independent ciphertext/proof-gate. It does NOT yet imply source false hiding or hard-TRUE security.

## Exact source-side remaining spectral condition

For uniform g and independent errors e,eta, write ω=exp(2πi/q), φ_e(a)=E[ω^(a·e)], φ_eta(v)=E[ω^(v eta)]. For all a∈F_q^m and v∈F_q, the EXACT FULL JOINT Fourier character is

    E[ω^(a·B+v p)] = 1[T_x a+b_x v=0] φ_e(a) φ_eta(v) ω^(vΔK).

Proof: averaging ω^(g·(T_x a+b_x v)) over independent uniform g cancels every nonzero frequency. Therefore by Parseval/Cauchy–Schwarz, the uniform-g K0,K1 total variation is bounded by

    TV(D0,D1) ≤ 1/2 sqrt( SUM_{a,v: T_x a+b_x v=0}
                     |φ_e(a)|² |φ_eta(v)|² |1-ω^(vΔ(K1-K0))|² ).

This is a mathematically exact reduction of the *sufficient statistical false-hiding test* to ALL joint dual characters. No negligible spectral bound is proven. Missing all short ORIGINAL witnesses does not imply such damping; R149's denominator-clearing and R138's pseudowitnesses remain mandatory adversarial tests.

## Executed bounded offline checker and decisive toy controls

The separately committed checker.py was actually executed with CPython standard library. It passed 20,172 assertions: exact common-K nearest decoding for two distinct witnesses and all bounded supported error tapes; exact transformation of actual scalar-LWE g into BOTH source outputs without source secrets; complete finite Fourier character identity for all characters in three q=11,m=2,t=1 examples; exact rational uniform-g K-distribution total variation.

Parameters q=11, Δ=5, e_i and eta uniform on {-1,0,1}:
- two_witness_true T=[1,1], b=1, v=(1,0)/(0,1): perfect supported-error correctness, TV(K0,K1)=1 (expected for publicly known satisfying witnesses).
- unreachable_false T=[0,0], b=1: no modular representation; uniform-g TV=0 exactly (only toy easy false).
- short_representations_false T=[1,1], b=5: NO v of ℓ1 norm≤1, yet uniform-g TV=11/27: false hiding may fail even without short witnesses.
Full checker source and captured output are attached. This is NOT a QPT hardness experiment or a generic-NP compiler.

## Next exact obligation

Construct, or prove unattainable in this architecture, a classical-PPT ORIGINAL-NP→(T_x,b_x,Rep) satisfying all-witness SAME-capability and a negligible full-dual-spectrum uniform-g hiding bound on EVERY false instance. Further prove arbitrary unauthorized QPT true-instance recovery/native forgery→an ACTUAL ORIGINAL witness or independent justified QPT break without volunteered representations. The native signing/checking key correlations, malicious N-of-N preauthorization/abort/DA, source SYS/BTC ancestry/PoW/fork/censorship assumptions and conditional no-EC-path native PQ endpoint remain separate unresolved requirements. Do NOT optimize this component or call it secure.

Local full derivation SHA256 4e23a7f96ac36fd8fc418c404d2c90a59b5e6d00962544ab89c93d6f2d6b42cf. No independent agent was invoked.
