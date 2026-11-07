# Shared-A minimum-width continuation (restricted SOURCE efficiency advance)

Status: positive efficiency improvement of the existing honestly generated dual-LWE SOURCE component, NOT an ORIGINAL NP witness-KEM, deployment, or concrete 128-bit QPT parameter certification.

Provenance: offline bounded research, 2026-10-30, automation turn 11, PR #1 research/pq-wkem-validation-20260918 starting head 783b0ff9b782eefe655593255613aa88cff99ad5. Selected exact predecessor research/pq-wkem/shared_A_target_separated_selective_open_20261030/RESEARCH.md at blob 352d3d352046641deb407e2334eb5749ed529343 and latest substantive comment 6525913412. No internet literature or whole-PR diff.

## Retained exact public distribution and release

For each signer h independently draw public A_h uniformly in F_q^(n x m). For each independent claim/path scope s draw U_hs uniformly in F_q^(n x L), Native.KeyGen to obtain a REAL (sk_hs, pk_hs), and for every related capsule j sample fresh r_hsj uniformly in F_q^n and independent chi^(m+L) errors eta, |eta_i|<=B. Publish A_h, U_hs, genuinely correlated pk_hs, full classical relation/statement/context/auxiliary, authenticated setup records, and related packets

    c_j=A_h^T r_j+eta_j[1:m] mod q,
    d_jl=U_hs,l^T r_j+eta_j[m+l]+g*a_l mod q,
    g=floor(q/2^ell),

where a_l are canonical ell-bit digits of the actual native sk. All U, native keys, r and errors are independent across claim scopes; A alone is reused per signer. Do NOT reuse target U or a native secret across claims. The target scope becomes opened if its key or its encryption coins are revealed. A corrupt signer may choose its own contributions, but the target signer A and U are honest uniform and independently authenticated in this restricted game.

SOURCE z_l is accepted only if z_l belongs to T_m={z in {-1,0,1}^m : ||z||_0=w} AND A_h z_l=U_hs,l for every l. A public offline Release computes nearest-center digits from d_jl-z_l^T c_j, reconstructs genuine sk, checks Native.PK(sk)=pk_hs, and signs the intended claim-scoped challenge using ordinary Native.Sign. For every distinct valid SOURCE opening,

    d_jl-z_l^T c_j = g*a_l + eta_j[m+l] - z_l^T eta_j[1:m].

Thus |error| <= B(w+1) regardless of z. Multiple valid SOURCE states recover the SAME precommitted capability. This is not a Lift from any ORIGINAL witness.

## Exact integer width calculation

Use the predecessor's illustrative, NOT security-calibrated q=16777213 prime, n=256, m_old=6800, w=2000, B=128, ell=5, L=52; C=100 independent scopes/signer, N=4 signers, J=2 related capsules, K=C*L=5200 side openings. The exact signed constant-weight alphabet cardinality is H_m=2^w*binomial(m,w). The joint PUBLIC PRE-DISCLOSURE statistical bound for K independently planted other-scope SOURCE openings sharing the same A is

    TV <= (K/2)*sqrt((q^n-1)/H_m).

Select the smallest m with the conservative exact-INTEGER sufficient condition

    H_m >= (K*K)*(2^258)*(q^n).       [1]

Condition [1] ensures TV <= 2^-130, two bits below the target 2^-128. The executed checker confirms m_new=4469 satisfies [1] while 4468 fails, using full integer binomial arithmetic. log2(H_4469/q^n)=283.049685175..., so the TV upper bound is approximately 2^-130.18054668. For uniform U and A, second-moment source-preimage existence followed by a K-target union bound gives P[at least one U lacks ANY SOURCE opening] <= K*q^n/H_m < 2^-270.705. Existence does NOT provide an efficient SourceOpen or ORIGINAL witness lift.

This is an exact width minimum for the FIXED q,n,w,K and statistical predicate [1], not an optimal LWE parameter set. With unchanged w and error support, g=floor(q/32)=524287, 2B(w+1)=512256<g and final circular gap q-31g=524316>512256: deterministic correct-release noise tolerance is exactly unchanged.

### Statistical and QPT justification

Over prime q, for every distinct signed z,z' the universal linear hash A*z has collision probability q^-n. It does NOT follow that A*z and A*z' are pairwise independent, because z'=-z can occur; only universality is needed. The collision/second-moment/Cauchy-Schwarz argument gives the single-column public leftover-hash statistical bound 1/2*sqrt((q^n-1)/H_m). Condition on A and telescope K independent planted side openings Z_i sampled uniformly in T_m, U_i=A*Z_i, then average over A to get the K bound. It applies to the PUBLIC pre-disclosure (A,U_i) joint distribution. AFTER a planted Z_i is disclosed, its complete joint law must be simulated explicitly (generate Z_i and U_i from A), not confused with arbitrary unknown ORIGINAL witness correlations. For a genuinely uniform target U, the preimage-count indicators over joint random (A,U) are pairwise independent even when z'=-z; their variance gives P[X=0]<=q^n/H_m.

The predecessor's independently stated assumption is decisional nonuniform-QPT LWE for uniform M_old=[A_old|U] in F_q^(n x (6800+L)), uniform r in F_q^n, errors chi^(6800+L), and independent uniform alternative V. It IMPLIES hardness at m_new=4469 without a stronger assumption: given an old challenge (M_old,V_old), DELETE 2331 A-column and corresponding V coordinates, RETAIN all L U columns. For each challenge world the projected distribution is EXACTLY the new ordinary-LWE or uniform world. A nonuniform coherent QPT distinguisher for new samples is therefore a distinguisher of identical advantage for old samples, with the same independent advice. No rewinding, classical security lift, SourceOpen oracle, or unexplained trapdoor.

The rest of the predecessor's full-public restricted hybrid is unchanged: genuinely correlated native pk, all independent other U/sk/capsules, simulated malicious other signers, authenticated context and arbitrary efficiently simulatable auxiliary inputs, adaptive COMPLETE disclosures of unrelated scopes, and J whole-vector target-capsule hybrids. The target's sk/r/eta and target SOURCE opening are never given. Quantum adversaries can measure the complete classical correlated view coherently with nonuniform quantum advice. No superposition signing/opening oracle is assumed. Unauthorized native signature/key recovery in the protected restricted SOURCE slot remains bounded by J*Adv_QPT-LWE plus genuine Native-EUF-CMA and setup-authentication advantages. Absolute 128-bit QPT LWE and Native-EUF-CMA resources remain uncalibrated and unproved.

## Concrete exact storage accounting

At 3 bytes/field element, N=4,C=100,J=2: old public SOURCE A+U=36,864,000 B; new A+U=29,703,168 B. Old encrypted vectors total 16,444,800 B; new total 10,850,400 B. Combined old=53,308,800 B and new=40,553,568 B: 23.9270665% reduction; m itself shrinks 34.2794118%. Native pk/signatures, original evidence, Bitcoin witnesses and authenticated context are excluded. L=52 is only a sizing illustration, not a claim about a particular deployed PQ signature key.

Exact offline Python check.py and captured OUTPUT.json accompany this note. The checker ran twice with 528 assertions and byte-identical outputs: full integer boundary/minimality/statistical/circular-decoding checks, exhaustive 405-outcome small-LWE coordinate-projection regression, two distinct signed SOURCE openings decoding the SAME secret under fresh packets, and a deliberate cross-claim reuse leak regression. These finite checks are NOT QPT hardness experiments.

## Unsolved original obligations

There remains NO classical-PPT witness-free Comp(R_original,x,claim,context,pk), usable public Lift(ORIGINAL W) for every valid ORIGINAL witness, nor jointly instantiated source-generation and ordinary-QPT-LWE challenge simulator for those ORIGINAL-derived correlations. The fixed-FALSE full-public security and arbitrary hard-TRUE unauthorized final-key/native forgery -> ORIGINAL witness or independent QPT break are absent; one must never require an adversary to supply an internal representation. Malicious one-honest N-of-N setup, pre-funding graph/abort/DA, SYS/BTC qualification and hypothetical native PQ Bitcoin endpoint remain unresolved. No security claim about the failed structured signed-unit Boolean compiler, public basis changes, padding, or premature native key release. This research component alone cannot authorize funding, merge, deployment, or stopping the research automation.
