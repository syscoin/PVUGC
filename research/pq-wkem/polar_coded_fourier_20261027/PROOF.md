# Polar-coded direct native-seed Fourier release — full mathematical checkpoint

Research-only, 2026-10-27 UTC, automation turn 5. This extends the actual open draft syscoin/PVUGC PR #1 on research/pq-wkem-validation-20260918, starting head 34ba3caa80a5d0b3e6a03c341a86e6dba4a6d915. Exact predecessor: direct_seed_repetition_20261027/README.md, Git blob 1220d333b8c5526a36e77a877247dc51d8069a3e. Offline derivation, not deployed PQ Bitcoin, standard-LWE witness encryption, or a practical generic-NP system.

## Algorithms and distribution

Fix a public ORIGINAL deterministic verifier R_x(w) with t witness-input bits and a bound x/context that includes relation identity, real burn/authorization/output, claim and UTXO, branch, anchor/window and native verification key. Retain the predecessor's homogeneous GF(2) SOURCE matrix C_x, public row basis B of ker C_x and b=B e_0. Any accepted ORIGINAL witness yields its own normalized one-hot v_w in ker C_x and publicly computable alpha_w with alpha_w B=v_w^T. This does not require different accepted witnesses to share states or short representations. Affine rows are exact; nonlinear AND/NAND factors use the existing four-label SOURCE convention.

Independently for each column, sample an error vector E with probability 1/3 of zero in each gate and 1/6 for each of four gate-label singleton errors, all other coordinates zero. Write P_z for the complete law of Q=B E+b z. The predecessor proves the EXACT character identity

    Fourier(P_1)(a)-Fourier(P_0)(a)
      = -2 rho  if a B is a normalized one-hot accepted ORIGINAL witness state,
      = 0       otherwise, rho=(2/3)^g,

where g counts nonlinear factors. Crucially this is a whole-quotient, not a selected-probe identity. In every FALSE ORIGINAL instance P_0=P_1 as full probability distributions. Any replacement sampler (including an optimized shared-input sampler) requires its OWN entire-distribution support proof and common rho; this note does not silently assert such an instantiation.

Generate actual native signing seed K in {0,1}^k and public pk(K) through its native key generator. Independently sample PUBLIC information dither S uniformly from {0,1}^k. Choose polar length N=2^m and information set I of exactly k positions using the certified process below; freeze all remaining polar input positions to zero. Put U=K XOR S into I, construct length-N codeword c=Enc_N(U), and for each j publish

    Q_j=B E_j + b c_j,

using INDEPENDENT fresh E_j. Publish full view (relation, x, source C_x/B, parameters N/I/rho, public S, all Q_j, actual pk(K), claim/branch/anchors/context, admissible auxiliary information and related capsules). Honest setup erases/protects K, every E_j, and signing/setup transcripts under the original honest-erasure model. No keyless Build, malicious-secure N-of-N ceremony, online authority, SOURCE-opening oracle, witness enumeration, public native-secret tag, random oracle KDF, or native adaptor algebra is invoked. Setup and Recover are classical polynomial time in their actual public output size.

For each valid ORIGINAL w, compute v_w and alpha_w, then y_j=alpha_w Q_j=c_j+v_w^T E_j. At fixed w the column errors are INDEPENDENT BSC((1-rho)/2); their distribution is identical for all valid w although different witnesses' errors on the SAME column can be correlated. Apply the public SC decoder to y, extract Uhat at I, output Khat=Uhat XOR S, and check actual pk(Khat)=pk before locally signing the intended challenge-path message. Bitcoin does not verify w or an NP circuit.

## Explicit polar specification and finite all-witness theorem

Specify the polar ordering, avoiding an easily made bit-index reversal. Recursively split input u into EVEN and ODD index subsequences. Encode both to a and d and emit (a XOR d, d). At N=1 emit the bit. SC decoding pairs channel LLRs (L_i,L_(i+N/2)), forms EVEN-subtree LLR via f(a,b)=2 atanh(tanh(a/2)tanh(b/2)), decodes even inputs, obtains their encoded a, forms ODD-subtree LLRs L_(i+N/2)+(-1)^a_i L_i, decodes odd inputs, and interleaves input estimates. Frozen leaves output zero; information leaves use binary ML likelihood. A rigorous exact-likelihood implementation may use rational LR recurrences R_minus=(R1 R2+1)/(R1+R2), R_plus=R2*(R1 if a=0 else 1/R1), with polynomial bit complexity for rational channel transition probabilities and polynomial N. The published short JS and longer local Python checkers test stable numerical SC, not constant-time production floating point.

Let Z_0=sqrt(1-rho^2), the Bhattacharyya parameter of BSC((1-rho)/2). The standard binary-memoryless-symmetric channel splitting argument has Z_plus=Z^2, Z_minus<=2Z-Z^2. Use ROOT-FIRST recurrence: split W into W_minus for EVEN input positions and W_plus for ODD input positions and THEN recurse on each half, interleaving leaf indices. Appending minus/plus transforms in the reversed sequence selects wrong information indices and is NOT a valid certificate for this encoder.

The implementation uses an exact upward-rounded dyadic certificate: D=2^P, P=t_eff+lambda+128, start integer z0=ceil(D sqrt(1-rho^2)) with conservative integer isqrt, and at each root-first branch use

    z_minus = min(D, 2z-floor(z^2/D)),
    z_plus  = min(D, ceil(z^2/D)).

These integers upper-bound all synthesized Z parameters. At a tested power of two N choose the k smallest leaf z_i (ties by index) as public information positions I and require the entirely INTEGER predicate

    2^(t_eff+lambda) * SUM_(i in I) z_i <= D.       (CERT)

The SC block-error probability averaged over independent uniform information bits is at most SUM Z_i. The public S makes U=K XOR S uniform for ANY FIXED native K, including a seed with checking-key correlations. Therefore every fixed accepted witness has failure probability bounded by SUM z_i/D over fresh S and errors. This is independent of witness state representation.

The number of decoding noise classes can be bounded without enumerating any witnesses. For the independent gate sampler, let J be the set of assignment-label error coordinates and

    r_E = rank_GF2( B restricted to J ).

The function E -> v_w^T E is determined by the restriction of the SOURCE v_w to the error span. There are at most 2^r_E such functions over ALL normalized SOURCE vectors. Two witnesses with the SAME function see identical observations in every released column, even when their ORIGINAL states differ. For deterministic internal wires, at most 2^t accepted ORIGINAL inputs exist. Accordingly set t_eff=min(t,r_E). A union bound over distinct noise functions (not a canonical witness construction) yields

    Pr_(S,E)[some accepted ORIGINAL w fails Recover]
       <= 2^t_eff * SUM_(i in I) z_i / D <= 2^-lambda.

An independent nondeterministic SOURCE compiler must instead bound all its accepted modes; do not use t as an unjustified shortcut. A toy source with eight free affine input wires and a single AND gate has 768 valid input assignments but only rank r_E=3, hence at most eight distinct decoding-noise functions. The rank is computed from PUBLIC linear algebra; no witness search occurs in Build.

## Full-public false-instance simulation and true-instance QPT extraction

For FALSE ORIGINAL x, whole-law P0=P1, independent fresh E_j, and publicly known S imply the COMPLETE joint column distribution equals P0^N even though codeword bits c_j are correlated through the private K and public dither. Given the REAL native pk and admissible checking/signature/context auxiliary challenge, the simulator samples S and P0 columns without K. This is exact joint distributional equality, and holds under arbitrary coherent QPT postprocessing with allowed quantum side information independent of the fresh private release randomness. It is NOT malicious retained-coin security. Any auxiliary secret-derived tag or native signature material outside the native challenge game requires its own simulator.

For true x let s_x<=2^t count accepted normalized SOURCE Fourier indices and let p_real be success of any arbitrary QPT exact-seed-recovery or fresh authorized-message native-signature-forgery algorithm on the WHOLE public view. Let p_native be success of the actual native challenger adversary that samples S, source/context and all columns from P0 while retaining real pk and declared legitimate signing interfaces. Define hybrids replacing each P_(c_j) with P0, retaining K, S, pk, every other Q and auxiliary material. Conditioned on K,S, each selected c_j is known to the extraction setup sampler; if zero the hybrid gap is zero, and if one its complete character difference is supported precisely on ORIGINAL witnesses, with common coefficient -2rho. The predecessor's controlled success-phase reflection followed by Fourier measurement, with coherent access to A and A-adjoint and one copy of properly independent quantum advice, directly produces a verified ORIGINAL witness from arbitrary successful seed recovery or fresh signature forgery. It never asks A to volunteer a SOURCE representation. Telescoping and Cauchy-Schwarz give

    eta=max(0,p_real-p_native),
    p_extract >= eta^2/(N^2 s_x rho^2) for s_x>0,
    p_real <= p_native+N rho sqrt(s_x p_extract).

On false x real and native-null success coincide in the matched experiment. This does NOT prove a hard-true work bound: a meaningful claim must independently bound QPT ORIGINAL evidence search with the extractor's actual coherent circuit/inverse access, quantum advice, computation and oracle budget. Arbitrary setup-coin-correlated advice, mixed same-key true capsules, adaptive selective opening, malicious N-of-N setup/abort and transaction-graph bypass are outside these reductions. Reused claim/path bearer credentials and already-authorized native signatures cannot be reclassified as fresh forgery. Conditional PQ native Bitcoin signatures/no-key-path outputs are not asserted deployed.

## Quantitative verified gain, and exact remaining obstacle

With k=256,t=256,lambda=128 and rho=2/3 (an illustrative ONE-nonlinear-gate SOURCE), dyadically certified N=16,384 columns, versus the predecessor's 1,223 majority repetitions per bit =313,088 columns, **19.109x fewer**. A conditional whole-source sampler with rho=1/2 yields 32,768 versus 556,800 columns, **16.992x fewer**. The fixed source is computationally easy and these are certified completeness and payload counts, NOT a 128-bit QPT hard-true parameter set. Public dither costs k additional bits. The total release payload is N*d+k bits, plus source, pk and claim context. SC coding/decoding is polynomial and O(N log N) elementary likelihood operations in the mathematical model.

Generic g still yields rho=(2/3)^g and exponentially expensive honest N; a more efficient code does not repair that exponential SOURCE signal, nor a missing source-dependent standard-QPT-LWE joint simulator. No actual SYS/BTC proof-of-work/fork circuit, BTC tag-density/reorg/censorship model, malicious ceremony, pre-signature graph or native PQ endpoint was compiled/verified. The next exact gap is a polynomial-rate efficient SOURCE sampler with the same witness-only full Fourier support and independently justified QPT work security, or a true distribution-preserving standard-LWE embedding of the actual structured ORIGINAL relation including all public key/context/related capsule correlations.

## Actually executed evidence and provenance

The independent longer local Python checker passed 9,346 assertions in two byte-identical runs: actual GF(2) true/false SOURCE distributions, 36 distinct-witness openings of the SAME 16-bit precommitted seed using public S and a 256-column polar code, exhaustive N=8 BSC outcomes for all four information messages, exact native-pk-conditioned false joint laws, noise-rank affine extensions, and certified N for 256-bit examples. Local-only source SHA256 c26fb789393ca92e83b059306e9ca0333cf3e4d8f2830f80c14999bcafa55070. The separately published self-contained Node checker passed 11 checks twice byte identically; it independently computes the dyadic certificates and exact N=8 public-dither BSC failure probability 104/729. No quantum hardware, QPT hardness evidence, deployed verification or external literature research is claimed.