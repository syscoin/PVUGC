# Fourier-L1 optimal span-filtered selector masks

Research-only, 2026-10-27. Continues EXACT verified predecessor at PR #1 branch SHA 7bbb4ca96bd2ba7b6bedbd9308e4a1565438596d: research/pq-wkem/selector_space_fourier_20261027/PROOF.md, Git blob d32da19a0d7ee1d658d018846a28fd78d3f9037c. This is a restricted construction-efficiency advance, not a practical generic-NP post-quantum witness-KEM.

## New physical sampler (no witnesses required)

In the preceding rank-r affine-selector batch, normalize h original AND/NAND constraints without adding nonlinear gates:

    c'_i = A_i(z)*b_i,    A_i(z)=a_i·z+gamma_i,  i=1,...,h,

where z is an r-bit affine selector and c'_i,b_i,z are publicly computable linear evaluations of the ORIGINAL homogeneous four-label SOURCE representation, with constants on v_0. Each a_i is a publicly known nonzero r-bit factor, and the normalization is checked against the original gate identity.

For each independent release column: (1) draw active subset S uniformly from all 2^h subsets; (2) draw eta uniformly from F2^r; (3) reject/retry if eta is not in span{a_i:i in S}; (4) draw beta uniformly from F2^r; (5) output the physical ORIGINAL-label linear error mask E whose character is

    <E,v> = eta·(z(v)+beta) + sum_{i in S} (c'_i(v)+A_i(beta)*b_i(v)).    (1)

No witness, common preimage, SOURCE-opening oracle, secret hash programming or canonical intermediate state is used. All coins remain secret under the prior honest-erasure setup assumption. Different columns and batches use independent masks.

For d_S=rank{a_i:i in S}, put

    Z=sum_{S subseteq [h]} 2^{d_S}.

The accepted triples (S,eta,beta) are exactly uniform among 2^r Z possibilities, because for each S precisely 2^{d_S} eta values are admissible. The per-attempt acceptance rate is Z/2^{h+r} >= 2^{-r}, and expected attempts <=2^r. Thus Build is expected polynomial for 2^r=poly(|source|); cap attempts at T and abort BEFORE funding, with per-batch-column abort <=exp(-T/2^r). Conditioning on acceptance leaves the exact uniform-triple distribution unchanged. A malicious participant's selective abort or retained randomness remains outside the proof.

## Exact character identity and optimality

For any normalized local SOURCE state define gate residual R_i=c'_i+A_i(z)b_i (all GF2). Condition on S. Averaging eta uniformly in the d_S-dimensional active selector span yields 0 unless z+beta is orthogonal to that span, or equivalently A_i(z)=A_i(beta) for all active gates. Exactly 2^{r-d_S} choices of beta satisfy this. Consequently,

    E_{eta,beta|S} (-1)^<E,v> = 2^{-d_S} (-1)^{sum_{i in S} R_i}.

The accepted subset probability is 2^{d_S}/Z. Summing over subsets therefore gives

    E_E (-1)^<E,v>
       = (1/Z) sum_S (-1)^{sum_{i in S} R_i}
       = (1/Z) product_i (1+(-1)^{R_i})
       = (2^h/Z) if every gate is valid, else 0.                         (2)

Thus rho_opt=2^h/Z is common to EVERY valid normalized state, and ALL invalid local modes have exact zero signal. The source predecessor's one-hot/three-hot label convention means a three-hot assignment has a complemented effective gate output and is rejected by this residual; no separate nonlinear checks are introduced. Independent disjoint gate batches multiply their biases.

This is locally Fourier-L1 optimal under the exact equal-signal/zero-invalid requirement for all local Boolean assignments. Let f(z,b,c)=1[all c'_i=A_i(z)b_i]. A direct Walsh transform gives nonzero coefficients only where, for S=output-frequency support, the right-input Fourier frequency is a realizable image of A_S(z) and selector frequency is in span{a_i:i in S}. There are 2^{2d_S} such coefficients for S, each with absolute value 2^{-(h+d_S)}. Thus

    ||Fourier(f)||_1 = Z/2^h.                                            (3)

For ANY probability mixture of affine sign characters realizing rho*f, its Fourier coefficients have total absolute mass <=1. Hence rho <=1/||Fourier(f)||_1=2^h/Z, attained by (1). This is NOT a global optimum after imposing arbitrary additional SOURCE affine constraints, nor a generic polynomial-rate universal sampler.

The old rank-r batch discarded only S=empty, eta!=0 and had rho_old=2^h/(2^{r+h}-2^r+1). Since Z<=2^{r+h}-2^r+1, this new sampler never lowers bias. It strictly improves whenever a nonempty selected subset has rank below r. For r=1 it is exactly the earlier optimal star. Also the Fourier L1 norm is submultiplicative under conjunction of disjoint gate sets; consequently optimal whole-batch rho is at least the product of the optimal split-batch biases. The old conservative merge heuristic is unnecessary for signal, though sampling/abort overhead must still be evaluated. For independent a_i=e_i, Z=3^h and rho=(2/3)^h, exactly matching independent-gate sampling.

## Exact examples and measurements

For rank r=2 and h=3 factors [x,y,x+y], the rank sum is

    Z=1+3*2+4*4=23,
    rho_opt=8/23=0.34782608696,
    rho_old_batch=8/29=0.27586206897,
    rho_independent=(2/3)^3=8/27=0.29629629630.

Bias improves by 27/23=1.173913 over the BEST previous independent-gate choice. Ideal Shannon BSC capacity improves from approximately 0.06428895 to 0.08912162 bits/column, a factor approximately 1.3863. This is an ideal rate comparison only: no newly computed certified polar block length or Syscoin circuit measurement is claimed.

For 12 factors, four each using x,y,x+y, the rank sum is 16291; rho changes from 4096/16381 to 4096/16291. Full batch improvement is necessarily smaller once almost all active subsets attain full rank. No assumption that low selector rank by itself makes source search hard is made: when ALL nonlinear constraints depend on r selectors, enumerating 2^r selector assignments leaves a linear source.

## Full public output: inherited proofs and exact gaps

Retain the pinned homogeneous ORIGINAL source C_x, a public basis B of ker(C_x) and shift b=B*e_0. For public q-bit column Q=B*E+b*z, define full distribution P_z. For any quotient Fourier index a, v=a^T B. If v_0=0, flipping hidden bit does not alter its character. If v_0=1, (2) applied over all disjoint physical batches gives common product rho precisely on accepted ORIGINAL one-hot SOURCE witness modes and zero elsewhere. Therefore the WHOLE-LAW identity is

    Fourier(P_1)(a)-Fourier(P_0)(a) =
       -2*rho if a represents a valid ORIGINAL witness,
       0 otherwise.                                                      (4)

For EVERY false ORIGINAL statement, the accepted Fourier set is empty, so P0=P1 as complete classical probability laws. Arbitrary QPT processing cannot distinguish identical full classical output distributions, subject to simulatable independent quantum auxiliaries.

Reuse the prior polar-coded native-release algorithm without alteration: generate independent precommitted native seed K and its actual pk(K), public uniform information dither S, codeword c=PolarEncode(K XOR S), and publish independent Q_j=B E_j+b c_j, full SOURCE relation/compiler, code, dither, real checking key, claim/UTXO/branch/anchors/window, intended path, admissible auxiliary information and related capsules. Every accepted ORIGINAL witness w has its OWN alpha_w with alpha_w B=v_w^T, giving iid BSC((1-rho)/2) observations of the SAME codeword. The public polar decoder returns the SAME K when successful. Its finite-length simultaneous all-witness certificate must be recalculated with this rho and the ACTUAL physical noise-space rank; this work makes no uncomputed reliability claim.

On false instances, a simulator given the REAL native pk/context samples public S and independent P0 columns without K, exactly matching their complete joint law. Secret-key-correlated tags and legitimate signatures are covered only if the native challenger supplies a matching simulation interface. Independent-key, independently simulatable related capsules compose in this restricted setting; same-key related true capsules, adaptive selective opening, arbitrary setup-coin-correlated advice and malicious N-of-N ceremonies do NOT follow.

For hard true x independent of newly generated K and noise, the predecessor's coherent-code-access, one-quantum-advice-copy, A/A-inverse full-transcript reflection proof applies to (4):

    p_recover <= p_native + N*rho*sqrt(s_x * p_original_extract).          (5)

This handles arbitrary QPT final-key recovery and suitably defined fresh native signing forgery only in the explicitly simulated native game. No requirement that A volunteers its internal representation. Coherent inverse access, simulation of source/checking-key correlations, cost-expanded work oracle resources and source independence are indispensable. For claim-bound Bitcoin/Syscoin evidence, no numerical quantum 100-block work theorem, useful multiplicity s_x, actual full verifier circuit, or reduction for key-dependent SOURCE has been supplied. The inequality cannot be advertised as practical PoW gating.

No standard-LWE structured ORIGINAL-SOURCE simulator, generic-NP polynomial-rate construction, native PQ Bitcoin script, N-of-N/abort proof, unrestricted multiple-capsule security or transaction-graph authorization theorem is established. PoW does not validate an unrelated arbitrary NP assertion. Keep the existing research automation enabled.

## Reproducible verification

The independent Python 3 checker in this record tests nine affine-selector batches by EXACT integer Walsh transforms on every local assignment (including offsets), exact spectral L1 and partition comparisons, and three original 15-coordinate SOURCE quotient fixtures. It passes 37,567 assertions twice with byte-identical output, including 92 physical masks, valid-character sum 32 and complete P0=P1 on a false source. The published compact JS checker independently verifies the same r=2,h=3 physical law and 612 finite checks twice. These are exact finite identities, NOT hardness experiments, deployed tests or a cryptographic security audit.

**Next exact target:** a polynomial-rate all-ORIGINAL-witness sampler for general large nonlinear circuits (possibly a source-dependent standard-QPT-LWE joint embedding) and a nonvacuous claim-specific Bitcoin/Syscoin work bound with real history, witness multiplicity and expanded extractor resources.