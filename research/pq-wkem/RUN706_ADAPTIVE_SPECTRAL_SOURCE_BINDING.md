# Run 706 — Global adaptive spectral SOURCE binding using the same residual masks

Research-only, 22 Oct 2026. Starting exact PR head: 0919b22fd91c973e5088e1ff61b53da11f856493 (open/draft/unmerged). Builds directly on Run 701 typed 3CNF SOURCE/rank (proof blob 94628f7a9248d6336476a9867552c5ef66d2e6cd), Run 704 vanishing-ideal residual shields (proof blob 67e2ea70503c0b4cf9379b89b90d98a536e56bba), Run 705 independent-QROM native-tag composition (blob 4fb4c89a8332bde4f373c4eef05ed374c0798755), and Run 259 downstream SOURCE binding (blob c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2). This result is a source-binding component, NOT a completed PQ WKEM or a key-only extractor.

## Construction delta and full public output

On a fixed statement/context x (including the claim/UTXO, branch, relation version and anchors/window), normalize SOURCE z=(1,y), y in F_q^n. Run 701 gives m typed gates G_i(y) of dimension 4b, satisfying rank(G_i(y))<=2b for every fully valid SOURCE. The complete public residual map r_i(y) has r(y)=0 iff y is accepted, yielding an ORIGINAL witness by the Run 701/259 extractor.

Choose s>=1 and matrix dimension N=2bm+s. Privately sample L_i,R_i and all typed-gate setup coins independently of key K and masks. Sample independent mask polynomials Q_i(y) in public spaces P_i tensor Mat_N(F_q), with an **independently uniform full N-by-N constant coefficient A_i for every i**. All other coefficients are independent of A_i. Publish only the **complete aggregated polynomial coefficient array** of

  C_x(y)=K I_N + sum_i L_i G_i(y) R_i + sum_i r_i(y) Q_i(y),

together with x, the public SOURCE specification, q, N, the native pk and exact-key tag, public polynomial spaces and decoder. Private factors, A_i/mask coefficients and signing key are not published. Any deterministic lossless public codec preserves the statement. The baseline Run 703/705 signing adapter and exact-key tag are unchanged.

Define an optional public acceptance predicate on a **supplied pair** (y,alpha), for alpha in F_q:

  SpectralAccept(y,alpha) := [rank(C_x(y)-alpha I_N) <= N-s].

## Theorem 1 — every-original-witness SAME-key completeness

For EVERY fully accepted SOURCE y, ALL residuals vanish simultaneously, and

  rank(C_x(y)-K I_N) <= sum_i rank(G_i(y)) <= 2bm = N-s.

The honest K is therefore an eigenvalue with geometric multiplicity at least s for all valid ORIGINAL witnesses, even if their resulting matrices differ. Run 696's previously established cofactor-free Krylov/recurrence/Frobenius root recovery still applies, followed by the existing exact-key native selector. This is a correctness result, NOT security of the public polynomial distribution.

## Theorem 2 — after-setup global SOURCE soundness, ANY candidate field root

Fix an INVALID normalized y and ANY fixed alpha in F_q. There is an index j with r_j(y)!=0. Condition on ALL setup randomness except the independent uniform constant matrix A_j in Q_j(y). Then

  C_x(y)-alpha I_N = fixed matrix + r_j(y) A_j

is **exactly uniform** over Mat_N(F_q). This is pointwise true independently of the baseline L/R distribution, while the following bound is simultaneously adaptive.

For a uniform N-by-N matrix U, the event rank(U)<=N-s means ker(U) contains some s-dimensional subspace T. For a fixed T, Pr[U*T=0]=q^(-Ns). There are GaussianBinomial_q(N,s) choices for T. Consequently,

  Pr[rank(U)<=N-s] <= GaussianBinomial_q(N,s) * q^(-Ns)
                       <= c_(q,s) * q^(-s^2),

where c_(q,s)=prod_{j=1}^s (1-q^(-j))^(-1). Union bound over ALL q^n normalized y and ALL q candidate alpha yields the unconditional pre-adversary bad-setup probability

  delta <= min(1, q^(n+1) * GaussianBinomial_q(N,s) * q^(-Ns))
         <= min(1, c_(q,s) * q^(n+1-s^2)).

On every good honest setup, no invalid (y,alpha) exists with SpectralAccept=1. **This is information-theoretic against unbounded adaptivity and arbitrary QPT coherent processing of the complete public coefficient array**, because the good event is a property of the sampled public polynomial itself. It continues to rule out an invalid pair even if the actual mask coins are later exposed (although such exposure destroys key hiding). There is no new release oracle, QROM reduction, SIS assumption or random-input-only qualification for this supplied-pair theorem.

A sufficient statistical-failure target kappa is s^2 >= n+1+ceil((kappa+log2 c_(q,s))/log2 q). For the prime q=2^256+297 and kappa=128, choosing s=ceil(sqrt(n+2)) suffices. As a **size illustration only**, a 3CNF with t=1000 original variables, c=5000 clauses has Run 701 n=t+2c=11000 and m=t+3c=16000. With b=1, s=105, N=32105 versus baseline N=32001. Dense matrix-entry capacity increases about 0.65%. The entire ciphertext is STILL impractically large: this is not a 128-bit PQ security parameterization or practical release claim.

## Exact composition and unresolved interface

Run 701's rank lemma alone was pointwise for a fixed invalid SOURCE under dense factors, not adaptively sound. Run 704's independent uniform hidden masks were introduced for exact key-independent **false-instance public ciphertexts** when there is a bounded polynomial identity sum_i r_i p_i=1. The SAME uniform constant mask coefficients, with the +s matrix padding, now guarantee adaptive **SOURCE acceptance soundness for all instances**. The Run 704 mask translation and Run 705 separately keyed ideal-QROM tag theorem are unchanged by increasing N and remain valid only under their original false-instance/unit-certificate premises. Given an accepted supplied pair (y,alpha), public Run 701/259 extraction recovers an ORIGINAL witness except for delta setup probability, with no separate SIS-binding check.

**Central unsolved arrow remains**: arbitrary unauthorized recovery of exact B or acceptable native signature on a hard TRUE instance -> an actual supplied accepted SOURCE/spectral pair (y,alpha), OR an independent QPT-hardness break. Knowing B is NOT a SOURCE. Native signer output alone does NOT contain y. False-instance masking for arbitrary NP, multiple TRUE capsules, malicious/abort-secure one-honest N-of-N setup, real Syscoin BTC/AuxPoW relation and Bitcoin PQ spending endpoint, concrete PQ hardness and public storage also remain open. Do not reclassify this supplied-pair source soundness theorem as key-only extraction.

## Executed checks

A complete Run 701 two-clause 3CNF SOURCE with 8 typed gates, 6 free field variables, N=19,s=3,q=101 and private random L/R/X plus full uniform residual matrices was compiled to its **public full degree-two coefficient array** by interpolation. The independent Python integration passed 1,426 assertions: two valid witnesses (nullity >=3), 57 invalid/full-field representations, all 101 candidate field roots for twelve invalid representations, and public/private matrix equality. Exact uniform-matrix rank census q=3,N=3,s=2 found 339/19683 matrices of rank <=1. Computed global bad-setup union upper bounds were 9.803931084e-7 for fixed true K and 9.901970395e-5 for ALL field alpha. These are finite algebra checks, not proof of any unknown cryptographic hardness.

Independently, a compact standard Node checker enumerated all 19,683 q=3,N=3 matrices, checked uniformity after a nonzero residual, both valid zero-residual inputs, and the Gaussian-subspace upper bound. It passed 39,370 assertions. Code/output are committed with this note. An extended checker, its output and exact provenance are preserved locally in the run package.

NEXT: construct an independent, QPT-justified hard-TRUE protected release/knowledge extraction layer that turns arbitrary key recovery or native forgery into a supplied source. The spectral rank test now certifies that supplied source; it does not produce one.
