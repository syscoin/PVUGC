# User-authorized literature assessment — 24 September 2026

The user explicitly authorized external lookup of five papers in a screenshot. This is an assessment and small independent algebra validation, not a complete WKEM or a full independent verification of these preprints. No production code or automation setting is changed.

Initial PR head observed: `8732d83cc1e88216b8904ae67b8565ee8e55a70f`. The latest Run-76/77 discussion was read. Progress comment: `5818155775`.

## Sources and evidence level

- Hair–Sahai, **Witness Encryption via Prime-Order Generic Groups**, arXiv:2609.18275v1: https://arxiv.org/html/2609.18275v1 . Full HTML accessible; relevant construction, classical security proof, rank reduction, extraction, and span-generation sections read. This is classical generic-group false-statement WE, not a concrete PQ/source-extractable KEM. Most promising transferable component: polynomial-size logarithmic-gap Boolean-factor MinRank and explicit low-rank source reconstruction.
- Zhengzhong Jin, **Witness Encryption for NP from SNARGs and Groups**, ePrint 2026/2063: https://eprint.iacr.org/2026/2063 . Primary abstract verified, PDF fetch failed. It specifies subexponentially sound SNARGs with polylogarithmic online verification after preprocessing, plus extractable generic-group WE for polylog-size circuits through a Karp–Levin GapMDP reduction. Full theorem/proof audit is NOT claimed.
- Shafik Nassar, Brent Waters, David J. Wu, **Obfuscating Non-Evasive Programs: Making Witness Encryption Positional**, ePrint 2026/1932: https://eprint.iacr.org/2026/1932 and https://www.cs.utexas.edu/~dwu4/papers/Cutoff-iO.pdf . Main theorem and definitions read. Assumptions include WE itself and LWE with subexponential modulus/noise ratio. The indexed result has `N^epsilon * poly_epsilon(...)` size for fixed epsilon; it is NOT an LWE-to-WE bootstrap.
- Bartusek–Malavolta, **Succinct Arguments for QMA from Collapsing Hash Functions**, ePrint 2026/2040: https://eprint.iacr.org/2026/2040 . Primary abstract verified, PDF fetch failed. Proof/delegation result; no offline public release compiler established by the available statement.
- Gay–Jeronimo, **Asymptotically Good Quantum Locally Testable Codes**, arXiv:2609.20780v1: https://arxiv.org/html/2609.20780v1 . Full HTML available; abstract/introduction/main-result discussion inspected, not the complete proof. Local-to-global coding geometry may help; code membership is not source-witness membership.

Additional lead found while following Jin's reference to lattice gaps: Hair–Sahai, **Polynomial-Factor Deterministic NP-Hardness for SVP in Every lp Norm with p > 2**, arXiv:2608.14529v3: https://arxiv.org/html/2608.14529v3 . Main theorem and overview read. Jin's exact citation to this particular version has not been verified.

Quantum background: Shor, https://arxiv.org/abs/quant-ph/9508027 . A classical generic-group theorem does not establish security against quantum discrete-log computation in a concrete efficiently implemented cyclic group.

## Independent checks actually executed

The accompanying standard-library checker ran twice with byte-identical JSON. This is an original small implementation, not author-provided code or an exhaustive verification of the published theorem.

For N=4, R=2, prime 257, it implements Hair–Sahai's geometric weight list and Section 4.6 partial-assignment linear updates. The unpadded tables have 510 rows and 5 columns. At every stage the computed basis exactly matches an independently enumerated truth-table span, with dimensions 1,2,4,8,16. All 30 transition checks pass.

For sum(b_i)=1 and the false sum(b_i)=5, the constrained spaces each have dimension 5 in this fixture. All 128 sampled nonzero false matrices have rank 5; this sampling is NOT a proof about every false matrix. Separately, all 128 supplied rank-at-most-two combinations of honest encodings produce a verified witness by the paper's column-basis candidate enumeration.

The program also checks a quantum-model boundary on an INDEPENDENT toy matrix space, not the paper's SAT compiler. Over F_5, define alpha by alpha^3+alpha+1=0 and use matrices with columns (z,alpha*z,0). All 124 nonzero matrices have rank 2. If group exponents are exposed, form B_s with rows s^T M_j. Structured exponent vectors lie in image(B_s), but uniform ones generally do not. Exact enumeration checks 1,125 structured memberships and 15,625 uniform vectors, with distinguishing gap 12524/15625. No Shor execution or quantum hardware was used. This is not a break of the classical generic-group theorem; it shows why a rank promise alone cannot certify a PQ implementation.

## Interpretation for the current research

**Most useful immediate transfer:** independently audit and prototype the weighted-table rank-gap compiler, rather than replacing the absent source gate with an assumed hidden evaluator. Its supplied-low-rank-to-witness theorem addresses the semantic representation size/gap problem. The step from arbitrary key recovery to an appropriate low-rank object remains separate.

For Jin, track the full extraction chain explicitly:

    recovered key -> witness of small verification circuit
                  -> accepting SNARG proof pi
                  -> original NP witness w.

The last arrow requires a knowledge/extraction mechanism; ordinary soundness alone is not that mechanism. This is an obligation for our stronger application, not a claimed defect in Jin's advertised ordinary-WE result.

For positional WE, setting the index space to all n-bit witnesses gives N=2^n and N^epsilon=2^(epsilon*n), still exponential for fixed epsilon. Choosing epsilon=1/n is outside the fixed-constant efficiency guarantee. Thus the theorem does not automatically supply efficient generic source extraction from an arbitrary decoder, and already assumes a base WE.

For qLTC/QMA, verification soundness and local testability do not by themselves produce a confidential key-bearing object. They cannot simply replace the nonlinear witness-restricted release operation.

## Two concrete parameter/interface cautions

The MinRank paper uses m=(N+1)(2NR+1) binom(2R,R), R=floor(log2 N), and p in [2^m,2^(m+1)). The literal unoptimized X-handle list alone is about 5.89 GB at N=16. This is a calculation of the theorem's stated encoding, NOT a lower bound on optimized implementations or a cryptographic benchmark. The separate rank-reduction theorem allows a much smaller supplied prime than that full encryption choice; improvements require a fresh complete parameter analysis.

The additional GapSVP theorem is in p-norm for p>2, with gap exponent epsilon<min((p-2)/(4p),1/8), and also covers infinity. Naive conversion to Euclidean geometry loses a factor d^(1/2-1/p) in ambient dimension d. The stated epsilon is smaller than that loss, so this is not automatically the Euclidean short-preimage gap needed by an isotropic Gaussian/LWE decoder. Audit its actual source-preserving code and norm geometry instead of relabeling it as an l2 result.

## Remaining obligations

None of the assessed results has been shown here to supply a practical generic-NP public offline PQ/source-extractable WKEM. Remaining: an independently justified PQ implementation of the complete key-bearing output; arbitrary-QPT key recovery to source witness or hardness break; auxiliary-input and malicious-secure erased-ceremony composition; and practical parameters. The stopping condition is not met.
