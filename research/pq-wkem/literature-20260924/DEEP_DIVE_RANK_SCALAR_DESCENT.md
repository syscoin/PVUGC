# Literature integration: order-parameterized rank compiler, binary scalar descent, and classical symbolic extraction

Date: 24 September 2026. Starting verified PR head: `841b4bbe5df0db54beb7e5ce9e5e0466d6412e5a`.

**Classification:** new derived algebraic extensions and a scoped classical-oracle extraction argument. Not a practical PQ WKEM, a general quantum-group theorem, or a full independent verification of every cited preprint.

The existing hourly automation `6ab0ca28f9908191bddd622d23ed0eb7` was updated successfully, retaining its hourly schedule and enabled state. Its old blanket prohibition on external literature was replaced by the user's explicit authorization to study these papers and directly relevant primary-source predecessors, revisions and refutations. All original complete-output/PQ/source-extraction/ceremony requirements and the stopping condition remain. Progress comment: `5818416969`.

This record and its checker are NEW research, not a retry or alternative publication route for the previous assessment's failed checker upload. That prior failure remains recorded in `ASSESSMENT.md` and comment `5818269940`.

## 1. Evidence and dependency ledger

Primary references inspected during the deeper pass:

* [HS-WE] Hair–Sahai, *Witness Encryption via Prime-Order Generic Groups*, arXiv:2609.18275v1, https://arxiv.org/html/2609.18275v1 . Sections 2–4, including the geometric determinant, weighted soundness/extraction, span generation and classical symbolic security argument were read. The claims below are derived extensions, not quotations of the authors' stated field or extraction theorem. No novelty-priority claim is made.
* [Jin] *Witness Encryption for NP from SNARGs and Groups*, ePrint 2026/2063, https://eprint.iacr.org/2026/2063 . Primary abstract and author publication listing verified. Full PDF remained unavailable in this pass; no full-proof audit is claimed. Soundness, small-circuit extractability and ORIGINAL source-witness extraction must remain separate.
* [NWW] Nassar–Waters–Wu, *Obfuscating Non-Evasive Programs: Making Witness Encryption Positional*, https://www.cs.utexas.edu/~dwu4/papers/Cutoff-iO.pdf . Main theorem and dependency/definition sections inspected. Assumes base WE plus LWE; the fixed-epsilon indexed-size theorem is not an LWE-to-WE construction or a polynomial-size result on all exponentially many witness indices.
* [BM] Bartusek–Malavolta, *Succinct Arguments for QMA from Collapsing Hash Functions*, ePrint 2026/2040, https://eprint.iacr.org/2026/2040 . Abstract verified; PDF inaccessible. Succinct proof/delegation alone is not confidential offline release and does not automatically meet Jin's online-verifier/knowledge interface.
* [GJ] Gay–Jeronimo, *Asymptotically Good Quantum Locally Testable Codes*, arXiv:2609.20780v1, https://arxiv.org/html/2609.20780v1 . Introduction, main-result and construction-overview material inspected, not all proofs. Uniform product expansion and local-to-global code geometry may be transferable. Code membership remains distinct from nonlinear source-witness membership.
* [HS-SVP] Hair–Sahai, *Polynomial-Factor Deterministic NP-Hardness for SVP in Every lp Norm with p > 2*, arXiv:2608.14529v3, https://arxiv.org/html/2608.14529v3 . Main theorem and proof overview inspected. It is a p>2/infinity gap, not an automatic Euclidean gap; standard norm conversion loses more than its advertised exponent. Worst-case NP-hardness also is not average-case SIS/LWE security.
* [CMV] Chatterjee–Mu–Vasudevan, *Public-Key Encryption from the MinRank Problem*, https://arxiv.org/html/2510.03752 and https://eprint.iacr.org/2025/1833 . Followed directly from [HS-WE]. Abstract, introduction, block-wise inner-product/duality overview inspected. The HTML labels itself arXiv:2510.03752v1 and its manuscript header says August 24, 2026; record both rather than assume a different version number. Its public-key distribution is planted A(s)+E for UNIFORM random binary matrix generators. Our statement-derived matrix spaces do not yet have that distribution or a reduction to it. Full composition audit remains next work.

## 2. Algebraic field-size extension

### 2.1 Input and construction

Encode the source verifier by Boolean quadratic equations q_j(b)=0 in N bits (including gate values), with b_0=1. Use AND/NOT/output constraints whose Boolean solution semantics are preserved in every field. Arbitrary integer source equations must not silently be reduced modulo a small characteristic if that changes their Boolean language.

Fix 1 <= R <= N. Let F be a finite field with size q>2NR and choose a known element gamma whose multiplicative order is greater than N. Let T be ANY set of 2NR+1 distinct field elements. In characteristic two, this means actual distinct extension-field elements, not integer multiples of 1.

Replace [HS-WE]'s weight forms by

    ell_(j,t)(b) = sum_(i=0)^N (gamma^(j-1) t)^i b_i,   j=1,...,R.

For every t in T and multi-index alpha with |alpha|<=R, set

    h_(alpha,t)(b) = product_j ell_(j,t)(b)^alpha_j.

Vertically stack h_(alpha,t)(b) v(b)v(b)^T, where v(b)=(1,b_1,...,b_N)^T. Take the span of WHOLE stacks A(b), not independent spans per block. Then impose all source-quadratic table tests in every block. This is exactly the [HS-WE] construction with a different geometric progression and sample set.

The number of block rows remains

    m = (N+1)(2NR+1) binom(2R,R),

and there are N+1 columns before optional zero padding.

### 2.2 Proposition: the field hypotheses above suffice for the Section-4 rank/extraction result

The resulting homogeneous space has a nonzero Boolean-right-factor rank-one encoding for every valid witness. Every supplied nonzero admissible matrix of rank <=R yields a valid source witness by the same column-basis list algorithm, taking at most 2^R candidate assignments. The space is computable without knowing a witness in time polynomial in its explicit dimensions, N, the source size, and field-arithmetic cost.

**Proof of the changed hypothesis.** In the geometric rank-condenser lemma, eliminate leading terms of independent degree-at-most-N polynomials so that their distinct degrees are e_1<...<e_rho. The leading determinant coefficient becomes

    (product_i leading_i) * det[(gamma^e_i)^(j-1)]_(i,j).

It is nonzero because all gamma^e_i are distinct: ord(gamma)>N. The determinant degree is at most N rho. The nonzero weighted-entry polynomial has degree at most NR. Their product is a nonzero polynomial of degree <=2NR, so at least one of the 2NR+1 distinct samples is good.

This is the only place the original p>2^N / integer sample-set argument is needed. The rest of the proof uses field linear algebra, Boolean identities b_i^2=b_i, and selectors product_{e_i=1} y_i product_{e_i=0}(1-y_i). It does not divide by factorials or require the characteristic to exceed R. Constants use b_0=1. The shared coefficients of the whole stack are retained throughout.

For completeness, the soundness steps remain: select a sample with both full column span and a nonzero block; use whole-column relations to justify replacements inside weighted sums up to the stated degree limits; express columns in rho actual-column coordinates; apply rho-variable Boolean selectors; every surviving selector gives Boolean values satisfying all source equations; if none do, every block at the good sample is zero, a contradiction. The source extractor takes actual independent columns, expresses all other columns in their basis, enumerates the 2^rho Boolean assignments to those basis coordinates, and verifies the resulting source assignment. These are the Section-4 arguments with 2 replaced by gamma.

The partial-assignment span generator also extends. Setting a previously zero bit to 1 adds a known delta_j to ell_j. The binomial identity expands each degree<=R weight into weights already listed; corresponding table row/column coordinates are substituted linearly. Binomial coefficients are interpreted in the actual field. Iteratively retain a basis of the old space plus its transformed image; then intersect with the public source constraints. Exponentially many assignments are never enumerated by this general algorithm.

### 2.3 Consequences and caution

One can choose a prime q>2NR of size O(NR), search for gamma of order>N, and use ordinary residues as the sample set. Since q is polynomial, a direct search/check is polynomial; no discrete-log assumption is involved.

Alternatively choose q=2^h>2NR with h=O(log(NR)), construct the extension field, and search for gamma of order>N. The small checker uses explicit irreducible polynomials, not a production field library.

**This changes the algebraic compiler, NOT the separate encryption parameters.** The original ciphertext sampler uses a grid of m distinct field values and its correctness/security proof has separate 1/p terms and large-prime requirements. Our small q may even be less than m. Plugging it unchanged into Section 3 is not justified.

A useful negative control: at N=5 in F_31, the element 2 has order 5, so degrees 0 and 5 alias and the two-column determinant vanishes at every one of the 21 tested samples. Choosing gamma=3 of order 30 fixes this: only one sample is rank-dropping. Merely decreasing p while retaining base 2 would be incorrect.

## 3. Binary scalar descent without losing rank-one witnesses

This is a derived observation, separate from the paper's prime-field encryption.

Let F=GF(2^h) and choose an F_2 basis beta_1,...,beta_h. For A in F^(m x b), expand every entry into its h binary coordinates and stack those coordinates VERTICALLY:

    D(A) in F_2^((hm) x b).

Do not use the usual h-by-h regular representation of every entry: that would multiply the rank of an honest matrix. Vertical coordinate expansion has the properties needed here.

### 3.1 Rank comparison

D is F_2-linear and injective. If r columns span D(A) over F_2, the same binary combinations of the corresponding original columns span A over F. Hence

    rank_F(A) <= rank_F2(D(A)).

For an honest A=u v^T with v in {0,1}^b,

    D(A)=D(u) v^T,

so its binary rank is exactly one.

Let S have F-basis M_1,...,M_k. Its entire binary-coordinate image has F_2 basis

    {D(beta_j M_i): i=1,...,k; j=1,...,h}.

Independence follows by collecting each group of h binary coefficients into one field coefficient. Thus the binary space has dimension hk, not merely the span of D(M_i).

### 3.2 Source extraction and false gap

A supplied nonzero binary matrix B in D(S) with rank<=R can be grouped back into its unique A in S. The comparison above gives rank_F(A)<=R, so Section 2's source extractor applies. Every false statement therefore has binary minimum rank greater than R, while every valid witness gives a rank-one binary matrix.

With R=floor(log2 N), m=O(N^4 log N) and h=O(log N), this is a polynomial-size binary homogeneous MinRank/source interface with the same logarithmic threshold. The rectangular binary matrices have hm rows and N+1 columns; optional zero-column padding preserves rank. This is not a proof that random binary MinRank instances are hard, and it does not furnish a key-bearing distribution by itself.

### 3.3 Literal size examples

For N=5,R=2,q=32, h=5:

    original table: 756 x 6 field entries;
    binary table:   3780 x 6 bits = 22680 bits per matrix.

For N=16,R=4, q=256 is enough for the algebra and h=8:

    original table: 153510 x 17 field entries;
    binary table: 1228080 x 17 bits = 20877360 bits per matrix.

These counts describe ONE dense matrix, not the full basis/encoder, a compressed implementation, or a secure ciphertext. A whole basis can be substantially larger. They must not be presented as deployment benchmarks or compared directly to the preceding assessment's entire large-prime X-handle list.

## 4. Classical symbolic collision-to-source extraction

The [HS-WE] paper states ordinary false-statement WE. Its symbolic proof and explicit low-rank extractor support the following scoped additional argument.

Use the paper's ORIGINAL prime-field ciphertext and its grid size m, with independent public basis M_1,...,M_k and rank threshold R. Let A be a classical generic adversary making at most Q oracle calls. Its advice is independent of the fresh encoding/encapsulation coins. Its local running time is included in the extractor cost.

Run A in the symbolic random-label simulation. Every known handle has a tracked formal expression

    c + alpha dot S + gamma dot Z.

For every pair of distinct formal handles, form its coefficient difference gamma and the public matrix

    M_gamma = sum_j gamma_j M_j.

If gamma is nonzero and rank(M_gamma)<=R, it is a NONZERO matrix because the published M_j are a basis. Invoke the source extractor immediately. There are at most H=m+k+Q+2 formal handles, hence O(H^2) pairs to scan. The extractor runs in polynomial time for polynomial Q and 2^R polynomial.

Let h_low be the probability that this symbolic execution yields such a low-rank pair. On the complementary event, every target-bearing pair has rank>=R+1. Under structured ciphertext evaluation, its collision probability is at most

    m^(-(R+1)) + 1/p.

Under the independent-uniform Y-handle experiment, a distinct affine form collides with probability at most 1/p. Pairs with gamma=0 have collision probability at most 1/p in either experiment. Fresh guessed valid encodings contribute O(Q/p), under the same polynomial-budget/large-prime regime as the original proof.

Conditioning on the symbolic transcript is legitimate: labels and local decisions in that transcript are sampled independently of the hidden s,r,eta. Coupling until the first nonformal collision, then union-bounding the high-rank pairs and guessed encodings gives

    delta_dist <= h_low + epsilon_high,

where a convenient bound is

    epsilon_high = binom(H,2)*(m^(-(R+1)) + 2/p) + O(Q/p).

The common bounded-sampling abort can be included exactly as in the paper. Therefore the explicit symbolic extractor succeeds with probability at least

    max(0, delta_dist - epsilon_high).

For prediction of a uniformly random challenge bit with success 1/2+adv, delta_dist=2adv after orienting the output convention.

**Scope:** this is a classical generic-group one-challenge extraction argument. It does NOT establish a QPT/coherent-oracle extractor, concrete cyclic-group security, a full multi-key/adaptive-auxiliary composition theorem, or a PQ WKEM. It is also not attributed to the authors as their stated theorem. The local checker validates the finite collision inequality and supplied-matrix extraction components, not an exhaustive adaptive-adversary simulation.

## 5. Why these results are useful but do not unlock the completed primitive yet

The new binary representation gives a concrete place to investigate [CMV]'s matrix-valued rank-metric product and duality rather than attempting to port a classical group oracle directly. But [CMV] assumes planted low-rank noise with uniformly random public generator matrices. D(S_x) is a worst-case statement-derived space with explicit structure, shared constraints, and many possible witnesses. A proof for that new joint distribution is required; worst-case NP-hardness does not provide it. In particular, square-zero-padding our rectangular space creates a common right kernel of dimension at least hm-(N+1). Invertible row/column disguises preserve that common-kernel dimension, whereas uniform full square matrix generators do not have that forced invariant. Ordinary basis scrambling is therefore not a reduction to CMV's distribution. A rectangular adaptation or a different embedding would need a fresh proof. The earlier reusable-factor RankHPS/factor-recovery failures in this PR must also be checked before proposing a transparent variant again.

For Jin, the extraction ledger remains

    recovered key -> witness of small verification circuit
                  -> accepting SNARG proof pi
                  -> ORIGINAL source witness w.

The final arrow requires an appropriate knowledge/extraction theorem and compatible parameters/QPT/auxiliary handling, not ordinary soundness alone. No such missing arrow is assumed here.

For [NWW], base WE is already an input. For N=2^n witness indices, N^epsilon remains exponential for fixed epsilon; setting epsilon=1/n is outside that fixed-constant theorem. For [HS-SVP], p>2 gaps cannot be declared l2 gaps without dimension loss. For [GJ]/[BM], robust code membership and proof soundness do not implement a confidential key-bearing object. These dependencies are now explicit in the hourly task.

## 6. Local validation actually executed

The NEW standard-library checker `rank_field_extensions.py` ran twice with byte-identical JSON. Its small exhaustive assignment tables serve only as independent validation oracles for the implemented span updates, not the proposed general encoding algorithm.

* All 2850 two-subspaces of F_7^4 satisfy the tested geometric determinant root bound (at most 5 observed drops, degree bound 6). This condenser-only fixture enumerates all seven points; it does not claim F_7 satisfies the full compiler sample count for R=2,N=3.
* Full compilers at (N,R,F)=(3,1,F_7),(5,2,F_23),(5,2,GF(32)) pass 52 transition identities; at every stage the generated space equals an independently enumerated truth-table span. All 90 supplied low-rank combinations extract a verified source witness.
* All 2400 nonzero matrices in one false 4-dimensional F_7 space were enumerated: 84 have rank3, 2316 rank4, none violate R=1.
* Binary scalar descent was tested on GF(8),GF(16),GF(32) spaces. All 7 nonzero matrices of the first false space were enumerated; the other two spaces used 128 nonzero samples each. Binary ranks never fell below field ranks. All 16 genuine encodings in the GF(32) true fixture retained binary rank1 and yielded verified witnesses.
* The low-order base-2 countercontrol and its high-order repair passed exactly.
* 100 tiny finite-grid bilinear collision bounds were checked exactly.

The tests support the implementation, not a cryptographic security assertion. Sampled high-rank results are not exhaustive soundness proofs; the statements above rely on the algebraic argument and the explicitly audited extension of the paper's proof.

## 7. Next experiment / handoff

1. Independently stress the field-flexible proof and binary descent on actual Boolean circuit constraints, larger exact spans, and varied characteristics. Seek a second proof review of the derived extension before treating it as a settled foundational lemma.
2. Audit [CMV] Section 3 duality and Section 4 encryption on its full distribution; determine whether a source-preserving randomized embedding can connect D(S_x) to that distribution WITHOUT a planted witness or extra releasable factor information. Record actual assumptions and any distributional obstruction, not a new assumption that restates desired WE security.
3. Obtain Jin's full manuscript and audit the entire source-extraction chain and concrete preprocessing/verification/gap parameters.
4. Keep [NWW], [BM], [GJ], and [HS-SVP] as explicit dependency-specific workstreams rather than claiming they already supply release.

The public offline key-bearing PQ encoding, arbitrary-QPT ORIGINAL-source extraction, malicious-secure erased setup with abort, auxiliary-input composition, and practical full-system costs remain unproved. The stopping condition is not met; the existing hourly automation remains enabled.
