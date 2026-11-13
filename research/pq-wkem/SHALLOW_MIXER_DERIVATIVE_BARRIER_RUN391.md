# Run 391 — shallow local reversible mixers admit a higher-order derivative distinguisher

2026-10-09. Bounded chosen-input falsifier; not WKEM, source extraction, a RIO break, or proof of 128-bit parameters. Connected starting PR: syscoin/PVUGC#1, branch research/pq-wkem-validation-20260918, head 48037d3a11556f5dd2a702973622094dd3badb47; open, draft, unmerged. Latest substantive ordinary comment 6067040320. Exact source checks: Run 390 blob a1efd75071fb530aa09ffd4ac1b8145778467139, Run 259 blob c7f3b77f0273ca1cbe6f0b31c1a086b8eb3acbf2, CLZ applicability blob c19d9d9cd515140e3ce62eac960cd548c0add622, Run 388 blob 0a01c1a5d7a12af4ab8cab9c7edae3fa05be88ce.

## Theorem and exact assumptions
Let P:{0,1}^n -> {0,1}^n be a public, freely callable permutation assembled from L layers of disjoint arbitrary 3-bit reversible gates, with arbitrary wire rearrangement between layers. Honest sampling/evaluation is classical PPT; attackers may be arbitrary QPT, have all public parameters/auxiliary data and multiple capsules, and evaluate P on chosen inputs (even coherently). The attack uses only classical oracle queries.

Every coordinate of a 3-bit bijection is balanced (four ones), so its top-degree Boolean ANF coefficient is the XOR of its eight table values = 0. Its algebraic degree is at most 2. Substitution across L layers implies each coordinate of P has degree at most D=2^L (capped at n); wire permutations do not affect the degree.

When D<n, set r=D+1 and choose r distinct bit directions e_i. For any base a and output coordinate j, compute the order-r finite derivative

T(P) = XOR_{S subseteq [r]} P_j(a XOR (XOR_{i in S} e_i)).

It is identically zero for every such depth-L mixer. The distinguisher requires Q=2^r=2^(2^L+1) public forward queries. For 2^L=O(log n), it is classical polynomial time and thus a QPT attack on the particular **ideal-random-forward-permutation** hypothesis.

For the exact uniform even-permutation baseline, let N=2^n and Q<=N-2. The alternating group A_N is (N-2)-transitive, so the Q queried output points have the same joint law as a uniform S_N permutation. A fixed output bit is a sample without replacement from N/2 ones and N/2 zeros. Thus for even Q,

Pr[T=0] = (1+(-1)^(Q/2) * binom(N/2,Q/2)/binom(N,Q))/2.

For relevant Q>=8 and N>>Q this is approximately 1/2; one test distinguishes with advantage approximately 1/2. This **already controls** the parity-sector invariant of local embedded gates. It is a higher-order differential attack, not a Simon hidden-period attack or a Grover key-search argument.

## WKEM applicability and boundaries
The theorem falsifies a release compiler *only if* it exposes this isolated shallow forward permutation to freely chosen inputs and relies on indistinguishability from a random even permutation. It does NOT extract the signing capability or an ORIGINAL witness, break an obfuscated inaccessible mixer, refute deep reversible mixing, or refute actual RIO/CLZ security games. If the source verifier is composed before the mixer, the composite may have high algebraic degree: one must prove the adversary can isolate the mixing oracle. No invented release assumption is introduced.

Attack taxonomy: statistical/algebraic fingerprints (3), chosen public evaluation (5), shallow global invariant (2). It is already a classical attack inside QPT, NOT a genuinely coherent quantum break (9). Local seams (1), correlated capsules (4), malicious coins (6), replay (7), checking-key correlations (8) remain separate obligations. Run 259 only proves accepted complete representation -> ORIGINAL witness or SIS break under its exact residual/extractor conditions; this distinguisher supplies no such representation.

## Literature and version correction
Canetti–Chamon–Mucciolo–Ruckenstein, *Towards General-Purpose Program Obfuscation via Local Mixing*, TCC 2024 / https://eprint.iacr.org/2024/006, studies RIO and a conditional route to iO; it does not claim shallow constant layers are uniformly random PRPs. Gay–He–Kocurek–O'Donnell, *Pseudorandomness Properties of Random Reversible Circuits*, https://arxiv.org/html/2502.07159v1, proves approximate k-wise independence for **much deeper** brickwork circuits (Theorems 2–4), which is compatible with this low-depth distinguisher. Critical erratum: https://arxiv.org/abs/2404.14648 is WITHDRAWN; an earlier candidate PRP-from-OWF security proof had an error. The corrected merged paper is https://arxiv.org/abs/2502.07159. Do not use the withdrawn computational claim. We inspected the merged HTML statements and introduction, not all proofs of both cryptography papers.

## Reproduction and bounded result
The committed standard JavaScript checker executes within a fresh V8 isolate. It exhaustively checks all 40320 three-bit permutations and the vanishing cubic ANF coefficient of each of the 3 output bits; verifies degree bounds by Mobius transform for sampled 6-bit composed circuits; verifies higher-order derivative zero for sampled 12-bit depth 1–3 local circuits; and compares independently sampled uniform even permutations. Captured JSON is its exact output. An independent **local-only** standard-library Python checker executed twice byte-identically, with 283573 assertions and 120 local / 120 even-permutation samples per depth (L=1,2,3), all shallow derivatives zero and baseline nonzero counts (65,61,60). These finite checks verify equations and fixtures, not a new hardness assumption.

## Missing obligations / handoff
Still UNPROVED: an actual WE-like protected local frontier; all-ORIGINAL-witness common K; full-public false-instance QPT hiding; unauthorized true-instance K/signature -> accepted Run259 representation -> ORIGINAL/SIS/QPT break; malicious one-honest N-of-N ceremony/abort/erasure and presignature graph; related claims/auxiliary view; concrete 128-bit costs; Bitcoin P2MR/native SLH endpoint. Next: isolate exact externally callable surfaces of a specific candidate protected source-admission/release region before importing reversible-mixer pseudorandomness. Production unchanged; PR draft/unmerged; WKEM stopping condition UNMET.
