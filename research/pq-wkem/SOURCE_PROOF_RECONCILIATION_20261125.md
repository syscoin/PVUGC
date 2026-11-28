# Proof-response reconciliation as a release repair — 2026-11-25 UTC

Status: rejected candidate; no missing-advance result, no native operation executed, no notification or PR comment.

## Continuity and selection

Actual syscoin/PVUGC PR #1 was open/draft/unmerged, branch research/pq-wkem-validation-20260918, start 5eb696b251b52c5bbba0d3ba438ec39d5a29f2bc. Read PR metadata, recent substantive comments through R225, exact head commit file metadata, and SOURCE_TRANSPARENT_CHALLENGE_SWITCH_20261125.md (blob b9a34db8a8158e4b5b65b082d61e5764536d8cca). Rechecked head and checked this new path absent (404). No external literature, full PR diff, or new Core claim.

Missing original operation: turn an arbitrary qualifying original certificate into the same fixed safe native capability as the setup's native-witness branch, without public recovery otherwise. The previous note achieved identical transparent first messages for a witness-preserving Hamiltonian-cycle proof of the tagged OR but independent hashes of its two distinct cycle responses gave unrelated pads. The mathematical change tested here is reconciliation BEFORE hashing: use a public error-correction helper to make different legitimate responses recover the same random pad. This is a foundation repair attempt, not packing or performance optimization. It does not demand that original witnesses are equal, nor assume access to a secret evaluator, low-degree private trace-coefficient oracle, or input-label switching oracle. The previous distinct-transcript hash-collapse argument does not directly apply because both openers would hash exactly the same recovered codeword.

## Concrete proposed Build and Open

Retain the previous note's conditional witness-preserving compiler: the bounded full original predicate R_x(w) includes all three OR grounds, and the other tagged branch is V_x(S) for the exact frozen native verification key and cancellation message in x. Let G_x be the resulting graph on n vertices; a qualifying source witness and the setup native signature each map to a Hamiltonian cycle. The setup publishes the prior transparent first message and its complete permutation/salt opening. For this trial only, use a response representation t in {0,1}^m, m=n^2, as the directed edge-incidence vector of a cycle in that permuted graph. Each honest response has exactly n ones. This is a mathematical encoding conditional on the same compiler; no actual source circuit or graph was constructed.

Take a field F of size at least m, e.g. GF(2^ceil(log2(m+1))), distinct evaluation points a_i, radius r=2n and k=m-2r>0 for n>4. Sample a uniformly random degree <k polynomial P over F, set c_i=P(a_i), and use an independently domain-separated ideal KDF with output length |S|. The new serialized fields are

    D_i = c_i + t_S,i
    E = S XOR KDF(ctx, canonical(c)).

Build obtains t_S from the native branch using S. Open obtains t_w from the full original witness branch, then applies unique Reed-Solomon decoding at radius r to D-t_w, and returns E XOR KDF(ctx, canonical(c_decoded)). The ordinary native verification can check the recovered capability, but is not considered access control. All code parameters and helper data are public, and setup can erase P and S after construction.

The honest reconstruction equation is exact:

    D - t_w = c + (t_S - t_w),
    wt(t_S - t_w) = 2(n - |supp(t_S) intersect supp(t_w)|) <= 2n.

Thus this candidate solves the previous pad mismatch at the level of honest correctness, for EVERY encoded qualifying original witness, conditional on the compiler. No witness-dependent random-oracle programming is needed. It does not change the native endpoint or require revealing the original witness on Bitcoin.

For clarity the decoder can be classical PPT without an assumed black box: given y, solve the linear equations Q(a_i)=y_i L(a_i) for monic L of degree r and Q of degree <=k+r-1. If there are at most r errors, take L with roots at all error coordinates (multiply by any monic polynomial to degree r), Q=P L. Any solution satisfies Q(a_i)=P(a_i)L(a_i) at at least m-r points. The difference Q-P L has degree at most k+r-1=m-r-1, so is identically zero. Division recovers P. This also proves uniqueness, including when fewer than r positions are wrong. Implementations can reject malformed or nondivisible solutions; on the promised radius no ambiguity occurs. This is a static derivation, not a claimed execution or a parameter recommendation.

## Joint simulator attempt and rejection before implementation

Try to simulate public helper fields while withholding S, using a pseudorandom codeword pad and an independent uniform E. This is not a sound hybrid. The public vector D itself has distance exactly n from c, since t_S is a cycle. As r=2n, the SAME classical decoder with the public zero approximation recovers c exactly. The pad is then publicly determined and E decrypts to S. In the simulated hybrid the decrypted value is uniform rather than the fixed capability; the public native check is available to distinguish an accepted native signature from a random string whenever that check has negligible random acceptance. Even without that acceptance-rate assumption, the direct exact-recovery failure of the real distribution is unconditional on KDF security. No source certificate is used. FALSE original instances still contain the native OR witness in the trial graph, so correctness of the attack on the proposed capsule does not require the original relation to be TRUE. This is a rejection of this candidate, not a security finding about existing bridge code.

The zero approximation is not a Hamiltonian cycle; a public Open if-check for R_x does not affect what can be computed from D. This distinction is precisely why proof soundness and native verification do not repair the release. No actual native key, signature, or deployed capsule is involved.

## Screen the natural radius/representation repair

A smaller radius r' would work only if EVERY relevant source cycle satisfies |supp(t_S) intersect supp(t_w)| >= n-r'/2. For any public approximation z with d(z,t_S)<=r', the public helper already suffices for the same recovery. In the incidence representation two explicit public centers are the all-zero vector (distance n) and the full permuted graph adjacency vector (distance |E(G_x)|-n). In particular r'>=min(n,|E(G_x)|-n) is immediately rejected. A public coordinate permutation or coordinatewise field translation preserves these distances, with the centers transformed accordingly. It is not a repair. These are statements about this decoder and encoding; no claim that every possible compiler has disjoint cycles or that every dense encoding admits such a public center.

A genuinely different reconciliation repair would need a classical-PPT encoding A_x of every branch response and an explicit decoding helper such that (1) all original witnesses provide side information within decoding range of A_x(S), (2) no public-only or unauthorized algorithm can recover its pad from the complete helper and auxiliary view, and (3) construction and simulation do not require enumerating future witnesses or a retained source secret. Merely proving a diameter bound for honest responses does not prove (2); a secret coordinate map requiring a new conditional evaluator to be applied by Open does not implement (1). No smaller radius sweep, dense basis change, toy circuit, source-pad tests, or additional coding work was undertaken. The next candidate must supply a mathematical reason for computationally hidden common side information, rather than assuming it or optimizing this code.

This static attempt leaves the original source dependence unsolved. It does not alter source authentication, claim/height/work/maturity constraints, all three OR grounds, R225 slot-global versus activation-specific scope, R316 coverage correction, malicious setup, QPT model, or the exact-signature versus accepted-forgery distinction. No full-public QPT reduction, actual graph compiler, native signing, tests, external reads, or executable qualifying Build/Open was produced. No ordinary PR comment.
