# SAI101 — Serialized sparse high-degree Boolean-ideal release trial (NONQUALIFYING)

## Starting point and new operation

Live syscoin/PVUGC PR #1 was inspected on branch research/pq-wkem-validation-20260918 at 00dd1a4eaae44f5dc38c43507d3f38d7884d92d2 (SAI100), with its exact SAI100 note and the SAI99 predecessor read. Issue comments since November 18 returned none. No Syscoin Core source/tests were used in this iteration.

The specific missing operation attempted was a polynomial-time *serialized public* Build/Open, unlike R327's private-coefficient oracle and SAI100's setup-picked unpredictable lookup labels. This attempt chooses high-degree sparse masks, multiplies by actual published Boolean source-gate polynomials, fully expands and canonicalizes the resulting polynomial, and publishes only its coefficient list. It has all-witness common-value correctness for its synthetic Boolean circuit, not for the ORIGINAL source verifier. It is provably insecure in the tested distribution. Do not treat it as a WE or FE advance.

## Concrete public Build/Open

Work over the Boolean quotient B_n = F_2[z_0,...,z_(n-1)]/(z_i^2-z_i). Encode source checks as public constraints f_j(z)=0 with at most s monomials of degree at most d. The checker uses exact SHA-Ch Boolean constraints

    f_Ch(x,y,z,t) = t + z + xy + xz

plus f_0=1+z_0, ensuring that the capsule's public constant coefficient is not just K.

Build selects independent 256-bit K and S and chooses a polynomial count of hidden sparse high-degree monomial masks Q_j(z) = sum_C b_(j,C)*z^C, with 256-bit independent b coefficients. The builder *expands* (not obfuscates) the complete public polynomial

    P(z) = K XOR sum_j f_j(z)*Q_j(z)
    D = S XOR K
    C = (public verifier/statement, full normalized P coefficients, D).

For any satisfying w, all f_j(w)=0, so P(w)=K and Open(C,w)=D XOR P(w)=S. This is genuinely polynomial-size in the chosen sparse masks and small source-constraint supports and needs no retained private evaluator or on-chain source verifier. But unrestricted public inspection defeats security.

## Degree-independent sparse-support public extractor

Let A be a monomial support in the fully public P. If a hidden mask monomial C contributes through a monomial B from public f_j, then Boolean multiplication requires A=B union C. Accordingly, B subset A and A\B subset C subset A. Since |B| <= d, at most 2^d possible C correspond to a fixed A,B.

The attacker enumerates

    Cand = union_{A in supp(P)} union_{j,B in supp(f_j), B subset A}
           { (j, (A\B) union U) : U subset B }.

The candidate count is at most |supp(P)| * m * s * 2^d, independent of the large degree of Q_j. For each candidate form the PUBLIC column g_(j,C)=f_j*z^C. Assemble and solve the coefficient equations

    coeff_A(P) = [A=empty]*K XOR sum_(j,C in Cand) coeff_A(g_(j,C))*b_(j,C).

This is a GF(2) linear system with 256-bit right-hand sides. The solver recovers K without any source witness if (i) the true masking decomposition is expressible over Cand and (ii) the constraints have a satisfying assignment. For (ii), if two solutions had distinct K, subtracting them would yield 1 in the constraint ideal. Evaluating at a true witness gives 1=0, a contradiction. Thus any consistent decomposition has the same K. The extractor need not know that witness. Condition (i) is guaranteed when each mask monomial appears in at least one surviving output term; destructive cross-mask cancellations can invalidate the sufficient condition, so no universal theorem for all compact encodings is claimed.

For fixed small d, this is polynomial public-coefficient extraction even with Q degree Omega(lambda). It differs from R327's 2^D black-box evaluation bound by **using the complete serialized sparse public encoding**. It neither supplies an independent original-source reduction nor rules out genuinely dense computational encodings.

## Executed checker and outputs

The exact Python 3 checker is committed beside this note. It builds eight synthetic systems, each with eight Ch gates and a fixed anchor among 32 Boolean bits; chooses 256-bit K and S and sparse mask monomials of degree roughly 10-23, deliberately outside each gate's local variable set; computes expanded P; checks correctness on a satisfying assignment; and gives the *attacker* only P and public constraints, NOT the witness or the sampled masks. It enumerates candidate supports, solves coefficient equations over GF(2), and recovers K and S in all eight seeded fixtures. The public constant coefficient is different from K in all eight. Two actual executions were byte-identical with exit code 0.

Actual maximum expanded degree: 24 or 25. Each capsule had 104 public monomial terms. Candidate support counts by seed: 2993, 2715, 2833, 2817, 3079, 2997, 3025, 2991. All eight had zero hidden mask monomials omitted by Cand and correct recovery. These are small synthetic data and do not test Bitcoin, SHA256d end-to-end, Core consensus, ChainLocks, native cancellation, or any QPT attack.

Exact local checker SHA256: 7408dfd18d1515bfcd00e2c6ccfc510b29e55a68d192af5cc0124ff0d01dbf9e.
Two local-only captured JSON outputs SHA256: 0f332ffbc62523aacf8764d16cf6e0b6e60902b2dbbf9c896951215752abd87e.
Full original local derivation SHA256: d0096cea4b21103c9cd11f96212aed2bc2119415cea7bc6491578b1448c8a8c8.
Output JSON files and the longer note are local-only and are not claimed to be GitHub-published.

## Constructive repair verdict and exact next equation

The high-degree sparse public encoding closes a *serialization* interface but fails secrecy. Raising degrees or rearranging sparse mask bases cannot suppress the displayed support-based linear recovery when the visibility condition holds. Densely expanding random masks is exponential. Publishing a compact private-keyed arithmetic circuit instead would require an independently implemented concealed public program/FE primitive; simply naming that operation does not instantiate it.

The original three independently usable OR challenge grounds, post-PQ contextual chain ID and strict tags, claim-prefix source relevance/maturity, outer-carrier fault authentication, no-PoB proof discipline, N-of-N one-honest setup, full native cancellation message/VK binding, and all hard-TRUE/FALSE/QPT/malicious-source requirements remain intact.

Missing is still an actual classical-PPT hash-only Build_original(x_W,sigma_cancel;rho)->C with public Open_original(C,w)=the SAME frozen safe cancellation capability for every qualifying ORIGINAL witness, and a joint full-public FALSE/hard-TRUE QPT reduction from unauthorized recovery or accepted native forgery to an ACTUAL ORIGINAL certificate or independent justified hash/native break. No such construction was found. No user progress comment or breakthrough notification, production write, deployment, or automation change is warranted.