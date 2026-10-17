# Run 250 — random-prime specialization rules out prime-created kernel geometry except with negligible probability

## Status

Bounded source/QGGM checkpoint. This run does **not** construct the required practical PQ witness-KEM and does **not** claim a concrete-group post-quantum attack on Hair–Sahai. It addresses the specific handoff left by the conversation-local Runs 248–249: could reduction modulo the paper's enormous sampled prime create a genuinely new, p-scale common-right-kernel direction that was absent from the integer/rational weighted-table presentation?

The answer is essentially **no for the paper's sampled-prime distribution**. For every fixed circuit there is one fixed nonzero integer specialization certificate Δ such that all constraint rank, source-space rank, and common-right-kernel rank/orientation are inherited from characteristic zero for every prime p not dividing Δ. A conservative direct-assignment height bound gives

`log2 |Δ| <= 2^N poly(N)`,

while Hair–Sahai use `p in [2^m,2^(m+1))` with

`m = (N+1)(2NR+1) C(2R,R) = Omega(N^3 log N)`.

Hence the probability that the sampled prime divides Δ is at most

`O(log2|Δ| / 2^m) = 2^{-Omega(N^3 log N)}`.

This rules out **prime-created modular kernel geometry** as the generic surviving escape route. It does **not** prove that the inherited rational kernel has polynomial-magnitude integer lifts; that height problem remains the blocker for turning the Run-248 quotient/LLL route into a universal attack.

## 1. Verified live starting point

Connected GitHub reads before research verified `syscoin/PVUGC#1`:

- branch `research/pq-wkem-validation-20260918`;
- starting head `978e75331da43e8bd80586f74d9eb7813e982b26`;
- PR open, draft, unmerged;
- latest substantive ordinary top-level comment `5945825660`;
- branch-visible Run-245 note blob `0ce778ac35e74f92dd77c8e96279dcea9f6b7d06`;
- branch-visible Run-245 checker blob `cf109612d606f1979fd9b1a1003de99db5af23c7`;
- exact Run-214 note blob `6a67013fda501295e631d5bb17bb7d50c4bd8be5`;
- exact Run-214 checker blob `b38c7eea6c6a2cb387b5dcb1b97ac018c0b03f32`.

No PR-wide diff was fetched. The current head is exactly two research commits ahead of the restored Run-221 head: Run 242 and Run 245.

## 2. Paper facts used

The current paper version checked in this run is Hair–Sahai, arXiv:2609.18275v1, 16 September 2026.

The relevant facts are explicit in the paper:

1. The proved witness-encryption theorem is in the **classical** prime-order generic-group model.
2. The supplied-prime reduction works deterministically for every prime
   `p > max(2^N,2NR)`.
3. With `R=floor(log2 N)`, the rectangular weighted-table matrix has
   `m=(N+1)(2NR+1) C(2R,R)` rows and `N+1` substantive columns before zero padding.
4. The weights are integer polynomials built from
   `ell_{j,t}(b)=sum_i (2^(j-1)t)^i b_i`, `t in {0,...,2NR}`,
   and monomials of total degree at most R.
5. The circuit equations are AND, NOT and acceptance equations with coefficients in `{0,+1,-1}` on Boolean assignments.
6. The scheme samples a prime in `[2^m,2^(m+1))`; prime density in this interval is `Omega(1/m)`. Repeated uniform candidates give expected polynomial time, and the capped sampler has negligible failure probability.

The direct assignment presentation below is used only for a specialization/height proof. It is **not** the paper's polynomial-time Section 4.6 implementation.

## 3. A fixed integer presentation of the compiler space

Fix the Boolean circuit and N. Put

- `B=2^N`, the number of Boolean assignments;
- `n=N+1`, the effective non-zero-padded column width;
- `K=(2NR+1) C(2R,R)`, the number of weights;
- `m=nK`, the rectangular row count.

For each Boolean assignment b, let `A(b)` be the paper's stacked weighted table before zero-column padding. Because every sample t, power of two, Boolean bit, and gate coefficient is an integer, there is an integer matrix

`E in Z^((m n) x B)`

whose b-th column is `vec(A(b))` evaluated over the integers.

Likewise define the integer constraint matrix C with rows indexed by `(gate equation s, weight h)` and columns by assignments:

`C[(s,h),b] = h(b) q_s(b)`.

For every eligible prime p, reducing E and C modulo p gives exactly the assignment presentation of the paper's field construction, and

`S_p = reshape( E_p ker(C_p) )`.

This identity does not require the assignment representation to be unique: the tests are linear functions of the resulting matrix, so every coefficient vector representing a matrix that passes all tests lies in `ker C_p`.

## 4. Specialization certificate

Let

`r = rank_Q(C)`.

Choose any nonzero r-by-r integer minor `delta_0` of C. If `p` does not divide `delta_0`, then

`rank_Fp(C_p)=r`,

because the chosen minor stays nonzero while every `(r+1)`-minor is the zero integer.

### 4.1 Fixed integer kernel generators

Use the chosen pivot minor D. For each free assignment coordinate f, Cramer's rule gives an integer kernel vector by setting its free coordinate to `delta_0` and its pivot coordinates to signed replacement-column determinants. Collect these columns in an integer matrix `K_0`.

Then

`C K_0 = 0` over Z,

and the free-coordinate minor of `K_0` is `delta_0 I`. Therefore for every `p` not dividing `delta_0`, the reductions of these vectors are independent and span all of `ker C_p`.

Set

`Q = E K_0` over Z.

For every such prime, the columns of `Q_p` span the complete source space `S_p`.

### 4.2 Source-rank stability

Let

`k = rank_Q(Q)`

and select a nonzero k-by-k minor `delta_1` of Q. For every prime avoiding `delta_0 delta_1`, the field source has exactly the same dimension k and a fixed selected set of Q-columns is a basis.

### 4.3 Common-right-kernel stability

Reshape those selected Q-columns as the k effective `m x n` source matrices and vertically stack them into

`G in Z^((k m) x n)`.

Let

`s = rank_Q(G)`

and select a nonzero s-by-s minor `delta_2`.

For every prime avoiding `delta_2`, `rank_Fp(G_p)=s`, so the common right kernel has the same dimension `n-s`. More strongly, applying the same Cramer construction to G gives a fixed integer basis for `ker_Q G` whose reduction spans `ker_Fp G_p` whenever `p` avoids `delta_2`.

Thus with

`Delta = delta_0 delta_1 delta_2 != 0`, 

all three objects are inherited from one fixed characteristic-zero presentation for every `p not dividing Delta`:

- constraint-kernel dimension;
- source-space dimension and a fixed source basis;
- common effective right-kernel dimension **and orientation**.

A modular-only kernel direction can occur only at a prime divisor of Delta.

## 5. Height bound for the direct assignment presentation

This bound is deliberately crude; it only needs to beat the paper's enormous prime interval.

Let `H_0` be an upper bound on the bit length of an integer weight evaluation `h(b)`. For

`a = max_{j,t} 2^(j-1)t <= N^2 R`,

we have

`|ell_{j,t}(b)| <= (N+1) a^N`

and therefore, because total weight degree is at most R,

`H_0 = O(N R log(N^2 R)) = O(N log^2 N)`.

The entries of E have magnitude at most the corresponding weight magnitude. On Boolean assignments every standard circuit gate residual `q_s(b)` is in `{-1,0,1}`, so the same bound applies to C.

Hadamard's determinant bound gives, for `B=2^N`,

`bitlen(delta_0) <= B H_0 + (B/2) log2 B + O(1)
                    = 2^N poly(N)`.

The Cramer kernel vectors have the same determinant-scale bit length. Each entry of Q is a sum of at most B products, so its bit length is still `2^N poly(N)`.

Crucially, although B is exponential, the source rank k is at most the rectangular ambient entry count

`m n = poly(N)`.

Therefore Hadamard applied to `delta_1` multiplies the previous bit-length bound by only a polynomial factor. The stack minor `delta_2` has order at most `n=N+1`, so it also has `2^N poly(N)` bit length. In total,

`boxed( log2 |Delta| <= 2^N poly(N) ).`

This is an **existential proof certificate**, not a polynomial-time procedure for computing Delta from the compact Section 4.6 compiler.

## 6. Random-prime consequence

Every prime in the scheme interval satisfies

`p >= 2^m`.

If Delta has t distinct prime divisors in that interval, then

`|Delta| >= (2^m)^t`,

hence

`t <= log2|Delta| / m`.

The interval `[2^m,2^(m+1))` contains `Omega(2^m/m)` primes by the density used in Hair–Sahai's own prime sampler. Repeated uniform integer proposals until the first prime produce a uniform prime from the interval; conditioning the capped sampler on success has the same symmetry. Therefore

`Pr_p[p | Delta] <= O(log2|Delta| / 2^m)`.

Now

`m=(N+1)(2NR+1) C(2R,R)`

and for `R=floor(log2 N)`,

`C(2R,R) >= 2^R >= N/2`,

so

`m >= N^3 R = Omega(N^3 log N)`.

Combining the bounds gives

`boxed( Pr_p[prime-created specialization change]
        <= 2^{-m + N + O(log N)}
        = 2^{-Omega(N^3 log N)}. )`

The checker's intentionally conservative finite bound on `log2(H_Delta / 2^m)` is already about

- `-495.89` at N=4;
- `-739.72` at N=5, where `m=756`;
- `-8796.32` at N=8;
- `-153468.62` at N=16.

These finite numbers are for the stated coarse direct-assignment bound, not exact bad-prime probabilities; the hidden constant is the interval prime-density constant.

## 7. Exact toy specialization check

The deterministic checker includes a genuinely nontrivial orientation test.

It uses an integer constraint matrix

`C=[2,2,2,2]`

and four assignment columns whose effective source matrices generate the row-difference space

`span{ (1,-1,0), (0,1,-1) }`.

The exact certificates are

- `delta_0=2` for the constraint rank;
- `delta_1=4` for source rank two;
- `delta_2=4` for stacked rank two;
- `Delta=32`.

The rational common right kernel is exactly

`span(1,1,1)`.

The checker enumerates every prime up to 97. The only certificate-dividing prime is 2, where all three ranks collapse. For every odd prime, all ranks are unchanged and `(1,1,1)` remains a generator of the one-dimensional common kernel. This finite fixture validates the specialization/orientation logic; it is not evidence for cryptographic security.

## 8. What this changes from Runs 248–249

Run 249 established prime-stability by small explicit determinant certificates for one literal false circuit. This run supplies the generic sampled-prime statement:

> For every fixed circuit, reduction modulo a randomly sampled Hair–Sahai encryption prime almost surely does **not** create a new common-right-kernel geometry. The modular kernel is the reduction of a fixed rational/integer kernel presentation except with probability `2^{-Omega(N^3 log N)}` over the paper's prime sampling.

So the remaining escape route is **not** “perhaps a huge prime happens to induce a strange kernel.”

The remaining question is the arithmetic height of the **inherited rational kernel**. The Cramer certificate above may have coefficients of magnitude `2^{2^N poly(N)}` in this deliberately exponential presentation. That is far too large for Run 248, which needs a quotient chart with polynomially bounded integer representatives so that the quotient bounded box remains short relative to p.

The next bounded pass should therefore analyze the polynomial-size Section 4.6 transition representation itself:

- can its exact rational row/right kernels be maintained with polynomial coefficient height, perhaps by exploiting the binomial transition structure and deterministic pivot order; or
- can one construct a growing circuit family whose inherited rational common kernel provably requires superpolynomial-height primitive generators?

That is a sharper target than more fixed-prime or fixed-circuit specialization checks.

## 9. QPT and application ledger

### Honest model
Classical polynomial-time Hair–Sahai setup/evaluation as published; the direct assignment matrix in this proof is an analysis representation only.

### Attacker model relevance
This checkpoint itself is algebraic and probabilistic over the public prime. It plugs into the prior QGGM exponent-recovery falsification branch only conditionally. It does not assert generic DLOG in a concrete group.

### Assumptions used
Only elementary integer linear algebra, Hadamard determinant bounds, and the same prime-density fact used by the paper's public-prime sampler.

### Exact conclusion
Except with negligible probability over the paper's sampled prime, the source dimensions and common-right-kernel geometry are reductions of a fixed characteristic-zero integer/rational presentation. Prime-created p-scale kernel directions are therefore not a generic hiding mechanism.

### Still unproved

- polynomial-magnitude integer lifts of the inherited rational common kernel;
- a universal Run-248 quotient/LLL attack;
- concrete-group QPT hiding or insecurity;
- false-statement full-public-output QPT hiding for a practical replacement encoding;
- arbitrary-QPT early final-capability recovery implying an ORIGINAL witness or independent PQ break;
- malicious one-honest N-of-N setup/abort/erasure composition;
- practical all-witness-same-key public witness-restricted release;
- the requested end-to-end PQ witness-KEM.

The practical stopping condition remains unmet.
