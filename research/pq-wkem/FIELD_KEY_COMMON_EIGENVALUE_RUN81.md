# Run 81 — direct field-key MinRank capsule with common-eigenvalue decapsulation

**Status:** constructive improvement to Run 79's honest decoding and KEM interface. It gives a classical, statement-only, public/offline capsule in which any valid witness recovers the same direct field key with high probability while allowing the randomizer rank to increase from `r<t/2` to `r<t`. It does **not** prove false-statement QPT hiding or arbitrary-QPT source extraction, so it is not the completed PQ WKEM.

**Starting verified PR head:** `c4a33a018607bda7d8e8b1d646d54df9c399e22e`.

The attempted opening Run-81 GitHub checkpoint was blocked by the tool safety layer before reaching GitHub. In accordance with the publication rule, that blocked write was not retried or rerouted in this run. The artifacts below are therefore local-only unless a later run independently needs them for current research and has write access.

No production path is changed.

## 1. Why revisit Run 79 correctness

Run 79 encoded a bit by shifting a witness-visible low-rank matrix by `mu I_t` and required the deterministic separation

    2r < t.

That condition throws away about half of the allowable randomizer rank. The complete-output Fourier suppression is exponential in `r`, so increasing `r` is directly valuable.

For a rank-one honest source matrix, the witness-visible random matrix has substantially more structure than the worst-case statement "rank <= r". Exploiting that exact distribution yields a stronger decoder.

## 2. Source interface and field choice

Work over a prime field `F_q`; the same algebra extends to finite fields.

Use the Hair–Sahai/derived field-flexible source interface:

* public basis `B_1,...,B_k`;
* public anchor functional `ell`, with coordinates `ell_i=ell(B_i)`;
* every valid Boolean source witness supplies coefficients `a` satisfying

      B(a)=sum_i a_i B_i = x y^T != 0,
      ell(a)=1;

* for a false statement every nonzero source codeword has rank at least `D`;
* a supplied sufficiently low-rank source codeword remains subject to the explicit source extractor.

The source compiler and its algebraic rank/extraction theorem are reused only as an algebraic component. The classical generic-group encryption theorem from Hair–Sahai is **not** imported.

The field may be much larger than the minimum needed by the algebraic compiler. This is useful for correctness below because the bit length of a field element, not the field's numeric magnitude, controls arithmetic complexity.

## 3. Construction — two capsules, one direct key

Fix block count `t` and randomizer rank parameter

    1 <= r < t.

Let `J_t` be the all-one `t x t` matrix and lift

    M_i = J_t tensor B_i.

Sample the final KEM key `K` directly from a public key subset `KSet subset F_q`. For example, if `q>2^lambda`, the canonical residues `0,...,2^lambda-1` encode exactly `lambda` key bits. There is no one-way KDF between the recovered algebraic key and the final key in this core interface.

For capsule `h in {1,2}`, independently sample

    R_h = sum_{j=1}^r u_{h,j} v_{h,j}^T

with uniform vectors of the appropriate dimension.

Publish for every source-basis coordinate

    C_{h,i}
      = <R_h, M_i>_t + K ell_i I_t.                    (1)

Setup knows the statement and fresh randomness but no witness.

A valid witness `a` forms

    D_h(a)
      = sum_i a_i C_{h,i}
      = <R_h, J_t tensor B(a)>_t + K I_t.              (2)

## 4. Exact honest distribution

Write the honest source codeword as

    B(a)=x y^T,

with nonzero vectors `x,y`.

Partition each `u_{h,j}` and `v_{h,j}` into `t` source-sized blocks. Define

    U_h[p,j] = <u_{h,j,p}, x>,
    V_h[q,j] = <v_{h,j,q}, y>.

Because `x,y` are nonzero and the original blocks are independent uniform field vectors, `U_h,V_h` are independent uniform matrices in `F_q^(t x r)`.

A direct blockwise calculation gives

    <R_h, J_t tensor x y^T>_t = U_h V_h^T.              (3)

Hence every valid witness sees exactly

    D_h = X_h + K I_t,
    X_h = U_h V_h^T,                                   (4)

where the two `(U_h,V_h)` pairs are independent and uniform.

The **distribution** of the pair `(D_1,D_2)` is therefore the same for every valid witness, with the same embedded `K`.

## 5. Decapsulation by common field eigenvalue

Since `rank(X_h)<=r<t`, zero is an eigenvalue of `X_h`. Therefore `K` is always an `F_q` eigenvalue of each `D_h`.

The witness computes both characteristic polynomials and finds their common `F_q` roots. If there is exactly one common root lying in `KSet`, output it; otherwise return failure.

Finite-field characteristic-polynomial computation, polynomial gcd, and finite-field root factoring are probabilistic polynomial time in `t` and `log q`. Honest users remain classical.

## 6. Correctness theorem

Define

    p_def(t,r,q)
      = 1 - product_{i=0}^{r-1}(1-q^(i-t)),             (5)

the probability that a uniform `t x r` matrix is not full column rank, and

    p_sing(r,q)
      = 1 - product_{j=1}^{r}(1-q^(-j)),                (6)

the probability that a uniform `r x r` matrix is singular.

### Lemma 1 — fixed nonzero spurious eigenvalue

For every fixed `delta != 0`,

    Pr[delta is an eigenvalue of X_h]
      <= p_def(t,r,q) + p_sing(r,q).                    (7)

**Proof.** Condition on `U_h` having full column rank. The map

    V_h^T -> V_h^T U_h

is then a surjective linear map row-by-row, so `V_h^T U_h` is a uniform `r x r` matrix.

Sylvester's determinant identity gives

    det(z I_t - U_h V_h^T)
      = z^(t-r) det(z I_r - V_h^T U_h).                 (8)

For `delta != 0`, `delta` is therefore an eigenvalue of `X_h` exactly when `V_h^T U_h-delta I_r` is singular. Translation by `delta I_r` preserves uniformity, so this conditional probability is `p_sing(r,q)`. Pessimistically count the rank-deficient `U_h` event to obtain (7). ∎

Useful elementary bounds are

    p_sing(r,q) < 1/(q-1),

    p_def(t,r,q)
      <= sum_{i=0}^{r-1} q^(i-t)
      < q^(r-t)/(q-1).                                  (9)

Thus

    p_delta < (1+q^(r-t))/(q-1).                        (10)

### Theorem 1 — per-witness same-key correctness

For any fixed valid witness,

    Pr[Decaps fails]
      <= r [p_def(t,r,q)+p_sing(r,q)]
      < r(1+q^(r-t))/(q-1).                             (11)

**Proof.** `K` is always a common root. A different common field root has form `K+delta` with `delta != 0`, where `delta` is a nonzero eigenvalue of both independent `X_1,X_2`.

The first matrix `X_1` has at most `r` distinct nonzero eigenvalues because `rank(X_1)<=r`. Condition on `X_1`. For every such eigenvalue, apply Lemma 1 to independent `X_2` and union bound. Restricting to roots in `KSet` can only decrease the failure probability. ∎

The theorem holds for **any** valid witness and all witnesses target the identical sampled key `K`. It is stronger than Run 79's `r<t/2` condition because it permits

    r=t-1.                                               (12)

At `r=t-1`, the simple bound is approximately `r/q`.

### Strong simultaneous-all-witness interpretation

If one requires a single encapsulation to decapsulate correctly for every valid Boolean witness simultaneously, there are at most `2^N` witness assignments. A direct union bound gives

    Pr[exists valid witness with ambiguity]
      <= 2^N r [p_def+p_sing].                          (13)

This can be made negligible by choosing a field with `O(N+lambda+log r)` bits. Field arithmetic remains polynomial, but making every matrix entry `Theta(N)` bits may be unattractive in practice for large source circuits.

Alternatively, with a roughly `lambda`-bit field and `L` independent capsules carrying the same `K`, the per-witness ambiguity falls at most as

    r [p_def+p_sing]^(L-1),

and then one may union-bound across witnesses. This trades ciphertext expansion for field size.

For the project's "every witness" requirement, the strong simultaneous version must be kept distinct from the usual pointwise correctness statement during parameter selection.

## 7. Direct KEM key instead of a bit-by-bit wrapper

A conceptual improvement is that (1) transports a **single field element**, not one bit.

Choose a public `2^lambda`-element subset of `F_q` and sample `K` uniformly from it. Decapsulation returns that exact element. This avoids an additional one-way KDF in the core source-extraction interface.

Why this matters: a conventional one-way KDF would preserve false-instance key privacy but could break the proof obligation

    recovered FINAL key -> recovered algebraic K -> source witness / PQ break,

because recovery of `H(K)` does not generally imply recovery of `K`.

A later concrete API can encode the selected field element canonically as `lambda` bits.

## 8. Complete-public-output Fourier theorem over `F_q`

The Run-79 Fourier calculation extends directly.

For each capsule `h`, let a complete-output additive character be indexed by matrices `Lambda_{h,i} in F_q^(t x t)`. Define the block matrix `N_h` whose `(p,q)` source-sized block is

    N_h[p,q] = B(a_h^{pq}),
    (a_h^{pq})_i = (Lambda_{h,i})_{pq}.                 (14)

For any fixed nontrivial additive character `psi` of `F_q`,

    E[ psi( sum_i <Lambda_{h,i},
                    <R_h,M_i>_t>_F ) ]
      = q^(-r rank(N_h)).                               (15)

Independence of the two capsules gives magnitude

    q^(-r(rank(N_1)+rank(N_2))).                        (16)

The key shift contributes phase

    psi(K sigma),

    sigma
      = sum_h sum_i ell_i tr(Lambda_{h,i}).             (17)

For two distinct keys `K,K'`, a character can distinguish them only if

    (K-K') sigma != 0,

hence `sigma != 0`. Then at least one capsule `h` has nonzero

    sigma_h=sum_i ell_i tr(Lambda_{h,i}).

At least one diagonal coefficient vector in that capsule has nonzero anchor. It is therefore a nonzero source codeword. On a false statement, its block has rank at least `D`, so

    rank(N_h)>=D.                                       (18)

Consequently every key-sensitive complete-output linear character has magnitude at most

    q^(-rD).                                             (19)

With `r=t-1`, this nearly doubles the rank exponent available in Run 79's deterministic `r<t/2` regime.

This theorem is information-theoretic algebra. It applies equally against classical and quantum distinguishers **if** it can be upgraded to a sufficiently small full statistical distance. The present individual-character bound does not do that.

## 9. The central security barrier remains

There are two capsules, each containing `k t^2` field elements. The ambient additive group therefore has dimension

    L = 2 k t^2

over `F_q`.

A minimum-rank-only Parseval/Cauchy bound gives roughly

    TV(P_K,P_K')
      <= q^(k t^2-rD).                                  (20)

The exact rank-weight spectrum may be much smaller than this crude count, but with only the minimum gap it is useless in the current Hair–Sahai parameter regime.

Increasing `q` dramatically improves honest common-eigenvalue correctness, but **does not rescue (20)** when its exponent is positive; in fact it makes that crude upper bound grow.

Therefore this run improves correctness and the KEM interface, not false-statement security.

## 10. Quantum-security classification

### Honest algorithm model

* setup/encapsulation: classical randomized polynomial time;
* witness decapsulation: classical randomized polynomial time because finite-field factoring may be randomized;
* no participant is needed online after setup.

These are compatible with a post-quantum scheme.

### Adversary model proved in this run

None beyond information-theoretic algebraic identities and correctness probability. The construction has **not** been proved hiding against PPT or QPT adversaries.

### Hardness assumptions imported

None for Theorem 1 and (15)-(19). Hair–Sahai's algebraic source compiler/extractor is reused, but its classical generic-group encryption security is not.

CMV's planted-MinRank PKE is relevant to the blockwise duality mechanism, but its public generators are uniformly random whereas ours are statement-derived. Its paper states ordinary polynomial-time security under planted MinRank; the paper motivates MinRank as a plausible post-quantum problem but does not give the QPT source-extraction theorem required here. No CMV security theorem is imported.

### Required endpoint still missing

We still need both:

1. false-statement hiding against arbitrary QPT adversaries for the **complete public output**;
2. arbitrary-QPT early recovery of the **final key** on a true statement implies an ORIGINAL source witness or breaks an independently justified QPT-hard assumption.

A classical attack would refute this target. Absence of a classical attack would not prove it.

## 11. Validation actually executed

The deterministic standard-library checker was executed twice with byte-identical stdout.

It validates:

* 360 exact identities showing that a valid rank-one source witness sees precisely `U V^T`;
* exhaustive `q=3,t=2,r=1` fixed-spurious-eigenvalue probabilities and exact two-capsule ambiguity probability;
* randomized direct field-key recovery controls at `(q,t,r)=(17,4,3),(257,4,3),(257,6,5)`, with the true key never absent;
* 700 complete-output block-character identities on a small false source code over `F_3`;
* 24 exact additive-character magnitude checks by exhaustive rank-one-mask enumeration;
* every sampled key-sensitive character in that false fixture retaining the source rank gap;
* simultaneous-all-witness correctness parameter tradeoff controls;
* explicit controls showing the two-capsule minimum-rank-only spectral bound remains vacuous.

These validate finite algebra/distributions only. They are not evidence of cryptographic security or QPT hardness.

## 12. Handoff

This run changes the useful parameter frontier:

* old deterministic decoder: `r<t/2`;
* new two-capsule common-eigenvalue decoder: any `r<t`, including `r=t-1`;
* final KEM key can be a direct field element rather than a bit-by-bit wrapper;
* every key-sensitive linear character on a false instance still inherits the source rank gap, now with the larger exponent `rD`.

The next security question remains the rank-weight spectral mass of the **actual** statement-derived source space, or a QPT-valid reduction of its complete distribution to an independently justified PQ assumption. If neither is achievable, the larger `r` only improves a candidate whose hiding is still unproved.

The generic-NP practical PQ WKEM stopping condition is **not met**.
