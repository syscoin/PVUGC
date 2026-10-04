# Consistency-kernel quotient collapse and random-dimension rank-noise tradeoff

## Status

This continuation starts from PR head
`f6eef957b87f3deec26210aab97afa0f29c3162e` and the small-block rank-condenser
checkpoint.

A natural next construction appears to solve the two defects of separate local
blocks at once:

1. force the *joint Fourier support* onto tuples that come from one common
   global representation, eliminating dual splicing; and
2. activate only one (or a few) local safe rank-noise blocks, retaining constant
   honest local bias instead of multiplying `Theta(N)` biases.

The first part works exactly. Unfortunately its complete public output has an
exact public sufficient statistic that removes the consistency mask. For the
random dense condenser family and additive local subspace noises considered
here, the statistic is distributionally just a **random-dimension version of
the previously audited global subspace sampler**. This yields a clean tradeoff:
on the saved false hidden-block fixture, making the completion attack negligible
forces honest rank-one Fourier bias back to the exponentially small safe-boundary
value.

This is a rejection of this additive linear-consistency architecture, not an
impossibility theorem for nonlinear/computational consistency encodings or for
generic PQ witness KEMs.

No external literature or web search was used.

## 1. Candidate: public analysis map plus an annihilator mask

Let the global matrix-frequency space be

    X = F_q^(N x C)

and let local condenser maps be

    L_j : F_q^N -> F_q^(d_j),   j=1,...,T.

Define the global-to-local analysis map

    Phi(M) = (L_1 M, ..., L_T M)                         (1)

into

    Y = direct_sum_j F_q^(d_j x C).

With the Frobenius pairing, its adjoint is

    Phi^*(Z_1,...,Z_T) = sum_j L_j^T Z_j.               (2)

The dual-splicing problem from the preceding checkpoint is that independently
decodable blocks permit an arbitrary tuple `(Z_1,...,Z_T)` even when no single M
has `Z_j=L_j M` for every j.

The candidate adds a random **consistency mask**

    K <- uniform ker(Phi^*)                              (3)

to an arbitrary local noise tuple `Nloc`, and publishes

    O = Nloc + K.                                       (4)

This is attractive because it enforces consistency in the *complete* Fourier
spectrum, not only in an intended decoder.

### Theorem 1 — exact Fourier support

For every local frequency `Z in Y`,

    E[chi_Z(O)]
      = 1[ Z in im(Phi) ] * E[chi_Z(Nloc)].             (5)

Proof: averaging the character over uniform `K in ker(Phi^*)` gives one exactly
on `(ker Phi^*)^perp = im(Phi)` and zero elsewhere.

Thus the exact two-block splicing frequency from
`RANK_CONDENSER_AND_DUAL_SPLICING.md` is killed, while both honest consistent
frequencies survive.

So far the candidate does exactly what was wanted.

## 2. Complete-public-output audit: the mask has a public sufficient statistic

Equation (5) is not enough. Apply the public adjoint to the actual output:

    S := Phi^* O
       = Phi^* Nloc,                                    (6)

because `Phi^* K=0`.

More strongly:

### Theorem 2 — exact quotient normal form

For **any** distribution of `Nloc`, conditioned on

    S=s,

the variable O is uniform on the affine fiber

    (Phi^*)^(-1)(s).                                    (7)

Indeed, for every fixed n with `Phi^* n=s`, `n+K` is exactly uniform on that
fiber, and mixtures of the same uniform fiber are unchanged.

Consequently O is exactly simulatable from S and fresh key-independent
randomness:

1. solve the public linear system `Phi^* y0=s`;
2. sample `k <- uniform ker(Phi^*)`;
3. output `y0+k`.

Therefore S is a complete public sufficient statistic for every key-dependent
property of O. The consistency mask removes inconsistent Fourier labels, but it
does **not** hide the quotient.

This is the same structural issue as the earlier public-quotient results, now
applied to the proposed multi-block consistency layer.

## 3. What the quotient is for local rank noise

Suppose one local block J is selected and all other blocks are zero. Then

    Nloc = (0,...,E'_J,...,0)

and (6) is simply

    S = L_J^T E'_J.                                     (8)

This is exactly the lifted local-noise object audited in the preceding
checkpoint.

For multiple active blocks,

    S = sum_(j active) L_j^T E'_j.                      (9)

Thus the consistency layer converts "separate blocks" back into the additive
global lift before an adversary has to do anything nonlinear.

### Theorem 3 — random dense local lifts are a global subspace mixture

Fix a local `m`-subspace `U_j <= F_q^(d_j)` and take uniform dense `L_j`.
The restriction

    L_j^T |_ U_j : U_j -> F_q^N

is a uniform `N x m` linear map. Let its image be `W_j`.

Conditioned on `dim(W_j)=r_j`:

* `W_j` is a uniform `r_j`-subspace of `F_q^N`;
* every lifted noise column is uniform in `W_j`.

For independent active blocks, put

    W = sum_j W_j,     R=dim(W).

A sum of independent uniform vectors from the `W_j` is uniform in W, so every
column of (9) is independent uniform in W. The joint law of the `W_j` is
`GL(N,q)`-invariant, hence conditioned on `R=r`, W is uniform among all
r-subspaces.

Therefore (9), averaged over the random-map setup used by the condenser
construction, is **exactly**:

    choose a random dimension R;
    choose a uniform R-subspace W <= F_q^N;
    sample each output column independently uniform in W.              (10)

This is the previous global random-subspace sampler with a random support
dimension. The small local ambient dimensions do not survive the public
quotient as a new distributional primitive.

This theorem concerns the random dense maps used in the current condenser
proposal. It does not rule out every deterministic/non-invariant condenser
family.

## 4. Arbitrary dimension mixtures: exact correctness/security tradeoff

Let

    pi_r = Pr[R=r],   r=0,...,N.

For a fixed nonzero rank-one frequency, the exact honest Fourier coefficient of
the r-dimensional global subspace sampler is

    a_r
      = [N-1 choose r]_q / [N choose r]_q
      = (q^(N-r)-1)/(q^N-1).                            (11)

Hence the mixture has honest rank-one bias

    alpha = sum_r pi_r a_r.                             (12)

Now use the saved false hidden-block diagnostic with a hidden `D x D` corner.
For `r <= N-D`, the public Schur-complement completion attack succeeds whenever
the visible lower-right block has rank r. Its exact probability is

    p_comp(r)
      = q^(D r)
        [N-D choose r]_q / [N choose r]_q
        product_(i=0)^(r-1) (1-q^(i-(N-D))).            (13)

For `r>N-D`, this particular pivot event is impossible.

Define the positive field constant

    c_q = product_(j=1)^infinity (1-q^(-j)).             (14)

For every `0 <= r <= N-D`,

    p_comp(r) >= c_q^2.                                 (15)

Proof: write the first factor in (13) as

    product_(i=0)^(r-1)
      (1-q^(-(N-D-i))) / (1-q^(-(N-i))).

Dropping the denominators only decreases the lower bound, and both this
numerator product and the final full-rank product in (13) are finite
subproducts of the factors defining `c_q`, hence each is at least `c_q`.

Let

    mu = Pr[R <= N-D].

The complete-output attack on the diagnostic false family therefore has

    P_attack >= c_q^2 mu.                               (16)

On the complementary safe dimensions `r >= N-D+1`, monotonicity of (11) gives

    a_r <= a_safe
         := (q^(D-1)-1)/(q^N-1).                        (17)

Combining (12), (16), and `a_r<=1` on the unsafe part yields

    alpha
      <= mu + a_safe
      <= P_attack / c_q^2
         + (q^(D-1)-1)/(q^N-1).                         (18)

### Consequence

Within this random-subspace-mixture architecture, if the saved false-instance
completion attack is required to have negligible probability, then for fixed
semantic threshold D and growing N the honest rank-one bias is at most

    negligible + Theta(q^(-(N-D+1))).                   (19)

So randomizing the number of active local blocks, using a one-block selector, or
mixing "unsafe high-signal" and "safe low-signal" branches does not evade the
earlier efficiency boundary. Any nonnegligible mass on the high-signal
low-dimensional branches gives the complete-output completion attack
nonnegligible mass as well.

This is stronger than the preceding fixed-dimension observation but still only
for the additive `GL(N)`-invariant subspace-mixture family and the stated
diagnostic false relation. It is not a universal lower bound for all WKEMs.

## 5. Explicit dual-splicing repair followed by quotient collapse

For the exact F2 dual-splicing fixture, use

    M(x) =
      [1  0]
      [0  1]
      [x 1+x],

with

    L1 = rows {1,3},
    L2 = rows {2,3}.

Vectorizing matrices makes Phi an `8 x 6` full-column-rank binary matrix.

The inconsistent tuple

    (L1 M(1), L2 M(0))

is **not** in `im(Phi)`, while both

    (L1 M(0), L2 M(0)),
    (L1 M(1), L2 M(1))

are. Uniform `ker(Phi^T)` masking therefore gives the spliced tuple Fourier
coefficient exactly zero and the honest tuples coefficient one.

But the public statistic (6) is

    Phi^*(Z1,Z2)
      = vec(L1^T Z1 + L2^T Z2),                         (20)

so a selector-local noise tuple is immediately converted into the same lifted
matrix object from Section 3.

This is a useful negative result: the candidate genuinely repairs the local
Fourier splicing defect, yet the *complete public output* still collapses to the
previously problematic global lift.

## 6. Validation actually executed

`consistency_quotient_check.py` uses only the Python standard library.

Fresh checks in this run:

1. **Exact quotient sufficiency over F2.**
   A full-column-rank `5 x 3` Phi, a deliberately nonuniform six-element local
   noise multiset, and all four kernel masks were exhaustively enumerated.
   Every conditional output fiber given `Phi^* O` is exactly uniform, and all 32
   Fourier modes obey (5).

2. **The exact dual-splicing fixture.**
   The vectorized map is `8 x 6` with kernel size four. Both honest consistent
   modes survive the kernel mask; the inconsistent `(x=1,x=0)` splice has
   character exactly zero. One hundred fresh random local matrices verify the
   adjoint identity (20).

3. **Sum-of-local-subspaces normal form.**
   All ordered pairs of the seven one-dimensional subspaces of `F2^3` were
   enumerated with two independent noise columns. Pair-sum ranks occur 7 times
   at rank one and 42 times at rank two. Conditioned on rank, every sum
   subspace has equal multiplicity; conditioned on the sum subspace, every
   matrix in `W^2` has equal probability.

4. **Completion and rank-one formulas.**
   For `(q,N,D)=(2,4,2)`, every global subspace and every complete `4 x 4` noise
   matrix were exhaustively enumerated for `r=0,1,2`:
   - `r=0`: attack `1`, honest bias `1`;
   - `r=1`: attack `144/240=3/5`, honest bias `7/15`;
   - `r=2`: attack `1536/8960=6/35`, honest bias `1/5`.
   These equal (11) and (13) exactly.

5. **Arbitrary mixture inequality.**
   One thousand fresh rational dimension mixtures were checked against the
   finite-product version of (18), using
   `c_(2,4)=prod_(j=1)^4(1-2^-j)=315/1024`; all passed.

These are exact finite algebra/distribution checks. They are not evidence for
a missing computational hardness theorem.

## 7. Current boundary

This run rules out a particularly natural attempt to combine the previous
small-block condenser with a public linear consistency layer:

    local condensers
      -> uniform annihilator mask to kill splicing
      -> random selector / few active safe local rank-noise blocks.

The Fourier consistency property is real, but the complete transcript has the
public quotient `Phi^*`, and under the current random dense local maps the
quotient is exactly a random-dimension global subspace sampler. Requiring the
saved complete-output false attack to be negligible then restores the
exponentially small honest signal.

What remains genuinely open is therefore narrower:

* a **nonlinear or computationally hidden consistency coupling** whose complete
  public output has no efficiently removable linear quotient;
* or a different inner PQ primitive whose security reduction handles the global
  representation directly and can invoke the existing source extractor;
* followed by the still-required final-key QPT recovery -> source-witness /
  independent-hardness reduction and malicious-secure setup/resource analysis.

The earlier full-verifier input-label compiler remains rejected; nothing here
reintroduces it. No completed generic PQ WKEM is claimed.
