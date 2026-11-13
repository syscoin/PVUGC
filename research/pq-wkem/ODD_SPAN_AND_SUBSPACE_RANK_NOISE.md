# Odd-span closure and random-subspace rank noise

## Status

This continuation starts from `QPT_FOURIER_EXTRACTION.md` at PR head
`9c5c9088afabe1d98d49012fbde0e1458ad6c42d`.

Two things are established here.

1. The binary additive-noise route has an **approximate odd-affine-span
   obstruction**. High decoding bias on several valid target preimages
   automatically gives high Fourier bias to their odd sum, whether or not that
   odd sum is a semantic proof. This applies to arbitrary correlated additive
   noise, not only iid BSC noise.

2. A new **random-subspace rank-noise sampler** has an exact rank-selective
   Fourier transform and avoids the specific reusable rank-one-factor
   presentation attacked in earlier runs. Its complete-output audit on the
   saved false affine block family has an exact phase boundary: below the
   spectral-cutoff dimension a Schur-complement attack recovers the hidden pad
   with nonnegligible probability; at and above the cutoff boundary the
   key-relevant hidden trace is information-theoretically uniform in that
   fixture. Unfortunately the honest rank-one signal at that boundary is
   exponentially small when the semantic rank threshold is far below the
   matrix dimension.

These are a barrier and a constructive partial result, not a completed generic
PQ witness KEM. No outside literature or web search was used.

## 1. Approximate odd-span closure is unavoidable for additive noise

Let `E` be an arbitrary random variable in `F_2^N`; coordinates may be
arbitrarily correlated. Define its character bias

    phi(z) = E_E [ (-1)^(<z,E>) ].

Take any frequencies `z_1,...,z_L` and put

    X_i(E) = (-1)^(<z_i,E>) in {+1,-1}.

Then

    (-1)^(<z_1+...+z_L,E>) = product_i X_i(E).

Pointwise,

    product_i X_i >= sum_i X_i - (L-1).

One way to see this is that the product can be `-1` only when at least one of
the events `X_i=-1` occurs. Taking expectations gives the exact universal
inequality

    phi(z_1+...+z_L)
      >= sum_i phi(z_i) - (L-1).                       (1)

Therefore, if every `phi(z_i)>=gamma`,

    phi(z_1+...+z_L)
      >= 1 - L(1-gamma).                               (2)

For odd `L`, if all `z_i` solve the same binary target equation

    A z_i = b,

then their sum also solves it:

    A(sum_i z_i) = L b = b.                            (3)

Consequently, if the odd sum is not source-extractable, its squared
data-noise Fourier weight is at least

    [1-L(1-gamma)]_+^2.                                (4)

For the `q=2` target coordinate of the additive raw-bit capsule there is no
separate odd scalar ambiguity, so this term lands directly in the
nonextractable key-dependent spectrum.

This is a statement about the spectrum of the complete additive channel. It
does not assert that a false source statement exists, and it does not by itself
construct an unauthorized key-recovery adversary. It says that the
information-theoretic strategy "make every valid proof high-bias and make every
nonsemantic target mode negligible" is incompatible with any short odd affine
dependency of the stated kind.

### 1.1 Exact OR-OHLC witness

Use two wire blocks and one four-state local block, with coordinates

    (x0,x1, y0,y1, q00,q01,q10,q11).

The OR predicate accepts `01,10,11`. Its three canonical OHLC vectors are

    z01 = (1,0, 0,1, 0,1,0,0),
    z10 = (0,1, 1,0, 0,0,1,0),
    z11 = (0,1, 0,1, 0,0,0,1).

Each has weight `B=3` and satisfies the complete binary linear OHLC equations.

Their XOR is

    zbad = z01 + z10 + z11
         = (1,0, 1,0, 0,1,1,1).                       (5)

The wire blocks now encode rejected assignment `00`, while the local-state
block has weight three. Nevertheless all public linear equations still hold,
because (3) is exact. Its total weight is `5=B+2`. This is the local failed
pseudostate from the previous Gap-OHLC analysis, now seen as an odd affine sum
of valid proof vectors.

Thus if all three valid proofs retain data-noise bias at least `gamma`,

    phi(zbad) >= 3 gamma - 2.                           (6)

At `gamma=0.9`, a bad nonsemantic target mode therefore has bias at least `0.7`
and squared mass at least `0.49`.

The lower bound is tight from marginal information alone. The three canonical
vectors are linearly independent. For `gamma>=1/3`, choose character signs
`(X1,X2,X3)` so that the all-plus outcome has probability
`1-3(1-gamma)/2` and each one-minus outcome has probability
`(1-gamma)/2`. Surjectivity of the three-character map lets this sign
distribution be realized by an additive noise distribution. Then every
`E[X_i]=gamma` and

    E[X1 X2 X3] = 3 gamma - 2.

The checker constructs this distribution explicitly for `gamma=9/10`.

### 1.2 Consequence for the QPT Fourier reduction

The phase-sandwich theorem in `QPT_FOURIER_EXTRACTION.md` needs the complete
nonextractable Fourier mass `Gamma_U` to be below the adversary's useful
correlation. Equations (1)-(6) show that this cannot follow merely from
high-bias correctness of all valid OHLC proof vectors, even with arbitrary
correlated additive noise.

A surviving linear-additive compiler therefore needs at least one of:

* semantic extraction from the relevant low-order odd affine closure of honest
  proof vectors;
* canonicalization strong enough that those nonsemantic odd sums do not arise
  among useful proof vectors; or
* a separately reduced computational mechanism that handles the resulting
  nonextractable modes.

Merely replacing iid coordinate noise with a more elaborate additive
distribution is not sufficient.

## 2. Constructive rank-selective sampler without reusable factors

The previous rank-sensitive attempt sampled a globally low-rank factorization
whose public quotient admitted matrix completion. The following sampler has a
clean invariant description instead.

Let the matrix frequency space be `F_q^(N x C)`. Choose a uniformly random
`m`-dimensional subspace

    U <= F_q^N,

and then sample each noise column independently and uniformly from `U`:

    E_j <- U,   j=1,...,C.                              (7)

Equivalently, conditioned on `U`, `E` is uniform over `U^C`.

For an additive character indexed by a matrix `M`, with a fixed nontrivial
field character `psi`, put

    chi_M(E) = psi( <M,E>_F ).

Let `r=rank(M)`.

### Theorem 2.1 — exact rank Fourier law

The characteristic function of (7) is

    phi(M)
      = { [N-r choose m]_q / [N choose m]_q,  m <= N-r,
        { 0,                                  m >  N-r. (8)

Here `[a choose b]_q` is the Gaussian binomial coefficient.

#### Proof

Condition on `U`. The average over one noise column is

    E_{e_j<-U} psi(M_j^T e_j),

which equals one exactly when `M_j in U^perp`, and zero otherwise. Since the
columns are independent, the complete character average equals one exactly
when every column of `M` lies in `U^perp`, i.e.

    col(M) <= U^perp.

The column space of `M` has dimension `r`, so `U` must be an `m`-subspace of
the `(N-r)`-dimensional space `col(M)^perp`. There are
`[N-r choose m]_q` such subspaces out of `[N choose m]_q` total. QED.

For a rank-one honest matrix,

    alpha_1
      = [N-1 choose m]_q / [N choose m]_q
      = (q^(N-m)-1)/(q^N-1).                           (9)

If

    m = N-D+1,                                          (10)

then (8) is exactly zero for every `rank(M)>=D`.

Thus if a semantic compiler proves

    target preimage M and rank(M)<D  ->  source witness,

this noise family creates an exact information-theoretic spectral cutoff at
the semantic extraction boundary. Unlike the earlier rank-one-factor
presentation, the sampled subspace can have dimension close to `N`.

That spectral statement is exact. Efficiency and complete-public-view security
still have to be audited.

## 3. Complete-public-view audit on the false affine block fixture

Use the same diagnostic false affine target as the earlier completion attack.
Write an `N x N` noise matrix in blocks with a hidden `D x D` upper-left block,

    E = [ E11 E12
          E21 E22 ].

Let setup choose a uniform affine mask `R in F_q^(D x D)` and publish

    C11 = E11 + R,

with all other blocks equal to the corresponding blocks of `E`, together with

    d = kappa + tr(R).                                  (11)

The public combination

    d - tr(C11) = kappa - tr(E11)                       (12)

shows that secrecy of `kappa` in this fixture is exactly the remaining
uncertainty of `tr(E11)` after the outside of `E` is revealed.

### 3.1 Unsafe side: `m <= N-D`

Every sample has `rank(E)<=m`. If the visible lower-right block has

    rank(E22)=m,

choose any invertible `m x m` pivot `P=E22[I,J]`. Vanishing of the corresponding
Schur complement gives the public reconstruction

    E11 = E12[:,J] P^(-1) E21[I,:].                    (13)

So (12) reveals the exact key.

For the random-subspace sampler, the probability of this event is

    p_comp
      = q^(D m)
        [N-D choose m]_q / [N choose m]_q
        prod_(i=0)^(m-1) (1-q^(i-(N-D))).              (14)

Reason: the projection of the random subspace `U` onto the bottom `N-D`
coordinates must be injective, and the `N-D` visible right-hand columns must
span the resulting `m`-space. The number of `m`-subspaces disjoint from the
top `D`-space is

    q^(D m) [N-D choose m]_q.

The second factor is the full-row-rank probability of a uniform
`m x (N-D)` coordinate matrix.

This is a complete-output key-recovery attack on the diagnostic false family
whenever the event occurs; it is not merely a failure of the intended decoder.

### 3.2 Safe side for this fixture: `m > N-D`

Now every `m`-subspace `U` has a nonzero intersection with the hidden top
coordinate space `T=F_q^D x {0}`:

    dim(U intersect T) >= m-(N-D) > 0.                 (15)

Condition even on `U` and on every public entry outside `E11`. For each hidden
column `j<=D`, its public bottom coordinates fix an affine coset of

    K_U = U intersect T.

The hidden column remains uniform on that coset, independently across hidden
columns. Pick a nonzero `k in K_U`; some top coordinate `k_j` is nonzero.
Varying hidden column `j` by `lambda k`, for uniform `lambda in F_q`, changes
`tr(E11)` by `lambda k_j`, which is uniform over `F_q`.

Therefore:

> If `m>N-D`, `tr(E11)` is exactly uniform even conditioned on `U` and the
> entire public outside of `E11`.

Mixing over the hidden `U` preserves uniformity. Hence this particular
completion/trace attack has exactly zero key advantage on the safe side.

The first safe integer is precisely (10), `m=N-D+1`, which is also exactly the
spectral rank-`D` cutoff point.

This does **not** prove security for every false affine relation; it proves that
the saved completion fixture has a sharp, auditable boundary for this sampler.

## 4. The correctness cost at the safe boundary

At `m=N-D+1`, equation (9) becomes

    alpha_1 = (q^(D-1)-1)/(q^N-1)
            ~= q^(-(N-D+1)).                           (16)

Moreover, for any nonzero scalar `t`, `rank(tM)=1`, so all nontrivial Fourier
coefficients of the scalar honest residual `<M,E>` equal `alpha_1`. Therefore

    <M,E>
      ~ alpha_1 delta_0 + (1-alpha_1) Uniform(F_q).     (17)

For `q=2`, an honest raw bit is correct with probability

    P_h = (1+alpha_1)/2.                                (18)

Independent repetition therefore has the usual inverse-square signal scale
`Theta(alpha_1^-2)` even before accounting for a final key length. This is
exponential when `N-D` grows linearly.

For the committed Boolean-moment compiler in `PROOFS.md`, the moment matrix has
`n+1` columns and extraction threshold `D`. One may orient the subspace sampler
on this smaller matrix side, so the most favorable analogue of (16) has

    N = n+1.

Fixed `D` keeps the explicit moment representation polynomial in `n`, but then

    alpha_1 ~= q^{-(n-D+2)},

which is exponentially small in the witness/circuit-wire count. Taking `D`
close enough to `N` to make the bias inverse-polynomial makes the explicit
degree-`D` moment representation grow very rapidly and, in the near-linear
regime, exponentially.

This is an efficiency obstruction for this **specific exact-cutoff composition**,
not a general impossibility theorem for rank-based WKEMs. A different succinct
semantic rank compiler with `D=N-O(log lambda)` would change the conclusion,
and none has been constructed here.

## 5. Validation actually executed

`odd_span_subspace_check.py` uses only the Python standard library and performs
fresh checks.

### Odd-span section

* constructs the three OR-OHLC canonical vectors and their rejected odd sum;
* verifies all four vectors satisfy the exact public linear equations;
* verifies valid weights `3,3,3`, bad weight `5`, and rank three of the valid
  vectors;
* constructs the exact tight `gamma=9/10` additive-noise distribution, obtaining
  honest biases `9/10` and bad bias `7/10`;
* checks inequality (1) with exact rational arithmetic on 400 independently
  generated correlated noise distributions.

### Rank-subspace section

* exhaustively enumerates all small subspaces and verifies (8) for every matrix
  rank for `(q,N)=(2,3),(2,4),(3,3)` and all nontrivial `m`;
* exhaustively verifies the completion attack and probability (14):
  - `(q,N,D,m)=(2,4,2,1)`: `144/240=3/5`;
  - `(2,4,2,2)`: `1536/8960=6/35`;
  - `(3,3,2,1)`: `162/351=6/13`;
  every completion event reconstructs the complete hidden block;
* exhaustively checks the safe-boundary trace theorem:
  - `(2,3,2)`: 448 complete samples, best conditional trace guess `1/2`;
  - `(2,4,2)`: 61,440 complete samples, best guess `1/2`;
  - `(3,3,2)`: 9,477 complete samples, best guess `1/3`.

These are algebraic/exhaustive small-field validations. They do not constitute
a cryptographic security experiment.

## 6. Current boundary

The latest QPT Fourier sampler removed the requirement that the adversary itself
output a structured mode. This run shows two complementary facts about trying
to satisfy the remaining spectral contract.

* In ordinary binary additive proof coordinates, high honest bias is
  automatically inherited by short odd affine combinations. Gap-OHLC alone
  therefore cannot make the complete nonsemantic spectrum negligible by merely
  changing the additive noise distribution.
* In matrix/rank coordinates, exact rank-selective spectral cutoff is possible
  with a transparent invariant sampler and the previous low-rank-factor
  completion attack has a sharp safe boundary. At that boundary, however, the
  honest signal is exponentially small for the currently proved fixed-`D`
  generic moment compiler.

The missing practical construction must therefore do something stronger than
either route as currently instantiated: an efficient semantic representation
whose low-order affine closure remains extractable, a succinct near-full-rank
semantic gap, or a computationally hidden/nonlinear consistency mechanism with
a reduction to an independently justified PQ assumption.

No complete generic PQ WKEM, malicious-setup composition, or secure deployment
parameter set is claimed in this note.
