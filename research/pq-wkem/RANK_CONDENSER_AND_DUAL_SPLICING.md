# Small-block rank condensers: geometric repair, lifted collapse, and dual splicing

## Status

This continuation starts from the exact random-subspace rank-noise result at PR
head `13282a6635dd0f219cd22ebca0e1cc7538bc354c`.

There is one constructive theorem and two complete-public-output obstructions.

1. A polynomial number of **small dense linear rank condensers** can
   simultaneously preserve rank `D` on every `D`-dimensional subspace.  Thus the
   previous exponential honest-signal loss is not forced by rank geometry alone:
   one can cover the large ambient space by `O(N)` local blocks of dimension
   `d=D+O(1)`, each of which has constant safe-boundary honest bias.

2. A hidden single small compressor followed by lifting its local subspace noise
   back to the original ambient space is distributionally just a mixture of the
   already-audited low-dimensional global subspace samplers.  Its output noise has
   rank at most the local noise dimension and inherits the saved completion
   attack with explicit nonnegligible probability.

3. Keeping the local blocks separate avoids that one lifted low-rank matrix, but
   loses global witness consistency.  A two-block false affine example has no
   global rank-one representation while each block separately has an
   honest-looking rank-one pseudorepresentation at a different affine point.
   Redundancy amplifies the splicer exactly as it amplifies an honest local
   decoder.

Accordingly, the condenser family is a useful semantic component, not a completed
WKEM.  The missing primitive is now a consistency-preserving aggregation that is
neither a low-rank lift nor independently decodable local blocks and that does
not multiply away the honest signal.

No external literature or web search was used.

## 1. Simultaneous small-block rank condensation

Let `V=F_q^N`, fix semantic threshold `D`, and choose local dimension

    d = D + kappa.

For a fixed `D`-subspace `W <= V` and a uniform linear map

    L <- F_q^(d x N),

the restriction `L|_W` is a uniform `d x D` matrix.  Therefore

    p = Pr[rank(L|_W)=D]
      = product_(i=0)^(D-1) (1 - q^(i-d)).              (1)

Take `T` independent maps `L_1,...,L_T`.  For a fixed W, multiplicative Chernoff
gives

    Pr[# {j : rank(L_j|_W)=D} < pT/2]
       <= exp(-pT/8).                                   (2)

The number of `D`-subspaces is the Gaussian binomial `[N choose D]_q`, and the
elementary bound used elsewhere in this record gives

    [N choose D]_q < 4 q^(D(N-D)).                      (3)

Hence

    Pr[exists W with fewer than pT/2 good maps]
      < 4 q^(D(N-D)) exp(-pT/8).                        (4)

In particular, for failure target `epsilon`, it is sufficient that

    T >= (8/p) [ D(N-D) ln q + ln(4/epsilon) ].          (5)

For fixed `q,D,kappa`, this is `O(N + log(1/epsilon))`.

If a matrix `M` has rank at least `D`, choose any `D`-subspace of its column
space.  Every map injective on that subspace satisfies

    rank(L_j M) >= D.                                   (6)

Thus one sampled family satisfying (4) simultaneously catches every matrix of
rank at least D in a constant fraction `p/2` of its local blocks.

### Local safe-boundary signal

Apply the previous random-subspace sampler inside a local `d`-dimensional block.
Its exact cutoff at semantic threshold D uses local noise-subspace dimension

    m = d-D+1 = kappa+1.                                (7)

Every local frequency of rank at least D has coefficient exactly zero.  A local
rank-one frequency has coefficient

    alpha
      = [d-1 choose m]_q / [d choose m]_q
      = (q^(D-1)-1)/(q^(D+kappa)-1).                    (8)

For fixed parameters this is a constant, not exponentially small in the original
ambient dimension N.

Example: `q=2,D=2,kappa=0` gives `alpha=1/3` and raw binary success `2/3`.

This is a real repair of the *geometric* efficiency problem from the previous
single-global-cutoff sampler.  It does not yet say how to compose the blocks.

## 2. Hidden one-block compression collapses to the old low-rank sampler

A tempting composition is to keep a small compressor hidden during setup.

Choose any `m`-subspace `U <= F_q^d`, a uniform `d x N` matrix L, sample local
noise columns independently and uniformly in U,

    E'_j <- U,

and publish only the lifted global noise contribution

    E = L^T E'.                                         (9)

Fix a basis of U.  The restriction

    T_U = L^T|_U : U -> F_q^N

is a uniform `N x m` linear map.  Let `R=rank(T_U)` and `W=image(T_U)`.  Then:

* `R` has exactly the rank distribution of a uniform `N x m` matrix;
* conditioned on `R=r`, W is uniform over all r-subspaces of `F_q^N`;
* conditioned on W, every column of E is independent uniform in W.

The last point follows because a uniform vector of U pushed through a surjective
linear map to W is uniform in W.

Therefore (9) is **exactly a rank-mixture of the previous global random-subspace
samplers**, with support dimension at most m.  Hiding L does not create a new
full-rank public-output distribution.

The exact mixing weights are

    Pr[R=r]
      = Nmat_q(N,m,r) / q^(Nm),                         (10)

where

    Nmat_q(N,m,r)
      = product_(i=0)^(r-1)
          (q^N-q^i)(q^m-q^i)/(q^r-q^i).

In particular,

    Pr[R=m] = product_(i=0)^(m-1)(1-q^(i-N)).           (11)

### Inherited completion attack

On the saved false hidden-block fixture, conditional on `R=m` the lifted noise is
the exact m-subspace sampler already audited.  If `m <= N-D`, the previous
Schur-complement attack therefore succeeds with probability at least

    Pr[R=m] * p_comp(N,D,m),                            (12)

where

    p_comp
      = q^(Dm)
        [N-D choose m]_q/[N choose m]_q
        product_(i=0)^(m-1)(1-q^(i-(N-D))).             (13)

Examples:

* `(q,N,D,m)=(2,4,2,1)`: lower bound `(15/16)*(3/5)=9/16`;
* `(2,4,2,2)`: `(105/128)*(6/35)=9/64`;
* `(3,3,2,1)`: `(26/27)*(6/13)=4/9`.

These are complete-output key-recovery events on that diagnostic false family,
not failures of only an intended decoder.

Thus "pick one small rank condenser secretly and lift" does not evade the prior
low-rank public-output attack.

## 3. Additive aggregation restores the signal problem

Another direct attempt sums T independently lifted local noises,

    E_total = sum_j L_j^T E'_j.                         (14)

Each term has rank at most m, so

    rank(E_total) <= T m.                               (15)

To cross the saved completion boundary purely by rank support requires

    Tm > N-D.                                           (16)

But for a rank-one honest frequency preserved by each public dense L_j, the
independent character factors multiply.  With local bias alpha<1, T such factors
give at most

    alpha^T.                                            (17)

For fixed local parameters, (16) requires `T=Omega(N)` and therefore makes (17)
exponentially small in N.

This is the same correctness obstruction in another form: enough independent
small blocks to remove the low-rank global support multiply away the honest
signal.

## 4. Separate local blocks admit dual splicing

Keeping the blocks separate avoids (14), but now an attacker can use a different
local affine representation in each independently decodable block.

The smallest exact example is over F2.  Define the global affine matrix

    M(x) =
      [ 1   0   ]
      [ 0   1   ]
      [ x  1+x  ],       x in F2.                       (18)

For both x=0 and x=1,

    rank M(x) = 2.                                      (19)

So this affine family has no global rank-one representation.

Use two 2-row projections:

    L_1 = select rows {1,3},
    L_2 = select rows {2,3}.                            (20)

Then

    rank(L_1 M(1)) = 1,
    rank(L_2 M(0)) = 1,                                 (21)

while for each *single* global x at least one of the two projected matrices has
rank 2.  Thus the pair is jointly rank-sound on this affine family, but each
block separately has an honest-looking rank-one pseudorepresentation, and the
two pseudorepresentations require inconsistent x values.

At `q=2,D=d=2,m=1`, the exact local rank-one bias is `1/3`; a local candidate
therefore predicts a raw bit with probability `2/3`.  If a naive construction
protects each share by independent repetitions of its local block, the false
splicer simply uses x=1 in block 1 and x=0 in block 2.

With 63 independent repetitions, exact majority success for each local share is

    h_63 = 0.9968806526003727...

and for a two-share XOR the splicer's success is

    h_63^2 + (1-h_63)^2
      = 0.9937807658571445...                           (22)

The attacker receives no global rank-one x because none exists.  Redundancy has
amplified two inconsistent local pseudorepresentations.

This rejects the **naive separate-block composition**, not the condenser family
itself and not every possible consistency mechanism.

## 5. What the constructive result actually buys

The previous exact global sampler seemed to require a semantic rank threshold
D close to ambient N in order to keep honest signal practical.  Section 1 shows
that rank geometry alone does not force that conclusion:

* `O(N)` public small maps can simultaneously hit every bad D-subspace;
* every local safe block can have constant rank-one signal.

The remaining problem is now more specific.  One needs an aggregation layer that
simultaneously has all three properties:

1. **global consistency:** a successful multi-block mode must correspond to one
   common admissible global representation, so Section 4 splicing is impossible;
2. **complete-view hiding:** it must not lift the local noises into a public
   globally low-rank object as in Section 2;
3. **nonvanishing correctness:** it must not multiply `Theta(N)` local biases as
   in Section 3.

A secure construction of that layer, with a reduction to an independently
justified PQ assumption or a complete information-theoretic proof, is still
missing.  Naming it a "consistency compiler" would merely rename the outstanding
witness-transfer problem.

## 6. Validation actually executed

`rank_condenser_check.py` uses only the Python standard library.

It performs fresh checks:

* enumerates all 651 two-dimensional subspaces of F2^6;
* samples 160 independent `3 x 6` maps; every one of the 651 subspaces has at
  least 91 rank-preserving maps (the theorem only asks for `pT/2=52.5`, with
  `p=21/32`);
* records the explicit union-bound failure upper bound
  `651 exp(-(21/32)*160/8) < 0.001299` for this exact enumerated Grassmannian;
* exhaustively enumerates all `4 x 2` binary linear maps, obtaining rank counts
  `1,45,210` for ranks `0,1,2`; conditioned on rank, every image subspace occurs
  equally often (`1`, `3`, and `6` maps per image respectively);
* verifies the inherited completion lower bounds `9/16`, `9/64`, and `4/9`
  exactly as rational numbers;
* verifies every rank statement in (18)-(21);
* exhaustively enumerates the local `F2^2,m=1` subspace-noise distribution and
  obtains rank-one zero-residual probability `2/3` and rank-two probability
  `1/2`;
* computes the 63-repetition majority and XOR-splicing probabilities in (22)
  exactly from the binomial distribution.

These checks validate finite algebra and counts.  They are not cryptographic
security experiments and do not establish the missing aggregation theorem.
