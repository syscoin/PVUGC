# Ideal-coset public encoding audit and a QPT Fourier source-extraction lemma

Starting checkpoint: PR #1 head
`c56fae28c6244534150e247338789043506e5a10`.

This pass does **not** complete a generic witness KEM.  It records:

1. a concrete polynomial/ideal-coset witness encoding attempt and an exact
   complete-public-output break for every explicit polynomial-size feature
   realization of that attempt;
2. a new reduction lemma converting an arbitrary QPT key predictor into an
   extractable Fourier mode when the post-hybrid complete transcript has
   polynomial L2 density and negligible nonsemantic Fourier mass;
3. an exact witness-multiplicity obstruction showing why that lemma does not,
   by itself, solve generic NP when exponentially many distinct witnesses
   induce distinct high-bias reconstruction modes.

No external literature or web search is used.

## 1. Constructive attempt: ideal-coset encoding

Let F=F_q and let B be a finite-dimensional public feature space for functions
of Boolean witness variables.  In the literal multilinear realization,

    B = F[X_1,...,X_n] / (X_i^2-X_i),

with the monomial basis indexed by subsets of [n].

Let public verifier constraints be g_1,...,g_m.  Choose a public multiplier
space R (for example monomials of degree at most t), and define the public mask
subspace

    M = span { r g_j : r in R, j in [m] } <= B.          (1)

A setup that knows the statement but no witness can choose a key K and a random
mask m in M and publish the complete coefficient vector

    F_K = K * 1 + m.                                     (2)

Every valid witness w satisfies g_j(w)=0, hence

    F_K(w)=K.                                             (3)

This is a genuine same-key, witness-restricted public encoding interface:
setup never uses a source witness, and every source witness evaluates the same
published object to K.

### 1.1 Exact false-instance hiding criterion

For a uniform mask on the public linear subspace M, the distributions for keys
K and K' are uniform on affine cosets K*1+M and K'*1+M.  Thus

    Enc(K) == Enc(K')  as distributions
        iff (K-K')*1 in M.                               (4)

For scalar keys over a field this gives a sharp dichotomy:

* if 1 in M, every key distribution is identical (perfect hiding);
* if 1 notin M, distinct keys have disjoint supports.

This is exactly the truncated Nullstellensatz/certificate condition for the
chosen public multiplier space.  It is useful for false statements, but it is
not enough for a WKEM because of the next complete-output attack.

## 2. Complete-public-output quotient attack on every true instance

Assume the statement has any valid witness w.  Evaluation at w is a public
linear functional on the coefficient vector and obeys

    ev_w(1)=1,
    ev_w(M)=0.                                           (5)

Therefore 1 is **not** in M.

But M and the target vector 1 are public in the ideal-coset construction.
Finite-dimensional linear algebra now constructs *some* functional lambda with

    lambda(M)=0,
    lambda(1)=1,                                         (6)

without finding w.  Applying it to the published vector gives

    lambda(F_K)=K.                                       (7)

This is not a computational attack on the NP relation.  It is the public
quotient map B -> B/M.

### Theorem (explicit public linear-mask barrier)

Let V be a public finite-dimensional vector space, T in V a public target, and
M <= V a public mask subspace.  Consider any ciphertext of the form

    C_K = K T + m,      m in M,                          (8)

with arbitrary (not necessarily uniform) mask distribution.  If there exists
an honest linear decoder l with

    l(T)=1 and l(M)=0,                                   (9)

then T notin M.  Gaussian elimination on public (T,M) computes a decoder l*
satisfying (9).  Hence l*(C_K)=K for every ciphertext and no witness is needed.

The attack costs polynomial time in the explicit public dimension, e.g.
O(N^3) field operations for a direct elimination implementation.

A small fixture shows that this quotient need not secretly be “finding the
witness.”  Over F_101 take the single Boolean constraint

    g(x,y,z)=1-xyz=0,

whose unique Boolean witness is `(1,1,1)`, and multiplier space
`span{1,x,y,z}`.  Gaussian elimination returns the public functional

    lambda(c)=c_1+c_x+c_y+c_z+c_xyz,

which annihilates `g,xg,yg,zg` and has `lambda(1)=1`, but is **not** evaluation
at `(1,1,1)` (that evaluation sums all eight multilinear coefficients).
It recovers K from (2) directly.  Thus even a unique-witness true instance can
admit a public pseudo-functional unrelated to a source witness.

The theorem does **not** claim impossibility for nonlinear/computationally
hidden encodings.  Its consequence is narrower and exact:

> replacing the earlier linear transfer tables by an explicit bounded-degree
> polynomial coefficient vector does not fix the complete-public-view problem.
> Witness evaluation is linear in those coefficients, so the public quotient
> recovers the same key.

For the literal full Boolean function algebra N=2^n.  One can make the quotient
attack exponential only by making the explicit encoder/output exponential,
which is excluded by the target requirements.  Publishing a compact arithmetic
circuit instead is not a free compression: the naive circuit contains K and
the mask randomness as readable constants.  Making such a compact program
reveal only black-box evaluation is precisely a new computational encoding
obligation, not something supplied by (2).

## 3. A positive reduction lemma: arbitrary QPT predictor -> Fourier mode

The previous Fourier checkpoints had a different unresolved step: even when
the complete transcript distribution has a semantic Fourier characterization,
an arbitrary key-recovery algorithm need not itself output a Fourier label.

There is a clean extraction lemma if the post-hybrid distribution is
sufficiently flat.

Let G be a finite abelian transcript group and U its uniform distribution.
For K in {0,1}, let P_K be the complete classical transcript distribution and
write its density relative to U as

    rho_K(y) = |G| P_K(y).

Define the signed key density

    Delta(y) = (rho_0(y)-rho_1(y))/2.                    (10)

Let A be an arbitrary QPT predictor.  Purify it and let

    f(y) = Pr[A(y)=0] - Pr[A(y)=1] in [-1,1].            (11)

If its key success is 1/2+delta, then

    <f,Delta>_U = 2 delta.                               (12)

Let S be an efficiently recognizable set of semantic Fourier labels from which
the existing deterministic source extractor returns a valid source witness.
Assume

    ||Delta||_2 <= B,                                    (13)
    || Fourier(Delta) restricted outside S ||_2 <= eta. (14)

Parseval and Cauchy-Schwarz give

    sum_{a in S} |fhat(a)|^2
      >= ((2 delta - eta)_+)^2 / B^2.                   (15)

### 3.1 Coherent sampler for an arbitrary quantum predictor

This is algorithmic, not merely existential.

Defer A's measurements and purify its coins/workspace into a unitary U_A with a
designated output qubit.  Let Z be +1 on output 0 and -1 on output 1, and set

    W = U_A^dagger Z U_A.

On a classical transcript basis state and clean workspace,

    W |y,0> = f(y)|y,0> + |y,perp_y>,                    (16)

where the second workspace component is orthogonal to |0>.

Start with the uniform superposition over y, apply W, apply the group quantum
Fourier transform to the y register, and measure the Fourier label together
with the workspace-clean flag.  The amplitude of |a,0> is exactly fhat(a).
Consequently one trial outputs a semantic label a in S with probability

    p_sem = sum_{a in S}|fhat(a)|^2
           >= ((2 delta-eta)_+)^2/B^2.                  (17)

Whenever membership in S and the source extractor are efficient, expected
repetition count is at most

    B^2 / (2 delta-eta)^2.                               (18)

Thus an actual WKEM proof can use the following hybrid template without a new
"knowledge" assumption:

1. replace the computational layer by its standard PQ security hybrid;
2. if A's success changes nonnegligibly, obtain a break of that independently
   justified assumption;
3. otherwise apply (15)-(18) in the hybrid distribution and extract a source
   witness.

This closes the **algorithmic predictor-to-mode** step under explicit,
checkable spectral conditions.  It does not prove that the current candidate
encodings satisfy those conditions.

## 4. Witness multiplicity obstruction for the Fourier extractor

Suppose M distinct witness reconstruction labels a_w all have key-dependent
Fourier coefficient magnitude at least gamma:

    |Deltahat(a_w)| >= gamma.

Parseval immediately gives

    B^2 = ||Delta||_2^2
        = sum_a |Deltahat(a)|^2
        >= M gamma^2.                                   (19)

Therefore the generic extraction lower bound (17) can deteriorate by a factor
of M.  If a generic NP statement has exponentially many distinct witness modes,
all with constant honest bias, B is necessarily exponential in the square root
of that multiplicity.

This is not an impossibility theorem: a particular adversary may have much more
concentrated Fourier mass, and a different encoding can collapse witness modes.
It is, however, an exact reason that "Fourier sample the arbitrary adversary"
does not automatically finish the generic-NP problem.

It also sharpens the next constructive target.  A successful inner encoding
must do at least one of:

* collapse many valid witnesses to a polynomial number of extractable semantic
  modes while retaining source extraction;
* give a different source extractor whose success is not paid for by the
  complete witness-mode multiplicity;
* or use a computational layer whose hybrid directly produces an extractable
  witness rather than a large family of high-bias public characters.

## 5. Relation to the existing random-subspace rank-noise candidate

The exact safe-boundary subspace sampler from the previous checkpoints has an
attractive property for (14): its Fourier coefficient is exactly zero above the
chosen rank cutoff.  If every nonzero target-sensitive mode below that cutoff
is source-extractable, then eta=0 information-theoretically.

Its previously recorded efficiency problem remains real: at the global safe
boundary the honest rank-one coefficient is approximately q^{-(N-D+1)}.  Making
D fixed keeps the semantic representation manageable but makes honest
correctness exponentially weak; taking D close to N restores signal but the
existing degree-D moment compiler was exponential.

The QPT lemma shows that this was not merely a proof-artifact: the global
safe-boundary channel is close to the *right extraction shape*, but still lacks
a practical semantic representation / correctness tradeoff.

## 6. Local validation performed in this run

`ideal_fourier_check.py` uses only the Python standard library and performs:

* an explicit true XOR-constraint ideal-coset fixture over F_101, constructs a
  public quotient functional by Gaussian elimination without supplying either
  satisfying witness, and recovers 500/500 random keys for independent random
  masks;
* a unique-witness `1-xyz=0` fixture where the computed quotient functional is
  provably not the unique witness-evaluation functional, yet recovers 300/300
  random keys;
* a false one-bit contradictory fixture where 1 is in the mask span and exact
  enumeration confirms identical ciphertext distributions for all keys;
* a false odd XOR triangle fixture, confirming that degree-2 multipliers already
  put 1 in the public mask span over F_101;
* exact Fourier calculations on F_2^4 for a semantic/nonsemantic two-character
  distribution, verifying (12), Parseval, the semantic-mass bound (15), and the
  coherent clean-workspace sampling probabilities;
* exact multiplicity checks for M=1..64 confirming B^2=M gamma^2 in the
  orthogonal-character fixture.

The QPT checker validates the finite Fourier algebra and the clean-workspace
amplitude formula; it does not execute quantum hardware or constitute a
cryptographic security experiment.

## 7. Current status

Proved in this pass:

* exact ideal-coset false-hiding criterion;
* exact public quotient attack on every explicit true-instance linear-mask
  coefficient encoding;
* QPT predictor-to-semantic-Fourier-mode extraction under polynomial L2 density
  and negligible nonsemantic spectral mass;
* exact witness-mode multiplicity lower bound on the required L2 parameter.

Still missing:

* a practical generic-NP inner encoding satisfying the spectral/hybrid
  conditions while giving every witness reliable same-key recovery;
* a way around exponential witness-mode multiplicity or a different extraction
  mechanism;
* the full independently justified PQ hybrid for that inner encoding;
* malicious-secure ceremony composition and concrete deployment parameters.

Accordingly, this is substantive progress and a rejected constructive candidate,
not a completed WKEM.
