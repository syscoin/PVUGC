# Run 10 — weak-capsule amplification with a real reconciliation layer

## Status

This continuation starts from `PROJECTIVE_OHLC_AND_FOURIER.md` at PR head
`f92f69b89c870fc4d503b362fddc4cf56001be0a`.

The previous XOR-share lemma changed the complete Fourier support correctly, but
left a practical conflict: requiring every raw share to decode reliably makes a
long XOR fragile, while making each false-instance capsule strongly contracting
can damage honest recovery.

This run supplies a complete **outer reconciliation/privacy-amplification
compiler** for any independent binary witness capsule with a constant honest /
false-instance gap. It does not solve the inner projective OHLC channel and it
does not solve the true-instance `key recovery -> witness/LWE break` reduction.
Accordingly it is not a completed generic WKEM.

No external literature or web search was used.

## 1. Exact bridge from the Run-9 Fourier mass to a weak bit channel

For one binary capsule let `P_0,P_1` be the complete public-output
distributions. With the Run-9 notation, define the odd projective spectral mass

    S_odd =
      sum_{A z + t b = 0, t odd} |Dhat(z,t)|^2.

The exact Fourier formula from Run 9 says that `P_0-P_1` has Fourier support
only on those odd projective characters, and each surviving Fourier coefficient
has magnitude `2 |Dhat(z,t)|`.

With the normalized character transform, Parseval gives

    sum_y |P_0(y)-P_1(y)|^2 = 4 S_odd / |G|.

Cauchy-Schwarz then gives

    TV(P_0,P_1) <= sqrt(S_odd).                    (1)

For a uniform hidden bit X, the optimal complete-view guessing probability is

    g := P_guess(X | Y)
       = (1 + TV(P_0,P_1))/2
       <= (1 + min(1,sqrt(S_odd)))/2.             (2)

This is useful because a single capsule no longer needs negligible spectral
mass. A constant weak-secrecy gap `g<1` is enough for the outer compiler below.
For example, proving `S_odd <= 1/4` gives `g <= 3/4`.

This is a full-output statement: `Y` is the entire public capsule, not the
prescribed witness decoder.

## 2. Product guessing probability

Let setup sample independent uniform bits

    X = (X_1,...,X_L)

and independently encapsulate each bit. On a false source statement suppose

    P_guess(X_i | Y_i) <= g_i.

Because the source bits and channels are independent,

    P_guess(X | Y)
      = product_i P_guess(X_i | Y_i)
      <= product_i g_i.                            (3)

For a common bound `g_i<=g`, this is `g^L`.

No computational assumption is used in (3).

## 3. Deterministic helper leakage lemma

Let setup publish any deterministic reconciliation helper

    S = f(X)

whose range has at most `2^R` values. The matrices/code description used to
define `f` can be public and independent of X.

Then

    P_guess(X | Y,S) <= 2^R P_guess(X | Y).       (4)

Proof: for each fixed public view y, each helper value contributes at most the
largest joint mass `max_x P[X=x,Y=y]`; summing over at most `2^R` helper values
and then over y proves (4).

This is deliberately stated for *arbitrary* deterministic helpers. It therefore
accounts for the full syndrome, not only its nominal rank when the advertised
range bound is `2^R`.

## 4. Statistical extraction with a 2-universal hash

Choose a public random seed rho for a 2-universal hash

    h_rho : {0,1}^L -> {0,1}^kappa

and set

    K = h_rho(X).

For every classical side-information value `(Y,S)`, pairwise universality and
Cauchy-Schwarz give the standard collision calculation directly:

    Delta( (rho,K,Y,S), (rho,U_kappa,Y,S) )
      <= 1/2 sqrt( 2^kappa P_guess(X | Y,S) ).

Combining (3)-(4),

    epsilon_sec
      <= 1/2 sqrt( 2^(kappa+R) product_i g_i ).   (5)

For identical channels,

    epsilon_sec
      <= 1/2 * 2^((kappa+R-L h)/2),
    h = -log2 g.                                  (6)

Because this is statistical distance between classical public distributions, it
already covers arbitrary QPT post-processing on a false statement.

Equation (6) is the main amplification theorem of this run.

## 5. A concrete efficient reconciliation layer: Reed-Solomon secure sketch

The remaining requirement is to let every valid witness recover X despite
independent raw bit errors without requiring every capsule to be correct.

Group X into m-bit symbols over `GF(2^m)`. In each block take `n <= 2^m-1`
symbols and a Reed-Solomon `[n,k]` code C. Let H be a parity-check matrix for C
and publish the syndrome

    S = H X.

This leaks at most

    R_block = (n-k) m

bits and is therefore covered exactly by (4).

A witness first obtains raw bit estimates X~. Let the corresponding symbol
vector be X~_sym. Choose any public solution x0 of

    H x0 = S.

Then

    c = X_sym - x0 in C

and

    X~_sym - x0 = c + E.

An ordinary RS decoder therefore recovers c, hence X, whenever at most

    t = floor((n-k)/2)

symbols are wrong.

If each raw witness bit has independent error probability at most `p_b`, a
symbol is wrong with probability at most

    p_sym = 1 - (1-p_b)^m,

and one block has correctness failure bounded by

    Pr[ Bin(n,p_sym) > t ].                       (7)

The syndrome computation, linear solve, RS decoding, and universal hashing are
all polynomial time. No online setup participant is needed after publication.

## 6. Illustrative outer target, not a claim about the current inner capsule

One concrete parameter calculation is:

    GF(2^8)
    RS(255,223), t=16
    L = 255*8 = 2040 raw bits
    R = 32*8 = 256 helper bits
    kappa = 256 key bits.

If an eventual inner capsule can prove

    honest raw-bit error p_b <= 2e-5
    false complete-view guess g <= 0.75,

then (7) gives

    correctness failure <= 3.78e-39
    = about 2^-127.64,

while (6) gives

    false-key statistical distance <= 2^-168.34.

These are **outer-layer target numbers only**. Run 9's explicit high-margin
scale-3 projective attack does not meet `g<=0.75`; its tested parameters instead
recover the false bit essentially perfectly. The example therefore does not
resurrect that rejected capsule.

The value of the calculation is to sharpen the remaining inner target. We no
longer need negligible per-capsule false leakage. A constant full-view weak gap
together with a very reliable witness decoder is sufficient for strong
false-instance key hiding.

## 7. Local validation

The attached checker performs three independent controls.

1. **Fourier-to-guess control.** Over a tiny Z_8 additive capsule it enumerates
   the complete distributions, computes TV exactly, enumerates every odd
   projective Fourier mode, and verifies (1)-(2).

2. **Helper/hash control.** For four uniform bits through independent BSC(0.35)
   false channels, it enumerates the full joint distribution. It verifies
   product guessing, the one-bit helper leakage bound, and averages statistical
   distance over the full 2-universal family of binary linear one-bit hashes.

3. **RS coset-recovery control.** Over F_17 it constructs an RS(8,4) code,
   publishes only a parity-check syndrome of a random source vector, adds up to
   two symbol errors, and recovers the exact source through coset translation
   and unique RS decoding in 200/200 fresh trials.

The practical GF(2^8) numbers are formula evaluations, not a production
implementation or a claim that the current inner OHLC capsule achieves the
required `p_b,g`.

## 8. What this closes and what it does not

Closed in this run:

- a rigorous full-output bridge from Run-9 odd spectral mass to an optimal
  false-bit guessing bound;
- a rigorous weak-to-strong false-instance amplification theorem;
- a real error-correcting reconciliation layer that does not require every
  share/capsule to decode;
- explicit leakage accounting for the public reconciliation helper.

Still open:

1. **Inner projective control.** For every false source statement, prove a
   useful constant bound such as `S_odd<1/4` (or directly `g<3/4`) for an actual
   efficient capsule while preserving very small honest bit error.
2. **True-instance extraction.** Recovering the privacy-amplified final key does
   not by itself output a source witness or a useful projective mode. A complete
   composition still needs a reduction from arbitrary early final-key recovery
   to source-witness extraction or an independently justified LWE/SIS break.
3. **Distributed setup composition and final concrete parameters.**

Thus this is a substantive construction of the missing reconciliation/wiretap
outer layer, but not the requested completed generic PQ WKEM.
