# Run 9 — projective pseudowitness break, exact error-quotient Fourier form, and an XOR-sharing repair lemma

## Status

This continuation starts from the exact one-hot linear compiler (OHLC) at PR head
`17d131d6d2af72ad824ac7daf23c6cc63d0cf8b1`.

It makes one necessary correction to the preceding cryptographic direction:

> Ordinary short-preimage soundness at the normalized target `H z=b` is not
> sufficient for a linear noisy release channel. A false statement can have a
> *scaled/projective* integer pseudowitness `H a=t b`, and the public ciphertext
> can be combined with `(a,t)` to form a second low-noise key channel.

A concrete false OHLC circuit has an explicit scale-3 pseudowitness. For the
direct dual-Regev-style binary capsule and ordinary bounded small errors, it
recovers the key on the false statement with certainty at the validated
parameters. Random row projection does not remove it.

This run also derives the exact Fourier normal form of the **complete** public
capsule distribution. That form identifies projective dual relations
`A z+t b=0`, not merely normalized preimages, as the correct security object.
Finally, an exact XOR-sharing lemma is derived: XOR sharing a key bit across
independent capsules forces every key-dependent Fourier term to use an odd
projective scalar in every capsule. This is a genuine full-output amplification
mechanism, but a complete parameterized WKEM and true-instance
key-recovery-to-witness/LWE reduction are still missing.

No external literature or web search was used.

## 1. Direct channel and projective attack

Consider the candidate binary capsule over `Z_q`:

    c = A^T s + e
    d = b^T s + e0 + Delta K,

where `K in {0,1}` and a genuine witness `z` satisfies `A z=b`. The intended
decoder uses

    d - z^T c
      = Delta K + e0 - z^T e.

Now suppose a public integer vector `a` and nonzero integer `t` satisfy

    A a = t b          (mod q).

Then *without* normalizing `a/t`, anyone can compute

    t d - a^T c
      = t Delta K + t e0 - a^T e.          (1)

This is a second decoder. Its noise is controlled by the ordinary integer size
of `(a,t)`, while its two key centers are `0` and `t Delta mod q`.

For coordinatewise bounded errors

    |e_j|, |e0| <= E,

the attack noise in (1) obeys the deterministic bound

    |t e0-a^T e|
      <= E (|t| + ||a||_1).                (2)

If the circular distance between the two scaled key centers is larger than twice
this quantity, the false-statement key is recovered exactly.

This attack is different from taking the modular vector `t^-1 a`. The latter
can have huge centered coefficients. Equation (1) clears the denominator before
decoding and therefore uses the small **integer projective representative**.

## 2. Explicit false OHLC scale-3 pseudowitness

Use four wire blocks:

    w0, w1, w2, w3,

with

    w2 = OR(w1,w1) = w1,
    w3 = XOR(w1,w2),

and force `w3=1`.

The circuit is false for every Boolean input because `w3=w1 XOR w1=0`.

OHLC has four 2-coordinate wire blocks and two 4-coordinate gate blocks, so

    B = 6.

Take scale `t=3`. Give each wire block the following count of its value-1
coordinate:

    p(w0)=1,
    p(w1)=1,
    p(w2)=2,
    p(w3)=3.

Thus the four wire blocks `(count(0),count(1))` are

    (2,1), (2,1), (1,2), (0,3).

For the OR gate use local-state counts, ordered `(00,01,10,11)`,

    (1,1,1,0),

and for the XOR gate use

    (0,2,1,0).

Every block sums to three. The gate marginals and output marginals match the
wire counts exactly. Therefore the resulting integer vector `a` obeys

    H a = 3 b

for the **full unprojected OHLC system**, even though the Boolean statement is
false.

Its sizes are

    ||a||_2^2 = 32,
    ||a||_1   = 18.

A scaled genuine one-hot vector would have squared norm

    t^2 B = 54.

Thus this is not merely a very long algebraic preimage; it is a low-energy
projective pseudowitness.

For every row projection `A=R H`, `b'=R b`,

    A a = R H a = 3 R b = 3 b'.

So the preceding random projection theorem cannot remove this object. That
theorem only excluded normalized short vectors at `t=1`.

## 3. Concrete false-key recovery

The attached checker uses

    q = 65536,
    Delta = q/2 = 32768,
    E = 1.

Because `t=3` is odd,

    3 Delta = Delta    (mod q).

The projective decoder therefore sees exactly the same binary center separation
as a genuine witness. From (2),

    |3 e0-a^T e| <= 1 * (3+18) = 21,

while the two centers are 32768 apart.

The key is therefore deterministically recoverable for every allowed error tape,
not merely with high empirical probability.

Fresh validation used 2,000 independently generated random projections, LWE
secrets, bounded error vectors, and random key bits. The public scale-3 attack
recovered all 2,000 keys. The largest raw attack noise actually observed was
16; the proved support bound is 21.

A separate true `XOR(w0,w1)=1` control recovered 1,000/1,000 keys under the same
channel parameters.

This breaks this direct high-margin capsule on an explicit false generic-NP
instance. It does **not** prove that every probabilistic/threshold parameter
choice around OHLC is impossible.

## 4. Universal block lower bound for scaled OHLC relations

The block-sum equations themselves give a useful projective norm floor.

For a `k`-coordinate integer block whose coordinates sum to integer `t`, write

    |t| = k u + r,    0 <= r < k.

Then the exact minimum squared norm of such a block is

    m_k(t)
      = r (u+1)^2 + (k-r) u^2.             (3)

This follows by convexity/exchange: two entries differing by at least two can be
moved one unit toward each other and strictly reduce squared norm.

Hence if an OHLC instance has `W` wire blocks and `G` gate blocks, every integer
projective relation `H a=t b` satisfies

    ||a||_2^2 >= W m_2(t) + G m_4(t).       (4)

For example,

    t=1: m_2=m_4=1,
    t=2: m_2=m_4=2,
    t=3: m_2=5, m_4=3.

This gives a real constant noise gap between a normalized one-hot witness and
every odd scale `|t|>=3`, but the gap is only constant. The explicit false
fixture shows such a scale-3 relation can actually exist.

## 5. Exact complete-view Fourier normal form

The correct security object for this linear noisy channel can be written
exactly.

Let

    C_A = { (A^T s, b^T s) : s in Z_q^d }

be the public linear code in `Z_q^(N+1)`. Let the noise vector be

    E = (e,e0)

with any distribution `D`; no Gaussian assumption is needed. The capsule for
bit `K` is a sample from

    U_{C_A} + D + Delta K e_last.

For a character indexed by `(z,t) in Z_q^N x Z_q`, with
`omega=exp(2 pi i/q)`,

    E[ omega^( z.c + t.d ) ]
      =
      1[ A z + t b = 0 ]
      * Dhat(z,t)
      * omega^(t Delta K),                  (5)

where

    Dhat(z,t)
      = E_D[ omega^(z.e+t e0) ].

Proof: average first over uniform `s`. The `s`-dependent phase is

    s^T(A z+t b),

whose group average is exactly zero unless `A z+t b=0`.

Equation (5) is the complete public-output distribution, not a prescribed
decoder analysis. It says that every key-dependent Fourier mode is indexed by
a **projective preimage**

    A z = -t b,    t != 0.

The normalized short-preimage theorem controls only one slice, `t=-1`.

The attached checker exhaustively verifies (5) over `Z_8` for every one of 1,024
tested `(z0,z1,t,K)` characters. Maximum numerical discrepancy from the exact
formula was about `1.1e-15`.

## 6. XOR sharing: a real full-view amplification identity

There is one constructive way to use the user's allowed redundant/N-of-N
composition without pretending that thresholding automatically creates secrecy.

Let `L` independent capsules encrypt random bit shares

    K_1,...,K_L,

conditioned on

    K_1 XOR ... XOR K_L = K.

Use an even modulus and `Delta=q/2`.

In a product Fourier character let `t_i` be the target-coordinate frequency in
capsule `i`. Averaging over the random XOR shares gives exactly:

- if the parities `t_i mod 2` are mixed, the Fourier coefficient is zero;
- if every `t_i` is even, the coefficient is independent of `K`;
- if every `t_i` is odd, the coefficient is multiplied by `(-1)^K`.

Therefore **every key-dependent complete-view Fourier mode must contain an odd
projective relation in every independent capsule**.

The checker exhaustively verifies this identity for all 512 frequency triples
over `Z_8` with three XOR shares.

This is useful because odd projective modes have a strict blockwise noise floor:
`t=1` is the semantic slice, while any other odd integer lift starts at
`|t|>=3`. Independent capsules multiply their character coefficients.

However this is not yet a completed WKEM:

1. a quantitative full-output bound must sum/control *all* odd projective modes,
   including projection-created modes and modular lifts;
2. reliable recovery of every XOR share conflicts with deliberately making each
   false-instance capsule noisy enough for strong contraction, so an actual
   reconciliation/wiretap code is still needed;
3. most importantly, on a true statement arbitrary efficient early key recovery
   still needs a reduction to source-witness extraction or an independently
   justified LWE/SIS break. Fourier existence alone does not algorithmically
   extract the relevant mode from an arbitrary classical/quantum adversary.

## 7. Consequence for the search

The previous OHLC result remains useful as an exact **normalized** semantic
compiler, but the cryptographic target must be upgraded from

    short preimage for H z=b

to a projective/full-channel statement controlling

    (z,t) with H z = -t b.

The direct high-margin dual-Regev capsule is rejected by the explicit scale-3
false instance above.

The XOR-sharing identity is the first outer composition in this line that
provably changes the *complete* key-dependent Fourier support rather than merely
changing an intended decoder. It is therefore worth retaining for a later
wiretap/reconciliation construction, but it does not by itself close the
arbitrary-key-recovery extraction requirement.

No complete efficient generic PQ WKEM or deployment parameter set is claimed in
this run.
