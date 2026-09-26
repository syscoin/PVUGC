# Run 8 — Canonical-Coset is eWKEM-equivalent; exact one-hot short-preimage compiler

## Status

This continuation corrects the interpretation of the preceding Canonical-Coset
candidate and adds a concrete generic-NP semantic compiler that may still be
useful for lattice/projective channels.

**Result 1:** the affine-support designated-verifier primitive assumed by
Canonical-Coset is black-box equivalent to the extractable witness-KEM being
sought. It is therefore a useful normal form, but not a weaker primitive or an
instantiation.

**Result 2:** there is a simple polynomial-size integer linear compiler for a
Boolean verifier in which every valid witness gives a norm-exact short preimage,
and every modular preimage below that same norm threshold extracts a genuine
witness. Random row projection preserves all witnesses and, with an explicit
union bound, can eliminate all nonsemantic short projected preimages with high
probability.

The remaining cryptographic gap is full-output key hiding/projectivity for this
structured short-preimage family under an independently justified PQ assumption.
No such reduction is completed here.

No external literature or web search was used.

## 1. Canonical-Coset is not a weaker primitive

Call the preceding affine-support primitive ASP. On statement x it supplies
public proving material pk and a public full-row-rank matrix Q, while setup knows
one hidden syndrome theta. Every valid witness can compute pi with

    Q pi = theta,

and early recovery of theta (or production of a member of that hidden slice by
a public adversary) is required to imply source-witness extraction or an
independently justified hardness break.

### ASP -> extractable WKEM

This is the preceding Canonical-Coset transform:

    Encap(x):
        (pk,Q,theta,tau) <- ASP.Setup(x)
        K = H("CC-WKEM" || x || ctx || theta)
        publish ct=(pk,Q,ctx, DEM.Enc_K(payload))
        erase theta,tau

    Decap(ct,w):
        pi <- ASP.Prove(pk,x,w)
        theta' = Q pi
        K' = H("CC-WKEM" || x || ctx || theta')

All valid witnesses obtain the same theta and hence the same K. The QROM
hidden-point argument can turn nonnegligible recovery of K into nonnegligible
recovery/querying of theta; the ASP extraction/hardness property then supplies
the source-side conclusion.

### Extractable WKEM -> ASP

Conversely, take any extractable WKEM with deterministic common-key correctness:

    (ct,K) <- Encap(x),
    Decap(ct,w)=K for every valid w.

Encode K as a field vector theta. Define

    pk = ct,
    Q = I,
    ASP.Prove(pk,x,w) = Encode(Decap(ct,w)).

Setup itself knows theta from Encap and can therefore output the simulator point
pi_sim=theta without knowing a source witness. The accepting affine slice

    Q pi = theta

is the singleton {theta}. A public adversary that produces any member of that
slice has recovered K, so the original extractable-WKEM security game gives
exactly the required ASP extraction/hardness conclusion.

High-probability correctness can be carried through by the same outer
reconciliation/repetition used by the WKEM; the exact deterministic version is
enough for the equivalence claim here.

Therefore

    affine-support DV common hidden syndrome
        <==black-box==>
    extractable witness KEM.

This does not make Canonical-Coset wrong. It means the missing affine-support DV
theorem is already the holy-grail primitive in another syntax. Treating it as an
independently available DV-PoK would violate the requirement not to replace the
missing construction by a WE-equivalent assumed compiler.

A subtle point from the prior run remains valid: a reduction that obtains theta
from the outer attacker can construct pi_hat by solving Q pi_hat=theta and then
invoke an extractor on the composed public adversary that derived theta. The
setup simulator itself is not a contradiction because it possesses erased toxic
state. The problem is not logical inconsistency; it is primitive equivalence.

## 2. Exact one-hot linear compiler (OHLC)

Compile a fan-in-two Boolean circuit into an integer linear system

    H_x z = b_x.

For every circuit wire i introduce a two-coordinate block

    x_i=(x_i,0,x_i,1).

For every binary gate g with inputs i,j introduce four local-state coordinates

    y_g,a,b,     a,b in {0,1}.

For every wire and gate block impose

    x_i,0 + x_i,1 = 1,
    sum_(a,b) y_g,a,b = 1.

For gate g=(i,j -> k) impose marginal consistency

    x_i,a = sum_b y_g,a,b,
    x_j,b = sum_a y_g,a,b,

and output consistency

    x_k,c = sum_(a,b : f_g(a,b)=c) y_g,a,b.

Public input wires, if any, are fixed by one additional linear equation; the
accepting output wire is fixed to 1.

A satisfying Boolean witness sets exactly one coordinate of every wire block and
one coordinate of every gate block to 1. If B is the number of blocks, its
integer squared norm is exactly

    ||z||_2^2 = B.

### Exact extraction theorem

Let z be any integer solution of H_x z=b_x with

    ||z||_2^2 <= B.

Every block has integer coordinates summing to 1. For an integer vector a with
sum a_j=1,

    sum a_j^2 >= 1,

with equality iff a is exactly one standard basis vector. There are B blocks,
so the total norm bound forces equality in every block. Thus every wire and gate
block is one-hot. The marginal equations make the local states globally
consistent, the truth-table equation makes every gate correct, and the fixed
output equation makes the circuit accept. Reading the input-wire blocks gives a
genuine source witness.

Hence

    H_x z=b_x and ||z||_2^2<=B
        => extract a satisfying witness.

This is an exact semantic theorem, not a computational assumption.

### Modular lift

All compiler coefficients are 0,+1,-1 and each row has constant support s. If z
is represented by centered residues and ||z||_2^2<=B, then each coordinate has
magnitude at most sqrt(B). If

    q > 2(s sqrt(B)+1),

an equality H_x z=b_x mod q cannot wrap. Therefore every modular short solution
is an integer short solution and the same extractor applies.

The compiler is polynomial size: two variables per wire and four per binary gate,
with O(1) rows per gate/wire.

## 3. Random row projection

Setup can sample

    R <- F_q^(d x m),

and publish

    H' = R H_x,
    b' = R b_x.

Every genuine witness survives identically. For any fixed z with

    delta_z = H_x z - b_x != 0 mod q,

one random row r satisfies r delta_z=0 with probability exactly 1/q, so

    Pr_R[H'z=b'] = q^-d.

Let S_B be all centered integer z with ||z||_2^2<=B. A crude bound is

    |S_B| <= (2 floor(sqrt(B))+1)^N.

On a false statement the extraction theorem says none of those short vectors
solves the full system. Hence

    Pr_R[exists short projected pseudopreimage]
      <= |S_B| q^-d.

Choosing

    d >= (log |S_B| + lambda ln 2)/ln q

makes this setup failure at most 2^-lambda. The bound already covers vectors
selected after the projected instance is published because the union is over the
entire bounded set.

## 4. Cryptographic boundary

OHLC gives the semantic short-preimage compiler:

    source witness -> short z with H'z=b',

and every short solution extracts a source witness except for the explicit
setup-bad probability above.

It does not by itself give key hiding. A dual-Regev-style capsule

    c = H'^T a + e,
    d = b'^T a + e0 + Delta K

lets a short z cancel the pad with small error, but H' is a structured random
projection of a public compiler. Ordinary uniform-matrix LWE does not immediately
imply security for the complete transcript. Gaussian elimination also gives
public long modular preimages whenever the affine system is soluble; the intended
separation is therefore a short-versus-long/noise separation. The earlier
wiretap, finite-Fourier, pseudocodeword, and full-view attacks apply to any proof
of that step.

If H has full row rank, choose a public pivot basis H=[I|P]. Then
H'=R[I|P]=[R|RP]. The pivot columns R are genuinely uniform and provide ordinary
LWE samples, but the target b'=Rb is a known long linear combination of those
columns. A public long affine preimage cancels the LWE secret and leaves a linear
combination of the error. The remaining problem is therefore proving that the
complete error quotient hides the key from every nonsemantic/long preimage and
nonlinear decoder while a semantic short preimage recovers it.

## 5. Fresh validation

The committed checker compiles XOR circuits.

True fixture `XOR(w0,w1)=1` has exactly two short integer solutions at the norm
threshold B, corresponding to (0,1) and (1,0). Over F_31 it has exactly the same
two short modular solutions.

False fixture `XOR(w,w)=1` has no witness. Exhaustive enumeration of every
integer vector with squared norm <=B finds no integer solution and no extra
modular solution over F_31.

Fresh random-projection experiments on the 577 short false-fixture vectors gave:

- d=2: 830/2000 projected instances admitted at least one short false vector;
  observed 0.415, union bound 0.6004162331.
- d=3: 95/5000; observed 0.019, union bound 0.01936826558.
- d=4: 0/5000; union bound 0.0006247827608.

Two true witnesses survived 200 independent d=3 projections each (400 checks).
The maximum fixture row support is four; the sufficient no-wrap lower bound is
18, and the tests use q=31.

These validate the finite algebra and enumeration only; they do not establish
PQ hiding or secure deployment parameters.

## 6. Classification

- Canonical-Coset / affine-support DV-PoK: normal form equivalent to extractable WKEM; not an independent instantiation.
- OHLC semantic compiler: concrete polynomial-time construction with exact short-preimage extraction.
- Random projected OHLC: concrete statement-only compiler with an explicit short-pseudopreimage setup bound.
- PQ key-hiding/projective layer for the structured projected family: unresolved.
- Complete efficient generic-NP public offline PQ witness KEM: not completed.

The next target is the structured error-quotient theorem for projected OHLC. A
successful proof must cover the complete public view, not only minimum preimage
norm or a prescribed decoder.
