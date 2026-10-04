# Linear consistency MACs, fractional splicing, and the affine-flow collapse

## Status

This continuation starts from PR head
`5fb1581bd30f9524b20ad5e3a281ed6d6678adfb`.

The run tests the next natural repair to the small-block rank-condenser route:
secret linear "consistency MACs" that telescope across local blocks.

The complete-public-output audit rejects that route more generally than the
preceding `ker(Phi^*)` example:

1. every linear telescoping MAC that cancels on the public global linear image is
   exactly a vector in the same public annihilator/kernel space; the public
   adjoint quotient strips it;

2. an explicit local-CSP table with value pads does not enforce an integral
   witness -- its public key-recovery condition is exactly a fractional
   local-consistency system, and an odd false cycle recovers the key by averaging;

3. even replacing the cyclic CSP table by an **acyclic layered path table** does
   not solve the problem.  The complete public output encodes an affine
   field-valued flow relaxation, not path existence.  A five-edge layered DAG
   with no source-to-sink path has an explicit signed flow whose public linear
   combination recovers the key exactly.  The attack works over F2 as well, where
   the minus sign becomes plus.

The third item corrects a tempting but false positive hypothesis tested in this
run.  Acyclicity alone does not turn linear flow into witness/path extraction
because field-valued cancellation can inject and cancel flow at unreachable
branch vertices.

No external literature or web search was used.  This is a rejection of linear
telescoping consistency; it is not an impossibility theorem for nonlinear or
computationally hidden consistency encodings.

## 1. Linear telescoping MACs are the preceding public kernel mask

Let X be the global representation space, with public local views

    L_j : X -> Y_j,

and define

    Phi(x) = (L_1 x,...,L_T x) in Y=direct_sum_j Y_j.

A linear local consistency MAC has secret coefficient tuple

    g=(g_1,...,g_T) in Y

and contributes `<g_j,z_j>` to local decoder j.  Exact cancellation on every
honest global linear image means

    sum_j <g_j,L_j x> = 0          for every x in X,

or equivalently

    Phi^* g = 0.                                        (1)

Thus

    g in ker(Phi^*).                                    (2)

If a public local transcript is shifted by such a mask,

    O = N + g,

then the public quotient strips it exactly:

    Phi^* O = Phi^* N.                                  (3)

An edge/overlap MAC is just a parametrization of (2).  If an edge e=(j,k)
compares a shared public linear feature

    P_(j,e) z_j = P_(k,e) z_k

and uses secret r_e, its contribution is

    <r_e,P_(j,e)z_j> - <r_e,P_(k,e)z_k>.

The corresponding coefficient tuple has components
`P_(j,e)^*r_e` and `-P_(k,e)^*r_e`, and satisfies (1) identically.

So the natural authenticated-overlap repair does not escape the previous public
quotient theorem.  This statement is limited to linear MAC functions/cancellation
identities.  A genuinely nonlinear hidden coupling is outside its scope.

## 2. Local satisfying-assignment table: exact fractional recovery

Take a cycle of local binary constraints c_i on `(x_i,x_(i+1))`.  Setup chooses
key shares k_i with

    K = sum_i k_i

and independent value pads `r_(i,b)`, b in {0,1}.  For every locally satisfying
pair `(a,b)` in relation R_i publish

    T_(i,a,b)
      = k_i + r_(i,a) - r_(i+1,b).                     (4)

A genuine global satisfying assignment selects one entry per constraint and the
pads telescope to K.

The complete table supports fractional selections too.

### Theorem 2 -- exact row-span characterization

A universal public linear combination of the table rows yields K iff there are
coefficients `lambda_(i,a,b)` supported on R_i such that

    sum_((a,b) in R_i) lambda_(i,a,b) = 1              (5)

for every constraint i, and the value marginals agree at every shared variable:

    sum_b lambda_(i,v,b)
      = sum_a lambda_(i-1,a,v)                         (6)

for every i and v in {0,1}.

Proof: compare the independent coefficient of every k_i and every r_(i,v).
Equations (5) are exactly the k_i coefficients; (6) are exactly cancellation of
the r_(i,v) coefficients.  Conversely those equations cancel every pad and leave
`sum_i k_i=K`.

Hence the table implements the affine/local-marginal relaxation, not integral
CSP satisfaction.

### Explicit false odd-cycle recovery

Let every R_i be inequality,

    R_i = {(0,1),(1,0)},

and n be odd.  There is no global binary assignment satisfying the cycle.  Over
any field of odd characteristic set both local coefficients to 1/2.  Every
marginal equals 1/2, so

    K = (1/2) sum_i [T_(i,0,1)+T_(i,1,0)].             (7)

The checker verifies (7) on 100 fresh random pad/share fixtures for each
n=3,5,7,9.

An exhaustive census over all 16^3=4096 triples of binary edge relations on a
triangle over F_101 gives

    satisfiable instances:             2397
    unsatisfiable instances:           1699
    target-row-span instances:         2557
    unsatisfiable but key-recoverable:  160
    unsatisfiable and nonrecoverable:   1539

Every satisfiable instance is recoverable as it must be, but 160 false instances
also expose K through the complete public table.

## 3. Acyclic path-table attempt and its exact affine-flow semantics

The next attempted repair was to remove the CSP cycle entirely.

Let G be a public layered DAG

    V_0 -> V_1 -> ... -> V_L,

with source s in V_0 and sink t in V_L.  Choose layer shares k_i with
`sum_i k_i=K`, give every vertex except s,t an independent pad r_v, and publish
for each edge e=(u,v) from layer i to i+1

    C_e = k_i + r_u - r_v.                             (8)

A real s-t path still has perfect correctness:

    sum_(e in path) C_e = K.                           (9)

The hoped-for converse -- "a linear combination yielding K contains a path" --
is false.

### Theorem 3 -- exact affine-flow characterization

Let f_e be coefficients on public edge values.  Then

    sum_e f_e C_e = K

as an identity in all hidden shares/pads iff

1. for every layer i,

       sum_(e in layer i) f_e = 1,                     (10)

2. for every padded nonboundary vertex v,

       sum_(e out of v) f_e - sum_(e into v) f_e = 0.  (11)

These are field-valued affine-flow equations.  They do **not** impose
nonnegativity, integrality, one-hot selection, or even that nonzero support is
reachable from s.

There is also an exact complete-output statement.  Write the public table as

    C = M x

for hidden vector x=(k_i,r_v), and let H(x)=sum_i k_i.  For uniform hidden
randomness conditioned on H(x)=K:

* if H is in rowspace(M), the corresponding public row combination recovers K
  exactly;
* if H is not in rowspace(M), there exists `delta in ker(M)` with H(delta)!=0,
  and translation by delta bijects every key-conditioned transcript fiber.
  Therefore the **entire public transcript distribution is identical for all K**.

Thus the architecture has an exact all-or-nothing linear-algebra audit -- but its
row-span condition is affine-flow feasibility, not witness-path existence.

### Five-edge false DAG

Use four layers

    V0={s}
    V1={a,b}
    V2={c,d}
    V3={t}

and edges

    s->a,
    a->c,
    b->c,
    b->d,
    d->t.                                               (12)

There is no s-t path: the only source-reachable branch ends at c, and the only
branch reaching t starts at unreachable b.

Nevertheless the edge coefficients, in the order (12),

    (1, 1, -1, 1, 1)                                   (13)

satisfy (10)-(11).  Hence

    C_(s,a) + C_(a,c) - C_(b,c) + C_(b,d) + C_(d,t)
      = K                                               (14)

for every setup randomness.

Over F2, -1=+1 and the same five public edges also sum to K.  So this is not an
artifact of rational averaging or odd characteristic.

This is a stronger warning than the odd-cycle example: **acyclicity does not
repair public linear path tables**.

## 4. Why the obvious linear repairs return to prior rejected objects

To rule out (13), the public encoding would have to enforce that the f_e are a
single integral/one-hot path rather than an arbitrary field-valued affine flow.
Linear edge pads cannot express the quadratic conditions needed to prohibit
simultaneous positive/negative branch injection.

Possible literal repairs are exactly the kinds already separated elsewhere in
the research record:

* add higher-order/path-history coordinates -- a moment/consistency hierarchy
  whose explicit size grows with the history order;
* forbid state reuse and encode path history explicitly -- the prior no-reuse
  constructions have exponential middle-layer/state lower bounds;
* use a nonlinear/computationally hidden transition authenticator -- this is the
  still-missing class and needs an independent PQ reduction, not a renamed
  witness-encryption assumption.

A generic binary witness can always be represented by the full prefix tree, but
that explicit table has Theta(2^n) states/edges and is expressly disallowed as
the target construction.  This run does not substitute it.

## 5. Fresh validation actually executed

`flow_table_check.py` uses only the Python standard library.

It verifies:

1. the linear-MAC identity
   `sum_j <g_j,L_jx> = <Phi^*g,x>` and samples 500 fresh tuples from
   `ker(Phi^*)`;

2. the false five-edge DAG (12): no s-t path, target K vector in public row span,
   exact coefficients (13), and exact recovery over F2, F3, F5, F101;

3. exhaustive hidden-randomness distributions on that false DAG over F3,
   confirming that the public linear combination (14) equals K on every
   transcript;

4. 100 fresh odd-cycle table fixtures for each n=3,5,7,9 over F101, all recovering
   K by (7);

5. all 4096 binary-relation triangle CSPs over F101, producing the census above.

These are algebraic/distribution tests, not a computational security experiment.

## 6. Current handoff

New proved results:

* every exact **linear** telescoping overlap-MAC lies in the prior public
  annihilator space and inherits the public quotient collapse;
* local value-pad tables recover K on every fractional marginal solution, with
  an explicit odd false cycle and 160 false-leak triangle instances;
* even a layered acyclic path table relaxes to affine field-valued flow and has
  the explicit five-edge false recovery (14).

The constructive attempt therefore fails before any PQ parameter question: the
complete public view permits algebraic splicing without a source witness.

Still missing:

* a succinct **nonlinear or computationally hidden** consistency/path
  authenticator whose complete public output does not admit a removable quotient
  or affine-flow relaxation;
* a reduction for that object to an independently justified PQ assumption;
* arbitrary-QPT early final-key recovery -> source witness / independent
  hardness break, followed by malicious-secure ceremony composition and concrete
  practical estimates.

No efficient generic-NP PQ witness KEM is obtained in this run.
