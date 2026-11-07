# Run 35 — public quotient strips the Run-34 radix randomizers; exact `l_infinity` source gap remains

**Status:** exact complete-public-output break of the Run-34 coupled radix construction, plus a reusable semantic norm observation for the Run-32 source compiler. This is **not** a completed witness KEM, PQ security proof, or deployment recommendation.

Starting checkpoint: PR #1 head `3002399951686ec4deb7d0d0d05eac25dd524711` (Run 34). This run does not add another p-adic digit and does not retry the Run-33 independent-share splice. It audits the complete public vector output of the already-published Run-34 construction before spending more effort on lift binding.

No external literature or web search was used. Production code is unchanged.

## 1. Run-34 capsule recalled

Let `H` be the Run-32 homogeneous 3CNF compiler matrix, with distinguished normalization coordinate `h`, and let `p` be an odd prime. Run 34 works over

    Q = p^2.

For each component `c=(j,alpha,t)`, with Boolean pair `(u_j,ubar_j)`, `alpha in F_p \ {+1,-1}`, and `t in {0,1}`, define

    w_c = e_(u_j) - e_(ubar_j) - alpha e_h + p t e_h.     (1)

Setup samples `z_c in F_p`, row-space mask `y_c`, additive share `s_c in F_p`, and vector pad `T_c in F_p^n`, subject to

    sum_c s_c = K mod p,
    sum_c T_c = 0 mod p.                                  (2)

It publishes

    C_c = H^T y_c + z_c w_c + p s_c e_h + p T_c mod p^2. (3)

Run 34 correctly proved a local radix identity and showed that the zero-sum `T_c` pads force complete Fourier characters to agree modulo `p`. That blocks the coarse Run-33 splice. Run 34 then found a p-adic lift splice.

The stronger issue below occurs *before* that lift analysis: the full public vectors reveal every `z_c` through the quotient by the public row space.

## 2. Public row-space quotient recovers every `z_c`

Reduce (3) modulo `p`. The share and vector-pad terms disappear, while the offset digit in `w_c` also disappears:

    C_c mod p = H^T (y_c mod p) + z_c \bar w_c,            (4)

where

    \bar w_c = e_(u_j) - e_(ubar_j) - alpha e_h in F_p^n. (5)

Let

    R = im(H^T) <= F_p^n.                                 (6)

If `\bar w_c notin R`, ordinary public Gaussian elimination computes a functional

    lambda_c in ker(H)

such that

    <lambda_c, \bar w_c> = 1.                             (7)

Applying it to the public capsule gives

    <lambda_c, C_c mod p> = z_c.                          (8)

The row-space mask vanishes because `H lambda_c=0`; no source witness is supplied to the algorithm.

### Lemma 1 — every Run-34 root direction is outside the row space

For the Run-32 3CNF compiler and every odd `p`, every direction (5) with `alpha != +/-1` is outside `R`.

It is enough to exhibit, for every pair `j` and root `alpha`, a linear-relaxation kernel vector `x` with

    Hx=0 mod p, h(x)=1,
    d_j(x):=u_j-ubar_j != alpha.                           (9)

Then `<x,\bar w_c>=d_j(x)-alpha !=0`, so `\bar w_c` cannot lie in `im(H^T)`.

Such an `x` is public and easy to construct without satisfying the Boolean relation:

* For a source-variable pair, choose its first coordinate freely so that `2u_j-1 != alpha`; choose the other source variables arbitrarily. Every clause has its own slack pair with coefficient `1`, so the clause equation can always be solved linearly.
* For a first slack pair of a clause, choose that slack freely to avoid `alpha` and solve the second slack because `2` is invertible modulo odd `p`.
* For a second slack pair, choose it freely and solve the first slack using its coefficient `1`.

All pair-complement equations are then satisfied by `ubar=1-u`.

Equivalently, the attack can simply compute a basis of `ker H` and search it for a nonzero pairing with `\bar w_c`; this is what the executable checker does.

### Theorem 2 — the complete public output exposes the full radix-randomizer vector

For every Run-34 component, `z_c` is a deterministic polynomial-time function of public `(H,w_c,C_c)` via (7)-(8). Thus the vector `(z_c)_c` is not hidden at all by the row-space masks.

This is a complete-output quotient attack, not the intended witness decoder and not the Run-34 p-adic lift splice.

## 3. After stripping `z_c`, the aggregate key is public

Having recovered every `z_c`, form the public vector

    D = sum_c (C_c - z_c w_c) mod p^2.                    (10)

Using (2)-(3),

    D = H^T Y + p K e_h mod p^2                           (11)

for public-unknown `Y=sum y_c`; the zero-sum vector pads vanish, and `p sum s_c = pK mod p^2`.

The remaining question is whether one needs a source witness to kill `H^T Y`. For the Run-32 compiler, the answer is no.

### Lemma 3 — every compiled 3CNF has a public normalized linear-relaxation kernel point

Set `h=1` and every source Boolean variable to `0`, with complement `1`. In a clause, let `L` be the number of negative literals, so the three literal coordinates sum to `L`. The clause equation is

    L + s_1 + 2 s_2 = 4.                                 (12)

Set

    r = 4-L,
    s_2 = floor(r/2),
    s_1 = r - 2 s_2,                                     (13)

and set each slack complement to `1-s_i`.

This produces an **integer** vector `x_rel` satisfying

    H x_rel = 0,
    (x_rel)_h = 1                                        (14)

for every 3CNF, satisfiable or not. It is generally not Boolean: when `L=0`, for example, `(s_2,\bar s_2)=(2,-1)`.

The construction uses only the public formula. It is a linear-relaxation point, not a source witness.

### Theorem 4 — deterministic public key recovery on every statement

Apply `x_rel` to (11):

    <x_rel,D>
      = <H x_rel,Y> + p K (x_rel)_h
      = p K mod p^2.                                     (15)

Hence

    K = (<x_rel,D>/p) mod p.                              (16)

The full attack is therefore:

1. reduce each capsule modulo `p`;
2. compute `lambda_c` by Gaussian elimination and recover `z_c`;
3. subtract `z_c w_c` and sum all capsules;
4. construct the public normalized linear relaxation `x_rel`;
5. evaluate (16).

It is polynomial time in the public compiler/capsule size. It uses no valid Boolean witness.

On a **false** statement this directly violates false-instance hiding: the key is recovered despite there being no source witness at all. Therefore no source-extraction caveat can rescue this candidate. On true statements the same algorithm is still witness-free; the false-instance break is already sufficient to reject the construction unconditionally.

Distinct-key complete transcript supports are disjoint because (16) is a deterministic public key function.

## 4. Scoped generalization: public additive randomizers with exact linear witness action

The quotient step is not specific to the chosen root table.

Let public capsules have the form

    C_z = H^T y + R_z + p V mod p^2,                      (17)

and suppose modulo `p` the randomizer has public linear form

    R_z mod p = z w + r,   r in im(H^T).                  (18)

Whenever `[w]` is nonzero in the public quotient `F_p^n / im(H^T)`, the quotient reveals `z` exactly. Uniform or nonlinear sampling of `y` cannot change that fact because `y` lies in the quotient kernel.

There is also a useful design boundary. If one insists that a public vector randomizer `R_z` have the exact linear action

    <x,R_z> = z <x,w>                                    (19)

for **every** `x in ker H`, then

    R_z - z w in (ker H)^perp = im(H^T),                 (20)

so its quotient is necessarily

    [R_z] = z[w].                                        (21)

Thus no additive row-space masking can hide the scalar `z` from the complete public output while retaining (19) on the whole linear kernel.

This is a scoped linear-functional barrier, not a generic impossibility theorem. A surviving construction must make correctness depend on genuine source-witness structure beyond the entire linear relaxation, or use a computational layer whose quotient does not simply reveal the witness-side randomizer. Merely renaming such a layer as a hidden evaluator would be circular with the WE-equivalent functionality already recorded in this PR.

## 5. Constructive semantic observation retained from Run 32: exact `l_infinity` gap

Run 32 emphasized the bad `l_2` gap: a false normalized vector can be only `+4` in squared norm above the honest threshold, and padding drives the multiplicative `l_2` gap to one.

The same source compiler has a stronger **coordinatewise** property that is worth retaining for future lattice attempts.

### Theorem 5 — exact infinity-norm source gap

For every satisfying 3CNF, the honest normalized vector has

    Hx=0, h=1, ||x||_infinity = 1.                       (22)

Conversely, let `x` be an integer vector satisfying

    Hx=0, h=1, ||x||_infinity <= 1.                      (23)

Each pair obeys `(u,1-u)`. If integer `u` is not `0` or `1`, then one of `u,1-u` has absolute value at least `2`, contradicting (23). Hence every pair is Boolean, and the clause rows force a satisfying assignment exactly as in Run 32.

Therefore on a false statement every normalized integer kernel vector obeys

    ||x||_infinity >= 2.                                 (24)

Unlike the `l_2` threshold, this is a factor-two gap independent of irrelevant padding.

For centered modular representatives, a sufficient no-wrap condition is `Q>20`: each pair row has coefficient `l_1` norm `3`, and each clause row has coefficient `l_1` norm at most `10`; with `||x||_infinity<=1`, every integer row product has absolute value below `Q/2`. Thus a centered modular vector satisfying `Hx=0 mod Q`, `h=1`, and `||x||_infinity<=1` also yields a source witness under this bound.

This does **not** give a KEM by itself. Ordinary inner-product noise is governed by a dual norm and still faces the previously recorded complete-view/splicing and odd-span spectral barriers. The point is narrower: the semantic compiler itself has a padding-resistant gap in a norm that Run 32 did not exploit. A future construction should not discard that property prematurely.

## 6. Validation actually executed

`public_quotient_radix_break_check.py` is standard-library-only. A fresh execution and an immediate rerun produced byte-identical JSON.

Executed checks:

* fixed **true** two-clause instance `(z OR z OR z) AND (z OR z OR z)`, where the public all-zero relaxation is explicitly **not** a source witness:
  * primes `p=5,7,11,13`;
  * `80` setup trials per prime;
  * every Run-34 root direction outside the public row space;
  * every complete `z_c` vector recovered exactly;
  * `320/320` final keys recovered;
* fixed **false** contradiction `(z OR z OR z) AND (!z OR !z OR !z)`:
  * the same four primes and `80` trials per prime;
  * every `z_c` vector recovered exactly;
  * `320/320` false-instance keys recovered;
* exhaustive one-variable/two-clause sign census:
  * all `64` ordered formula pairs at each of the four primes (`256` attacked formulas total);
  * `62` satisfiable and `2` unsatisfiable formulas per prime;
  * every root direction outside row space and `256/256` keys recovered;
* random satisfiable instances:
  * `20` independently generated formulas per prime, `2..5` variables and `3..7` clauses;
  * the generator retains a known witness only as a **test oracle**; the attack is not given it;
  * every public linear relaxation is a non-witness;
  * `10` setups per formula, giving `800/800` exact `z`-vector recoveries and `800/800` key recoveries;
* exact small semantic `l_infinity` census over all `64` one-variable/two-clause sign formulas, enumerating normalized pair values in `[-2,2]`:
  * all `62` satisfiable formulas have minimum normalized-kernel `l_infinity=1`;
  * both unsatisfiable formulas have minimum `l_infinity=2`;
  * no other case occurred.

Across the fixed, exhaustive, and random attacks the checker recovered `1696/1696` tested keys. These executions validate the finite linear algebra and implemented public attack; they are not evidence for security of a replacement construction.

## 7. Result and handoff

**Proved in this run:**

* every Run-34 radix scalar `z_c` is exposed by the public quotient modulo `p`;
* after stripping them, the zero-sum shares/pads collapse to one public aggregate `H^T Y + p K e_h`;
* every Run-32 compiled statement has a public normalized linear-relaxation kernel point, so that aggregate exposes `K`;
* consequently Run 34 is publicly key-recoverable on false as well as true statements, independently of the p-adic lift splice;
* the Run-32 source compiler nevertheless has an exact padding-resistant `l_infinity` gap `1` versus `>=2` for normalized integer kernel points.

**Still unresolved:**

* a polynomial-size witness-restricted encoder whose complete public quotient does not expose its witness-side randomizers;
* a way to exploit the `l_infinity` semantic gap without reintroducing per-coordinate representation splicing or the prior odd-span/spectral failures;
* an arbitrary-QPT early-key-recovery reduction to a source witness or an independently justified PQ break for a surviving inner primitive;
* malicious-secure setup composition and concrete end-to-end parameters for that surviving primitive.

The stopping condition is not met. The next constructive direction should move away from public additive randomizers whose intended witness action extends to the entire linear kernel; that extension is exactly what makes the quotient attack unavoidable.
