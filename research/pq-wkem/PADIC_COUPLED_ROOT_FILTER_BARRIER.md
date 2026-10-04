# Run 34 — p-adically coupled affine-root filters: first-layer splice repair and next-digit lift attack

**Status:** constructive strengthening of Run 33 plus an exact complete-output false-instance break. This is **not** a completed witness KEM, a PQ security proof, or a deployment recommendation.

Starting checkpoint: PR #1 head `dbd58f53bfbd7d3e404c2f046b24f2348f29583d` (Run 33). The Run-32 normalized integer-kernel compiler and the Run-33 contradiction fixture are retained. This run does not return to independent XOR shares: it explicitly couples all local channels so that the old two-vector splice is information-theoretically masked unless the chosen kernel characters agree modulo a common prime.

No external literature or web search is used. Production code is unchanged.

## 1. Why strengthen the Run-33 filter

Run 33 had an exact local channel, but every `(pair,prime)` capsule was independently decodable. On the false formula

    (z OR z OR z) AND (!z OR !z OR !z),

one public exact kernel pseudovector could be used on some components and a second pseudovector on the remaining component. Nothing forced the local decoders to refer to one representation.

The new attempt adds a zero-sum vector pad shared across **all** components. In the complete Fourier view this forces all surviving component characters to have the same reduction modulo `p`. This really kills the old Run-33 splice. The failure found here is subtler: characters can still choose different lifts modulo `p^2` while agreeing modulo `p`.

## 2. Source relation and notation

Use the Run-32 homogeneous linear compiler. It has a distinguished coordinate `h` and, for every Boolean pair `j`, coordinates

    (u_j, ubar_j)

with row

    u_j + ubar_j - h = 0.                              (1)

Write

    d_j(x) = u_j - ubar_j.                              (2)

A genuine normalized source witness has

    Hx = 0 over the integers,
    h = 1,
    d_j(x) in {-1,+1} for every j.                      (3)

For the concrete false fixture there are five pairs `(z,a,b,c,d)`. At `h=1` its two clause rows reduce to

    a + 2b = 4 - 3z,
    c + 2d = 1 + 3z.                                    (4)

No all-Boolean solution exists.

## 3. A p-ary radix filter over Z_(p^2)

Fix an odd prime `p` and put

    Q = p^2.                                             (5)

For a pair `j`, a root

    alpha in F_p \ {+1,-1},

and an offset digit `t in {0,1}`, define the public direction

    w_(j,alpha,t)
       = (e_(u_j) - e_(ubar_j)) - alpha e_h + p t e_h.  (6)

For a character/vector `x`, let

    e_(j,alpha,t)(x)
       = <x,w_(j,alpha,t)>
       = d_j(x) - alpha h(x) + p t h(x)  (mod p^2).     (7)

The basic scalar radix channel is

    r = z e + p q  (mod p^2),                            (8)

where `z,q` are in `F_p`.

### Lemma 1 — exact three-way radix law

1. If `e mod p != 0`, the map `(z,q) -> r` is a bijection from `F_p^2` to `Z_(p^2)`. In particular `q` is recovered uniquely:

       z = (r mod p) * e^(-1) mod p,
       q = (r - z e)/p mod p.                            (9)

2. If `e = p k` with `k != 0 mod p`, then uniform `z` makes `r` uniform on `p F_p`, independently of `q`. The share is perfectly erased.

3. If `e = 0 mod p^2`, then

       r = p q,                                          (10)

   so `q` is exposed exactly.

The checker exhausts all `e` and all `q` for `p=3,5,7`; every case matches this trichotomy.

The third branch is the new danger. Run 33 only needed to distinguish unit from nonunit behavior at one modulus. Once a radix digit is added so that shares can be coupled, an *exact zero at the next digit* becomes a public share decoder.

## 4. Coupled-share construction

Let `C` be the set of all triples `(j,alpha,t)` from (6). There are

    |C| = 2 N (p-2)                                     (11)

components for `N` Boolean pairs.

To encode one key symbol `K in F_p`, setup samples:

* shares `s_c in F_p`, uniformly subject to

      sum_c s_c = K;                                    (12)

* vector pads `T_c in F_p^n`, uniformly subject to

      sum_c T_c = 0;                                    (13)

* independent `z_c in F_p`;
* independent `y_c in Z_(p^2)^m`.

It publishes, for every component `c=(j,alpha,t)`,

    C_c = H^T y_c + z_c w_c + p s_c e_h + p T_c
          (mod p^2).                                    (14)

Setup uses only the statement and the chosen key; it does not know a source witness.

### Honest decoding

For a genuine source witness `x`, `h=1` and `d_j=+-1`. Since every published root excludes `+-1`,

    e_c(x) != 0 mod p                                   (15)

for every component. The witness computes

    r_c = <x,C_c>
        = z_c e_c(x) + p(s_c + <x,T_c>) mod p^2         (16)

and applies Lemma 1 to recover

    q_c = s_c + <x,T_c> mod p.                          (17)

Summing all components cancels the vector pads:

    sum_c q_c
      = K + <x,sum_c T_c>
      = K.                                               (18)

So every valid witness recovers the same key exactly.

## 5. What the zero-sum pads really enforce in the complete output

The coupled pads are not heuristic. Their complete Fourier effect is exact.

Consider a Fourier character tuple `(x_c)_c` for the whole published tuple `(C_c)_c`.

* Averaging each `y_c` kills the coefficient unless

      H x_c = 0 mod p^2                                 (19)

  for every component.

* Averaging `(T_c)_c` subject to `sum T_c=0` kills the coefficient unless

      x_c = x_c' mod p                                  (20)

  coordinatewise for every pair of components `c,c'`.

For one coordinate this is the elementary sum

    sum_{T_1+...+T_C=0}
       omega_p^(x_1 T_1 + ... + x_C T_C),               (21)

which is nonzero exactly when all `x_c` are equal in `F_p`. The vector statement follows coordinatewise. The checker exhausts this identity for all character triples at `p=3` and `p=5`.

* Averaging the additive shares subject to (12) then gives the key phase for their common `h mod p`.

Thus Run 33's original attack using two kernel vectors with **different mod-p reductions** is genuinely neutralized: the pad error becomes uniform in `F_p`. In the finite control, replacing the one bad component by the old Run-33 pseudovector gives a nearly uniform error histogram and succeeds only at the expected `1/p` rate.

This is real constructive progress. It is not enough.

## 6. Why the two root offsets would work if one full lift were forced

Fix a common character `x` satisfying (19) and suppose for some pair

    d_j(x) = alpha h(x) mod p.                           (22)

Then

    e_0(x) = p k,
    e_1(x) = p(k+h)                                      (23)

for some `k in F_p`.

If the key phase is sensitive, `h != 0 mod p`. Hence `k` and `k+h` cannot both be zero. By Lemma 1, at least one of the two offset components has a nonzero multiple of `p` and perfectly erases its share.

This was the intended repair: enumerate every non-Boolean root `alpha`, then use the two next-digit offsets so a false common representation cannot make every share readable.

The flaw is that (20) forces only a common **mod-p class**, not a common lift modulo `p^2`.

## 7. Explicit p-adic lift splice on the Run-33 false formula

Retain the exact integer kernel pseudovector

    x0: (z,a,b,c,d) = (0,0,2,1,0),                      (24)

with `h=1` and complements `(1-u)`. Its pair differences are

    (-1,-1,3,1,-1).                                     (25)

So the only non-Boolean root is the `b` pair with `alpha=3`.

For every odd prime `p>=5`, define a homogeneous kernel direction modulo `p` by

    u_h = u_z = u_c = u_d = 0,
    u_a = 1,
    u_b = -1/2,                                          (26)

with complements negated. It obeys

    H u = 0 mod p,
    d_b(u) = -1 mod p.                                  (27)

Now lift

    x1 = x0 + p u  (mod p^2).                            (28)

Then

    x1 = x0 mod p,
    H x1 = 0 mod p^2,                                   (29)

but the next digit of the bad pair has changed.

For the two `alpha=3` components:

* on `(t=0)`, use `x0`. Since `d_b(x0)=3`,

      e_(b,3,0)(x0) = 0 mod p^2;                        (30)

  Lemma 1 exposes that masked share;

* on `(t=1)`, use `x1`. Since the lift changes `d_b` by `-p`,

      e_(b,3,1)(x1)
        = (3-p) - 3 + p
        = 0 mod p^2.                                    (31)

  That masked share is also exposed.

Every other component can use `x0`: its root differs from the relevant pair ratio modulo `p`, so its `e` is a unit modulo `p` and Lemma 1 decodes the masked share normally.

Crucially, **all selected characters are equal modulo `p`** by (29). Therefore the global zero-sum pads still cancel:

    sum_c <x_c,T_c>
      = <x0 mod p, sum_c T_c>
      = 0.                                               (32)

The attacker recovers every `q_c`, sums them, and obtains `K` exactly.

No Boolean source witness exists. No source witness is found by the attack.

### Theorem 2 — deterministic false-instance complete-output break

For the coupled construction (14), on the false formula (4), every prime `p>=5` admits the public character selection above. It recovers the encoded key symbol for every setup randomness.

Consequently distinct-key complete transcript supports are disjoint and their total variation distance is 1.

This is stronger than showing one Fourier coefficient survives: it is an explicit polynomial-time decoder of the full false-instance output.

## 8. The actual boundary exposed by this run

The new coupling closes the **coarse representation splice** from Run 33 but leaves a **p-adic lift splice**:

* zero-sum pads in `p F_p^n` bind all component characters only modulo `p`;
* the radix root test depends on the next digit modulo `p^2`;
* a false mod-p kernel class with a nontrivial homogeneous tangent direction can choose that next digit independently in different components;
* the exact-zero branch of Lemma 1 then exposes each share.

This suggests a finite-radix ascent problem. Moving the coupling to the next digit is not automatically a repair: a construction that merely adds another independent radix layer must audit whether different characters agreeing through that layer can splice at the following lift. This note does **not** claim an impossibility theorem for every p-adic or nonlinear realization.

A surviving repair needs something stronger than another finite independent digit:

1. a mechanism that binds the **entire representation used by all root tests**, not only a residue class; or
2. a representation whose false mod-p kernel classes are Hensel-rigid, so there is no tangent direction that can independently alter the next root digit; or
3. a computational source-binding layer with an actual reduction to an independently justified PQ assumption, rather than an assumed WE-equivalent evaluator.

The current Run-32 compiler is linear, so its homogeneous tangent space is public and the explicit direction (26) exists on the contradiction gadget.

## 9. Validation actually executed

`coupled_root_filter_check.py` is standard-library-only. A fresh run and an immediate rerun produced byte-identical JSON.

Executed checks:

* exhaustive scalar radix law for every `e in Z_(p^2)` and every key-share symbol at `p=3,5,7`:
  * every unit-`e` case partitions the whole residue ring into `p` disjoint share supports;
  * every nonzero multiple-of-`p` case gives identical supports for all shares;
  * `e=0` exposes the share exactly;
* exhaustive zero-sum-pad Fourier control for all 3-character tuples at `p=3,5`: equality modulo `p` is exactly the nonvanishing condition;
* exhaustive 32 Boolean assignments for the contradiction fixture: zero source witnesses;
* exact kernel/lift identities (27)-(31) for `p=5,7,11,13`;
* 250 honest setups at each of those four primes:
  * `70,000/70,000` local masked-share decodes;
  * `1,000/1,000` final same-key recoveries;
* 250 false setups at each prime using the p-adic lift splice:
  * `70,000/70,000` local masked-share decodes;
  * `1,000/1,000` false final-key recoveries;
  * exactly two `e=0` local decodes per setup (the two bad-root offset shares), all remaining local decodes use the unit branch;
* old Run-33-splice controls: `7,200` setups using the old second pseudovector only on the bad component. The recovered-key error is spread across all `F_p` residues rather than cancelling, consistent with the exact mod-p pad-coupling theorem.

These executions validate the finite identities and the implemented attack. They are not evidence for security of an unbroken replacement.

## 10. Resource shape of the rejected candidate

For a 3CNF with `N = n + 2m` Boolean/slack pairs, the Run-32 ambient vector has `1+2N` coordinates. This candidate publishes

    2 N (p-2)                                             (33)

capsule vectors, each with `1+2N` residues modulo `p^2`, for roughly

    2 N (p-2)(1+2N) = O(p N^2)                           (34)

residues. With fixed small `p` this is polynomial and superficially practical enough to warrant the complete-output audit; the attack is therefore not dismissing an exponential encoder.

## 11. Remaining obligations

The stopping condition remains unmet. Still missing are:

* a polynomial-size common-representation binder that survives the p-adic lift attack (and the earlier quotient, interpolation, finite-difference, recurrence, low-rank-completion, and label-recovery attacks);
* arbitrary-QPT early-key recovery -> source witness or an independently justified PQ break for the **complete** output;
* a false-instance hiding proof for a surviving inner primitive;
* malicious-secure setup composition and concrete end-to-end parameters for that surviving primitive.

The useful handoff is precise: the Run-33 local exact filter can be upgraded into a radix-coupled root system that really binds the first residue layer, but any next attempt must bind or rigidify the *lift*, not merely repeat the same construction at one more digit.
