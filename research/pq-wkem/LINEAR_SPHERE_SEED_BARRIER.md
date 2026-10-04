# Linear-seed succinctification of sphere representatives: exact false-cover break

Starting checkpoint: PR #1 head
`168c512b714eaa037e2a1eed5f42b01757117e83`.

## Status

The preceding sphere-representative construction repaired the old finite-cover
leakage by giving every explicit state an **independent** random representative
`v_s` of one nonlinear key fiber `Q(v_s)=k`. Its remaining defect is size: one
independent hidden vector per possible state is exponential for a generic NP
witness space.

This pass tests the most direct succinctification attempt rather than assuming a
hidden evaluator: derive all representatives from one short hidden seed using
public invariant-preserving linear maps,

    z <- S_k,
    v_s = L_s z.

For the quadratic-sphere instantiation the natural maps are public orthogonal
matrices `O_s`, since `Q(O_s z)=Q(z)=k`.

This compression **fails under the complete public output**. On any false cover
orbit `O`, the transcript exposes

    Z_O = sum_(s in O) v_s = A_O z,
    A_O = sum_(s in O) L_s.

Whenever `A_O` has a public left inverse, the false statement reveals the hidden
seed and therefore the key exactly. There is an explicit two-state false orbit
for which this happens for every odd field and every dimension `d>=2`, including
the `d=8` regime used in the previous statistical bound.

This is a barrier for **public linear/orthogonal seed expansion**, not an
impossibility theorem for nonlinear or computationally hidden representative
generators. It also does not solve the separate problem of publishing an
exponentially indexed token family succinctly.

No external literature or web search was used. Production code is unchanged.

## 1. Candidate compressed construction

Retain the finite permutation-cover transfer from the previous checkpoint. Let
`S_0` be the first-layer state set and let `pi` be public monodromy. Instead of
sampling independent

    v_s <- S_k = {v in F_q^d : Q(v)=k}

for every `s`, setup samples only one hidden seed

    z <- S_k.

For every state, choose a public linear map `L_s`. The quadratic-sphere candidate
uses

    L_s = O_s in O_d(F_q),

so all representatives obey

    v_s = O_s z,
    Q(v_s)=Q(z)=k.                                    (1)

The published edge tokens remain

    Y_e = m_e + r_tail(e) - r_head(e),                 (2)

where a first-layer edge from state `s` carries `m_e=v_s` and other edges carry
zero. A genuine fixed point still obtains exactly one `v_s` after one lap and
therefore correctly computes `k=Q(v_s)`.

Thus the candidate preserves the attractive same-key correctness while reducing
the representative entropy from one sphere sample per state to one sphere
sample plus public state maps.

The question is whether the independence that made false cover sums mix has
survived. It has not.

## 2. Complete-output orbit-sum theorem

The complete-transcript normal form from the preceding checkpoint did not rely
on independence of the representatives. On a directed cover component for a
monodromy orbit `O`, uniform vertex pads make the full edge transcript uniform
inside the affine fiber determined by its edge sum. Therefore the public
transcript deterministically exposes

    Z_O = sum_(s in O) v_s.                            (3)

Under the compressed generator `v_s=L_s z`, this becomes

    Z_O = A_O z,
    A_O := sum_(s in O) L_s.                           (4)

This gives the following exact public-output theorem.

### Linear-seed leakage theorem

Let a hidden parameter `theta in F_q^m` generate state representatives by public
linear maps

    v_s = L_s theta,     L_s in F_q^(d x m).

Let `O` be any public false cover orbit. If

    A_O = sum_(s in O) L_s

has a public left inverse `B` (`B A_O = I_m`), then the complete public
transcript reveals

    theta = B Z_O.                                      (5)

Consequently **every** public key function `K=kappa(theta)` is recovered exactly
on that false instance. No property of `kappa`, no Fourier approximation, and no
chosen decoder is needed.

Proof: equation (4) is a deterministic function of the complete transcript and
`B Z_O = B A_O theta = theta`. QED.

This theorem is broader than the quadratic sphere. Orthogonality only supplies a
particularly natural way to preserve the same-key invariant while compressing
the representatives.

## 3. Explicit false two-cycle for every odd field

Take any odd prime `q` and dimension `d>=2`. Define

    R = [ 0  -1 ]
        [ 1   0 ]

and

    O_a = I_d,
    O_b = diag(R, I_(d-2)).                             (6)

Both are orthogonal because `R^T R=I_2`. Let the public monodromy swap the two
states `a` and `b`. There is **no fixed point**, so this is a false instance in
the finite-cover relation.

Its unique monodromy orbit is `{a,b}` and

    A = O_a + O_b
      = diag(I_2+R, 2 I_(d-2)).                         (7)

Now

    det(I_2+R) = det([1 -1; 1 1]) = 2,

hence

    det(A) = 2^(d-1) != 0                              (8)

in every odd characteristic. The false public transcript therefore exposes

    Z = v_a+v_b = A z,
    z = A^(-1) Z,
    k = Q(z).                                           (9)

Only a **single false orbit of length two** is needed. The prior `2+3` Bezout
attack is not involved.

## 4. The statistical mixing repair collapses completely

The previous construction's false-orbit security came from convolution of
independent sphere representatives:

    X_1+...+X_h,       X_i independently uniform on S_k.

Here a two-cycle instead gives

    Z = (O_a+O_b) z,                                   (10)

which is just one sphere sample passed through an invertible linear map. There is
no convolution and hence no Fourier-power decay.

In fact false-key transcript separation is perfect for the explicit two-cycle.
For distinct nonzero keys `k != k'`, the sphere sets `S_k` and `S_k'` are
disjoint. Since `A` is invertible, their images `A S_k` and `A S_k'` are also
disjoint. Orbit sum is a public deterministic function of the transcript, so

    TV(Transcript_k, Transcript_k') = 1.               (11)

Thus this candidate does not merely lose a few bits of the Run-22 statistical
bound; it changes the false-instance distributions from close-to-common-uniform
to perfectly distinguishable.

## 5. Complete-transcript audit of the two-cycle

For two states, write pads `r_a,r_b` and representatives `v_a,v_b`. The public
edge tokens are

    Y_a = v_a + r_a-r_b,
    Y_b = v_b + r_b-r_a.                               (12)

Their sum is exactly

    Y_a+Y_b = v_a+v_b = Z.                             (13)

Conversely, for fixed `Z`, every edge pair `(Y_a,Y_b)` satisfying
`Y_a+Y_b=Z` occurs with the same multiplicity: choose the pad difference
`delta=r_a-r_b` arbitrarily, and there are exactly `q^d` common shifts of
`(r_a,r_b)` giving that `delta`.

So the attack in (9) uses a **complete sufficient statistic** of the full public
view; no unexamined edge-coordinate leakage or intended-decoder assumption is
being hidden in the argument.

## 6. What this rules out

The result rejects the following natural bridge from the positive explicit-state
primitive to a short hidden description:

1. sample one (or, by the theorem, any linearly recoverable collection of) hidden
   seed vectors;
2. derive every witness/state representative by public linear maps;
3. preserve the common key through a public invariant such as a quadratic norm;
4. keep the same telescoping public transfer.

Random public orthogonal maps do not help. A random sum may often be invertible,
but the explicit construction above already gives a deterministic false relation
where it is always invertible.

The theorem also identifies the necessary check for any future *linear* multi-seed
variant: stack the false-orbit sum equations. If their public block matrix has a
left inverse for the hidden seed vector, the complete transcript recovers all
seeds and therefore any key derived from them. Avoiding one invertible orbit is
not enough if several orbit equations jointly have full column rank.

## 7. What remains open

This is **not** a general impossibility theorem for succinct same-key
representatives. It leaves at least these possibilities logically open:

* a nonlinear seed expansion whose false-orbit observables do not invert the
  seed and can be reduced to an independently justified PQ assumption;
* a computationally hidden state evaluator whose public representation does not
  expose the seed and whose release property is proved from a weaker standard
  primitive rather than assumed;
* a different inner encoding in which successful public recovery Fourier-samples
  directly into the existing source-witness extractor without storing one
  representative per witness state.

However, an ordinary public circuit containing the hidden seed is not such a
solution: it simply publishes the seed. And postulating an evaluator that keeps
the seed hidden while releasing a same-key representative exactly on a valid NP
witness would restate the missing WE-like functionality.

So the next continuation should **not** return to public linear/orthogonal seed
compression of the sphere construction. The unresolved core remains a succinct
nonlinear/computational consistency mechanism with an actual arbitrary-QPT
recovery reduction.

## 8. Validation actually executed

`linear_sphere_seed_check.py` uses only the Python standard library. Fresh checks:

* for `q in {3,5,7,11,101}` and `d in {2,4,8}`, verified `O^T O=I` for (6),
  verified `det(I+O)=2^(d-1) mod q != 0`, and constructed the exact inverse;
* ran 500 random `q=101,d=8` false two-cycle transcripts; all 500 recovered the
  exact hidden seed and key from the public orbit sum;
* exhaustively enumerated all `3^(2d)=81` pad pairs for every one of the 9 seeds
  in the `q=3,d=2` fixture, verifying that the complete transcript has exactly
  `q^d=9` edge pairs in its affine fiber and every pair has multiplicity `q^d=9`;
* exhaustively enumerated all `5^4=625` seeds at `q=5,d=4`; the orbit-sum supports
  for keys `1,2,3,4` each have size 120 and every pairwise intersection is empty,
  confirming exact pairwise TV distance 1;
* ran 200 general random linear-seed fixtures over `F_7^3` conditioned on an
  invertible two-state sum map; all 200 recovered the hidden vector exactly.

These tests validate the stated finite algebra and implementation. They do not
prove a security property for a different nonlinear/computational generator.

## 9. Result classification

**Proved:** complete-output linear-seed leakage theorem; explicit orthogonal
false two-cycle; exact false-key statistical distance 1 for that candidate.

**Implemented:** deterministic finite-field checker for the theorem and explicit
attack.

**Actually tested:** the five groups listed in Section 8.

**Conjecture:** none is needed for the break proved here. Nonlinear succinct
representative generation remains an open direction, not a claimed construction.

**Stopping condition:** not met.
