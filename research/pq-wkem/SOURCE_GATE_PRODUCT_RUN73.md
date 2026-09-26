# Run 73 — global product-program source gate composes with Run-72 LWE, but complete public linear closure recovers the target on a false CNF

**Status:** substantive constructive source-gate attempt, exact false-statement break, and a low-degree repair barrier. **Not a completed generic-NP witness KEM.**

Starting verified PR head: `fec61cb879180f4f4c833300cbd904e9694e3984`.

This run uses no external literature/web search and changes no production path.

## 1. Why this candidate is materially different from the rejected local input-label interface

Run 72 isolated a useful native primitive: once a high-entropy parent capability already exists, ordinary LWE gives a public offline one-way transport to a child capability, including a `k`-parent/AND form.

The remaining source problem was that a public local interface

```
GetLabel(i,b)
```

can simply be invoked for both `b=0` and `b=1`.

This run therefore does **not** allocate independent source labels. It gives an assignment one **global terminal capability** obtained from a single product over all variable choices. Each variable is queried once, and its chosen matrix simultaneously affects every clause in which it occurs. Thus there is no per-occurrence input label to splice.

If the terminal target could only be obtained from a satisfying assignment, it would be a valid parent for the Run-72 LWE transport.

The complete public output shows that the natural transparent linear representation does not have that property.

## 2. Exact CNF product compiler

Let a CNF formula have variables `x_1,...,x_n` and clauses `C_1,...,C_m`.

For each variable `i` and bit `b`, define the diagonal `(m+1) x (m+1)` matrix

```
G_{i,b} = diag(1, g_{i,b,1}, ..., g_{i,b,m}),
```

where

```
g_{i,b,c} = 0   if assigning x_i=b satisfies some literal of C_c,
              1   otherwise.
```

For a full assignment `w`, define

```
G(w) = product_i G_{i,w_i}.
```

Because the matrices are diagonal, the first coordinate is always one and clause coordinate `c` equals the product of the per-variable "not yet satisfied by this assignment" bits. Therefore

```
G(w) = diag(1, u_1(w), ..., u_m(w)),                 (1)
```

where `u_c(w)=1` iff `C_c` is violated by the complete assignment.

Let

```
G_* = diag(1,0,...,0).
```

Then

```
G(w)=G_*  iff  w satisfies the CNF.                  (2)
```

This is an exact polynomial-size semantic compiler. It does not use a source witness during setup.

## 3. Hidden-basis telescoping and a common target capability

Setup samples independent invertible matrices

```
S_0,...,S_n <- GL_{m+1}(F_q)
```

and publishes

```
T_{i,b} = S_{i-1}^{-1} G_{i,b} S_i.                 (3)
```

Choose

```
z_0 = (1, z_1, ..., z_m)^T
```

with nonzero clause coordinates, and publish

```
z = S_n^{-1} z_0.
```

For assignment `w`, anybody can compute

```
s(w) = (product_i T_{i,w_i}) z
     = S_0^{-1} G(w) z_0.                            (4)
```

The setup target is

```
s_* = S_0^{-1} G_* z_0
    = S_0^{-1} e_0.                                  (5)
```

Every satisfying witness obtains exactly the same `s_*`.

This is the constructive point of the run: the source semantics are global rather than a bag of independently accessible input labels.

### Distribution of the target parent

For uniform `S_0 in GL_d(F_q)`, `S_0^{-1}e_0` is uniform over the nonzero vectors of `F_q^d`. Its statistical distance from a uniform vector in `F_q^d` is exactly `q^{-d}`.

Thus if this source encoder were sound, using `s_*` as the parent secret in the clean Run-72 LWE transport would differ from the standard uniform-secret LWE experiment only by negligible statistical distance for ordinary cryptographic dimensions.

The checker exhaustively verifies the group-action claim in the control case `GL_2(F_3)`: all eight nonzero target vectors occur exactly six times among the 48 invertible matrices.

## 4. Composition with the Run-72 LWE transport

After computing `s_*`, setup can transport a fresh root capability `k_root` with the Run-72 bitwise LWE token

```
b_j = <a_j,s_*> + Delta * Bits(k_root)_j + e_j.       (6)
```

A satisfying witness computes `s_*` by (4), subtracts the parent term, and recovers `k_root`.

If unauthorized recovery of `s_*` required a source witness, then the existing Run-72 reduction would handle the remaining local reverse direction under standard LWE.

The next section shows that the transparent source encoder fails before LWE hardness is reached.

## 5. Exact complete-public-output break on a zero-witness CNF

Consider

```
F_0 = (not x) AND (not y) AND (x OR y).               (7)
```

There is no satisfying assignment.

For the three assignments

```
w_10 = (1,0)
w_01 = (0,1)
w_11 = (1,1),
```

their clause-violation vectors are

```
u(w_10) = (1,0,0)
u(w_01) = (0,1,0)
u(w_11) = (1,1,0).
```

Hence from (1),

```
G(w_10) + G(w_01) - G(w_11) = G_*.                  (8)
```

The coefficient sum is `1+1-1=1`, so the constant coordinate is also correct.

Hidden-basis telescoping is linear. Multiplying (8) by `S_0^{-1}` on the left and `z_0` on the right gives

```
s(w_10) + s(w_01) - s(w_11) = s_*.                  (9)
```

All three terms on the left are computable from the complete public transcript. None is a source witness, because `F_0` has no witnesses.

Thus the attacker recovers the exact target parent capability without solving LWE, without recovering any hidden basis, and without finding a satisfying assignment.

It can then use `s_*` to decrypt the otherwise-correct Run-72 LWE token.

The finalized checker obtains:

* `500/500` exact false-statement parent recoveries by (9);
* `500/500` subsequent root-capability recoveries through a fresh Run-72-style LWE transport.

This is a source-transfer failure, not an LWE attack.

## 6. General linear clause-defect closure theorem

The previous attack is not specific to the diagonal basis.

Suppose a terminal source representation has the form

```
R(w) = R_* + sum_c u_c(w) D_c,                       (10)
```

in any public or secretly linearly embedded vector space, where `u_c(w)` is the clause-violation indicator.

For `F_0` above,

```
R(w_10) = R_* + D_1
R(w_01) = R_* + D_2
R(w_11) = R_* + D_1 + D_2.
```

Therefore

```
R(w_10) + R(w_01) - R(w_11) = R_*.                  (11)
```

Any linear change of basis, public projection, secret conjugation followed by public coordinates, or other linear embedding preserves (11).

The checker samples 1,000 random defect embeddings in dimensions `2,4,9,17`; every one satisfies the exact recovery identity.

This theorem closes the natural "randomize the clause coordinates harder" repair as long as the complete public representation remains linear in the clause-defect vector.

## 7. Constructive repair attempt: nonlinear feature lifting

A natural next move is to replace the raw defect vector `u` by nonlinear features such as all multilinear monomials through degree `d`.

The three-point attack above is indeed killed by a quadratic cross term. That is a real improvement on that one fixture.

However there is an exact family showing that every fixed low degree still admits a false affine recovery.

For `r >= 2`, consider the unsatisfiable formula

```
F_r = (AND_{i=1}^r not x_i) AND (x_1 OR ... OR x_r). (12)
```

The unit clauses require `x=0^r`; the final OR clause rejects exactly `0^r`, so the conjunction is false.

For every nonzero assignment `w`, the violation vector is

```
u(w) = (w_1,...,w_r,0).                              (13)
```

The target violation vector is `0`.

Let `P(u)` be any multilinear polynomial of degree `< r`. The Boolean-cube alternating-sum identity gives

```
P(0) =
  sum_{w != 0} (-1)^{|w|+1} P((w,0)).                (14)
```

Proof: every monomial of degree `< r` misses at least one of the first `r` variables, so its full `r`-dimensional alternating difference is zero. Rearranging the term at `w=0` gives (14).

The coefficients in (14) sum to one (take `P=1`), so this is an affine combination.

Consequently **every explicit multilinear feature lift of degree `< r` still puts the target feature vector in the affine span of invalid full assignments.**

At degree `r`, the monomial `u_1...u_r` separates the identity. The checker verifies the exact threshold for every `r=2,...,7`, totaling 1,290 feature-coordinate equalities below the threshold and six degree-`r` separations.

### Scope of this lower bound

If all monomials through degree `r` are expanded explicitly, the feature dimension contains `2^r` terms, which is the exponential encoder forbidden by the target requirements.

This is **not** a proof that every compact high-degree circuit requires exponential resources. A compact nonlinear evaluator can compute high-degree functions without expanding every monomial. But Run 67 already showed that a transparent public evaluator with reconstructible effective coefficients does not automatically hide the key. A surviving repair therefore has to provide a computationally hidden nonlinear evaluation mechanism, not merely a larger public feature list.

## 8. What has and has not been proved

### Proved in this run

1. The CNF product compiler (1)-(2) is exact and polynomial-size.
2. Hidden-basis telescoping gives every satisfying assignment the same terminal target capability (3)-(5), with no witness known at setup.
3. That target is uniform over nonzero vectors under a uniform hidden basis, hence statistically `q^{-d}` from uniform-secret LWE.
4. The zero-witness formula (7) recovers the exact target by the public affine identity (9).
5. The same attack applies to every linearly embedded clause-defect representation (10).
6. The family (12) defeats every explicit multilinear feature lift of degree `<r` by the exact inclusion-exclusion identity (14).

### Implemented and tested

The standard-library checker implements:

* the clause-product compiler;
* hidden-basis setup/evaluation;
* the explicit false-statement affine attack;
* a small Run-72-style LWE transport after the recovered parent;
* random clause-defect embedding controls;
* the low-degree inclusion-exclusion family;
* exhaustive `GL_2(F_3)` target-distribution control.

The checker was executed twice with byte-identical JSON.

### Not proved

This run does **not** prove:

* impossibility of all compact nonlinear source gates;
* security of a compact high-degree repair;
* an arbitrary-QPT final-key-recovery-to-witness theorem;
* false-instance hiding for a completed construction;
* malicious-secure distributed setup/erasure;
* auxiliary-input composition;
* concrete secure parameters.

## 9. Current handoff

Run 72 removed one local mystery: standard LWE suffices once the right parent capability exists.

Run 73 shows a polynomial **global** semantic source encoder can avoid independent source labels and still fail because its complete public representation admits affine synthesis of the target from inconsistent invalid assignments.

The next useful target is therefore narrower:

> construct a compact nonlinear/computational source encoder `w -> s(w)` such that all satisfying witnesses obtain one common high-entropy `s_*`, while computing `s_*` from the complete transcript either yields a satisfying witness or breaks an independently justified PQ assumption.

It must not expose a public linear/affine closure of invalid terminal states, an explicit low-degree feature list, or a transparent evaluator whose effective key-bearing function can be reconstructed. If such an encoder is obtained, the Run-72 LWE transport is already available for the downstream one-way capability layer.
