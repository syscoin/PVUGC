# Run 71 — rank-r hidden-subspace transports are publicly reversible; bounded orthogonal noise preserves the false alternating walk

**Status:** constructive hidden-subspace / noisy noncommutative attempt plus exact complete-output attack and bounded-noise theorem. **Not a completed WKEM and not an LWE/SIS break.**

This run starts from PR head `52c0be7fb4e7ca41c742580763f1735090878ea4` and Run 70. It does not retry the commutative exponent binder or the transparent rank-one matrix-unit attack. The goal is the route left open there: replace exposed one-dimensional state lines by higher-rank hidden channels and then ask whether noise can make those channels one-way while preserving offline witness composition.

No external literature or web search is used. Production code is unchanged.

## 1. Constructive candidate: dense rank-r state channels

Work over a finite field `F_q`. Each semantic node/state `v` has a hidden rank-r channel represented by public-space maps

```
C_v : F_q^r -> F_q^d,
R_v : F_q^d -> F_q^r,
R_v C_v = I_r.
```

Setup can obtain these from a secret dense basis: if `S_v in GL_d(F_q)`, take the first `r` columns of `S_v^{-1}` for `C_v` and the first `r` rows of `S_v` for `R_v`.

To avoid the rank-one gauge structure from Run 70, also sample an independent dense hidden node gauge

```
H_v in GL_r(F_q).
```

For a directed transition `u -> v`, publish the full `d x d` matrix

```
T_uv = C_u H_u^{-1} H_v R_v.                         (1)
```

Let `z in F_q^r` be a fixed nonzero internal message vector. Publish the start row and endpoint column

```
ell   = z^T H_s R_s,
b_K   = K C_t H_t^{-1} z,                              (2)
```

with `z^T z = 1` (the checker uses `z=e_1`).

A genuine directed path

```
s = v_0 -> v_1 -> ... -> v_L = t
```

telescopes exactly:

```
ell T_{v0v1} ... T_{v(L-1)vL}
  = z^T H_t R_t,
```

and therefore

```
ell T_{v0v1} ... T_{v(L-1)vL} b_K = K.               (3)
```

The setup knows the public transition graph/statement but does not need a source witness. The matrices are dense under random bases/gauges, and the public objects no longer expose rank-one projective lines.

This is a real strengthening of the Run-70 rank-one toy construction. It nevertheless fails for a more basic reason.

## 2. Exact public reverse-lift lemma

Suppose a public row at node `v` has the legitimate internal form

```
y_v = z^T H_v R_v.                                    (4)
```

For any incoming edge `u -> v`, an attacker can solve the **public linear system**

```
x T_uv = y_v                                           (5)
```

for any solution `x`. A solution always exists because the hidden legitimate predecessor row is one.

### Lemma 2.1 — every solution is good enough for the next channel

For every solution of (5),

```
x C_u = z^T H_u.                                       (6)
```

Consequently, for every outgoing edge `u -> w`,

```
x T_uw = z^T H_w R_w = y_w.                            (7)
```

### Proof

Substitute (1) into (5):

```
x C_u H_u^{-1} H_v R_v = z^T H_v R_v.
```

Right-multiply by `C_v` and use `R_v C_v=I_r`:

```
x C_u H_u^{-1} H_v = z^T H_v.
```

Since `H_v` is invertible,

```
x C_u H_u^{-1}=z^T,
```

which is (6). Then

```
x T_uw
 = x C_u H_u^{-1} H_w R_w
 = z^T H_w R_w.
```

No hidden basis, hidden gauge, rank factorization, discrete logarithm, or source witness is needed. Gaussian elimination on the **published transition matrix** is enough. QED.

A useful point is that `x` need not equal the hidden canonical predecessor row. It may differ arbitrarily in directions killed by `C_u`; equation (7) says those differences disappear on every next outgoing transport. The checker explicitly validates cases where the public reverse solution differs from the hidden row but has exactly the same action on the next channel.

## 3. Consequence: directed consistency collapses to undirected connectivity

Starting with the public `ell`, an attacker can traverse a public edge in either direction:

* forward along `u -> v`: `y <- y T_uv`;
* backward along `u -> v`: solve `x T_uv = y` and set `y <- x`.

By induction with Lemma 2.1, after **any undirected walk** from `s` to a node `v`, the row acts exactly as the legitimate row `z^T H_v R_v` on the next state channel. If the underlying undirected graph connects `s` to `t`, the attacker obtains a row whose pairing with `b_K` is exactly `K`.

Therefore this candidate does not bind a directed source path. It binds only the undirected connected component.

### Explicit false relation

The checker uses

```
s -> A <- C -> B -> t.                                (8)
```

There is no directed path from `s` to `t`: from `s` one reaches only `A`, which has no outgoing transition. But there is the undirected alternating walk

```
s -> A <- C -> B -> t.                                (9)
```

The public attack does:

1. multiply by `T_sA`;
2. solve `x T_CA = current` to walk backward to `C`;
3. multiply by `T_CB`;
4. multiply by `T_Bt`;
5. pair with `b_K`.

It returns `K` exactly.

This is the rank-r / dense-gauge analogue of Run 70's scalar alternating-gauge attack, but the new proof no longer depends on rank-one factorization or recoverable projective labels.

## 4. More general interpretation

Equation (5) exposes the structural problem: an exact public linear transport cannot be made information-theoretically one-way merely by hiding the bases in which it is simple. If a legitimate channel element has a predecessor, public linear algebra can compute *some* predecessor, and Lemma 2.1 shows that any predecessor is sufficient for continued composition in the node-potential construction.

This result is scoped to the node-potential rank-r family (1). It is not an impossibility theorem for every noncommutative encoder. In particular, a surviving construction could try to make reverse transport computationally hard rather than linearly solvable. But then it must still preserve public offline forward composition for every valid source witness.

## 5. Bounded full-rank noise does not repair the orthogonal transport special case

The most direct repair is to make the published matrices full rank by additive noise. To isolate that idea without condition-number artifacts, consider the stable orthogonal special case over the reals.

Each hidden node has an orthonormal frame `U_v in R^{d x r}` with

```
U_v^T U_v = I_r.
```

The noiseless transition is the rank-r partial isometry

```
A_uv = U_u U_v^T.                                      (10)
```

A directed path telescopes. Importantly, the public transpose is the exact reverse transport:

```
A_uv^T = U_v U_u^T.                                    (11)
```

Now publish

```
A~_uv = A_uv + E_uv,
```

with a deterministic operator-norm bound

```
||E_uv||_2 <= epsilon.                                 (12)
```

The attacker traverses a reverse edge using `A~_uv^T`. Transposition preserves the noise norm, so a false alternating walk and a true directed walk are products of factors with the **same** per-step perturbation budget.

### Theorem 5.1 — identical product-stability bound

For any length-L walk, directed or alternating, let `B_i` denote the appropriate noiseless forward matrix or transpose, and `B~_i=B_i+F_i` the published forward matrix or transpose. Then

```
||B_i||_2 = 1,
||F_i||_2 <= epsilon,
```

and

```
|| product_i B~_i - product_i B_i ||_2
    <= (1+epsilon)^L - 1.                              (13)
```

### Proof

Use the standard telescoping expansion, or induct on `L`. Since every noisy factor has norm at most `1+epsilon`, the sum of all nonempty error terms is bounded by

```
sum_{j=1}^L binom(L,j) epsilon^j
 = (1+epsilon)^L - 1.
```

The argument is unchanged when a factor is transposed because both the noiseless and error operator norms are transpose-invariant. QED.

With unit-norm public start/end anchors, the same bound applies directly to the recovered scalar key coordinate. Thus any correctness theorem for the honest path that relies only on this bounded-noise product margin automatically gives the false alternating walk the same margin.

For `L=4`, sign decoding of a key in `{+1,-1}` is deterministically correct whenever

```
(1+epsilon)^4 - 1 < 1,
```

namely

```
epsilon < 2^(1/4)-1 = 0.1892071150...
```

The checker uses much smaller values and observes full success for both true and false walks. The proof, not the sample rate, is the substantive statement.

### Scope of this noisy theorem

This does **not** say that arbitrary LWE-like full-rank noise is reversible. If noise is large enough that the hidden transport is computationally concealed, equations (5)/(11) need not be useful. But then the construction owes a new public offline composition mechanism for legitimate witnesses. Merely adding a large error to (1) destroys the exact transport that gave correctness.

So the straightforward continuum

```
transparent exact transport
    -> small bounded noisy transport
    -> large computationally hiding noise
```

has a sharp unresolved transition: the first point is publicly reversible by Gaussian elimination, the second is still robustly reversible in the orthogonal model, and the third no longer has an identified native witness-composition algorithm.

## 6. Tests actually executed

The finalized standard-library checker was run twice with byte-identical JSON output.

Exact finite-field tests:

* primes `101,103,107`;
* `(d,r)=(4,1),(5,2),(6,3)`;
* **450/450** false instances of (8) had no directed accepting path and the public reverse-lift attack recovered the exact fresh key;
* **450/450** true forward-path controls recovered the exact key;
* every one of the **450** reverse steps had the same next-channel action as the hidden canonical predecessor;
* a separate **400** public-reverse lemma test had **400/400** same-source action equalities, while in **400/400** cases the Gaussian-elimination solution was *not* the hidden canonical row itself.

Bounded-noise orthogonal tests:

* ambient dimension `d=8`, block rank `r=2`, walk length `L=4`;
* fresh random sign key in `{+1,-1}` each trial;
* `epsilon in {0.001,0.005,0.01,0.02,0.05}`;
* 250 fresh false alternating walks and 250 true directed walks at each epsilon;
* **1250/1250** false sign-key recoveries and **1250/1250** true sign-key recoveries;
* every observed scalar error was below the proved bound `(1+epsilon)^4-1`.

The test program does not establish cryptographic security or insecurity outside the stated algebraic/bounded-noise families. It validates the finite identities, the public reverse algorithm, and the numerical special case used by the proof.

## 7. Security meaning and next obligation

Run 70 showed that transparent rank-one matrix units leak state lines and scalar gauges. Run 71 removes the rank-one dependency: **dense rank-r node-potential transports are still publicly reversible even if the hidden subspace bases and `GL_r` gauges themselves are never recovered.** Small bounded full-rank noise also does not fix the stable orthogonal realization.

The surviving target must therefore be genuinely **directional and computationally one-way** at the transport level:

1. a valid source witness must be able to compose the public object forward, completely offline;
2. the same public object must not support a reverse lift, generalized inverse, alternating walk, affine/exponent pseudorepresentation, or transparent interpolation attack;
3. false-instance complete-output hiding must reduce to an independently justified PQ assumption;
4. on true instances, arbitrary QPT final-key recovery must yield a source witness or such a PQ break.

A naive instruction to “LWE-encrypt the transition matrices” is not yet such a primitive: once the matrix channel is hidden strongly enough to defeat the public reverse step, the present construction no longer supplies the public multiplication/composition operation a witness needs. Introducing a generic encrypted multiplication layer would simply move the missing witness-restricted release mechanism elsewhere unless its native algorithms and reduction are given.

Malicious-secure erased setup, auxiliary-input composition, concrete parameters, and end-to-end resource estimates remain downstream obligations. The stopping condition is not met.
