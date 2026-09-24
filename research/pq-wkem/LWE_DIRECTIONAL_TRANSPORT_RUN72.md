# Run 72 — standard-LWE directional transport works locally; generic-NP source-label transfer remains the missing primitive

**Status:** constructive local transport result plus exact reductions and a complete-public-view source-label regression. **Not a completed WKEM.**

This run starts from verified PR head `4e18c693ea1c8d961d565f47f0db7d0d363a6187` and the Run-71 dense hidden-channel result. It continues the posted Run-72 checkpoint. No external literature or web search is used. Production code is unchanged.

The main positive result is deliberately narrower than the requested generic-NP witness KEM:

* once a high-entropy capability is already available, there is a very simple public offline **directional transport** whose reverse problem is exactly standard search-LWE, not a new "extended LWE" assumption;
* the same idea gives a native `k`-of-`k`/AND transport;
* but it still does **not** solve the source-witness transfer problem. A future NP witness has no cryptographically privileged way to obtain exactly one initial input capability from a public transcript. Publishing or publicly deriving both local labels reproduces the already-established complete-public-view input-label/splicing failure.

That distinction is the substantive result of this pass: Run 71's *native transport* gap can be repaired under ordinary LWE, but this does not repair the actual *generic-NP source witness* gap.

## 1. Audit of the checkpoint candidate

The checkpoint proposed, for an edge `u -> v`,

```
T = B x_u + z                (mod q)
x_v = Round_p(A z),
```

where `z` is short and setup uses an erased trapdoor for `A` to program the chosen child capability.

### 1.1 Unrounded form is publicly reversible

If `p=q` so that the child publishes/represents the exact syndrome

```
x_v = A z,
```

then

```
A T - x_v = A B x_u.                              (1)
```

Whenever `A B` has full column rank, ordinary public Gaussian elimination recovers `x_u`. No lattice problem is reached. The checker validates 500/500 such public recoveries.

### 1.2 Rounded form has a standard-LWE projection, but the full token has extra auxiliary structure

Let `Enc(x_v)` be the center of the rounding cell and write

```
A z = Enc(x_v) + delta,
```

where `delta` is the rounding residual. Then

```
A T - Enc(x_v) = A B x_u + delta.                 (2)
```

Thus a reverse step from a known child capability exposes an ordinary LWE-shaped sample with matrix `A B`, secret `x_u`, and small error `delta`.

This is useful, but **equation (2) alone is not a full-view reduction** for the checkpoint token: the public transcript also contains `A`, `B`, and the unprojected `T = B x_u+z`, with `z` drawn from a trapdoor-programmed short-preimage distribution correlated with `A` and `x_v`. Claiming security from (2) would require simulating that auxiliary view from standard LWE. No such reduction is proved here.

The checker validates (2) in 600/600 random finite instances. That is an algebraic identity check, not security evidence.

## 2. Remove the unnecessary auxiliary view: a clean standard-LWE transport

The trapdoor and `z` are not needed for the transport functionality.

Work modulo `q`. A node capability is a uniformly random vector

```
s_v in Z_q^n.
```

To transport a full `q`-ary capability while keeping the **parent secret** in the ordinary uniform-secret LWE regime, encode the child coordinatewise in binary. Let

```
ell = ceil(log_2 q),
M   = n ell.
```

Let `Bits(s_v) in {0,1}^M` be the binary encoding of all coordinates. Let `Delta` be the bit-message spacing (the checker uses `q=257`, `Delta=128`) and let `chi` be a small error distribution.

For every bit position `j`, sample an independent public row

```
a_j <- Z_q^n,
e_j <- chi,
```

and publish

```
b_j = <a_j,s_u> + Delta * Bits(s_v)_j + e_j  (mod q).    (3)
```

The public edge token is `(A,b)`, where `A` has the rows `a_j`.

A holder of `s_u` computes

```
r_j = b_j - <a_j,s_u>
```

and rounds `r_j` to `0` or `Delta`, recovering every bit of `s_v`.

The setup knows the statement/graph and samples node capabilities itself. It needs no source witness and no lattice trapdoor for this local transport.

### Correctness

If the error remains inside the bit-decision radius, all `M` bits decode correctly. This is ordinary LWE message embedding. The checker obtains exact child recovery in 500/500 single-edge trials and 300/300 six-edge chains at its small correctness parameters.

## 3. Exact reverse reduction to standard search-LWE

This is the main positive theorem.

### Theorem 3.1

Suppose an algorithm, given a public token `(A,b)` of (3) and the exact child capability `s_v`, recovers the parent capability `s_u` with probability `epsilon`.

Then there is an algorithm with the same success probability that solves standard search-LWE with `M` samples, uniform secret `s_u in Z_q^n`, and error distribution `chi`.

### Reduction

Given a search-LWE challenge

```
(A, y = A s + e),
```

choose any child capability `s_v`, compute its public bit-message vector `m=Bits(s_v)`, and give the reverse algorithm

```
(A, b = y + Delta*m, s_v).
```

This is distributed **exactly** as a transport token with parent `s`. If the reverse algorithm outputs the parent, output it as the LWE secret.

There is no trapdoor simulation and no extra error leakage. QED.

The checker validates the exact challenge-embedding identity in 500/500 trials and the reverse residual identity in 500/500 fresh tokens.

### Decision form

Likewise, if an adversary distinguishes two child capabilities from `(A,b)` without the parent capability, then shifting a decision-LWE challenge by either known message vector gives a decision-LWE distinguisher. A uniform vector remains uniform after a fixed additive shift.

This is only a local token theorem. It is not yet an arbitrary-final-key theorem for a whole generic-NP construction.

## 4. `k`-parent / AND transport

For parent capabilities `s_1,...,s_k`, publish for each child-message bit

```
b_j = sum_i <a_{i,j}, s_i>
      + Delta * Bits(s_v)_j
      + e_j.                                           (4)
```

A holder of **all** parent capabilities subtracts all parent terms and recovers the child.

More importantly, fix one missing parent `t`. Give the adversary:

* the child capability `s_v`;
* every other parent capability `s_i`, `i != t`;
* the full public token.

Subtracting the known parent terms and the known child message leaves

```
y_j = <a_{t,j},s_t> + e_j,
```

which is exactly a standard LWE instance for the missing parent.

Therefore recovery of any one missing required parent from this strongest local auxiliary view implies search-LWE. The checker validates this exact identity in 500/500 two-parent trials and forward correctness in 500/500.

This is a useful native primitive: a binary gate can require both input capabilities before releasing an output capability, without a public reverse generalized inverse of the Run-70/71 kind.

## 5. What this *does* solve: native directional encryption

At the local-transport layer the Run-71 handoff is no longer mysterious.

The transparent matrix constructions failed because the same public linear map admitted a reverse solve. Equations (3)-(4) instead make a reverse solve an LWE secret-recovery problem.

The construction also makes the "native encryption versus source-witness transfer" distinction concrete:

* **native encryption/transport:** solved here conditionally on ordinary LWE;
* **source-witness transfer:** still unsolved.

The latter is the actual generic-NP obstacle.

## 6. Why this is not yet a generic-NP WKEM

One can use (4) as the internal token of a garbled Boolean gate:

* each wire/value pair gets a random capability `s_{w,0},s_{w,1}`;
* for every truth-table row `(a,b)`, publish a two-parent token that releases `s_{out,f(a,b)}` from `s_{left,a}` and `s_{right,b}`.

If an evaluator already has **exactly one** consistent capability per source wire, the public circuit can be evaluated forward offline.

But setup knows the statement, **not the future source witness**. The unsolved step is how the public transcript gives a witness holder exactly the labels matching its witness while preventing arbitrary public acquisition of both labels.

### 6.1 Local public bit gates cannot solve this

Suppose a proposed source-label interface is a public offline algorithm

```
GetLabel(PP, i, b) -> s_{i,b}
```

whose only private input is the raw witness bit `b`.

Then anyone can run the public algorithm twice, once with `b=0` and once with `b=1`, and obtain both labels. Randomized local computation does not change this: the attacker can run both branches.

So the source gate has to depend on the **global NP relation/witness**, not merely on a local bit. But a public algorithm that releases the correct hidden labels only for globally valid witnesses is precisely the missing witness-restricted public encoding; it cannot be assumed as a subroutine.

This is not a new impossibility theorem for all WE. It states why ordinary LWE transport does not itself instantiate the source gate.

## 7. Complete-public-view regression: the old input-label splice survives perfectly

To verify that the new transport has not accidentally repaired the already-known source-label failure, the checker instantiates the false formula

```
(z) AND (NOT z).
```

It has zero witnesses.

Give the complete public evaluator **both** source labels `s_{z,0}` and `s_{z,1}`. Publish:

1. a unary LWE transport from `s_{z,1}` to the "first clause true" capability;
2. a unary transport from `s_{z,0}` to the "second clause true" capability;
3. a two-parent transport from the two clause-true capabilities to the root capability.

The public attacker uses `z=1` in the first local branch and `z=0` in the second, then decrypts the AND token. It obtains the exact root capability although no single source assignment satisfies the formula.

The checker obtains 400/400 root recoveries on this false fixture.

This is intentionally classified as a **regression/control of the previously established complete-public-view input-label attack**, not a new generic attack on LWE. The LWE layer behaves correctly; the source labels were already overexposed.

## 8. A scoped affine source-gate barrier

There is a second exact boundary worth recording because it prevents a tempting "just use the public linear witness relation as the parent secret" shortcut.

Let the public source relation be an affine fiber

```
S = { s in F_q^d : H s = u } = s_0 + ker H.
```

Suppose a fixed public affine/LWE parent term `M s` is required to land in the **same decoding cell** for every `s in S`.

### Theorem 8.1

If the decoding cell is a proper subset of `F_q` in every active coordinate, then

```
M v = 0   for every v in ker H.                       (5)
```

Hence every row of `M` lies in the row space of `H`, and `M s` is publicly computable from any public particular solution of `H s=u`.

### Proof

Fix `v in ker H`. For every `lambda in F_q`, `s_0+lambda v` lies in `S`.

If some coordinate of `M v` is nonzero, then as `lambda` ranges over `F_q` the corresponding coordinate of

```
M(s_0+lambda v)
```

ranges over **all** of `F_q`. It cannot remain inside one proper decoding cell. Therefore `Mv=0`.

The row-space/public-computability conclusion is standard finite-field linear algebra. QED.

The checker validates 350 random affine fibers where `M=R H`: the parent term is constant on every sampled fiber and a public Gaussian-elimination particular solution recovers that constant in 350/350 cases. It also checks 350 nonannihilating directions; the offending scalar sweeps all 17 field values exactly.

### Scope

Real NP witnesses form a nonlinear/discrete subset, not the whole public affine relaxation. The theorem therefore does **not** prove that every witness-only LWE source gate is public. It does prove that a compiler whose correctness simply extends to the whole public affine relaxation collapses immediately, which is the same boundary encountered in earlier public-quotient attacks.

## 9. Complete-output / composition limits of the positive transport result

The local reductions in Sections 3-4 are exact, but a full WKEM proof still needs much more.

In particular, this run does **not** claim:

* that arbitrary final-key recovery from a whole circuit can always be localized to one reverse LWE edge;
* a security proof for key-dependent/cyclic capability graphs;
* authenticated/CCA transport (the checker is only a correctness/algebra model);
* a witness-restricted source-label compiler;
* false-statement hiding for a completed generic-NP public object;
* malicious-secure distributed generation/erasure of all node capabilities;
* auxiliary-input composition;
* concrete security parameters.

For an acyclic circuit, ordinary hybrids may eventually prove useful, but that proof still cannot start until the source labels themselves are obtained in a witness-restricted way. Publishing both labels invalidates the source semantics before any LWE hybrid is relevant.

## 10. Resource shape

The literal bitwise construction is intentionally simple, not optimized.

For capability dimension `n` and modulus `q`:

```
M = n ceil(log_2 q)
```

LWE samples are used per transported capability.

A single-parent token stores approximately

```
M (n+1)
```

`q`-ary elements; a two-parent token stores approximately

```
M (2n+1)
```

elements.

The checker prints illustrative, **non-security-recommended**, unpacked counts at `n=256,q=12289`:

* single-parent: 921,088 modulus elements, about 12.90 Mbit;
* two-parent: 1,838,592 modulus elements, about 25.74 Mbit.

Packing, a proper LWE KEM/PKE encoding, or transporting only a short symmetric seed could reduce this substantially. No parameter/security claim is attached to these figures.

## 11. Tests actually executed

The finalized standard-library checker was run twice with byte-identical JSON.

Deterministic seed: `720072001`.

Fresh executed checks:

* **500/500** unrounded checkpoint fixtures satisfied (1) and public Gaussian elimination recovered the parent;
* **600/600** rounded checkpoint projection identities (2);
* **500/500** clean single-parent forward decodes;
* **500/500** exact reverse-to-search-LWE residual identities;
* **500/500** exact challenge embeddings;
* **500/500** two-parent forward decodes;
* **500/500** missing-parent residuals exactly equal standard LWE samples after the other parent and child are supplied;
* **300/300** six-edge directed chains recovered the final capability;
* **400/400** root recoveries on the zero-witness `(z) AND (NOT z)` public-both-input-label splice fixture;
* **350/350** affine-fiber constant-term controls and public recoveries;
* **350/350** nonannihilating affine directions swept the full field.

The tests validate finite algebra and implementation only. The search/decision-LWE conclusions come from the explicit reductions, not from empirical hardness.

Checker SHA-256:

`b10164628abef5b476b06f5bebdfd6e2d7307fee40ecce50aff8dd8a87f6ee83`

Captured validation SHA-256:

`b1679eca37c1f72d91cf906e217767c123d9c39843221b13f98cc275327a7ba5`

## 12. Result / handoff

This pass produces a real positive primitive:

> **Standard LWE is enough for public offline one-way directional capability transport, including an AND/k-of-k local transport, once the required parent capabilities already exist.**

It also cleanly separates that primitive from the unsolved requirement:

> **A generic-NP WKEM still needs a public, offline, relation-wide source-witness gate that gives a valid witness the correct hidden source capabilities without exposing both local choices or assuming the desired WE-strength release compiler.**

The posted Run-72 checkpoint's trapdoor-preimage auxiliary view is therefore unnecessary for native transport. Removing it yields a cleaner standard-LWE reduction. But the result is **not** the stopping condition: arbitrary-QPT final-key recovery -> source witness / independent PQ break for a complete generic-NP construction, false-instance hiding, malicious-secure setup/erasure, auxiliary-input composition, authentication, and practical parameters remain unresolved.
