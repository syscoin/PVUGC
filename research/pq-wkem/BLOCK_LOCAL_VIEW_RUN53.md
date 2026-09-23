# Run 53 — integral local-view compiler, exact block gap, and componentwise witness switching

## Scope and starting checkpoint

This run starts from PR head `36e162ed4e2af7adbc2d8ed1274289ee5e897f87` after reading the current PR discussion, including Run 52. It does **not** retry the rejected public additive-support mask, public linear sketch, public linear evaluator, radial gate, tensor-factor, or denominator-atlas candidates.

The constructive question here is narrower and new: can the source relation itself be compiled into a polynomial-size **native linear preimage relation** with a nonvanishing metric gap that excludes the exact short pseudorepresentations seen in Runs 32/43/48?

The answer is positive for a block maximum norm. The obvious blockwise release composition then fails for a different reason: a false instance can use a *different* exact signed representation for each release component. This is a source-witness-transfer failure, not a failure of the local block gap.

No claim below is a complete WKEM or an LWE/SIS security proof.

---

## 1. Compiler

Consider a Boolean verifier expressed as constant-arity local constraints. It is enough to state the construction for CNF clauses; the one-hot extraction lemma applies to any finite local truth table.

For clause/constraint block `b`, let

- `V_b` be its local Boolean variables,
- `A_b subseteq {0,1}^{|V_b|}` be exactly the locally valid rows,
- `z_{b,a} in Z` for `a in A_b` be signed integral row coefficients,
- `p_i in Z` be one shared marginal for each global Boolean variable/wire `i`.

Publish the affine linear relation

```
sum_{a in A_b} z_{b,a} = 1                                           (normalization)
sum_{a in A_b} a_i z_{b,a} = p_i    for every i in V_b                (shared marginal)
```

A genuine Boolean satisfying trace `w` maps to

```
z_{b,a} = 1[a = w|_{V_b}],    p_i = w_i.
```

Thus every honest block is one-hot and has squared Euclidean norm one.

For 3-CNF with `m` clauses and `n` variables, every proper 3-clause has seven valid local rows. The direct representation therefore has

- `7m+n` coordinates,
- `4m` equations,
- at most `22m` nonzero matrix entries.

This is polynomial and sparse; no exponential truth table over the global witness is used.

---

## 2. Proved block-gap theorem

### Lemma 2.1 — normalized integral block

Let `z in Z^r` satisfy

```
sum_i z_i = 1.
```

Then

```
||z||_2^2 = 1
```

if and only if `z` is a standard basis vector. If `z` is not one-hot, then

```
||z||_2^2 >= 3.
```

### Proof

`||z||_2^2=1` over the integers means exactly one coordinate is `+1` or `-1` and all others are zero. The normalization forces the sign to be `+1`.

A non-one-hot integral normalized vector cannot have squared norm `0`, `1`, or `2`: norm `0` contradicts normalization; norm `1` was just classified; norm `2` would require exactly two coordinates in `{+1,-1}`, whose sum is in `{-2,0,2}`, not one. Since the squared norm is a nonnegative integer, it is at least three. QED.

### Theorem 2.2 — exact source extraction at block radius one

Let `(z,p)` satisfy the complete local-view relation. If

```
max_b ||z_b||_2^2 = 1,
```

then a satisfying Boolean global trace can be extracted in polynomial time.

### Proof

Lemma 2.1 makes every block exactly one-hot on a locally valid row. For any shared variable `i`, the marginal equation says `p_i` equals the `i`-th bit of each incident one-hot row. Hence all incident local rows agree on that bit. Reading those common bits gives a globally consistent Boolean trace, and every local constraint is valid because every chosen row lies in `A_b`. QED.

### Corollary 2.3 — false-instance gap

For a false statement, every exact integral solution satisfies

```
max_b ||z_b||_2^2 >= 3.
```

Therefore this compiler has a constant multiplicative semantic gap `1 -> >=3` in the block metric

```
||z||_{2,infinity}^2 := max_b ||z_b||_2^2.
```

This is materially different from the Run-43 global `l2` gap that tended to one as padding grew.

### Modular version

For odd `q>2`, take centered representatives. If an exact solution modulo `q` has every block squared centered norm at most one, every block contains exactly one centered coefficient in `{+1,-1}`. The normalization `sum z = 1 mod q` forces `+1`, not `-1`. The marginal equations then force each shared `p_i` to the common bit in `{0,1}`. The same extractor applies.

This theorem is source binding **for a supplied representation satisfying the block bound**. It does not yet show that arbitrary key recovery produces such a representation.

---

## 3. Exact signed lift of a falsified CNF clause

The same compiler has a useful adversarial structure that matters for release composition.

Let a width-`k` OR clause, `k>=2`, have unique falsifying local row `f in {0,1}^k`. Its valid rows are every `a != f`. Define

```
q_f(a) = (-1)^(d_H(a,f)+1),    a != f.
```

Then exactly:

```
sum_{a != f} q_f(a) = 1,
sum_{a != f} a_i q_f(a) = f_i   for every i,
||q_f||_2^2 = 2^k - 1.
```

### Proof

Write `b=a xor f`. For normalization,

```
sum_{b != 0} (-1)^(|b|+1)
 = sum_{r=1}^k C(k,r)(-1)^(r+1)
 = 1.
```

If `f_i=0`, the `i`-th first moment is

```
sum_{b_i=1} (-1)^(|b|+1)
 = sum_{c in {0,1}^{k-1}} (-1)^|c|
 = 0.
```

If `f_i=1`, `a_i=1-b_i`, so the moment is total mass `1` minus the zero quantity above, hence one. Every one of the `2^k-1` coefficients is `+1` or `-1`, giving squared norm `2^k-1`. QED.

### Consequence 3.1 — every Boolean assignment has an exact signed lift

For any global Boolean assignment `t`, define each clause block by

- the one-hot row `delta_{t|V_b}` if `t` satisfies clause `b`;
- `q_f` if `t` falsifies clause `b`.

All block normalizations and all shared marginals hold **exactly over the integers**. A satisfied 3-clause block has norm squared one; a falsified 3-clause block has norm squared seven.

Thus the linear relaxation is intentionally broad, but the block maximum norm exactly records whether all clauses can simultaneously be one-hot.

---

## 4. Componentwise witness switching

A natural attempt to exploit the block gap is to secret-share the KEM key across blocks and give each share an independently amplified native-preimage test for one block. This avoids the vanishing global `l2` ratio: a malformed 3-clause has local norm `sqrt(7)` instead of one.

The problem is that **different components need not use the same representation**.

For any proper target clause `b`, choose any global Boolean assignment `t` that satisfies `b`. Build the signed lift from Section 3. Then target block `b` is one-hot even if the formula is globally false. Other violated clauses absorb the inconsistency through their signed `q_f` blocks.

Therefore:

> For every individual clause component of a false CNF, there exists an exact public preimage whose target clause block has honest norm one.

More generally, every checked clause subset `S` that is jointly satisfiable can be made simultaneously one-hot by choosing an assignment satisfying `S` and using signed lifts only on clauses outside `S` that it violates.

So a release layer that separately tests local blocks is vulnerable unless it cryptographically binds all tests to one common representation/source witness.

---

## 5. Explicit false fixture

Take three variables and all eight possible sign patterns of a width-3 clause:

```
( +/-x1 OR +/-x2 OR +/-x3 ).
```

The conjunction is false: each Boolean assignment falsifies exactly the clause whose signs oppose that assignment.

For each of the eight assignments `t`:

- seven blocks are honest one-hot rows,
- the unique falsified block is the seven-entry signed inclusion-exclusion vector,
- all shared marginals are exactly `p=t`,
- the full public linear relation is satisfied over the integers.

Hence each lift has block norms

```
(1,1,1,1,1,1,1,7)
```

up to permutation.

For **every target block** there are seven such false global representations in which that target is one-hot. The checker verifies all `8*7=56` target-one-hot switching representations.

No one of these is a source witness; the formula has no satisfying assignment.

---

## 6. Audited native block-release candidate

To test whether repetition repairs the switching issue, instantiate the affine relation as

```
B y = d  (mod q).
```

For target block `b`, one repetition publishes

```
a = B^T s + e + W e_b,
c = d^T s + e0 + mu*kappa,
```

where

- `e` is dense baseline ternary noise,
- `e_b` is independent ternary noise supported only on target block `b`,
- `kappa` is that component's key share.

Any exact preimage `y` cancels the hidden pad:

```
c - y^T a
 = mu*kappa + e0 - y^T e - W z_b^T e_b.
```

The tested local component uses

```
q = 1,000,003 (prime)
mu = 200,000
W = 10,000
acceptance radius T = 15,000
R = 20 independent repetitions per share.
```

For the eight-clause fixture, an honest or switching representation has target block one-hot. Its complete residual error is deterministically bounded by

```
1 + 17 + W = 10,018 < T,
```

so all repetitions recover the component share.

If instead the **same representation is forced to have the target block malformed**, the target contraction is a sum of seven signed iid ternary errors. Its sign pattern does not change the distribution. Because the dense baseline contribution is at most 18,

- sums in `{-1,0,1}` are always accepted;
- sums with absolute value at least two are always rejected.

Exactly

```
1107 / 2187 = 0.5061728395...
```

of one-repetition target-error vectors are accepted. Twenty independent repetitions would therefore leave only

```
(1107/2187)^20 = 1.218924361...e-6
```

acceptance **if the same malformed target block had to be used throughout**.

But componentwise switching chooses a different exact preimage for each target block, making that target one-hot. The full public capsule attack therefore recovers every N-of-N share and their XOR key despite the absence of any common satisfying witness.

This is a concrete distinction between:

1. a native component whose intended low-norm preimage test can be amplified strongly; and
2. transfer from a **single source witness** across all components.

The second property is still missing.

### Important security scope

This native capsule is an algebraic test harness, not a claim that the structured matrix `B` itself gives decisional LWE. The attack does not need to solve for `s` or distinguish LWE samples: the public signed preimage cancels `B^T s` directly. Thus even granting computational opacity of the pad would not repair this source-transfer failure.

---

## 7. Executed validation

`block_local_view_run53_check.py` is standard-library Python. It was run twice locally after the final edit; the two JSON outputs were byte-identical.

Captured results:

- 10,028 bounded normalized integral vectors checked for the block-gap sanity; no non-one-hot norm-one vector and no normalized norm-two vector occurred. The observed minimum non-one-hot squared norm is 3 for dimensions >=3 (5 for dimension 2).
- 124 exact inclusion-exclusion identities checked for every excluded point at widths 2 through 6.
- all 8 Boolean assignments lifted against the false eight-clause core; exactly 56 one-hot blocks and 8 norm-seven blocks were observed.
- all 56 target-one-hot switching representations verified exactly.
- 20 larger unsatisfiable fixtures containing the core, totaling 400 target components, each checked with an exact signed relation and one-hot target.
- direct extractor control passed on the satisfiable seven-clause formula obtained by removing one core clause.
- 100 false-instance N-of-N capsule trials, 8 shares each, 20 repetitions per share: 16,000 exact residual identities; 800/800 shares recovered; 100/100 XOR keys recovered by switching.
- exact forced-malformed one-repetition acceptance is `1107/2187`; the 20-repetition probability is `1.2189243610837672e-6`.
- 100 honest trials on the satisfiable seven-clause control, 20 repetitions each: 700/700 components recovered.

These executions validate the implementation and the finite identities. They are **not** used as evidence of QPT security.

Final local SHA-256 values before publication:

- checker: `e91e0b7f8264c756cc60a365e31b2166edf17eed9b816a5e0d7cea8e4a6c0de1`
- captured JSON: `c4469f37396a11455385514384af7b70def67cf05f34520f304c4ecef80c7ccb`

---

## 8. What is proved, what failed, and what remains

### Proved in this run

1. A polynomial-size local truth-table relation with an exact constant semantic gap in `||.||_{2,infinity}^2`: honest = 1; false >= 3.
2. Polynomial-time source extraction from any supplied exact representation with every block at radius one (and the centered modular analogue).
3. Exact inclusion-exclusion signed lifts for falsified CNF clauses.
4. Componentwise switching: any separately checked satisfiable clause subset can be made one-hot inside an exact global signed representation, even on a false formula.
5. On the explicit false core, N-of-N block-local repeated native release is completely broken by choosing a different public preimage for each share.

### Implemented, but not promoted to a security theorem

- the sparse local-view compiler and extractor;
- exact signed clause lifts;
- the repeated block-local native capsule;
- complete public contraction attacks and true controls;
- concrete polynomial resource counts.

### Still unresolved

- A release mechanism that enforces the **same source representation/witness across all local tests** without an online party, exponential encoder, custom on-chain verifier, or an assumed WE-equivalent compiler.
- Arbitrary-QPT early key recovery -> source witness or independently justified PQ-hardness break.
- A complete-output LWE/SIS reduction for such a common-representation release.
- Malicious-secure setup/erasure and auxiliary-input composition for a surviving inner primitive.
- End-to-end concrete security/resource parameters.

The new block compiler improves the source geometry, but it does not complete the WKEM. A plausible next target is therefore not another local threshold tweak: it is a **common-representation binding mechanism** whose public offline transcript can be reduced to an independent PQ assumption. A construction that merely lets each component prove existence of some local preimage will repeat the switching failure above.
