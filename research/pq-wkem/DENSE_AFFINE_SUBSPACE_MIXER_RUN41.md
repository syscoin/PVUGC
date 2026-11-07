# Run 41 — dense affine-subspace mixers: exact public-likelihood collapse

**Status: constructive dense-channel attempt, complete-output theorem, and negative result. This is not a completed WKEM or a security proof.**

This run starts from PR head `1d53234dc5ae41ef09955f2b3506efaff29a4373` and the Run-40 boundary: sparse/asymmetric hit processes with only `H=O(log lambda)` active opportunities admit exact subset-partition likelihood evaluation. The goal here is not to revisit those walkers. It is to test the most direct **dense, non-factorizing, exponentially supported** replacement.

No external literature was fetched. Production code is unchanged.

## 1. Constructive attempt

Work over `F_2^n`; the same single-subspace argument works over any finite vector space.

Let `R <= F_2^n` be the public constraint-mask row space already present in the quotient view, and let `Delta` be the public key shift. Instead of sparse or product noise, setup chooses a public high-dimensional subspace

```
S <= F_2^n
```

and optionally a public affine center `a`. It samples

```
r <- U_R,
s <- U_S,
C = r + a + s + K Delta.                              (1)
```

If `dim(S)=Theta(n)`, this is genuinely dense and has exponential support. There is no list of `O(log lambda)` hit locations and no Run-40 subset partition to enumerate.

A more flexible version chooses one of `M` public affine subspaces:

```
i <- p_1,...,p_M,
s <- U_{S_i},
C = r + a_i + s + K Delta.                            (2)
```

The intended hope was that a source witness could evaluate an invariant of this dense correlated carrier while a party without a witness would face a hard high-entropy decoding problem.

That hope fails for the public-subspace form, even if the witness decoder is arbitrary and nonlinear.

## 2. Single-subspace theorem: identical or publicly disjoint

Let

```
T = R + S.
```

### Lemma 2.1 — sum of the two uniform subspaces is uniform

If `r <- U_R` and `s <- U_S` independently, then `r+s` is uniform on `T`.

**Proof.** Every `t in T` has exactly `|R intersect S|` representations `t=r+s`. Hence all elements of `T` have the same probability. QED.

Therefore

```
C | K=k  ~  U_{a + k Delta + T}.                      (3)
```

### Theorem 2.2 — complete-output dichotomy

Exactly one of the following holds.

1. `Delta in T`. Then the two key-conditioned public distributions are **identical** and their TV distance is `0`.
2. `Delta notin T`. Then `a+T` and `a+Delta+T` are disjoint cosets, their TV distance is `1`, and anyone recovers `K` exactly by public linear-algebra membership testing.

This is decoder-independent. It does not assume that the honest party uses the intended linear witness character.

In particular, exponential support does not help: a support of size `2^Theta(n)` can still be perfectly classified by one public row reduction.

## 3. Consequence for generic-NP witness transfer

Suppose the statement-only setup is efficient and publishes `R,S,a,Delta` as above. Define the public predicate

```
A = [ Delta notin R+S ].                               (4)
```

On a true statement, assume some valid source witness decapsulates with probability at least `1-epsilon` over setup/capsule randomness and a uniform key bit. On setups with `A=0`, Theorem 2.2 makes the key information-theoretically independent of the transcript, so *every* decoder succeeds with probability exactly `1/2`. Even granting success `1` whenever `A=1`,

```
1-epsilon <= 1/2 + Pr[A=1]/2,
```

hence

```
Pr[A=1 | true] >= 1-2 epsilon.                         (5)
```

On a false statement, the following unauthorized public decoder is polynomial time:

- compute `A`;
- if `A=1`, identify the public coset and recover `K` perfectly;
- if `A=0`, output a random bit.

Its success is

```
1/2 + Pr[A=1 | false]/2.                              (6)
```

Thus false-statement hiding advantage at most `eta` forces

```
Pr[A=1 | false] <= 2 eta.                              (7)
```

Equations (5) and (7) mean the *public membership test itself* separates true from false statements. Repeating the efficient statement-only setup amplifies the gap. Therefore a generic construction of this public-subspace form with negligible `epsilon,eta` would place its NP language in randomized polynomial time. For an NP-complete source relation this is a structural collapse, not a PQ hardness reduction.

This is not presented as an unconditional theorem that `NP != BPP`; it is a precise reduction showing where the candidate would have to get its power.

## 4. Polynomial mixtures of dense affine subspaces

The single-subspace all-or-nothing law might look too rigid, so consider (2) with an explicit public list

```
(p_i, a_i, S_i),  i=1,...,M,
```

where `M` is polynomial and each rational `p_i` has polynomial bit length. Let

```
T_i = R + S_i.
```

### Theorem 4.1 — exact public likelihood

For every observed capsule `c` and key bit `k`,

```
P[C=c | K=k]
  = sum_i p_i * 1[c-k Delta-a_i in T_i] / |T_i|.      (8)
```

Each membership predicate and each `dim(T_i)` is obtained by Gaussian elimination. Hence both key likelihoods are computable **exactly in polynomial time** in `n`, `M`, and the public probability bit lengths.

The public MAP rule

```
guess 0 if P[C=c|0] >= P[C=c|1], else 1              (9)
```

is therefore polynomial time.

### Corollary 4.2 — witness decoders cannot have a private statistical advantage

For a uniform key bit, MAP is Bayes-optimal pointwise. Consequently its success probability is at least that of **any** decoder using the same public capsule distribution, including a decoder parameterized by a valid source witness.

Thus if a valid witness has useful completeness on a true statement, the public MAP algorithm has at least that much raw key-recovery probability without being given the witness.

This does not by itself prove that no extractor could ever turn that public MAP algorithm into a source witness. It shows the exact remaining obligation: such an extractor would have to derive the source witness from a completely explicit public likelihood algorithm. Composing an efficient generic extractor with statement-only setup and this MAP decoder would yield a generic source-witness finder. That is not supplied by the affine-subspace construction and cannot be hidden behind a newly named assumption.

### Corollary 4.3 — the true/false gap becomes publicly testable

Under the target interface, the efficient setup/encapsulation algorithm can be run by an experimenter and returns the encapsulated key to its caller. If true-instance completeness is `1-epsilon`, public MAP success is at least `1-epsilon`. If false-instance security bounds every PPT adversary by `1/2+eta`, it also bounds this public MAP algorithm. By running fresh public setup/encapsulation trials, comparing MAP's guess with the known generated key, and estimating its success, one obtains a BPP decision procedure whenever the completeness/security gap is inverse-polynomial or larger.

Again, this is a candidate-class reduction, not an assertion that generic NP is already in BPP.

## 5. Public scrambles do not repair the construction

Let `F` be any public efficiently invertible bijection and publish

```
Y = F(C).
```

The attacker computes `F^{-1}(Y)` and applies (8). Total variation and MAP success are invariant under the bijection. A dense invertible linear scramble is therefore cosmetic.

A non-invertible public map can merge likelihood classes, but it also discards information available to every witness. To be useful it would need a *witness-dependent* inversion/evaluation mechanism. Producing that mechanism from the statement without a source witness is exactly the missing witness-restricted public encoding problem, not a solution to it.

## 6. What was actually implemented and tested

`dense_affine_subspace_mixer_run41_check.py` is standard-library-only and implements independent GF(2) row reduction, span membership, direct distribution enumeration, the closed-form likelihood (8), exact rational MAP success, and public invertible scrambles.

The captured run used deterministic seed `1101353342` and executed:

- **420** random single-subspace fixtures for `n=4..9`;
- exact direct-enumeration equality with (3) in every fixture;
- **165** `Delta in R+S` cases with TV exactly `0`;
- **255** `Delta notin R+S` cases with TV exactly `1`;
- **14,840** public coset-membership decoder point checks in the disjoint cases;
- **180** explicit affine-mixture fixtures with `2..6` components;
- **43,200** exact key-likelihood coordinate checks against direct enumeration;
- **4,320** comparisons of public MAP against arbitrary table decoders and linear-character decoders; MAP was never worse and was strictly better in **4,142** comparisons;
- **180** public dense invertible-scramble controls with exactly preserved TV/MAP;
- a separate `n=16` dense control with `dim(R)=4`, `dim(S)=10`, `dim(R+S)=13`, support size **8192 per key**, and TV exactly `1` with perfect public membership decoding.

The checker was executed twice and the captured JSON was byte-identical. These tests validate the finite algebra and implementation only; they do not establish cryptographic security.

Local SHA-256 values before publication:

```
dd6844e4841c272f29a26dd57781ae0402f7b41bcd4053eb3ec5f80b6cf01f7e  dense_affine_subspace_mixer_run41_check.py
b5f93e3790306d42ba7fe9c74bf07cefbe330565c3ad331b19246da868903b4f  dense-affine-subspace-mixer-run41.json
```

## 7. Boundary after this run

This run closes a broad natural interpretation of Run 40's "dense correlated channel" escape hatch:

- one public dense affine subspace gives **identical or publicly disjoint** key laws;
- a polynomial explicit mixture of such subspaces gives **exact polynomial public likelihoods**;
- exponential support and dense basis vectors do not create witness restriction;
- public invertible scrambling does not help.

A surviving dense channel must therefore leave the class of publicly likelihood-evaluable affine-code mixtures. The credible next options are narrower:

1. a **nonlinear high-entropy distribution** whose complete quotient likelihood is not publicly tractable, together with an independent PQ assumption/reduction for that hardness; or
2. a hidden setup-time structure that is erased, while the final public object still lets *every* valid source witness evaluate the required invariant but does not expose a public likelihood oracle.

Option 2 is exactly where source-witness transfer becomes delicate: if the public witness evaluation mechanism is merely assumed, it is a WE-equivalent release compiler and does not satisfy the goal.

The central stopping obligations remain unresolved: arbitrary-QPT early key recovery must imply source-witness extraction or an independently justified PQ break; false complete-output hiding must be proved; setup/auxiliary-input composition and the malicious-secure ceremony must be proved; and concrete practical parameters must be supplied.
