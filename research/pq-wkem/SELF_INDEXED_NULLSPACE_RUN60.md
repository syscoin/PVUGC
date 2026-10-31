# Run 60 — public self-indexing challenge: exact nullspace grinding and roundwise switching

## Status and verified starting point

This run starts from verified PR #1 head

`eccc555d71f2eb3cf77f5a037c0ce9e1b4bb44f9`

after Run 59.  The PR was open, draft, and unmerged at the start of the pass.

The preceding checkpoints are kept in force.  In particular:

* Run 53 gives a polynomial local-view compiler with an exact block gap:
  a normalized integral block has squared norm `1` iff it is one-hot, while a
  non-one-hot block has squared norm at least `3`;
* Runs 53--55 show that separately decodable components can use different exact
  pseudorepresentations;
* Run 54 shows that a linear hidden common-representation pad telescopes out of
  a complete public affine-preimage transcript;
* Runs 56--59 close several linear/affine path-binding repairs.

This pass tests a different idea rather than retrying those constructions:

> derive the challenged local view from the **entire supplied representation**
> itself, using a public random affine "Fiat--Shamir-style" self-indexing map.

The hope is that a fixed false representation cannot know in advance which one
of its blocks will be challenged.  I test the strongest dense version: every
round checks **all blocks except one**.  A fixed false representation whose only
malformed block is `f` passes a round only if the self-indexer omits exactly `f`.

The result is negative for the explicit public-affine self-indexer below.
The malformed block of the Run-53 local-view relation has a large exact integral
nullspace.  The attacker can solve the public self-challenge *inside that
nullspace*, producing a fresh exact pseudorepresentation per key-share round
whose omitted block is exactly its only malformed block.

This is a proved attack on this self-indexing candidate.  It is **not** a
generic impossibility theorem for every deterministic hash, nonlinear binder,
or canonical source encoding.  No external literature/web search was used.
Production code is unchanged.

---

## 1. Width-k all-exclusions false core

Let

\[
B=2^k.
\]

There are shared Boolean marginals

\[
p=(p_1,\ldots,p_k).
\]

For every

\[
f\in\{0,1\}^k
\]

make one local constraint block whose valid truth-table rows are all

\[
a\in\{0,1\}^k\setminus\{f\}.
\]

Equivalently, block `f` says "the local assignment is not `f`."  The conjunction
of all `B` blocks is false, since every Boolean assignment equals one excluded
row.

For block `f`, introduce signed integral coordinates

\[
z_{f,a},\qquad a\ne f,
\]

with the Run-53 local-view equations

\[
\sum_{a\ne f}z_{f,a}=1,
\qquad
\sum_{a\ne f}a_i z_{f,a}=p_i
\quad(1\le i\le k).                                      \tag{1}
\]

For any Boolean assignment `t`, all blocks `f != t` can be represented by the
one-hot row `a=t`.  The single block `f=t` has the inclusion/exclusion lift

\[
q_t(a)=(-1)^{d_H(a,t)+1},\qquad a\ne t,                  \tag{2}
\]

which has the same normalization and marginals `p=t`.

Thus every Boolean `t` gives an **exact false representation** with exactly one
malformed block.  In that malformed block,

\[
\|q_t\|_1=\|q_t\|_2^2=B-1.                               \tag{3}
\]

The attack below fixes `t=f=0^k`; one false affine family is enough.

---

## 2. The malformed block has an exact integral nullity B-k-2

For `f=0^k`, the malformed block has one coordinate for every nonzero bit-vector

\[
a\in\{0,1\}^k\setminus\{0\}.
\]

Let `M` be the `(k+1) x (B-1)` integer matrix whose column for `a` is

\[
(1,a_1,\ldots,a_k)^T.
\]

The malformed fiber is

\[
Mz=(1,0,\ldots,0)^T.                                    \tag{4}
\]

### Lemma 2.1 — unimodular pivot minor

Take the `k+1` columns corresponding to

\[
e_1,\ldots,e_k,\quad e_1+e_2.
\]

They form a square integer matrix of determinant `+/-1`.

One direct way to see this is to solve for their coefficients.  For any
nonzero row `a`, write `w=|a|` and put

\[
x_u=w-1,
\]
\[
x_1=a_1-w+1,\qquad x_2=a_2-w+1,
\]
\[
x_i=a_i\quad(i\ge3).
\]

Then

\[
(1,a)
=
\sum_{i=1}^k x_i(1,e_i)
+x_u(1,e_1+e_2).                                        \tag{5}
\]

All coefficients are integers, so the selected square matrix has an integral
inverse and determinant `+/-1`.

Consequences:

1. `rank_Z(M)=k+1`;
2. the integral kernel is a saturated direct summand;
3. its rank is

\[
\boxed{D=(B-1)-(k+1)=2^k-k-2;}                           \tag{6}
\]

4. reduction modulo `2` gives a `D`-dimensional subspace, not a collapsed
   quotient.

### Explicit integral basis

For every nonpivot column `a`, define

\[
v_a=e_a-\sum_i x_i e_{e_i}-x_u e_{e_1+e_2},             \tag{7}
\]

using the integer coefficients above.  Then

\[
Mv_a=0.
\]

Each `v_a` has a unique coefficient `+1` on its own nonpivot coordinate, so
their reductions modulo `2` remain independent.  Write the resulting basis
matrix as

\[
N\in\mathbb Z^{(B-1)\times D}.                           \tag{8}
\]

Every

\[
z(t)=q_0+Nt,\qquad t\in\mathbb Z^D,                      \tag{9}
\]

is therefore another **exact** malformed-block representation with the same
Boolean marginals `p=0`.

This is the malleability used by the self-challenge attack.

---

## 3. Constructive candidate: public affine self-indexing

Consider `R` key-share rounds.  In round `r`, publish a random affine selector
on the parity of the complete supplied representation:

\[
J_r(y)=G_r\bar y+h_r\in\mathbb F_2^k,                   \tag{10}
\]

where `bar y` denotes coordinatewise reduction modulo `2`.  Interpret the
`k` output bits as one of the `B=2^k` block indices.

The intended dense challenge checks every block **except**

\[
J_r(y).
\]

At the semantic level, imagine granting the candidate an ideal local release
gate:

* round `r` holds key share `kappa_r`;
* it releases `kappa_r` iff every challenged block is one-hot;
* otherwise it releases no useful information;
* the final key is the XOR (or any fixed public N-of-N reconstruction) of all
  round shares.

This ideal gate is deliberately *stronger* than any concrete local capsule
constructed so far.  It is used only to isolate whether public self-indexing
solves the common-representation problem.  It is **not** claimed as an
implemented witness KEM or as an allowed replacement for the missing
witness-selective release mechanism.

### Honest completeness

A genuine source witness has every block one-hot, hence passes every possible
selector output and gets every round share.

### Why the candidate initially looks strong

Fix one false representation `y_0` whose only malformed block is `0^k`.
For a uniform affine selector, a fixed `y_0` passes one round only when

\[
J_r(y_0)=0^k,
\]

which has probability exactly

\[
2^{-k}=1/B.                                              \tag{11}
\]

If the same representation had to be used in all `R` independent rounds, its
pass probability would therefore be

\[
B^{-R}.                                                  \tag{12}
\]

For the executed `k=8,R=128` fixture this is

\[
2^{-1024}.
\]

So self-indexing appears to have converted the Run-53 malformed block into a
very strong repeated check **if one silently assumes a common
representation**.

That assumption is exactly what must be audited.

---

## 4. Complete adaptive attack: solve the self-challenge in the nullspace

Fix all one-hot blocks and the shared marginal `p=0`; vary only the malformed
block by (9).  The fixed coordinates of the complete representation merely add
a public affine offset to (10).  Restricting (10) to this exact false fiber gives

\[
J_r(z(t))
=
A_r\bar t+c_r,                                          \tag{13}
\]

where

\[
A_r=G_r\bar N\in\mathbb F_2^{k\times D}.                \tag{14}
\]

Because `bar N` has rank `D`, a uniform public `G_r` induces a **uniform**
`k x D` binary matrix `A_r`.

The attacker wants the self-indexer to omit the only malformed block, i.e.

\[
J_r(z(t_r))=0^k.
\]

It therefore solves the public linear system

\[
\boxed{A_r\bar t_r=c_r.}                                \tag{15}
\]

Whenever `A_r` has full row rank, a solution exists for **every** `c_r`, and
ordinary Gaussian elimination finds one in polynomial time.

Lifting the solution bits to integer coefficients `t_r in {0,1}^D` and forming

\[
z_r=q_0+Nt_r                                             \tag{16}
\]

preserves every local-view equation exactly over the integers.

The complete false representation for round `r` now has:

* block `0^k`: possibly very non-one-hot, but omitted by construction;
* all other `B-1` blocks: exactly one-hot on assignment `0^k`;
* shared marginals: exactly `0^k`.

Thus **every block actually challenged in that round is honest-radius one**.
The ideal local gate releases the real share.

The attacker repeats this independently for every key-share round.  No one
representation need satisfy all selectors.

This is precisely the source-transfer distinction from Runs 53--55, now against
a representation-dependent public challenge rather than an independent hidden
selector.

---

## 5. Exact success probability for a random affine selector

For a uniform `k x D` binary matrix with `D >= k`,

\[
\Pr[\operatorname{rank}(A_r)=k]
=
\prod_{i=0}^{k-1}(1-2^{i-D}).                            \tag{17}
\]

A union bound gives

\[
\Pr[\operatorname{rank}(A_r)<k]
\le
\sum_{i=0}^{k-1}2^{i-D}
=
\frac{2^k-1}{2^D}.                                      \tag{18}
\]

Therefore across `R` independently sampled public affine selectors,

\[
\Pr[\text{some round not covered by the full-rank attack}]
\le
R\,\frac{2^k-1}{2^D}.                                   \tag{19}
\]

This is only an upper bound on attack failure: rank-deficient systems can also
be consistent and solvable.

For

\[
k=8,\qquad B=256,\qquad D=246,\qquad R=128,
\]

(19) is

\[
2.8864977063760146\times10^{-70}
<2^{-231.00}.                                           \tag{20}
\]

Contrast:

* **fixed representation:** all-round pass probability `2^-1024`;
* **adaptive exact pseudorepresentation per round:** the proved full-rank attack
  misses some round with probability at most about `2^-231`.

The self-challenge has therefore amplified the wrong object.  It strongly
rejects one fixed false representation while leaving a large exact affine false
fiber from which a new representation can be solved for every public challenge.

---

## 6. This is not merely brute-force hash grinding

The selector in this pass is an explicit, polynomial-time, pairwise-linear
public hash family.  The attack does not model a random oracle and does not
search `2^k` challenges.

For every full-rank round it solves one `k x D` linear system.

At `k=8`:

* `B=256` blocks;
* malformed block has `255` coordinates;
* exact integral nullity `D=246`;
* the complete Run-53-style block representation has
  `256*255+8 = 65,288` coordinates;
* the attack solves only an `8 x 246` binary system per round.

This is comfortably polynomial.  The family can also scale with the security
parameter by choosing `B=2^k` polynomial in that parameter; then `D=B-k-2` is
already linear in `B`, and the rank-failure term in (18) is exponentially small
in `B`.

The attack is classical, so it also applies to a QPT adversary.

---

## 7. A single common representation really is excluded in the executed fixture

The checker also stacks the selector equations from successive rounds:

\[
A_1t=c_1,\ldots,A_rt=c_r.
\]

For the deterministic `k=8` fixture, every one of the 128 individual systems is
solvable, but the stacked system becomes inconsistent after 31 rounds.

This is not needed for the attack and is not a probabilistic theorem.  It is a
useful control: the executed candidate really does kill the **same**
pseudorepresentation across repeated challenges.  What fails is the missing
cryptographic requirement that all share recoveries come from that same
representation.

---

## 8. Why ordinary share composition and public tags do not repair this pass

Suppose the final session key is reconstructed from per-round shares by XOR,
Shamir reconstruction, N-of-N operator roots, or another public deterministic
reconstruction rule.

Once the attacker has obtained each genuine round share using its own
`y_r`, the reconstruction algorithm has no memory of which representation
produced which share.  It returns the real key.

A public digest/tag `tau(y_r)` checked *after* share decoding is likewise only a
procedural check: the attacker already has the shares and can run the public
reconstruction while ignoring that API check.

To make a tag cryptographically binding, the share itself would need to remain
masked under a **hidden tag-dependent function** whose masks cancel only when
all components use one common tag/representation.  A public linear realization
of exactly that idea is the Run-54 cancellation failure.  Publishing a new
witness-selective hidden evaluator for the tag would simply move the missing
primitive rather than prove it.

This does not rule out a genuinely nonlinear/computational tag binder with a
standard-assumption complete-output reduction.  It states what that binder
would have to add beyond public self-indexing and ordinary secret sharing.

---

## 9. Important scope: what this attack does and does not close

### Proved in this run

1. The width-`k` all-exclusions false core has an exact malformed-block integral
   fiber of nullity

   \[
   D=2^k-k-2.
   \]

2. An explicit unimodular pivot minor gives an integral kernel basis whose
   reductions modulo `2` retain all `D` dimensions.

3. A uniform public affine self-selector restricted to that fiber is a uniform
   `k x D` binary affine system.

4. Full row rank lets a polynomial attacker construct an exact false
   representation whose unique malformed block is exactly the omitted block.

5. The full-rank probability is (17), giving the concrete all-round attack bound
   (19).

6. Ordinary per-round/N-of-N share reconstruction does not impose a common
   representation after the shares have been individually recovered.

### Not proved / deliberately not claimed

* that every deterministic cryptographic hash family has this algebraic
  solvability property;
* a random-oracle attack theorem;
* that a compiler which **canonically removes all pseudorepresentation
  malleability before hashing** is broken by this same nullspace argument;
* an implementation of the ideal witness-selective local release gate;
* a generic impossibility theorem for nonlinear/computational common-witness
  binders;
* any LWE/SIS break;
* arbitrary-QPT early key recovery -> source witness/SIS for a surviving
  construction.

In particular, a canonical representation layer can remove the exact
nullspace-grinding degree of freedom used here.  But it still needs a real
public-offline cryptographic release mechanism whose complete transcript
enforces that canonical representation across all key-bearing components.
That is not supplied by this run.

---

## 10. Validation actually executed

`self_indexed_nullspace_run60_check.py` is standard-library-only and
deterministic.  The finalized checker was executed twice from the local
container and the two JSON outputs were byte-identical.

It checked:

* the explicit integral kernel construction for every `k=3,...,8`;
* exact malformed-block normalization and all `k` marginal equations;
* parity-kernel ranks

  `3,10,25,56,119,246`

  for `k=3,...,8`, exactly matching `2^k-k-2`;
* the `k=8,B=256,D=246,R=128` main fixture:
  * 128/128 restricted selector matrices had full row rank 8;
  * 128/128 public affine systems were solved;
  * every lifted integer representation remained an exact malformed-block
    solution;
  * every resulting selector output was exactly the malformed block `0^8`;
  * all 128 idealized round shares and the XOR key were recovered;
  * the largest particular solution used only 7 kernel-basis vectors;
  * the largest malformed-block `L1` norm observed was 285;
  * the largest squared `L2` norm observed was 541;
  * the largest absolute malformed-block coefficient observed was 12;
  * the stacked fixed-representation system first became inconsistent after
    31 rounds;
  * the unadapted canonical malformed representation happened to pass only
    1/128 rounds.
* 2,000 finite rank/solvability trials for each `k=3,4,5,6`; observed full-rank
  frequencies agree with the exact formula and all 2,000 `k=5` and all 2,000
  `k=6` systems were solvable.

The checker SHA-256 is

`925bb645126083f8acd1548c60e14c63436c8658231172f56d63a854046d02e9`

and the captured JSON SHA-256 is

`7b160610cb1bd8e4aa4420984a40c9c6f83b79132cad324c6c1685a9f01f6768`.

These executions validate the stated finite algebra and implementation.  They
are not security evidence for an unbroken replacement.

---

## 11. Handoff

The stopping condition is not met.

Runs 55 and 60 now bracket two obvious challenge-based repairs:

* an **independent hidden selector** does not prevent complete-public-view
  candidate-list recovery/switching (Run 55);
* a **public representation-dependent affine selector** can be solved inside a
  large exact pseudorepresentation fiber and switched independently per share
  (this run).

A surviving construction therefore needs more than "hash the representation to
pick the test."  It needs either:

1. a source/canonical representation with no efficiently exploitable exact
   malleability **and** a cryptographic release layer that binds every key share
   to that same canonical object; or
2. a genuinely nonlinear/computational common-witness binder whose complete
   public output reduces to LWE/SIS or another independently justified PQ
   assumption.

The central unresolved obligation remains the same one isolated by Run 42:
arbitrary early key recovery must be forced to yield a sufficiently
source-bound object (or an independent PQ break).  Public self-indexing by
itself does not provide that transfer.
