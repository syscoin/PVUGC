# Run 259 — global fingerprint source binding: growing codimension and an SIS compression route

## Checkpoint

This bounded pass started from the live `syscoin/PVUGC#1` state read through the connected GitHub integration:

- branch: `research/pq-wkem-validation-20260918`
- starting SHA: `417b0c726660529822053f40e3b479af79e8b4d1`
- PR state: open, draft, unmerged
- exact newest checkpoint: `LOCAL_BLOCK_ENUMERATION_BARRIER_RUN258.md`, blob `bddc863560d98640dabc5b80cb8574979b4ca4ea`
- latest substantive ordinary PR comment at start: `5945825660`

Run 258 ruled out assigning an independently openable projective/recentered block to every local gate or wire-consistency predicate. This run asks the next narrower question: can global consistency itself be compressed into a **single nonseparable public representation check** without returning to independently searchable local blocks?

The answer splits cleanly.

1. A random linear fingerprint of the complete residual vector gives an information-theoretic source-binding theorem, but the effective codimension must grow with the size/linear dimension of the invalid residual family. A fixed small codimension is not a generic solution.
2. Replacing statistical fingerprinting by an Ajtai/SIS-style hash gives a compact computational source-binding theorem: any invalid accepted representation immediately yields an ordinary SIS solution in one straight-line step.
3. Neither construction is yet the WE-like release compiler. Since every valid witness has zero residual, any release evaluator that receives the witness only through this residual channel collapses to a public constant and is therefore publicly computable.

Thus this pass supplies a genuine **global ORIGINAL-source binding layer** and a precise growing-codimension lower bound, but it leaves the hard arrow `capability recovery -> accepted witness-dependent representation` unresolved.

No production path is changed.

---

## 1. Residual-map model

Fix a statement `x` and a finite representation domain `Z_x`. Let

\[
\rho_x:Z_x\to \mathbb F_q^m
\]

be a public residual map with

\[
\rho_x(z)=0
\quad\Longleftrightarrow\quad
z\text{ is a globally valid source representation.}
\tag{1}
\]

Assume there is a deterministic public extractor `SrcExt(x,z)` such that every zero-residual representation yields an ORIGINAL witness:

\[
\rho_x(z)=0
\Longrightarrow
R(x,\mathsf{SrcExt}(x,z))=1.
\tag{2}
\]

For a Boolean/R1CS-style verifier, `z` may be the complete assignment and `rho_x(z)` the vector of all gate, Booleanity and consistency residuals. Unlike Run 258, the construction below never publishes one release oracle per residual coordinate. It fingerprints the entire residual vector at once.

---

## 2. Information-theoretic global folding

Sample a public matrix

\[
S\leftarrow \mathbb F_q^{t\times m}
\]

and define the folded acceptance predicate

\[
\mathsf{FoldAccept}_{S,x}(z)=1
\iff
S\rho_x(z)=0.
\tag{3}
\]

Every genuine source representation has residual zero, so completeness is perfect.

### Theorem 1 — fixed invalid representation

For every fixed `z` with `rho_x(z) != 0`,

\[
\Pr_S[S\rho_x(z)=0]=q^{-t}.
\tag{4}
\]

**Proof.** Each independent uniform row of `S` has zero inner product with a fixed nonzero vector with probability exactly `1/q`. Multiply over `t` rows. ∎

### Corollary 1 — adaptive/unbounded source binding after setup

Let

\[
B_x=\{z\in Z_x:\rho_x(z)\ne0\}.
\]

Then

\[
\Pr_S[\exists z\in B_x:S\rho_x(z)=0]
\le |B_x|q^{-t}.
\tag{5}
\]

This is a bound on the **existence** of any bad representation after the public setup is fixed. Therefore, conditioned on the complementary good-setup event, no adversary—classical, QPT, computationally unbounded, adaptive to `S`, or equipped with arbitrary public postprocessing—can output an invalid accepted representation, because none exists.

For a Boolean representation space of at most `2^N` candidates,

\[
\Pr[\mathrm{bad\ setup}]\le 2^Nq^{-t}.
\tag{6}
\]

Thus choosing

\[
\boxed{t\ge \left\lceil\frac{N+\kappa}{\log_2 q}\right\rceil}
\tag{7}
\]

makes the bad-setup probability at most `2^-kappa`.

This is a clean arbitrary-QPT statement because the security event is information-theoretic and occurs before any adversary is run. No QROM, rewinding, extractor, or quantum-advice argument is needed.

---

## 3. Growing-effective-codimension lower bound

The previous union bound is only sufficient. There is also an exact lower bound showing why fixed codimension cannot generically replace Run 258.

Suppose the invalid residual set contains every nonzero vector of a `d`-dimensional subspace

\[
U\le\mathbb F_q^m,
\qquad
U\setminus\{0\}\subseteq \rho_x(B_x).
\tag{8}
\]

### Theorem 2 — subspace obstruction

If `t<d`, then **every** linear fingerprint `S in F_q^{t x m}` accepts at least one invalid residual from `U`.

**Proof.** The restriction `S|_U:U -> F_q^t` has rank at most `t<d`, so its kernel contains a nonzero `u`. By (8), `u` occurs as an invalid residual. ∎

Therefore a universal global linear fingerprint must have effective codimension at least the largest such residual-subspace dimension.

When `t>=d` and `S` is uniform, the exact probability that `S|_U` is injective is the full-column-rank probability of a uniform `t x d` matrix:

\[
\boxed{
\Pr[\ker(S|_U)=\{0\}]
=
\prod_{i=0}^{d-1}(1-q^{i-t}).
}
\tag{9}
\]

For `t=d+s`, a direct union bound gives

\[
\Pr[\ker(S|_U)\ne\{0\}]
\le
\sum_{i=0}^{d-1}q^{i-t}
=
\frac{q^{-s}(1-q^{-d})}{q-1}.
\tag{10}
\]

This is the desired growing-effective-codimension answer: if the invalid residual geometry itself contains a growing `d`-dimensional linear family, no fixed number of global folds can remove it. One needs approximately `d + kappa/log_2(q)` rows for `kappa` statistical bits.

---

## 4. Run-258 false CSP is repaired by one global fingerprint relation

Run 258 used the globally false Boolean system

\[
x_0=0,\qquad x_1=1,\qquad x_0=x_1.
\tag{11}
\]

Over `F_5`, take residuals

\[
\rho(x_0,x_1)=(x_0,\ x_1-1,\ x_0-x_1).
\tag{12}
\]

All four Boolean assignments have nonzero residuals. Local blockwise release nevertheless failed because every individual constraint was separately satisfiable.

The deterministic checker exhausts every public folding matrix `S` for `t=1,2,3` and finds:

- `t=1`: bad setup probability `73/125 = 0.584`, versus union bound `4/5`;
- `t=2`: `2353/15625 ~= 0.150592`, versus `4/25 = 0.16`;
- `t=3`: `61753/1953125 ~= 0.031617536`, versus `4/125 = 0.032`.

So a single **global** relation does remove the logical local-enumeration flaw with the predicted `q^-t` decay. This is not yet a practical security level; it is a finite exact check of the theorem and the Run-258 counterexample.

For illustration only, with `q=12289` and target `kappa=128`, equation (7) requires 85 rows for a `2^1024` candidate universe and 311 rows for a `2^4096` universe. This is polynomial and information-theoretic, but not necessarily compact enough for the intended generic compiler.

---

## 5. Computational compression with an SIS/Ajtai hash

The statistical construction can be compressed by replacing enough random folds with a collision-resistant lattice hash, at the price of an additional assumption.

Let `Enc` be an injective public binary encoding of the residual vector and let

\[
c_0=\mathsf{Enc}(0).
\]

Sample

\[
A\leftarrow\mathbb Z_q^{n\times L}
\]

uniformly, where `L=|Enc(rho)|`, and publish the target digest

\[
h_0=A c_0\bmod q.
\]

Define

\[
\mathsf{SISAccept}_{A,x}(z)=1
\iff
A\mathsf{Enc}(\rho_x(z))=h_0\pmod q.
\tag{13}
\]

Completeness is again perfect.

### Theorem 3 — invalid acceptance gives ordinary SIS

Suppose a QPT algorithm outputs an invalid accepted `z`. Set

\[
e=\mathsf{Enc}(\rho_x(z))-c_0.
\tag{14}
\]

Then:

1. `e != 0` by injectivity of `Enc` and invalidity of `z`;
2. `Ae=0 mod q` by (13);
3. for binary encoding, `e in {-1,0,1}^L`, hence
   \[
   \|e\|_2\le\sqrt L.
   \tag{15}
   \]

Thus one successful invalid representation is a valid solution to

\[
\mathsf{SIS}_{n,L,q,\sqrt L}.
\]

The reduction is straight-line and lossless apart from the adversary's own success probability: sample/use the SIS challenge matrix as `A`, run the adversary once, compute the public residual and encoding, and return `e`. There is no rewinding, no RO/QROM programming, and no requirement that the honest evaluator be quantum.

This is the same basic collision-to-SIS geometry used by Ajtai-style lattice hash functions: a collision `Ae=Ae'` yields the short kernel vector `e-e'`. Regev's lattice-cryptography survey gives the modular subset-sum hash and collision-to-short-vector reduction; Peikert's trapdoor-function treatment states the corresponding collision-resistance implication from SIS. A later lattice ZK treatment explicitly refers to `H_SIS` as an Ajtai-style SIS-based hash.

### Exact assumption ledger

The theorem above does **not** derive SIS from LWE. The exact cryptographic assumption is:

> for the chosen `(n,L,q,beta=sqrt(L))`, ordinary average-case SIS remains hard for arbitrary QPT algorithms.

If an LWE-only final construction is required, this row is therefore not enough. It is a useful source-binding option, not a claim that standard LWE implies it.

---

## 6. Why this still is not the WE-like release compiler

There is a simple but important barrier.

Suppose a proposed witness-side release evaluator receives the witness only through a public function of the residual:

\[
\mathsf{Eval}(P,x,z)=F(P,x,\rho_x(z)).
\tag{16}
\]

For every valid source representation, `rho_x(z)=0`. Therefore

\[
\mathsf{Eval}(P,x,z)=F(P,x,0),
\tag{17}
\]

which is publicly computable without a witness.

So neither the random fingerprint nor the SIS digest can itself be the hidden projective value. They are **binding checks** only. A viable release layer must still use a witness-dependent representation in a way that:

1. all valid witnesses reconstruct the same capability;
2. an outsider cannot evaluate the valid branch from the public zero residual;
3. arbitrary-QPT capability recovery yields an accepted witness-dependent representation (or an independently justified QPT break);
4. that representation then falls under Theorem 1/2/3 or another global source extractor to recover the ORIGINAL witness.

The public checking key `pk=PK(K)` does not change this conclusion. The present source-binding theorem does not hide `K` and does not prove that an adversary recovering or forging under `pk` must output `z`.

---

## 7. Relation to Run 123 and the current extraction chain

Run 123 isolated a clean dual-mode theorem:

`FINAL-key recovery -> canonical hidden value -> ORIGINAL witness`

provided there is a statistically close extraction mode whose correct canonical value itself extracts a source witness.

Run 259 supplies a different, downstream piece:

\[
\boxed{
\text{accepted global representation }z
\Longrightarrow
\text{ORIGINAL witness}
\]

with either:

- information-theoretic setup soundness from enough random global folds; or
- a straight-line QPT reduction to ordinary SIS using the Ajtai-hash form.

The missing arrow remains

\[
\boxed{
\text{capability recovery / accepted forgery}
\Longrightarrow
\text{accepted witness-dependent }z.
}
\]

A construction that merely exposes the zero residual does not provide that arrow.

---

## 8. QPT/security ledger

| Component | Honest model | Adversary model | Assumption | Exact conclusion |
|---|---|---|---|---|
| fixed-vector global folding | classical public setup | unbounded / QPT | none | one invalid residual survives with probability exactly `q^-t` |
| finite-domain global folding | classical public setup | unbounded / QPT adaptive after seeing `S` | none | bad-setup probability `<= |B_x| q^-t` |
| residual-subspace theorem | classical algebra | unbounded | none | if `t<d`, some nonzero residual in a contained `d`-subspace always survives |
| SIS residual hash | classical public setup | arbitrary QPT outputting classical `z` | exact `SIS_{n,L,q,sqrt(L)}` QPT hardness | invalid accepted `z` gives a straight-line SIS solution |
| zero-residual release barrier | classical public eval | classical, hence QPT | none | residual-only valid-branch evaluator is publicly computable |
| capability recovery -> accepted `z` | classical public/offline | arbitrary QPT | **missing** | needed before source binding solves WKEM extraction |
| generic PQ WKEM | classical public/offline | arbitrary QPT | must also prove false-instance hiding, full public-key correlation, malicious setup | **UNPROVED** |

No PPT-only theorem is relabeled as QPT security. The random-fold theorem is information-theoretic; the SIS theorem states the exact QPT hardness assumption it needs.

---

## 9. Reproducible checker

`global_fingerprint_source_binding_run259_check.py` is deterministic and standard-library only.

Final validation:

- `py_compile` passed;
- two complete executions were byte-identical;
- 255 explicit assertions;
- exact `q^-t` fixed-vector annihilation counts;
- exact full-column-rank law for eleven small `(q,d,t)` grids;
- exhaustive verification that every map with `t<d` has a nonzero kernel vector;
- exhaustive `F_5` Run-258 false-CSP fingerprint census through `t=3`, including all 1,953,125 matrices at `t=3`;
- a toy Ajtai-hash collision fixture with 35 binary pair collisions, each producing a short nonzero kernel vector;
- explicit residual-only public-value negative control;
- finite parameter arithmetic for equation (7).

These are algebra/probability checks only. They do not prove SIS hardness, LWE hardness, the missing recovery-to-representation extractor, or malicious N-of-N setup security.

---

## 10. Core handoff

Run 258's local-enumeration failure is not a reason to abandon global residual encodings. A single nonseparable fingerprint of the **entire** residual vector has a clean source-binding theorem. However:

- information-theoretic linear folding needs growing effective codimension, and a `d`-dimensional invalid residual subspace forces `t>=d`;
- an Ajtai/SIS hash can compress that binding computationally, but introduces ordinary QPT-SIS as a separate assumption;
- because all valid witnesses have residual zero, neither route can carry the hidden capability by itself.

The next bounded pass should therefore target the now-isolated missing object: a witness-dependent public/projective representation `Z(w)` such that all valid `w` recover one common capability, while arbitrary-QPT recovery of that capability yields `Z` (or a standard-assumption break). Run 259 can then sit immediately behind it as the global consistency/source-extraction layer. A candidate that feeds only the zero residual into release should be rejected immediately by Section 6.

The practical generic-NP public/offline PQ witness-KEM stopping condition remains **unmet**.

## Sources

- Live exact dependency: `syscoin/PVUGC#1`, `LOCAL_BLOCK_ENUMERATION_BARRIER_RUN258.md`, blob `bddc863560d98640dabc5b80cb8574979b4ca4ea` at starting SHA `417b0c726660529822053f40e3b479af79e8b4d1`.
- Oded Regev, *Lattice-based Cryptography*, modular subset-sum/Ajtai hash discussion: https://cims.nyu.edu/~regev/papers/crypto2006.pdf .
- Chris Peikert, *Public-key cryptosystems from the worst-case shortest vector problem* / trapdoor-function treatment; collision implies SIS kernel vector: https://people.csail.mit.edu/cpeikert/pubs/trap_lattice.pdf .
- Lattice ZK treatment explicitly using an Ajtai-style SIS hash: https://eprint.iacr.org/2018/716.pdf .
