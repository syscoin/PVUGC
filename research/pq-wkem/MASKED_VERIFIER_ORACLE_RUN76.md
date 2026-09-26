# Run 76 — one-pad masked verifier has ideal QPT source extraction; direct GGM programming is witness-revealing or exponential

**Status:** constructive semantic compression of the Run-75 ideal object, a direct arbitrary-QPT source-extraction theorem in the ideal oracle model, and exact barriers for the ordinary GGM/prefix-programmed realization. **Not a completed generic-NP public offline PQ witness KEM.**

Starting verified PR head: `3cfa6b21326ff9e2e04eb6b46ae7cec7e8c372a7`.

No external literature or web search was used. Production code is unchanged.

## 1. Starting point

Run 75 supplied an ideal clause telescope with two important properties:

* every valid witness obtains the same key;
* on a false statement, even the **complete allowed difference table** is information-theoretically independent of the key.

Its practical gap was a compact PQ realization of the difference-only constrained evaluator. Ordinary component-wise GGM keys leaked the component mask functions, while clear exact key-homomorphic PRFs fell into a public linear-image distinguisher.

The present run asks whether the pointwise telescoping masks were semantically necessary at all.

They are not.

## 2. One-pad masked verifier

Let the NP relation be

\[
R(x,w)\in\{0,1\}
\]

and let the key space be \(\{0,1\}^{\kappa}\).

Setup chooses independently

\[
K,U \leftarrow \{0,1\}^{\kappa}.
\]

Define the semantic evaluator

\[
T_{x,K,U}(w)=
\begin{cases}
K,&R(x,w)=1,\\
U,&R(x,w)=0.
\end{cases}                                               \tag{1}
\]

Equivalently, over a bitwise XOR representation,

\[
T(w)=U\oplus R(x,w)(K\oplus U).                         \tag{2}
\]

The **unprotected circuit** for (2) is only the size of the verifier plus \(O(\kappa)\): it hardcodes \(K,U\), runs the verifier, and selects one of the two strings. Of course publishing that raw circuit is invalid because inspection reveals both constants. The point is only that semantic circuit size is not the bottleneck.

### Correctness

Every valid witness receives exactly the same key \(K\).

Setup needs the statement and verifier but does not need a witness.

### False-instance full-table hiding

If \(x\) is false, \(R(x,w)=0\) for every \(w\), hence the **entire truth table**

\[
\{T(w):w\in\{0,1\}^n\}
\]

is the constant table \(U\) and is exactly independent of \(K\).

Thus the exponentially many independent masks of Run 75 are not information-theoretically necessary. A single pad is enough **if** the public representation leaks no more than the evaluator's black-box behavior.

That last qualification is the whole cryptographic problem.

## 3. Ideal-oracle arbitrary-QPT recovery implies source-witness extraction

The one-pad object admits a direct quantum query theorem. This is stronger than merely observing that a classical adversary has to try a witness.

Let

\[
A_x=\{w:R(x,w)=1\}.
\]

For fixed \(K,U\), define standard quantum XOR oracles

\[
O_1:\ |w,z\rangle\mapsto |w,z\oplus T_{x,K,U}(w)\rangle
\]

and

\[
O_0:\ |w,z\rangle\mapsto |w,z\oplus U\rangle.
\]

They differ only on query inputs in \(A_x\).

Consider an arbitrary QPT algorithm \(\mathcal A\) making at most \(Q\ge1\) oracle queries.

Let

\[
p_1=\Pr[\mathcal A^{O_1}\text{ outputs }K].
\]

Because \(O_0\) is independent of the uniform \(K\),

\[
p_0=\Pr[\mathcal A^{O_0}\text{ outputs }K]=2^{-\kappa}.
\]

Write

\[
\delta=p_1-2^{-\kappa}.
\]

Assume \(\delta>0\).

### Theorem 1 — black-box quantum extraction

There is a black-box extractor using \(\mathcal A\) that outputs a valid source witness with probability at least

\[
\boxed{\frac{\delta^2}{4Q^2}}.                         \tag{3}
\]

Hence nonnegligible ideal-oracle key recovery by a polynomial-query QPT adversary gives nonnegligible source-witness extraction with polynomial loss.

### Proof

For a fixed choice of \(K,U\) and purified internal randomness, let

\[
|\psi_t^0\rangle
\]

be the state immediately before query \(t\) in the \(O_0\) execution, and let \(\Pi_A\) project the query-input register onto \(A_x\).

Define

\[
a_t=\|\Pi_A|\psi_t^0\rangle\|.
\]

The two query unitaries are identical off \(A_x\). Their operator difference has norm at most \(2\) on the accepting subspace. Replacing the \(O_0\) queries by \(O_1\) one at a time and using the triangle inequality gives the standard hybrid bound directly:

\[
\bigl\||\psi_Q^1\rangle-|\psi_Q^0\rangle\bigr\|
\le
2\sum_{t=1}^{Q} a_t
\le
2\sqrt{Q\sum_{t=1}^{Q}a_t^2}.                         \tag{4}
\]

Any final measurement probability gap is at most the trace distance and hence at most the right-hand side of (4). Averaging over \(K,U\) and internal randomness, and applying Cauchy/Jensen once more,

\[
\delta
\le
2\sqrt{Q\,\mathbb E\!\left[\sum_t a_t^2\right]}.
\]

Therefore

\[
\mathbb E\!\left[\sum_t a_t^2\right]
\ge
\frac{\delta^2}{4Q}.                                  \tag{5}
\]

Now the extractor samples a uniform query index \(t\), runs \(\mathcal A\) against \(O_0\) until immediately before that query, measures the query-input register, and checks the measured string with the public relation \(R(x,\cdot)\).

Its success probability is exactly

\[
\frac1Q\,
\mathbb E\!\left[\sum_t a_t^2\right]
\ge
\frac{\delta^2}{4Q^2},
\]

which proves (3). ∎

### Scope

This theorem is **only** for the ideal oracle interface. A real public encoding may leak representation information that is not obtainable by oracle queries. The theorem does not justify replacing that missing compiler by an obfuscation assumption.

It does show precisely what a successful compiler has to preserve: once the public object is no more informative than the masked-verifier oracle, the requested arbitrary-QPT source-extraction property follows by a direct reduction rather than by a new named assumption.

## 4. Interface-level equivalence: a secure compact masked verifier is already the target WKEM

Suppose there is a polynomial-size public encoding algorithm

\[
\mathsf{Compile}(x,K,U)\to P
\]

and public evaluator

\[
\mathsf{Eval}(P,w)
\]

realizing (1) with negligible error, while its complete representation satisfies the required PQ security.

Then the generic witness KEM is immediate:

* **Encaps**\((x)\): sample \(K,U\), compute \(P\), output ciphertext \(P\) and key \(K\);
* **Decaps**\((P,w)\): return \(\mathsf{Eval}(P,w)\).

A valid witness gets \(K\). On false instances, the required hiding of the compiler is exactly the KEM hiding requirement. The stronger requested true-instance condition—unauthorized key recovery implies a source witness or a separate PQ break—is likewise exactly the compiler's non-black-box security obligation.

Conversely, any completed witness KEM already gives witness encryption of an arbitrary payload \(M\) in the standard KEM/DEM way by publishing

\[
C_{\rm sym}=M\oplus H(K)
\]

beside the KEM ciphertext (or using an authenticated symmetric DEM).

Therefore the one-pad compression is a useful **ideal specification**, but a secure compact realization is not a smaller generic primitive that can simply be assumed. It already solves the core task.

This is why the stopping condition is not met by Theorem 1.

## 5. Constructive instantiation attempt: ordinary GGM/prefix programming

The direct attempt is to start from a pseudorandom tree and patch one side of the verifier truth table.

A normal GGM constrained token for a prefix \(p\) gives the subtree seed for the cylinder

\[
[p]=\{w:p\text{ is a prefix of }w\}.
\]

To program \(K\) exactly on the accepting set while leaving a base value/pseudorandom value elsewhere, an ordinary **pure-prefix** realization needs a disjoint family of accepting cylinders whose union is the accepting set.

One can instead start from \(K\) and patch the rejecting set. That needs a pure-rejecting prefix cover.

Both directions fail generically.

## 6. Barrier 1: an explicit accepting-prefix cover is already a witness finder

### Theorem 2 — positive-cover setup violates the no-witness requirement generically

Let \(C_x\) be an explicit exact accepting-prefix cover:

1. every \(p\in C_x\) satisfies \([p]\subseteq A_x\);
2. \(\bigcup_{p\in C_x}[p]=A_x\).

If \(A_x\neq\varnothing\), then \(C_x\neq\varnothing\). Given any \(p\in C_x\), fill its remaining bits arbitrarily. By property 1, the resulting full string is a valid witness.

Therefore any PPT setup algorithm which, from an arbitrary true instance \(x\) and **without a source witness**, outputs such an explicit nonempty accepting cover is itself a PPT witness-finding algorithm.

Ordinary GGM prefix constrained keys expose the prefix/depth associated with each subtree seed, so they fall in this explicit-cover model.

This does not prove that all opaque constrained tokens reveal witnesses. It proves that the most direct positive-region GGM compilation is incompatible with the intended setup model unless the underlying NP search is already easy.

The checker constructs 280 nonempty exact accepting covers for small planted CNFs and, from the first public prefix alone, extracts and verifies a witness in all 280 cases.

## 7. Barrier 2: even easy predicates can require exponentially many prefix tokens

A setup might instead patch the rejecting side, avoiding the positive-cover witness-finding issue.

Pure-prefix GGM programming still has an unconditional worst-case size barrier.

Consider the polynomial-size parity verifier

\[
R_{\rm par}(w)=1
\iff
w_1\oplus\cdots\oplus w_n=0.                         \tag{6}
\]

### Theorem 3 — parity prefix lower bound

Every proper prefix \(p\) of length \(<n\) has at least one unfixed input bit. Flipping that bit toggles parity, so \([p]\) contains both an accepting and a rejecting completion.

Hence **no proper prefix is a pure accepting cylinder or a pure rejecting cylinder**.

Therefore the unique minimal pure-prefix covers consist of leaves:

\[
|C_{\rm accept}|=|C_{\rm reject}|=2^{n-1}.           \tag{7}
\]

The predicate itself has an \(O(n)\)-size circuit; the exponential blowup is solely a limitation of ordinary static prefix-subtree programming.

At only 32 bytes per correction token:

* \(n=32\): \(2^{31}\) tokens = \(2^{36}\) bytes;
* \(n=64\): \(2^{63}\) tokens = \(2^{68}\) bytes;
* \(n=128\): \(2^{127}\) tokens = \(2^{132}\) bytes;
* \(n=256\): \(2^{255}\) tokens = \(2^{260}\) bytes.

The checker exhaustively verifies, for \(n=1,\ldots,10\), that every proper prefix is mixed and both minimal covers have exactly \(2^{n-1}\) leaves.

### Scope

This is a lower bound for the ordinary prefix-subtree realization, **not** for every compact branching program, circuit encoding, lattice encoding, or hidden-state machine. Parity itself has a tiny two-state automaton. The point is that plain GGM prefix programming does not provide a generic compact compiler for verifier predicates.

A more powerful hidden-state compiler is exactly where the representation-security problem returns.

## 8. Why “program rejecting regions instead” does not solve the generic problem

The reject-side approach avoids Theorem 2 because explicit reject regions do not themselves contain a witness certificate.

But Theorem 3 applies symmetrically: parity's rejecting side also needs \(2^{n-1}\) pure-prefix tokens.

For CNF, the rejecting set is a union of small clause-falsifying subcubes, but one global GGM input ordering can place the fixed coordinates late, and overlapping reject regions need a consistent overwrite rule. Run 75's per-layer reorderings worked only because each independent mask function served at most two adjacent clauses; collapsing to one global masked verifier removes that locality.

No generic polynomial-size reject-side GGM compiler is obtained here.

## 9. Complete-public-output audit

The ideal one-pad oracle is excellent semantically:

* false statement: full table perfectly hides \(K\);
* true statement + witness: exact common-key recovery;
* arbitrary QPT black-box key recovery: source extraction by Theorem 1.

But publishing the literal verifier circuit exposes \(K,U\), and ordinary GGM programming fails before any LWE/PRF hardness claim can help:

* accepting-side explicit programming requires setup to reveal/find a witness;
* either-side pure-prefix programming can be exponential even for a linear-size verifier.

Thus this run does **not** convert Run 75's ideal theorem into a PQ construction.

It instead shows that the pointwise-mask complexity was not the fundamental issue. The fundamental missing object is a compact public representation of

\[
w\mapsto U\oplus R(x,w)(K\oplus U)
\]

whose representation leaks no useful information beyond what an evaluator can obtain by witness queries, under an independently justified PQ assumption.

Assuming such a compiler would simply assume the core witness-KEM / witness-encryption problem.

## 10. Relation to Run 72's native LWE transport

Run 72 remains useful but downstream.

If the masked-verifier layer yielded one high-entropy parent capability only through a valid witness, ordinary LWE directional transport could safely derive subsequent offline capabilities.

The present gap is earlier: constructing the source parent itself.

No LWE break is claimed here, and standard LWE by itself has not yet supplied the required masked-verifier representation.

## 11. Fresh validation actually executed

`masked_verifier_oracle_run76_check.py` is deterministic.

It was executed twice and produced byte-identical JSON.

The captured run validates:

* 360 guaranteed-false CNFs; for four independent keys per fixture, every complete one-pad truth table was the same constant-\(U\) table (`1,080` cross-key table-equality checks);
* 420 planted-true CNFs and every enumerated satisfying witness, totaling the captured `satisfying_witness_evaluations`, all returning the same \(K\);
* exact minimal accepting and rejecting parity prefix covers for \(n=1,\ldots,10\), with sizes \(2^{n-1}\);
* every proper parity prefix in those exhaustive cases is mixed;
* 280 explicit accepting-prefix-cover controls, each yielding a verified witness from its first prefix;
* 84 two-dimensional Grover/hybrid numerical controls, all respecting the state-distance hybrid bound and the random-query extraction lower bound;
* concrete prefix-token resource estimates through \(n=256\).

These tests validate finite semantics, combinatorics, and numerical inequalities. They are not the basis for the proofs and are not PQ security evidence.

## 12. Current handoff

### New proved positive result

The one-pad ideal masked verifier is enough semantically, and in the ideal quantum-oracle model it satisfies the requested **arbitrary-QPT key recovery -> source-witness extraction** property with explicit probability loss

\[
\delta^2/(4Q^2).
\]

### New proved negative/boundary results

The direct ordinary GGM realization does not solve the problem:

1. an explicit accepting-prefix compiler would itself find a source witness on every true instance;
2. prefix programming either acceptance or rejection can require \(2^{n-1}\) tokens for an \(O(n)\)-size parity verifier.

### Remaining central obligation

Construct, rather than assume, a compact PQ public encoding of the masked-verifier oracle (or an equivalent source primitive) whose **complete representation** has a reduction to ordinary LWE/LWR/SIS or another independently justified assumption, and whose non-black-box leakage preserves source extraction.

That compiler must not be:

* an assumed WE/iO/FE-equivalent release primitive;
* an exponential truth-table/prefix encoder;
* a public source-label interface;
* a transparent linear/affine representation with the previously proved splice or image attacks;
* an online release service.

Only after this source layer exists do malicious-secure N-of-N setup composition, auxiliary-input composition, concrete parameters, and Run-72 downstream transport become meaningful.

The full stopping condition is therefore **not met**.
