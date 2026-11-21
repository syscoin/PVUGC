# Run 87 — public-anchor dichotomy: exact false-anchor annihilation would decide the NP language

**Status:** new structural impossibility/result for the current linear-source WKEM direction. It rules out a broad class of “repair the source space until every false representation has zero key anchor” strategies. It does **not** construct the missing QPT-secure release layer and is not a completed WKEM.

**Starting verified PR head:** `52b5cc0d3650ed6c29dbf2225ecbfc9c08208503` on `research/pq-wkem-validation-20260918`.

No production path is modified.

## 1. Why this matters after Runs 82–86

The recent rank-gap work repeatedly encountered the same temptation:

1. keep a public polynomial-time exact-span compiler for a linear source space;
2. keep a public linear anchor `ell` with `ell(A(w))=1` for honest witness encodings;
3. add enough public constraints/features that, on every false statement, every surviving source vector has anchor zero.

If step 3 could be achieved exactly and generically, the key shift in the Run-79/81 family could disappear identically on false statements, giving information-theoretic false-key independence before any cryptographic masking argument.

This run shows that such a target is too strong for a generic polynomial-time public compiler: **the final public basis itself would decide the language.**

The result is independent of MinRank, LWE, SIS, generic groups, and the specific finite-difference attacks.

## 2. Abstract source interface

Let `L` be a language. On public input `x` and setup randomness `rho`, let a classical polynomial-time compiler output

    PP(x;rho) = (B_1,...,B_k, ell),

where:

* `B_1,...,B_k` are an explicit basis of a finite-field linear space

      S_{x,rho} = span{B_1,...,B_k};

* `ell : S_{x,rho} -> F` is an efficiently evaluable public linear functional.

Assume witness completeness in the source layer:

> for every valid witness `w` to `x in L`, an efficient classical algorithm computes a matrix `M_w in S_{x,rho}` with
>
>     ell(M_w)=1.

This is the exact shape used by the anchored source constructions: the witness representation is normalized to the same public key coefficient.

## 3. Theorem 1 — public-anchor dichotomy

For every explicit basis `(B_1,...,B_k)` and public linear functional `ell`, exactly one of the following holds:

1. **annihilating case**

       ell(B_i)=0 for every i,

   in which case `ell(M)=0` for every `M in S`;

2. **normalizable case**

   some `ell(B_j) != 0`, in which case the public matrix

       M* = ell(B_j)^(-1) B_j

   is efficiently computable and satisfies

       ell(M*)=1.

### Proof

Linearity proves the first case immediately. In the second case, scaling `B_j` by the public inverse of its nonzero anchor gives anchor one. No search problem is involved. ∎

### Consequence

For a public explicit linear source space, **finding some anchor-one representation is never a hardness assumption** once the anchor is nonzero on the space.

The only potentially hard distinction is additional structure of that representation: low rank, bounded factor, short coefficient vector, source semantics, or some separately justified cryptographic property.

This sharpens the extraction target. An extractor cannot treat “the adversary found coefficients with anchor one” as source-witness evidence: if the false source has any nonzero anchor at all, such coefficients are public linear algebra.

## 4. Theorem 2 — exact false-anchor annihilation gives a decision algorithm

Assume deterministic polynomial-time compilation and perfect source completeness.

Suppose additionally that

    x notin L  =>  ell(M)=0 for every M in S_x.          (1)

Then `L` is decidable in deterministic polynomial time.

### Decision algorithm

On input `x`:

1. run the compiler to obtain `(B_1,...,B_k,ell)`;
2. compute `ell(B_i)` for every basis element;
3. accept iff at least one value is nonzero.

### Correctness

If `x in L`, source completeness supplies `M_w in S_x` with `ell(M_w)=1`. Therefore `ell` cannot vanish on every basis vector, so the algorithm accepts.

If `x notin L`, property (1) says `ell` vanishes on the whole source space and therefore on every basis element, so the algorithm rejects.

Everything is polynomial time. ∎

For an NP-complete language, such a compiler would therefore imply `P=NP`.

This is a conditional complexity consequence, not a proof that `P!=NP`.

## 5. Theorem 3 — randomized setup gives the analogous BPP barrier

Now let setup be classical probabilistic polynomial time.

Suppose, for some functions `eps_Y(n), eps_N(n)`, that:

* on every `x in L`, with probability at least `1-eps_Y`, the completed public source space contains an `M` with `ell(M)=1`;
* on every `x notin L`, with probability at least `1-eps_N`, `ell` annihilates the completed public source space.

The same basis-anchor test decides membership with the same two error probabilities.

Thus if both errors are below `1/3` for all sufficiently large inputs, `L in BPP`. With negligible cryptographic errors, an NP-complete language would satisfy `NP subseteq BPP`.

If true-instance completeness is perfect and false annihilation fails with probability at most `1/2`, the test is one-sided in the corresponding sense.

No rewinding, random oracle, extraction, or quantum argument is involved; the decision procedure is ordinary classical basis inspection.

## 6. Distributed erased setup does not remove the barrier

The project permits a malicious-secure ceremony with temporary erased trapdoors and at least one honest participant.

That does not evade Theorems 1–3 **when the successfully completed transcript contains the explicit public basis and public anchor used by the source layer**.

After completion, anyone can run exactly the same basis-anchor test. Temporary secrets and their erasure are irrelevant to that public linear-algebra fact.

If honest setup can abort, the theorem applies to the distribution of completed transcripts whenever completion occurs with efficiently usable probability. Making completion itself infeasible on one side is not a useful public setup construction.

A possible escape is to make the relevant anchor or source object cryptographically hidden rather than publicly evaluable. That is no longer the public-anchor model and would require its own QPT-secure reduction.

## 7. Corollary — a generic exact “violation-indicator anchor kill” cannot be a cheap source repair

For a Boolean system one can define, information-theoretically, a global violation indicator

    I_x(b) = 0  if b satisfies all equations,
             1  otherwise.

If a source compiler could, in polynomial time, impose enough exact public linear constraints that every false source vector obeyed

    sum_b lambda_b = 0,

while every honest satisfying assignment retained anchor one, then the final basis would satisfy precisely the decision criterion of Theorem 2.

Therefore any apparent generic construction of this kind must give up at least one of:

* polynomial-time exact-span generation;
* universality for arbitrary NP instances;
* exact false-anchor annihilation;
* public efficient anchor evaluation;
* honest anchor-one completeness.

This explains why a high-degree “global unsatisfiability indicator” is not, by itself, a free repair of the recent finite-difference families. If it could be incorporated into the same explicit polynomial-time exact-span interface with the desired exact effect, SAT would become easy by inspecting the resulting basis.

## 8. Hair–Sahai instantiation of the barrier

Hair–Sahai's weighted-table compiler has exactly the public-basis side of the theorem:

* the matrix space is given by an ordered explicit basis;
* Section 4.6 computes the span exactly by public linear transitions and Gaussian elimination;
* intersecting with the source constraints is another homogeneous linear system;
* a satisfying assignment gives an explicit rank-one matrix and its coordinates in the output basis.

Those are algebraic compiler facts only. Their witness-encryption theorem remains a **classical prime-order generic-group** theorem, not a concrete QPT theorem.

Hence a modification of this exact-span compiler that made the ordinary public anchor vanish on the entire false source space for every false SAT instance would immediately instantiate Theorem 2.

The recent finite-difference survivors are therefore not merely an inconvenience that one should expect to eliminate all the way to exact anchor zero with a small public linear patch. A generic exact annihilation endpoint would itself collapse the decision problem.

## 9. Implication for the Run-79/81 key-shift architecture

Let the public source basis be `B_i` with public anchor coordinates

    ell_i = ell(B_i).

There are only two possibilities on any statement.

### Case A — all `ell_i=0`

The key-shift coefficient vanishes on the whole source space.

If this happened generically on every false statement while completeness gave anchor one on every true statement, basis inspection would decide the language.

### Case B — some `ell_j != 0`

Then a public anchor-one source matrix is immediate:

    M* = B_j / ell_j.

Therefore security cannot rely on hiding which coefficient vector has anchor one. The full burden is on the **rank-sensitive/computational masking layer** to make this public high-rank normalized representation useless, while a valid witness's special low-rank/bounded-factor representation decodes.

This is the right interpretation of the Run-82/85/86 low-rank false directions: the danger is not merely that they have nonzero anchor. Public nonzero anchor is unavoidable in the normalizable branch. The danger is that they have enough extra structure to make the cryptographic mask distinguishable or decodable.

## 10. Relationship to the standard-LWE positive component

Run 72 established an exact standard-LWE reduction for **local directional capability transport once a parent capability already exists**.

That result is compatible with the present barrier:

* local LWE transport supplies computational one-wayness under a separately assumed QPT-hard LWE distribution;
* it does not produce the source capability from a raw NP witness;
* the present theorem says a public linear source compiler cannot solve that source problem merely by making the false anchor disappear exactly, unless the language itself becomes efficiently decidable.

So the remaining constructive target should be stated computationally, not as exact anchor elimination:

> construct a public source release in which false instances may have public anchor-one high-rank representations, but using them to recover the final key is QPT-hard under an independently justified assumption, whereas every valid witness has a special representation that classically decodes the same key.

No standard-LWE/SIS reduction for that source release is proved in this run.

## 11. Quantum-security classification

### Honest algorithm model

The compiler/basis inspection considered here is classical polynomial time.

### Adversary model

The normalization and decision procedures are classical PPT. Therefore the impossibility applies a fortiori to any claim that relies on security against arbitrary QPT adversaries.

### Hardness assumptions

None are used in Theorem 1. Theorems 2–3 are complexity implications: exact or overwhelming false-anchor annihilation plus honest completeness would place the language in `P` or `BPP` respectively.

### Reduction model

Straight-line classical computation only. No quantum auxiliary information, superposition queries, QROM, rewinding, or extraction appears.

### Exact conclusion

This run proves an **architectural impossibility/decision barrier** for public exact-anchor annihilation. It does **not** prove false-statement hiding, QPT hiding, or arbitrary-QPT source extraction for a WKEM.

## 12. Validation actually executed

`public_anchor_dichotomy_run87_check.py` is deterministic and standard-library-only apart from the already-published exact compiler helper `research/pq-wkem/literature-20260924/rank_field_extensions.py`.

It was executed twice with byte-identical JSON.

The checks include:

* `14,000` generic basis/linear-functional identities confirming that vanishing on a basis is exactly vanishing on the span;
* `694` random public normalizations where a nonzero anchor coordinate was scaled to an anchor-one source vector;
* the published `N=3,R=1,p=7` weighted-table fixtures:
  * true source dimension `4`, public nonzero anchor present;
  * false source dimension `4`, public nonzero anchor also present;
  * the first normalized false basis vector has rank `3`;
* an **exhaustive tiny-cube oracle control** that appends the semantic global violation indicator by enumerating assignments:
  * the true fixture retains nonzero anchor;
  * the false fixture's augmented space has anchor zero;
* `80` random tiny systems of linear equations where this exhaustive indicator-augmented basis test agreed exactly with brute-force satisfiability.

The indicator experiment is intentionally labelled an **oracle/exhaustive control**. It is not a claimed polynomial implementation of the high-degree constraint in Hair–Sahai's quadratic table. Its purpose is to validate the theorem's consequence: if such an exact generic basis were cheaply available, public anchor inspection would decide satisfiability.

Passing tests are not evidence of cryptographic security.

## 13. Current dependency / assumption ledger

| Component | Honest model | Adversary model | Assumption | Exact conclusion |
|---|---|---|---|---|
| Hair–Sahai weighted-table source compiler | classical PPT | n/a for algebra | none for algebraic rank/source theorem | explicit basis; rank-one witness; supplied-low-rank source extraction |
| Hair–Sahai encryption theorem | classical | classical generic-group adversary | generic-group model | ordinary false-statement WE, not concrete PQ |
| Run-72 directional transport | classical PPT | reduction can target QPT if base LWE is QPT-hard and interface is classical/straight-line | standard search/decision LWE for the local token | local one-way capability transport only |
| Run-87 public-anchor dichotomy | classical PPT | classical attack, hence also QPT | none; `P/BPP` consequence for exact/overwhelming annihilation | rules out generic public exact-anchor-kill as the missing source compiler |

## 14. Handoff

The next research target should **not** be another attempt to make the public false source have exactly zero anchor everywhere.

The useful target is now narrower and computational:

1. keep the explicit source basis and allow public anchor-one high-rank representatives;
2. identify a witness-specific low-rank/bounded-factor structure that every valid witness can compute;
3. build a public mask whose complete output is QPT-secure under standard LWE/SIS or another independently justified PQ assumption even given arbitrary public anchor-one high-rank representatives;
4. prove arbitrary QPT recovery of the **final** key yields either an ORIGINAL source witness or a break of that base assumption.

This run does not meet the stopping condition.
