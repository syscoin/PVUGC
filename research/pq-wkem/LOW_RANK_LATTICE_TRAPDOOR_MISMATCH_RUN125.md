# Run 125 — Low-rank / lattice-trapdoor mismatch: a generic short preimage is not a Hair–Sahai source object

## Status and handoff consumed

This run began from the connected GitHub record for `syscoin/PVUGC#1`:

- branch: `research/pq-wkem-validation-20260918`
- starting head: `4198b1815d3edc7be41ec1cb25c0c46fab24610e`
- PR: open, draft, unmerged
- latest substantive ordinary PR comment: `5847380543`, recording verified publication of Runs 112–121.

Exact branch files read before deriving this note included Run 121 (VTDH fixed-digest canonicalization), Run 120 (public affine pseudowitness/noise attack), Run 114 (linear-HPS restricted-witness dichotomy), Runs 109–110 (hidden-input EPHF and noisy gadget-projection barriers), Run 112 (setup-known-invariant correction), and the 24 September Hair–Sahai literature assessment.

The immediate local handoff from Runs 122–124 was also retained:

1. Run 122 corrected the VTDH hiding ledger: the current formal Section-5 proof can be QPT-lifted **conditionally** from QPT hardness of its exact decisional-LWE family by a straight-line reduction; this does not supply source extraction.
2. Run 123 isolated a sufficient *statistical dual-mode source hash* interface: the same canonical hidden target in statistically close Hash/Ext public modes, witness evaluation of that target, and Ext-mode extraction of an ORIGINAL source witness from the correct target.
3. Run 124 corrected the EHPS analogy: Wee's public evaluator takes sampler randomness, not the relation witness; PEPRF has closer witness-evaluation syntax but not the fixed-instance generic-NP/QPT/source-extraction theorem.

Run 125 tests the most obvious remaining constructive splice: use a lattice trapdoor in the Ext mode and ask it to return the low-rank Hair–Sahai object consumed by the source extractor.

The result is a **barrier to the generic splice, not an impossibility theorem for every specially correlated lattice construction**.

---

## 1. Exact Hair–Sahai object that extraction would have to produce

The current Hair–Sahai paper is arXiv:2609.18275v1 (16 September 2026). Its formal MinRank reduction constructs a public linear matrix space

\[
\mathcal S_x\subseteq \mathbb F_p^{m\times m}
\]

with

\[
R=\lfloor\log_2 N\rfloor,
\qquad
m=(N+1)(2NR+1){2R\choose R},
\]

and later chooses a prime

\[
p\in[2^m,2^{m+1}).
\]

For a true statement, every satisfying witness yields a nonzero rank-one matrix

\[
uv^T\in\mathcal S_x,
\qquad v\in\{0,1\}^m,
\qquad \mathrm{wt}(v)\le N+1.
\]

For a false statement, every nonzero matrix in the space has rank at least `R+1`.

The useful transferable component for this project remains the semantic direction already recorded in the research branch: a **supplied sufficiently low-rank object in the actual statement-derived space** can be used to recover an ORIGINAL source witness. The paper's witness-encryption security itself is classical generic-group security, not a concrete post-quantum theorem.

Therefore an SDMSH-style extraction mode cannot merely output "some lattice preimage." It must output an object satisfying the algebraic source condition needed by the low-rank extractor.

---

## 2. Rank and Euclidean shortness are not aligned

A generic SIS/GPV-style trapdoor interface naturally certifies a norm condition such as

\[
\|z\|_2\le \beta
\]

for a vector preimage.  Vectorizing a matrix does not turn this into a rank certificate.

For every `m>=2`, compare over any sufficiently large field:

\[
I_m=\operatorname{diag}(1,\ldots,1),
\qquad
J_m=\mathbf 1\mathbf 1^T.
\]

Then

\[
\operatorname{rank}(I_m)=m,
\qquad
\|I_m\|_F=\sqrt m,
\]

while

\[
\operatorname{rank}(J_m)=1,
\qquad
\|J_m\|_F=m.
\]

Thus the **full-rank** matrix is strictly shorter than this rank-one matrix.

More generally, for any `1<=R<m`, let `D_{R+1}` be the diagonal matrix with `R+1` ones and let `O_{R+1}` be an `(R+1)x(R+1)` all-ones block embedded in the same ambient matrix. Then

\[
\operatorname{rank}(D_{R+1})=R+1,
\quad
\|D_{R+1}\|_F^2=R+1,
\]

but

\[
\operatorname{rank}(O_{R+1})=1,
\quad
\|O_{R+1}\|_F^2=(R+1)^2.
\]

So even a matrix that is *just one rank above* the desired threshold can be much shorter than a rank-one matrix.

### Consequence

A proof of "trapdoor inversion returns a short preimage" does **not** imply

`trapdoor inversion -> rank <= R -> Hair–Sahai source extraction`.

Any construction taking this route needs an additional **rank-correlated** property of the exact trapdoor-output distribution. That property is not supplied by standard SIS/LWE short-preimage syntax alone.

This is a semantic/interface statement, independent of any computational hardness assumption.

---

## 3. Ambient low-rank matrices are exponentially sparse

For square `m x m` matrices over `F_p`, the exact number of rank-`r` matrices is

\[
N_{m,r}(p)=
\frac{\prod_{i=0}^{r-1}(p^m-p^i)^2}
     {\prod_{i=0}^{r-1}(p^r-p^i)}.
\]

For the present barrier a simpler bound is enough. Every matrix of rank at most `R` has a factorization

\[
M=UV,
\qquad
U\in\mathbb F_p^{m\times R},
\quad
V\in\mathbb F_p^{R\times m},
\]

by padding a smaller-rank factorization if necessary. Hence

\[
|\mathcal L_{\le R}|
\le p^{2mR}.
\]

Since there are `p^{m^2}` ambient matrices,

\[
\boxed{
\Pr_{M\leftarrow U(\mathbb F_p^{m\times m})}
[\operatorname{rank}(M)\le R]
\le p^{-m(m-2R)}
}
\tag{1}
\]

whenever `m>2R`.

This is deliberately a safe, loose bound. The exact rank count is even sharper in the parameter range of interest.

---

## 4. Min-entropy form: a generic high-entropy Ext sampler almost never lands in the source set

Let `D` be **any** distribution on ambient matrices whose maximum point mass is at most

\[
2^{-h}.
\]

For any event `E`, the elementary counting inequality gives

\[
\Pr_D[E]\le |E|2^{-h}.
\]

Writing the entropy deficit from ambient uniform as

\[
\Delta=m^2\log_2p-h,
\]

and setting `E=L_{<=R}`, (1) gives

\[
\boxed{
\Pr_D[\operatorname{rank}(M)\le R]
\le
2^{-m(m-2R)\log_2p+\Delta}.
}
\tag{2}
\]

Therefore, if a proposed Ext-mode trapdoor output is still close to a high-min-entropy ambient preimage distribution, it will not feed the Hair–Sahai low-rank extractor with useful probability. To make low rank occur with probability `1-epsilon`, the distribution must pay essentially the whole codimension-like entropy deficit

\[
\Delta
\gtrsim
m(m-2R)\log_2p.
\]

This is **not** a claim that a concrete GPV sampler has the premises of (2); that must be proved for its exact induced matrix distribution. It is a diagnostic: the desired Ext sampler must be very strongly correlated with the low-rank/source geometry, rather than being a generic short/high-entropy inversion sampler.

---

## 5. Statement-derived subspace caveat: ambient rarity is not enough

The Hair–Sahai extractor works in the actual public statement-derived space `S_x`, not in all of `F_p^{m x m}`.

Ambient rarity alone cannot prove anything about a specially structured subspace. A one-dimensional subspace such as

\[
\operatorname{span}(E_{11})
\]

consists entirely of rank-at-most-one matrices even though rank-at-most-one matrices are rare in the ambient space.

For a distribution `D_x` supported on `S_x` with min-entropy `h_x`, the correct bound is

\[
\boxed{
\Pr_{D_x}[\operatorname{rank}(M)\le R]
\le
|\mathcal S_x\cap\mathcal L_{\le R}|\,2^{-h_x}.
}
\tag{3}
\]

Thus Run 125 does **not** replace the Run-79 priority. It sharpens it:

> To justify a lattice Ext mode over the actual Hair–Sahai compiler, one needs the low-rank mass of the **actual statement-derived space under the exact correlated trapdoor-output distribution**, not an ambient MinRank count and not a generic shortness theorem.

That is precisely where the complete rank-weight/spectral calculation remains relevant.

---

## 6. Practicality warning for the naive dense matrix-to-lattice embedding

The issue is not only semantic.

Using the paper's exact displayed matrix order and the lower bound `log2 p >= m`, a literal dense vectorization of one `m x m` field matrix requires at least

\[
m^2\cdot m=m^3
\]

bits before any lattice trapdoor overhead.

The deterministic checker obtains:

| N | R | m | matrix entries `m^2` | raw dense bits lower bound `m^3` | decimal TB |
|---:|---:|---:|---:|---:|---:|
| 4 | 2 | 510 | 260,100 | 132,651,000 | 0.0000166 |
| 8 | 3 | 8,820 | 77,792,400 | 686,128,968,000 | 0.0858 |
| 16 | 4 | 153,510 | 23,565,320,100 | 3,617,512,288,551,000 | **452.19** |
| 32 | 5 | 2,669,436 | 7,125,888,558,096 | 19,022,103,448,969,553,856 | **2,377,762.93** |

So at the already-small illustrative `N=16`, **one literal dense matrix vector is at least about 452 decimal TB**. A generic lattice trapdoor over `m^2≈2.36×10^10` explicit coordinates is not a practical route.

This does not contradict Hair–Sahai's polynomial-time theorem: their construction exploits a structured polynomial-size representation and generic-group handles. It also does not prove that every compressed or implicit lattice encoding is impractical. It rules out treating the literal dense matrix as a routine LWE/SIS vector and expecting practical parameters.

---

## 7. Consequence for the Run-123 dual-mode target

Run 123's abstract extraction arrow was

\[
\text{correct canonical target in Ext mode}
\longrightarrow
\text{ORIGINAL source witness}.
\]

Hair–Sahai suggests a possible decomposition

\[
H_P(x)
\xrightarrow{\text{Ext trapdoor}}
M\in\mathcal S_x,\ \operatorname{rank}(M)\le R
\xrightarrow{\text{HS source extractor}}
w.
\]

Run 125 shows why a **plain lattice trapdoor** does not supply the first arrow:

1. norm-shortness does not imply low rank;
2. a generic high-entropy ambient output has negligible low-rank mass;
3. a literal dense embedding is far outside the practical target even at small theorem parameters;
4. the only meaningful possibility is a trapdoor distribution deliberately correlated to the actual source subspace/rank geometry.

But that correlation creates the next security obligation: Hash-mode and Ext-mode complete public outputs must remain statistically close (or otherwise support a quantum-valid recognizable-event mode switch), while the Hash mode must not itself contain enough trapdoor structure to manufacture a source-bearing low-rank object. This is exactly the Run-112/123 separation requirement.

---

## 8. QPT/security classification

### New rank/norm and counting lemmas

- honest algorithm model: ordinary classical finite-field/integer computation;
- adversary model: none; the statements are information-theoretic;
- hardness assumption: none;
- reduction model: direct algebra/counting, no oracle, rewinding, extraction, QROM, or quantum auxiliary state;
- conclusion: generic Euclidean short-preimage syntax is insufficient to imply low-rank source extraction; high-min-entropy ambient distributions have negligible low-rank mass under (2).

Because these are unconditional structural statements, they apply equally in the presence of QPT adversaries. They do **not** provide QPT hiding.

### Hair–Sahai component

- honest algorithms: classical polynomial time in the generic-group model;
- stated false-statement adversary: classical generic adversary, not arbitrary QPT against a concrete group implementation;
- useful conclusion imported here: source-preserving Boolean-factor MinRank structure / supplied-low-rank semantic extraction;
- QPT endpoint status: **not supplied** by the paper.

### Lattice Ext mode

- no concrete construction is established here;
- no claim is made that ordinary LWE/SIS trapdoor distributions satisfy the min-entropy premise in the relevant matrix coordinates;
- no QPT reduction from an actual correlated low-rank trapdoor sampler to standard LWE/SIS has been shown;
- therefore the missing source-release construction remains **UNPROVED**.

---

## 9. Reproducible checker

`low_rank_lattice_trapdoor_run125_check.py` is deterministic and standard-library-only. Two finalized executions were byte-identical.

The captured output records **1,067 assertions**, checking:

1. the exact finite-field square-matrix rank-count formula against exhaustive enumeration for small `p,m`;
2. the safe factorization bound `#rank<=R <= p^(2mR)`;
3. explicit rank/Frobenius counterexamples through `m=32`;
4. threshold counterexamples for every tested `1<=R<m`;
5. finite min-entropy/event-cardinality controls;
6. exact Hair–Sahai parameter arithmetic for `N=4,8,16,32` using the current v1 displayed formula;
7. an explicit statement-subspace caveat where a low-dimensional subspace is entirely low-rank despite ambient rarity.

These tests validate algebra and arithmetic only. They are not cryptanalytic evidence for or against LWE/SIS and do not establish any QPT hardness assumption.

---

## 10. Updated handoff

Do **not** try another generic `vectorize low-rank matrix -> GPV short preimage -> call Hair–Sahai extractor` construction. The missing first arrow is real.

The highest-value next target is now narrower:

1. compute or bound
   \(
   |\mathcal S_x\cap\mathcal L_{\le R}|
   \)
   and, more importantly, the **rank-weight mass under the actual candidate correlated Ext distribution**, for the real Hair–Sahai statement-derived space;
2. design an **implicit/structured** Ext sampler whose correct canonical target yields a source-bearing low-rank object without explicitly vectorizing an `m x m` dense field matrix;
3. prove Hash/Ext full-public-view closeness by a quantum-valid straight-line reduction to an independently justified QPT-hard distribution;
4. immediately test whether the same structure lets HashSetup manufacture the low-rank object itself (Run 112 collapse) or exposes an ambient pseudorepresentation (Runs 109–110, 114, 120).

A candidate that merely adds a lattice trapdoor to the ambient matrix coordinates does not meet these obligations.

The practical generic-NP public/offline post-quantum witness-KEM stopping condition remains **unmet**.