# Run 74 — compact high-degree source programs: occurrence-splitting theorem and the shared-handle boundary

**Status:** constructive compact high-degree source-program attempt, exact complete-public-view break for repeated witness reads, and an exact failure of purely local consistency-check repairs. **Not a completed generic-NP witness KEM.**

Starting verified PR head: `8562a1d6d1471f0f32eb5b29c0fc0de0223c00fe`.

This run uses no external literature/web search and changes no production path.

## 1. Why this run follows Run 73 rather than restarting an old candidate

Run 73 ruled out the natural explicit low-degree feature repair for its global source encoder. It deliberately left one semantic escape open:

> a compact nonlinear circuit may have high algebraic degree without explicitly publishing all monomials.

This run tests the most direct realization of that escape.

The attempt is useful even though it fails: at the ordinary circuit level, a polynomial-size high-degree CNF acceptance program is trivial. The missing question is whether a **public offline capability implementation** of that program actually forces all repeated reads of one witness variable to denote one source witness.

The answer is no for the natural per-occurrence public-choice interface.

This is distinct from Run 73's affine-terminal attack. The failure here occurs even before using an affine combination of terminal states: a single malformed *choice schedule* traverses the public program.

## 2. Constructive compact high-degree source program

For a CNF with clauses `C_1,...,C_m`, define the literal-falsity bit for literal `ell` under assignment `w` in the usual way and

\[
u_c(w)=\prod_{\ell\in C_c} (1-\ell(w)).
\]

Thus `u_c(w)=1` iff clause `c` is violated. Define

\[
A(w)=\prod_{c=1}^m (1-u_c(w)). \tag{1}
\]

Then exactly

\[
A(w)=1 \iff w \text{ satisfies every clause}. \tag{2}
\]

Let `L` be the total number of literal occurrences. Equation (1) has a compact arithmetic circuit:

* `L` witness-literal reads;
* `sum_c(|C_c|-1)` multiplications inside clauses;
* `m-1` multiplications to combine clause-satisfaction bits.

For nonempty CNF this is exactly `L-1` multiplications, plus linear-time negations/subtractions. Its formal degree can grow linearly with `L`; no `2^r` monomial table is required.

So at the **semantic circuit level**, compact high degree really does evade Run 73's explicit-feature-size objection.

## 3. The public repeated-read implementation

The direct public offline realization gives every read occurrence its public alternatives. If variable `x_i` occurs in clauses `c_1,c_2,...`, the evaluator chooses the `0` or `1` source token independently at each occurrence.

Write an occurrence-local schedule as

\[
\widetilde w=\{w_{c,i} : x_i\text{ is read in clause }c\}.
\]

Then the public program computes

\[
\widetilde A(\widetilde w)
 = \prod_c \left(1-u_c(w_c)\right),                 \tag{3}
\]

where `w_c` is the local assignment assembled from the choices used in clause `c`.

Equation (3) is not evaluation of (1) on one global witness unless the cryptographic representation already binds equal variable names across all occurrences.

## 4. Occurrence-splitting theorem

### Theorem 1 — local-block source programs enforce the split relation

Let a public offline source program be a composition of blocks

\[
B_1,\ldots,B_t
\]

where block `j` is allowed to select its source-value alternatives independently of the source selections used by all other blocks. Suppose reaching the accepting output requires every block to accept its own local selection.

If every block has at least one locally accepting assignment, then there exists a public choice schedule that reaches the accepting output, regardless of whether the conjunction of the block relations has a common global witness.

### Proof

For each block `j`, choose any locally accepting assignment `a_j`. Independence of source selections means the evaluator may use `a_j` in block `j` without constraining its choices in any other block. Therefore every block accepts simultaneously under the concatenated occurrence-local schedule `(a_1,...,a_t)`. No common assignment is required. ∎

### Corollary 1 — CNF collapses to per-clause satisfiability

Every nonempty CNF clause is individually satisfiable. Therefore the repeated-read implementation of (1) accepts **every CNF with no empty clause**, including unsatisfiable formulas.

This is stronger than a computational attack: it is an exact semantic mismatch between the intended NP relation and the public program's actual relation.

## 5. Minimal exact counterexample

For

\[
F=(x)\land(\neg x),                                  \tag{4}
\]

the intended compact polynomial is

\[
A(x)=x(1-x)=0
\]

for both Boolean values. There is no source witness.

The occurrence-split public program instead has two reads,

\[
\widetilde A(x_1,x_2)=x_1(1-x_2).                   \tag{5}
\]

Choosing

\[
x_1=1,\qquad x_2=0
\]

gives

\[
\widetilde A=1.
\]

No affine synthesis, hidden-basis recovery, LWE attack, or exhaustive witness search is involved.

The same construction applies clause-by-clause to arbitrary CNF.

## 6. Why local equality/checksum blocks do not repair it

A natural repair is to add constraints intended to enforce that repeated copies agree, for example

\[
x_{c,i}=x_{c',i}.                                    \tag{6}
\]

If an equality block itself receives fresh independent source reads, Theorem 1 applies recursively.

For (4), keep the clause reads

\[
x_1=1,\qquad x_2=0.
\]

For each additional equality checker choose its *own* fresh pair `(a,a)`. Every equality checker accepts, while the two clause reads remain inconsistent.

Hence adding any number of ordinary local equality/hash/checksum blocks does not create a global witness handle. It only appends more individually satisfiable blocks to the split relation.

This is an exact modeling statement. It does **not** say that a cryptographically shared commitment or authenticated handle cannot bind occurrences. It says such a handle must already prevent independent source substitution across blocks; that is the unresolved primitive rather than a free software-level check.

The branch already records the stronger source-gate / witness-encryption boundary in `BRANCHING_INTERTWINER_AND_WE_BOUNDARY.md`; this run does not rename that boundary or claim a construction from it.

## 7. Compact high-degree family: explicit escape closed

To tie the result directly to Run 73's remaining escape, consider

\[
F_r=\left(\bigwedge_{i=1}^r \neg x_i\right)
    \land (x_1\lor\cdots\lor x_r).                  \tag{7}
\]

This formula is false for every Boolean assignment.

Its compact acceptance circuit is

\[
A_r(x)=
\left(\prod_i(1-x_i)\right)
\left(1-\prod_i(1-x_i)\right),                      \tag{8}
\]

which has formal degree up to `2r` before Boolean reduction and circuit size `O(r)`. Thus it is precisely a compact high-degree representation rather than an explicit monomial table.

Yet the repeated-read realization accepts immediately:

* in unit block `not x_i`, choose local `x_i=0`;
* in the final OR block, choose any local nonzero assignment, e.g. `x_1=1`.

All blocks accept while no common witness exists.

So compact algebraic degree alone does not repair source transfer when repeated witness reads remain independently selectable.

## 8. Hidden masking and N-of-N operator replication

The theorem is about the relation implemented by public choices, not about whether intermediate block states are visible.

If each locally accepting block transition is wrapped in a hidden basis, randomized encoding, or an otherwise correct capability transport, the same occurrence-local accepting schedule is still a valid sequence of transitions unless the wrapper itself binds the repeated source occurrences.

Likewise, suppose `N` ceremony operators independently publish root shares using the same occurrence-split source semantics and the final key needs all `N` shares. The malformed schedule is relation-valid for every operator, so replication does not restore global witness consistency.

The checker includes an explicit semantic N-of-N control. This is **not** a claim that all threshold or MPC ceremonies fail; a ceremony that constructs a genuine shared nonlinear source handle is outside the theorem.

## 9. Complete-public-output audit

For this candidate, the complete public transcript exposes one choice interface for each source occurrence. Nothing in the transcript identifies two occurrences as cryptographically inseparable.

Therefore the actual accepted relation is the product of the local block relations:

\[
R_{\rm split}
=
\{(a_1,\ldots,a_t): R_j(a_j)=1\ \forall j\},        \tag{9}
\]

rather than

\[
R_{\rm source}
=
\{w: R_j(w|_{I_j})=1\ \forall j\}.                  \tag{10}
\]

The projection from one global witness into (9) exists, but the converse is false. Formula (4) is the smallest counterexample.

This audit is independent of the downstream Run-72 LWE capability transport. If an occurrence-split program reaches the parent capability, LWE correctly protects only against parties that lack that parent; it cannot distinguish how the parent was obtained.

## 10. Implemented validation

`compact_high_degree_occurrence_split_run74_check.py` is standard-library-only and deterministic.

The exact captured run checks:

* `9,920` consistent-assignment evaluations of the compact CNF circuit against ordinary CNF semantics;
* three explicit zero-witness fixtures and `14` exhaustive consistent assignments, all rejected;
* `500` randomly generated guaranteed-unsatisfiable CNFs (each includes `(x_0)` and `(not x_0)`), all `500` accepted by a clause-local occurrence splice;
* `3,027` local clause blocks, all satisfied in those splice schedules;
* the compact false family (7) for every `r=2,...,12`, all globally false and all occurrence-split accepting;
* `68` equality-repair cases ranging from zero through `512` local equality blocks, all still accepting with inconsistent clause reads;
* `300` semantic N-of-N controls for `N=2,...,16`, releasing all `2,700` modeled shares under the same split relation;
* `480` resource-accounting instances, verifying the direct compact circuit uses exactly `L-1` multiplications.

The checker was executed twice and the JSON outputs were byte-identical.

Passing tests do not establish cryptographic security. They validate only the finite semantics and identities stated above.

## 11. What is proved, and what remains conjectural/open

### Proved in this run

1. Equation (1) is an exact polynomial-size, potentially high-degree CNF acceptance circuit.
2. With independently selectable public source alternatives at repeated reads, the implemented relation is the occurrence-split relation (9).
3. Any set of individually satisfiable local blocks can therefore be traversed without a common global witness.
4. Every CNF with nonempty clauses is vulnerable under the per-clause repeated-read interface.
5. Purely local equality/checksum blocks with fresh source reads do not repair the split.
6. Compact high degree by itself does not repair source transfer.
7. N-of-N replication of the same semantically split relation does not repair the source-consistency defect.

### Not proved

This run does **not** prove:

* impossibility of every compact high-degree or nonlinear source encoder;
* insecurity of a primitive that already supplies one cryptographically shared witness handle;
* an LWE/SIS break;
* an arbitrary-QPT final-key-recovery-to-source-witness theorem;
* complete false-instance hiding for a surviving construction;
* malicious-secure setup composition or practical parameters.

## 12. Precise handoff

Run 73 closed explicit low-degree feature expansion. Run 74 closes the direct compact-high-degree workaround **when compactness is obtained by re-reading public witness alternatives independently at local constraints**.

A surviving construction must therefore bind all uses of each witness component *inside the key-bearing primitive itself*. The handle cannot be merely a public software equality test, another independently selectable local block, an affine terminal representation, or a transparent reconstructible evaluator.

The remaining constructive target is:

> a compact public offline shared-witness handle that lets any valid NP witness drive the nonlinear source computation to one common high-entropy parent capability, while any QPT algorithm obtaining that parent from the complete transcript yields a source witness or breaks a separately justified PQ assumption.

If such a source primitive is obtained, Run 72 already supplies a standard-LWE downstream directional transport. The source primitive itself remains the central unresolved obligation.
