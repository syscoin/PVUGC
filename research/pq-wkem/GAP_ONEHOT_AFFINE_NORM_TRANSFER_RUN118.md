# Run 118 — bounded-occurrence gap transfer for the one-hot affine compiler

## Status

Verified starting PR head: `a0803edfa691f184e33ca92620471a81c17c611c` on branch
`research/pq-wkem-validation-20260918`. PR #1 was open, draft, and unmerged. The
latest substantive ordinary PR comment was `5843580758`, which records the verified
interactive publication of Runs 104–108 and 110–111.

This run continues the local Run-117 handoff. Run 117 established an exact affine
compiler for 3SAT:

- every satisfying assignment gives an integer one-hot vector `z` with
  `M_phi z=t_phi` and `||z||_1=B=n+m`;
- every supplied centered modular solution with `||z||_1<=B` yields an ORIGINAL
  satisfying assignment, once `q>2(B+1)`.

The remaining concern was that this source gap looked extremely thin: a false formula
that is only one clause away from satisfiable has a signed ambient solution only two
units above the honest l1 norm. Run 118 gives the exact quantitative answer.

> For the Run-117 compiler, the excess affine-preimage norm is controlled, up to the
> maximum variable occurrence `Delta`, by the minimum number of violated clauses.
> Consequently a bounded-occurrence constant-gap 3SAT instance induces a **constant
> multiplicative gap in both l1 and squared l2 norm** of every affine preimage.

This is a positive semantic/source-compilation result. It does **not** solve the
standard-LWE carrier problem left by Runs 115–117, and it does not by itself imply
QPT hiding.

No production path is changed.

---

## 1. Setup and negative-mass accounting

Let `phi` be a 3CNF on `n` variables and `m` clauses. Use the Run-117 compiler:

- every global variable has a two-coordinate one-hot group;
- every clause has one coordinate for each locally satisfying 3-bit assignment;
- every group has coordinate sum `1`;
- clause-local first moments are constrained to equal the corresponding global
  variable bits.

Let

\[
B=n+m.
\]

For any integer group vector `g` satisfying

\[
\sum_k g_k=1,
\]

define its **negative mass**

\[
N(g)=\frac{\lVert g\rVert_1-1}{2}.
\tag{1}
\]

Because `g` is integral and has sum one, `N(g)` is a nonnegative integer. Also

\[
\lVert g\rVert_2^2\ge \lVert g\rVert_1=1+2N(g),
\tag{2}
\]

because `x^2>=|x|` for every integer coordinate.

For a complete affine solution `z`, write `N_i` for variable-group negative masses
and `N_j^C` for clause-group negative masses, and put

\[
N_{\rm tot}=\sum_iN_i+\sum_jN_j^C.
\tag{3}
\]

Since the groups are disjoint,

\[
\boxed{
\lVert z\rVert_1=B+2N_{\rm tot}
}
\tag{4}
\]

and

\[
\boxed{
\lVert z\rVert_2^2\ge B+2N_{\rm tot}.
}
\tag{5}
\]

Thus the only way to stay near the honest norm is to keep the total signed negative
mass small.

---

## 2. Lower bound from violated clauses

Let `Delta` be the maximum number of clause **positions** in which any variable
occurs, counting repeated literals.

Given any integer affine solution `z`, call a variable **good** if its variable group
has `N_i=0`. Equation (1) then forces that group to be exactly one-hot, hence it fixes
a Boolean value. Assign those fixed values to the good variables and assign arbitrary
bits to the remaining bad variables.

Let `V(a)` be the number of clauses violated by this rounded assignment.

Every violated clause is of one of two types.

### Type A — clause touches a bad variable

The number of such clauses is at most

\[
\Delta\cdot \#\{i:N_i>0\}
\le
\Delta\sum_iN_i.
\tag{6}
\]

### Type B — every variable in the clause is good

The consistency equations force the signed clause-local distribution to have first
moments equal to the induced global 3-bit assignment.

If the clause is violated, that induced 3-bit assignment is the unique local
falsifying point and is absent from the clause group's allowed support. Therefore the
clause group cannot be one-hot. Hence

\[
N_j^C\ge1.
\tag{7}
\]

The number of all-good violated clauses is therefore at most

\[
\sum_jN_j^C.
\tag{8}
\]

Combining (6) and (8), for `Delta>=1`,

\[
V(a)
\le
\Delta\sum_iN_i+\sum_jN_j^C
\le
\Delta N_{\rm tot}.
\tag{9}
\]

Let

\[
U(\phi)=\min_a V(a)
\]

be the minimum possible number of violated clauses. Since `U(phi)<=V(a)`, every
integer affine solution satisfies

\[
N_{\rm tot}\ge
\left\lceil\frac{U(\phi)}{\Delta}\right\rceil.
\tag{10}
\]

Substitution into (4) and (5) gives the main lower bound:

\[
\boxed{
\lVert z\rVert_1
\ge
B+2\left\lceil\frac{U(\phi)}{\Delta}\right\rceil
}
\tag{11}
\]

and

\[
\boxed{
\lVert z\rVert_2^2
\ge
B+2\left\lceil\frac{U(\phi)}{\Delta}\right\rceil.
}
\tag{12}
\]

This applies to **every** integer affine representation, not only representations
constructed from Boolean assignments.

---

## 3. Matching upper bound up to `Delta`

The lower bound is meaningful only if it is not an artifact of a loose relaxation.
There is also an explicit upper construction.

Fix any Boolean assignment `a`. Variable groups are set one-hot. A satisfied clause
uses its induced local satisfying assignment as a one-hot clause group.

For a violated clause, let `f in {0,1}^3` be the unique falsifying local bit triple.
For `f=000`, the integer affine identity

\[
011+100-111=000
\tag{13}
\]

uses only satisfying local assignments, its coefficients sum to one, and its
coefficient l1 and squared-l2 norms are both three.

Coordinatewise bit-complement is an affine map. Because the coefficients in (13) sum
to one, complementing exactly the coordinates where an arbitrary `f` has value one
transports (13) to an affine representation of that `f`, still using three allowed
local satisfying assignments with coefficients `(+1,+1,-1)`.

Therefore every assignment violating `V(a)` clauses gives an exact integer affine
solution with

\[
\boxed{
\lVert z(a)\rVert_1
=
\lVert z(a)\rVert_2^2
=
B+2V(a).
}
\tag{14}
\]

Taking the best Boolean assignment gives

\[
\boxed{
B+2\left\lceil\frac{U(\phi)}{\Delta}\right\rceil
\le
L_1^*(\phi)
\le
B+2U(\phi),
}
\tag{15}
\]

where `L_1^*` is the minimum l1 norm of any integer affine preimage. The same lower
bound holds for the minimum squared-l2 norm, and the same explicit upper construction
has squared-l2 norm `B+2U(phi)`.

So the affine excess norm tracks MAX-3SAT unsatisfied-clause distance to within the
bounded-occurrence factor `Delta`.

---

## 4. Bounded-occurrence gap transfer

Suppose a 3CNF family has

\[
U(\phi)\ge \varepsilon m
\tag{16}
\]

on NO instances and maximum occurrence at most `Delta`.

Then every false-instance affine preimage obeys

\[
\lVert z\rVert_1,
\lVert z\rVert_2^2
\ge
B+
2\left\lceil\frac{\varepsilon m}{\Delta}\right\rceil.
\tag{17}
\]

If unused variables are removed, `n<=3m`, hence `B=n+m<=4m`. Ignoring the favorable
rounding term,

\[
\boxed{
\frac{\lVert z\rVert_1}{B},
\frac{\lVert z\rVert_2^2}{B}
\ge
1+\frac{\varepsilon}{2\Delta}.
}
\tag{18}
\]

Thus **constant clause gap plus constant occurrence produces a constant
multiplicative affine-preimage gap**.

This is directly relevant because bounded-occurrence hard MAX-3SAT families are
standard complexity objects. Berman--Karpinski--Scott report approximation hardness
for exact 3-literal SAT instances in which every variable occurs exactly four times.
Their paper is evidence that the required constant-occurrence / constant-gap regime is
not artificial.

Dinur's PCP proof gives a general gap-amplification framework: it amplifies the
fraction of unsatisfied constraints while retaining polynomial size, and uses
bounded-degree expander constraint graphs as a central ingredient. This makes a
source-preserving bounded-occurrence gap reduction a plausible compiler component.

However, this run does **not** claim to have fully audited one concrete PCP-to-3CNF
pipeline with exact witness-recovery map, exact `epsilon,Delta`, and practical blowup.
Those concrete source-preservation and parameter details remain an implementation
obligation.

---

## 5. Source-preserving generic-NP use

For this project we need more than ordinary gap hardness: an honest ORIGINAL witness
must efficiently produce the affine short preimage, and an exact satisfying affine
witness must permit recovery of an ORIGINAL source witness.

A safe composition target is therefore:

1. a source-preserving Karp reduction whose satisfying assignment contains/decodes an
   ORIGINAL NP witness;
2. a perfect-completeness gap-amplification layer with an efficient honest prover;
3. bounded-occurrence enforcement;
4. the Run-117/118 one-hot affine compiler.

If the gap-amplification proof variables are not themselves source-decodable, the
source-preserving Karp component must remain explicitly enforced rather than silently
replaced by PCP soundness. Soundness on false statements is not a knowledge theorem
for true statements.

This run establishes the algebraic gap-transfer layer only.

---

## 6. Modular form

Let a centered modular vector `z` obey

\[
\lVert z\rVert_1\le T.
\]

Every compiler row has coefficients of magnitude at most one and target coordinate in
`{0,1}`, so

\[
|(Mz-t)_r|\le T+1.
\tag{19}
\]

If

\[
q>2(T+1)
\tag{20}
\]

and `Mz=t mod q`, every residual is a multiple of `q` with magnitude below `q/2`, so
it is exactly zero over the integers. The bounds above then apply unchanged.

Hence, for a desired false-instance threshold

\[
T< B+2\left\lceil\frac{\varepsilon m}{\Delta}\right\rceil,
\]

choosing `q>2(T+1)` prevents modular wraparound from bypassing the gap.

---

## 7. Relation to the noisy-HPS / standard-LWE path

Runs 115–116 need a short affine preimage because witness evaluation of

\[
b=A^Ts+e,
\qquad
 y=t^Ts+e_0
\]

produces projected error controlled by the witness representation. Run 117 supplied
an exact source extractor only at the boundary `||z||_1=B`; Run 118 now shows how a
bounded-occurrence clause gap can give a constant multiplicative source gap in both
l1 and squared-l2 geometry.

For iid centered Gaussian coordinate noise, the linear form `eta^T z` has variance
proportional to `||z||_2^2`, so (18) yields a constant variance separation between
honest one-hot witnesses and every false-instance affine preimage **provided the
carrier really exposes independent isotropic noise in these source coordinates**.

That proviso is the central unresolved issue.

A constant variance gap is not by itself false-statement hiding, and it is not an
arbitrary-QPT extraction theorem. Gaussian tails overlap. A repetition/ECC or
hypothesis-testing layer would need its own all-witness correctness and security
proof.

More importantly, the public carrier is still structured. The standard-LWE reduction
from Run 116 applies cleanly only when the public sample matrix has the required
average-case distribution. Publishing a trapdoor lift `R` with `A R=M_phi` transforms
an LWE sample to

\[
R^T(A^Ts+e)=M_\phi^Ts+R^Te,
\tag{21}
\]

so ordinary LWE hardness does **not** automatically survive the auxiliary `R` view.
The next carrier must prove that auxiliary-input distribution, or avoid exposing such
a lift.

Thus Run 118 repairs the *norm-gap* side of Run 117 but not the *random-carrier*
side.

---

## 8. Comparison with Hair--Sahai

Hair--Sahai's 2026 deterministic GapSVP reduction gives a polynomial approximation
gap in every fixed l_p norm with `p>2` (and in l_infinity), substantially larger than
the constant gap derived here. Its value to this project remains source-preserving
geometric amplification.

The Run-118 result is different and complementary:

- it works directly with the affine one-hot representation already compatible with
  the Run-115/116 projected-hash algebra;
- it gives an exact l1 and squared-l2 accounting identity;
- the gap is only constant after bounded-occurrence gap amplification;
- it still does not yield a uniform random LWE carrier.

No worst-case GapSVP theorem is relabeled as average-case SIS/LWE hardness.

---

## 9. QPT/security ledger

### Algebraic gap theorem

Honest algorithm model: classical deterministic polynomial time.

Adversary model: none. Equations (4)–(18) are unconditional integer linear-algebra and
combinatorial statements.

Conclusion: supplied affine preimages of a bounded-occurrence gap formula have a
provable norm gap; exact honest witnesses retain all-witness affine correctness.

### PCP / bounded-occurrence literature

These are classical complexity reductions and approximation-hardness results. They
do not establish cryptographic hiding against QPT adversaries.

The exact generic-NP source-preserving PCP composition and concrete parameters are
not completed here.

### Standard LWE / SIS

Not invoked as a proved endpoint in this run. In particular, the structured affine
matrix is not declared QPT-hard merely because a future trapdoor lift might use
lattices.

### Still missing

1. a public average-case carrier whose complete auxiliary output is reducible to an
   independently justified QPT-hard assumption;
2. preservation of the Run-118 source gap through that carrier;
3. arbitrary-QPT FINAL-key recovery to ORIGINAL witness or a standard QPT-hardness
   break;
4. malicious-secure erased setup/abort and auxiliary-input composition;
5. concrete practical parameters.

The stopping condition is not met.

---

## 10. Validation

`gap_onehot_run118_check.py` is deterministic and standard-library-only. Three
executions were byte-identical.

It checks:

- 25,807 integer group vectors for the exact negative-mass identity and
  `l2^2>=l1`;
- all eight possible forbidden local 3-bit triples for the three-term
  `(+1,+1,-1)` affine representation;
- 78 assignment-to-affine-preimage constructions across signed, repeated-literal,
  satisfiable and unsatisfiable fixtures;
- exhaustive low-negative-mass affine solutions of the smallest contradictory
  repeated-variable formula, finding exact minimum `l1=l2^2=B+2`;
- the global rounding/charging inequality `V(a)<=Delta*N_tot` on every exact fixture
  solution encountered;
- modular no-wrap controls;
- explicit finite parameter rows for bounded occurrence and constant clause gaps.

Total assertions: **52,242**.

These checks validate finite algebra/functionality identities only. They are not a
computational-security experiment and do not establish LWE, SIS, or QPT hardness.

---

## 11. Next handoff

The highest-value next target is no longer another source-gap gadget. The source side
now has a concrete route to a constant affine norm gap.

Audit the **uniform-carrier embedding** directly:

- generate a statistically uniform `A` with an erased lattice trapdoor;
- sample/publicize whatever short lift is needed to map the gap-amplified source
  representation into `A`;
- analyze the *complete* auxiliary distribution, especially transforms such as
  `R^T b=M^T s+R^T e`;
- either give a straight-line QPT reduction to standard LWE/SIS, or exhibit a public
  structured-sample attack;
- quantify whether the constant l1/l2^2 gap survives the lift strongly enough for
  correctness-vs-pseudowitness separation.

A proof that `A` alone is uniform is not sufficient if public short lifting data makes
its associated LWE sample nonstandard.
