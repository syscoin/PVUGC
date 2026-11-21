# Run 58 — signed-permutation transport removes the modular denominator gap but enables column-wise public routing

**Status:** constructive follow-up to Run 57. This run tests the most natural modular/noise-stable realization left open by the Run-57 row-span theorem: make every branch transition a signed permutation so every honest witness evaluator has integral `0,±1` coefficients and never amplifies iid small error. The complete-output audit rejects that realization. This is **not** a generic impossibility theorem for modular affine transport, is **not** an attack on standard LWE, and is **not** a completed witness KEM.

Starting verified PR head: `c0ade8c974beb595148f4fae73b878a3b7263e87` (Run 57). The Run-57 exact row-span theorem and modular short-evaluator gap were read before this pass. No external literature or web search was used. Production code is unchanged.

## 1. Constructive escape hatch tested

Run 57 proved that for the complete affine transport

\[
C_{i,b}=R_{i+1}-R_iA_{i,b}+E_{i,b},
\]

a true path always implies a **public** exact endpoint evaluator. What remained open over `Z_q` was quantitative: public Gaussian elimination can return rational/modular coefficients whose centered representatives are huge, while a real witness path gives a structured short evaluator. The real least-norm theorem does not remove that modular denominator issue.

The natural repair is therefore to choose every branch matrix

\[
A_{i,b}\in\{0,\pm1\}^{d\times d}
\]

to be a **signed permutation matrix**. Then every suffix product is again signed permutation. An honest path evaluator uses only `0,±1` coefficients, has no modular denominators, and maps iid small errors to iid small errors without Euclidean amplification.

This looks like a plausible way to turn the remaining modular short-evaluator gap into a source-binding mechanism: perhaps finding a short endpoint evaluator would require finding the one common witness path.

It does not. The complete public transcript permits **column-wise path splicing**.

## 2. Public column-routing theorem

Let

\[
A(w)=A_{0,w_0}A_{1,w_1}\cdots A_{L-1,w_{L-1}},
\]

and let the public target be a signed permutation `T`. A source witness is one **common** word

\[
w\in\{0,1\}^L,\qquad A(w)=T. \tag{1}
\]

As in Run 57, define a matrix-valued evaluator

\[
Q(C)=\sum_{i=0}^{L-1}\sum_{b\in\{0,1\}} C_{i,b}Q_{i,b}. \tag{2}
\]

The endpoint identity

\[
Q M_A=\mathcal L_T,\qquad
\mathcal L_T(R)=R_L-R_0T \tag{3}
\]

is equivalent to

\[
\sum_b Q_{L-1,b}=I, \tag{4}
\]

\[
\sum_b Q_{i-1,b}=\sum_b A_{i,b}Q_{i,b}
\quad (1\le i\le L-1), \tag{5}
\]

and

\[
\sum_b A_{0,b}Q_{0,b}=T. \tag{6}
\]

Because each `A_{i,b}` maps a signed basis vector to a signed basis vector, solve these equations **one target column at a time**.

For target column `j`, set

\[
v_L=e_j,\qquad v_0=Te_j.
\]

Find branch bits `b_i^{(j)}` and signed basis states `v_i` such that

\[
v_i=A_{i,b_i^{(j)}}v_{i+1}. \tag{7}
\]

This is ordinary reachability in a layered graph having only `2d` signed-basis states per layer and two outgoing labeled transitions per state. Dynamic programming finds a route in polynomial time whenever one exists.

Now define

\[
Q_{i,b}e_j=
\begin{cases}
v_{i+1},& b=b_i^{(j)},\\
0,&\text{otherwise}.
\end{cases} \tag{8}
\]

For this column, (4) gives `v_L=e_j`, every interior coefficient in (5) is

\[
v_i-A_{i,b_i^{(j)}}v_{i+1}=0,
\]

and (6) gives

\[
A_{0,b_0^{(j)}}v_1=v_0=Te_j.
\]

Therefore:

> **Column-routing theorem.** If every target column `Te_j` is individually reachable from `e_j` through the public signed-permutation layers, then polynomial-time public routing constructs an endpoint evaluator `Q` satisfying
>
> \[
> \boxed{Q M_A=\mathcal L_T}
> \]
>
> whose coefficients are all in `{0,±1}`, with exactly one nonzero coefficient per output column per layer.

A true instance automatically satisfies the premise: its common witness word supplies an individual route for every column. The public algorithm does **not** need to recover that common word and may choose a different branch word for each column.

The checker generated 600 random true `d=4,L=10` programs. It recovered the exact endpoint in **600/600** cases. In **590/600** fixtures the synthesized column routes were not all the same branch word. Thus even on true instances the short public evaluator usually produced by this deterministic routing rule did not correspond to one source witness word.

## 3. Exact false instance: every column is reachable but no common witness exists

The distinction is not merely philosophical. There are false targets with no common path but with all columns independently reachable.

Take `d=2,L=2` and

\[
A_{0,0}=
\begin{pmatrix}0&1\\1&0\end{pmatrix},
\qquad
A_{0,1}=
\begin{pmatrix}0&-1\\-1&0\end{pmatrix},
\]

\[
A_{1,0}=I,
\qquad
A_{1,1}=
\begin{pmatrix}0&-1\\-1&0\end{pmatrix}.
\]

The four common path products are

\[
\left\{
\begin{pmatrix}0&1\\1&0\end{pmatrix},
-I,
\begin{pmatrix}0&-1\\-1&0\end{pmatrix},
I
\right\}.
\]

Choose

\[
T=
\begin{pmatrix}0&-1\\1&0\end{pmatrix}. \tag{9}
\]

No common word reaches `T`.

But column 0 is reached by word `(0,0)`:

\[
A(0,0)e_0=e_1=Te_0,
\]

while column 1 is reached by the different word `(1,0)`:

\[
A(1,0)e_1=-e_0=Te_1.
\]

The public column-routing evaluator therefore satisfies (3) even though the source statement is false.

If generic statement-only setup programs

\[
R_L=R_0T+S_K, \tag{10}
\]

then on the exact public transcript

\[
\boxed{Q(C)=S_K} \tag{11}
\]

with no source witness.

The fresh checker sampled 1,000 independent hidden-frame/key-carrier choices for this false target and recovered the exact arbitrary matrix `S_K` in **1000/1000** cases.

### Exhaustive small census

This false fixture is not isolated. The checker exhaustively enumerated:

* all `8^4=4096` binary-branch `d=2,L=2` signed-permutation programs;
* all eight signed-permutation targets for each program.

After excluding true targets, there are **19,264** false `(program,target)` pairs. Of these, **3,456** still have a column-wise public endpoint evaluator, and **1,088 / 4,096** programs have at least one such false target.

This is an exact finite census, not a complexity asymptotic.

## 4. Noisy transcript: the public evaluator has the same scalar error law as an honest path

Now publish

\[
C_{i,b}=R_{i+1}-R_iA_{i,b}+E_{i,b}. \tag{12}
\]

Fix an output column `j` and output row `r`. The column-routing evaluator gives

\[
(QE)_{r,j}
=
\sum_{i=0}^{L-1}
\pm E_{i,b_i^{(j)}}[r,k_i], \tag{13}
\]

because at each layer `Q` selects exactly one signed basis coordinate.

If the scalar transcript errors are iid from a distribution symmetric under sign, then the `L` summands in (13) are independent and each has exactly the base error law. Therefore

\[
\boxed{(QE)_{r,j}\ \stackrel{d}{=}\ E_1+\cdots+E_L.} \tag{14}
\]

An honest common-path evaluator in a signed-permutation program has exactly the same structure: every suffix matrix is signed permutation, so every output coordinate is also a sum of one signed scalar error from each layer. Hence its scalar marginal has the **same** law (14).

For deterministic bounded error `|E|\le B`, both public and honest evaluators obey the same bound

\[
|(QE)_{r,j}|\le LB. \tag{15}
\]

This removes the precise Run-57 modular loophole for this candidate class: the public evaluator uses integral `±1` coefficients, so there is no denominator-to-large-residue conversion.

### Exact ternary control

For a fresh `d=4,L=8` true program, the checker extracted the public and honest coefficient signs for one designated output entry and exhaustively enumerated all `3^8=6561` iid ternary error vectors. The two exact histograms were identical:

`{-8:1,-7:8,-6:36,-5:112,-4:266,-3:504,-2:784,-1:1016,0:1107,1:1016,2:784,3:504,4:266,5:112,6:36,7:8,8:1}`.

With `q=257`, binary phase `128`, and ternary transcript error, the deterministic bound is eight. The checker then executed 5,000 fresh noisy true-instance trials: the public route decoded **5000/5000** and the honest path decoded **5000/5000**.

### Noisy false control

For the explicit false target (9), take

\[
S_K=128K\,I\pmod{257}
\]

and ternary transcript error. The public route uses only `L=2` scalar errors for each designated diagonal entry, so its absolute centered error is at most two while the binary centers are 128 apart. Thus decoding is deterministic for **every** such bounded error realization.

The checker sampled 5,000 fresh setups/errors/key bits and recovered the false-statement key **5000/5000** times; the maximum observed centered error was two.

This is a complete-output false-instance break of the signed-permutation realization. It does not solve an LWE problem; it exploits a public short transport relation.

## 5. Rigidity: exact integral Euclidean nonexpansiveness is exactly the attacked class

There is a reason signed permutations are the natural Run-57 repair.

Let

\[
A\in\mathbb Z^{d\times d}
\]

have full rank over the reals and satisfy

\[
\|A\|_{2\to2}\le1. \tag{16}
\]

For every standard basis column,

\[
\|Ae_j\|_2\le1.
\]

A nonzero integer vector has Euclidean norm at least one, so every column `Ae_j` must be exactly a signed basis vector. Full rank forces those basis coordinates to be distinct. Therefore:

> **Integral nonexpansive rigidity lemma.**
>
> Every full-rank integer matrix with Euclidean operator norm at most one is a signed permutation matrix.

So within centered integral lifts, **exact** Euclidean nonexpansiveness forces precisely the transport family broken above.

The checker exhaustively enumerated all matrices over `{-1,0,1}` for dimensions two and three. The full-rank matrices whose integer columns all have norm at most one were exactly the `8` and `48` signed permutations respectively.

This lemma does **not** cover:

* modular transitions whose useful centered lift has operator norm greater than one but whose products/noise are controlled by another mechanism;
* non-Euclidean or correlated noise shaping;
* nonlinear/computational transport;
* or a standard-assumption construction in which the complete short-evaluator problem remains hard.

## 6. What this proves and what it does not

### Proved in this run

1. Signed-permutation affine transport admits a polynomial-time public `0,±1` endpoint evaluator on every true target.
2. The evaluator can splice **different branch words by output column**; it need not encode one source witness.
3. There are explicit and exhaustively witnessed false targets with no common branch word but with a public short endpoint evaluator.
4. For iid symmetric scalar transcript noise, each public output coordinate has exactly the same `L`-fold error marginal as an honest signed-permutation path; bounded-error magnitude has the same `LB` bound.
5. Full-rank integral Euclidean-nonexpansive transitions are necessarily signed permutations.

### Not proved

This run does **not** prove that every modular affine transport has a short public evaluator. In particular it does not settle transitions with centered norms greater than one, dense modular mixing, correlated/noise-shaped transcripts, or nonlinear/computational binders.

It also does not prove an attack on standard LWE/SIS. No generic LWE secret is recovered. The attack is a public structural evaluator specific to this transport construction.

Finally, nothing here gives the required arbitrary-QPT early-key-recovery -> source-witness / independent-PQ-break reduction for a surviving construction.

## 7. Validation actually executed

`signed_permutation_transport_run58_check.py` is deterministic and standard-library-only. After finalization it was executed twice and the captured JSON outputs were byte-identical.

Recorded controls:

* explicit false `d=2,L=2`: no common path; 1,000/1,000 exact endpoint recoveries;
* 600 random true `d=4,L=10`: 600/600 exact endpoint recoveries, with 590/600 synthesized route families using more than one branch word across columns;
* exhaustive `d=2,L=2` census: 19,264 false `(program,target)` pairs, 3,456 with a column-wise public evaluator, 1,088 programs with at least one such false target;
* exact ternary `L=8` scalar-noise histogram equality over all 6,561 error vectors;
* 5,000/5,000 public and 5,000/5,000 honest noisy true-instance decodes;
* 5,000/5,000 noisy false-instance public key recoveries;
* exhaustive rigidity controls over 81 two-dimensional and 19,683 three-dimensional `{-1,0,1}` matrices, yielding exactly 8 and 48 qualifying signed permutations.

Checker SHA-256:

`5a1534d31ad6cc233315c1355e91e19fc1a11bdfd8c05d1a3c73e33f46c90843`

Captured validation SHA-256:

`d2cc101ef8c2fb6b2008acfaec6664ff2b7137eca9e2005693e661329211152d`

These tests validate the finite algebra and implementation. They are not evidence that any surviving construction is secure.

## 8. Handoff

The signed-permutation/noise-isometry route is rejected. Run 57's modular short-evaluator gap therefore cannot be solved simply by making the witness suffix products exact integral isometries.

A surviving affine route would have to use transitions outside this rigidity class while simultaneously satisfying all of the following:

1. every valid witness still gives coefficients short enough for reliable modular decoding;
2. public complete-output synthesis does **not** admit equally short coordinate-spliced evaluators;
3. false targets do not acquire short evaluators through a relaxation analogous to column-wise reachability;
4. hardness of finding a decoding-useful public evaluator reduces to an independently justified PQ assumption rather than a newly named short-evaluator assumption; and
5. arbitrary QPT early recovery of the final key is converted to a source witness or that independent assumption break.

The broader alternative remains to leave affine transport entirely and construct a genuinely nonlinear/computational source-witness-selective evaluator. Malicious-secure erased-setup composition and concrete end-to-end parameters remain downstream of a surviving inner primitive.

The stopping condition is **not met**.
